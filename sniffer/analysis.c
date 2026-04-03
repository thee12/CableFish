/*
 * analysis.c — Anomaly detection engine implementation
 *
 * Phase 4 change: individual static detectors now return alert_type_t
 * (ALERT_NONE if they did not fire). check_anomalies() collects all
 * return values and returns the highest-priority non-NONE result.
 *
 * Console alert output (printf) is unchanged — all detectors that trigger
 * still print to stdout immediately. The return value is an ADDITIONAL
 * signal used by parse.c to populate the log record; it does not replace
 * or suppress console output.
 *
 * Internal call chain:
 *   check_anomalies()
 *     ├── detect_syn_scan()        → alert_type_t
 *     ├── detect_dns_anomaly()     → alert_type_t
 *     └── detect_high_traffic()   → alert_type_t
 */

#include "analysis.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>   /* TH_SYN, TH_ACK */

/* ============================================================
 * Per-IP tracker table — internal
 * ============================================================ */

static ip_tracker_t *lookup_or_create_tracker(ip_table_t *tbl, uint32_t ip)
{
    uint32_t idx = fnv1a32(&ip, sizeof(ip)) & IP_TABLE_MASK;

    for (ip_tracker_t *t = tbl->buckets[idx]; t != NULL; t = t->next) {
        if (t->ip == ip) return t;
    }

    ip_tracker_t *t = (ip_tracker_t *)calloc(1, sizeof(ip_tracker_t));
    if (t == NULL) {
        fprintf(stderr, "Error: calloc failed for ip_tracker_t\n");
        return NULL;
    }
    t->ip             = ip;
    t->next           = tbl->buckets[idx];
    tbl->buckets[idx] = t;
    return t;
}

/* ============================================================
 * DNS QNAME parser (RFC 1035 §3.1)
 *
 * Returns the human-readable domain name length in characters,
 * or -1 if the payload is a response, malformed, or too short.
 * ============================================================ */
static int dns_qname_len(const uint8_t *payload, int payload_len)
{
    if (payload_len < MIN_DNS_HDR_LEN) return -1;

    uint16_t flags   = ((uint16_t)payload[2] << 8) | payload[3];
    if (flags & 0x8000) return -1;   /* QR=1: response, not a query */

    uint16_t qdcount = ((uint16_t)payload[4] << 8) | payload[5];
    if (qdcount == 0) return -1;

    const uint8_t *ptr      = payload + MIN_DNS_HDR_LEN;
    int            remaining = payload_len - MIN_DNS_HDR_LEN;
    int            name_len  = 0;
    int            first     = 1;

    while (remaining > 0) {
        uint8_t label_len = *ptr;
        if (label_len == 0)                  break;  /* root label: end */
        if ((label_len & 0xC0) == 0xC0)      break;  /* compression pointer */
        if ((int)(1 + label_len) > remaining) break;  /* truncated */

        if (!first) name_len++;   /* dot separator */
        name_len += label_len;
        first = 0;

        ptr       += 1 + label_len;
        remaining -= 1 + label_len;
    }
    return name_len;
}

/* ============================================================
 * Detector: SYN scan
 *
 * Returns ALERT_SYN_SCAN when the threshold is crossed and the cooldown
 * has elapsed; ALERT_NONE otherwise.
 *
 * Counts pure SYN packets (SYN set, ACK clear) per source IP across all
 * flows. A scanner probes many ports, each producing a separate flow with
 * syn_count=1; only the IP-level aggregate reveals the pattern.
 * ============================================================ */
static alert_type_t detect_syn_scan(const packet_info_t *pkt, ip_table_t *trackers)
{
    if (pkt->proto != IPPROTO_TCP) return ALERT_NONE;
    if (!(pkt->tcp_flags & TH_SYN)) return ALERT_NONE;
    if (  pkt->tcp_flags & TH_ACK)  return ALERT_NONE;

    ip_tracker_t *t = lookup_or_create_tracker(trackers, pkt->src_ip);
    if (t == NULL) return ALERT_NONE;

    /* Reset counter if current packet is outside the current window */
    if (t->syn_count == 0 ||
        timeval_diff_secs(&pkt->ts, &t->syn_window_start) > THRESH_SYN_WINDOW_SECS) {
        t->syn_count        = 0;
        t->syn_window_start = pkt->ts;
    }

    t->syn_count++;

    if (t->syn_count >= THRESH_SYN_COUNT) {
        double since = timeval_diff_secs(&pkt->ts, &t->last_syn_alert);
        if (t->last_syn_alert.tv_sec == 0 || since >= ALERT_COOLDOWN_SECS) {
            char src[INET_ADDRSTRLEN];
            ip_to_str(pkt->src_ip, src, sizeof(src));
            printf("ALERT SYN_SCAN SRC_IP=%s COUNT=%u\n", src, t->syn_count);
            fflush(stdout);
            t->last_syn_alert   = pkt->ts;
            t->syn_count        = 0;
            t->syn_window_start = pkt->ts;
            return ALERT_SYN_SCAN;
        }
    }
    return ALERT_NONE;
}

/* ============================================================
 * Detector: DNS anomaly
 *
 * Two independent sub-signals:
 *   LONG_DOMAIN — single query for a name > THRESH_DNS_NAME_LEN chars.
 *                 Returns ALERT_DNS_ANOMALY_LONG immediately on detection.
 *   HIGH_FREQ   — > THRESH_DNS_FREQ_COUNT queries in a sliding window.
 *                 Returns ALERT_DNS_ANOMALY_FREQ when threshold crossed.
 *
 * If both fire in the same call, LONG_DOMAIN takes precedence (checked
 * first). Both still print their own console alert lines.
 * ============================================================ */
static alert_type_t detect_dns_anomaly(const packet_info_t *pkt, ip_table_t *trackers)
{
    if (pkt->proto != IPPROTO_UDP)                              return ALERT_NONE;
    if (pkt->dst_port != DNS_PORT && pkt->src_port != DNS_PORT) return ALERT_NONE;
    if (pkt->src_port == DNS_PORT)                              return ALERT_NONE; /* response */

    ip_tracker_t *t = lookup_or_create_tracker(trackers, pkt->src_ip);
    if (t == NULL) return ALERT_NONE;

    char src[INET_ADDRSTRLEN];
    ip_to_str(pkt->src_ip, src, sizeof(src));

    alert_type_t result = ALERT_NONE;

    /* --- Sub-signal 1: long domain name --------------------------------- */
    if (pkt->transport_payload != NULL &&
        pkt->transport_payload_len >= MIN_DNS_HDR_LEN) {
        int nlen = dns_qname_len(pkt->transport_payload,
                                 pkt->transport_payload_len);
        if (nlen > THRESH_DNS_NAME_LEN) {
            double since = timeval_diff_secs(&pkt->ts, &t->last_dns_alert);
            if (t->last_dns_alert.tv_sec == 0 || since >= ALERT_COOLDOWN_SECS) {
                printf("ALERT DNS_ANOMALY SRC_IP=%s DETAIL=LONG_DOMAIN LEN=%d\n",
                       src, nlen);
                fflush(stdout);
                t->last_dns_alert = pkt->ts;
                result = ALERT_DNS_ANOMALY_LONG;
            }
        }
    }

    /* --- Sub-signal 2: high query frequency ----------------------------- */
    if (t->dns_count == 0 ||
        timeval_diff_secs(&pkt->ts, &t->dns_window_start) > THRESH_DNS_WINDOW_SECS) {
        t->dns_count        = 0;
        t->dns_window_start = pkt->ts;
    }
    t->dns_count++;

    if (t->dns_count >= THRESH_DNS_FREQ_COUNT) {
        double since = timeval_diff_secs(&pkt->ts, &t->last_dns_alert);
        if (t->last_dns_alert.tv_sec == 0 || since >= ALERT_COOLDOWN_SECS) {
            printf("ALERT DNS_ANOMALY SRC_IP=%s DETAIL=HIGH_FREQ COUNT=%u\n",
                   src, t->dns_count);
            fflush(stdout);
            t->last_dns_alert   = pkt->ts;
            t->dns_count        = 0;
            t->dns_window_start = pkt->ts;
            /* HIGH_FREQ only overwrites result if no LONG_DOMAIN fired */
            if (result == ALERT_NONE) result = ALERT_DNS_ANOMALY_FREQ;
        }
    }

    return result;
}

/* ============================================================
 * Detector: high traffic volume
 *
 * Returns ALERT_HIGH_TRAFFIC when a single flow's byte total exceeds
 * THRESH_HIGH_BYTES and the per-flow cooldown has elapsed.
 * ============================================================ */
static alert_type_t detect_high_traffic(flow_entry_t *flow, const packet_info_t *pkt)
{
    if (flow->total_bytes < THRESH_HIGH_BYTES) return ALERT_NONE;

    double since = timeval_diff_secs(&pkt->ts, &flow->last_alert_time);
    if (flow->last_alert_time.tv_sec != 0 && since < ALERT_COOLDOWN_SECS)
        return ALERT_NONE;

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    ip_to_str(flow->key.src_ip, src, sizeof(src));
    ip_to_str(flow->key.dst_ip, dst, sizeof(dst));

    printf("ALERT HIGH_TRAFFIC FLOW %s:%u <-> %s:%u BYTES=%" PRIu64 "\n",
           src, flow->key.src_port,
           dst, flow->key.dst_port,
           flow->total_bytes);
    fflush(stdout);

    flow->last_alert_time = pkt->ts;
    return ALERT_HIGH_TRAFFIC;
}

/* ============================================================
 * Public API
 * ============================================================ */

void analysis_init(ip_table_t *tbl)
{
    memset(tbl, 0, sizeof(*tbl));
}

void analysis_free(ip_table_t *tbl)
{
    for (int i = 0; i < IP_TABLE_SIZE; i++) {
        ip_tracker_t *curr = tbl->buckets[i];
        while (curr != NULL) {
            ip_tracker_t *next = curr->next;
            free(curr);
            curr = next;
        }
        tbl->buckets[i] = NULL;
    }
}

/*
 * check_anomalies — central dispatch; returns the highest-priority alert.
 *
 * Priority order (checked last = highest priority, overwrites earlier):
 *   SYN_SCAN < DNS_ANOMALY < HIGH_TRAFFIC
 *
 * All detectors are always called regardless of earlier results so that
 * console alerts fire for every detector that triggers. The return value
 * only reflects the highest-priority one for the log record.
 */
alert_type_t check_anomalies(flow_entry_t        *flow,
                             const packet_info_t *pkt,
                             ip_table_t          *trackers)
{
    alert_type_t result = ALERT_NONE;
    alert_type_t a;

    a = detect_syn_scan(pkt, trackers);
    if (a != ALERT_NONE) result = a;

    a = detect_dns_anomaly(pkt, trackers);
    if (a != ALERT_NONE) result = a;

    /* HIGH_TRAFFIC checked last — highest priority, overwrites any prior */
    a = detect_high_traffic(flow, pkt);
    if (a != ALERT_NONE) result = a;

    return result;
}
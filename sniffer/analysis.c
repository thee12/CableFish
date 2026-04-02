/*
 * analysis.c — Anomaly detection engine implementation
 *
 * Internal structure:
 *   lookup_or_create_tracker()  — per-IP state table management (static)
 *   dns_qname_len()             — DNS wire-format QNAME parser (static)
 *   detect_syn_scan()           — SYN scan detector (static)
 *   detect_dns_anomaly()        — DNS anomaly detector (static)
 *   detect_high_traffic()       — High traffic detector (static)
 *   check_anomalies()           — public dispatch, calls all three
 */

#include "analysis.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>      /* INET_ADDRSTRLEN */
#include <netinet/in.h>     /* IPPROTO_TCP, IPPROTO_UDP */
#include <netinet/tcp.h>    /* TH_SYN, TH_ACK           */

/* ================================================================
 * Per-IP tracker table — internal only
 * ================================================================ */

/*
 * lookup_or_create_tracker — find or allocate an ip_tracker_t for `ip`.
 *
 * The IP address is hashed directly (4 bytes) using FNV-1a for the bucket
 * index. New trackers are calloc'd so all counters and timestamps start at
 * zero; tv_sec == 0 is used as the "never fired" sentinel for alerts.
 */
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

/* ================================================================
 * DNS QNAME parser
 *
 * DNS query wire format (RFC 1035 §3.1):
 *   Fixed 12-byte header followed by one or more questions.
 *   QNAME: sequence of length-prefixed labels ending with a zero byte.
 *     Example: \x03www\x06google\x03com\x00 → "www.google.com" (14 chars)
 *
 * Returns the character count of the domain name, or -1 if:
 *   - payload is too short for the DNS header
 *   - the QR bit is set (packet is a response, not a query)
 *   - QDCOUNT == 0 (no questions)
 *   - a compression pointer is encountered (safe abort; uncommon in queries)
 * ================================================================ */
static int dns_qname_len(const uint8_t *payload, int payload_len)
{
    if (payload_len < MIN_DNS_HDR_LEN) return -1;

    /*
     * DNS flags field at bytes [2..3].
     * Bit 15 (QR): 0 = query, 1 = response.
     * We only analyse queries.
     */
    uint16_t flags   = ((uint16_t)payload[2] << 8) | payload[3];
    if (flags & 0x8000) return -1;

    /* QDCOUNT at bytes [4..5] */
    uint16_t qdcount = ((uint16_t)payload[4] << 8) | payload[5];
    if (qdcount == 0) return -1;

    /* QNAME starts immediately after the 12-byte DNS header */
    const uint8_t *ptr       = payload + MIN_DNS_HDR_LEN;
    int            remaining  = payload_len - MIN_DNS_HDR_LEN;
    int            name_len   = 0;
    int            first      = 1;

    while (remaining > 0) {
        uint8_t label_len = *ptr;

        if (label_len == 0) {
            break;  /* root label: end of QNAME */
        }

        if ((label_len & 0xC0) == 0xC0) {
            /* Compression pointer — safe to stop here */
            break;
        }

        if ((int)(1 + label_len) > remaining) {
            break;  /* truncated packet */
        }

        if (!first) name_len++;  /* dot separator between labels */
        name_len += label_len;
        first = 0;

        ptr       += 1 + label_len;
        remaining -= 1 + label_len;
    }

    return name_len;
}

/* ================================================================
 * Detector: SYN scan
 *
 * Counts pure TCP SYN packets (SYN set, ACK clear — connection initiations)
 * per SOURCE IP across all flows. A port scanner sends one SYN per target
 * port, each creating a separate flow; aggregating at IP level reveals it.
 *
 * Sliding window:
 *   If the current packet arrives more than THRESH_SYN_WINDOW_SECS after
 *   the window opened, the counter resets and the window restarts.
 *
 * Alert suppression:
 *   After firing, counter and window reset so the next window starts fresh.
 *   The ALERT_COOLDOWN_SECS gap prevents alert floods during a long scan.
 * ================================================================ */
static void detect_syn_scan(const packet_info_t *pkt, ip_table_t *trackers)
{
    /* Only pure SYN packets (connection initiation, not SYN-ACK) */
    if (pkt->proto != IPPROTO_TCP)         return;
    if (!(pkt->tcp_flags & TH_SYN))        return;
    if (  pkt->tcp_flags & TH_ACK)         return;

    ip_tracker_t *t = lookup_or_create_tracker(trackers, pkt->src_ip);
    if (t == NULL) return;

    /* Reset counter if outside the current sliding window */
    if (t->syn_count == 0 ||
        timeval_diff_secs(&pkt->ts, &t->syn_window_start) > THRESH_SYN_WINDOW_SECS) {
        t->syn_count        = 0;
        t->syn_window_start = pkt->ts;
    }

    t->syn_count++;

    if (t->syn_count >= THRESH_SYN_COUNT) {
        double since_last = timeval_diff_secs(&pkt->ts, &t->last_syn_alert);
        if (t->last_syn_alert.tv_sec == 0 || since_last >= ALERT_COOLDOWN_SECS) {
            char src[INET_ADDRSTRLEN];
            ip_to_str(pkt->src_ip, src, sizeof(src));
            printf("ALERT SYN_SCAN SRC_IP=%s COUNT=%u\n", src, t->syn_count);
            fflush(stdout);
            t->last_syn_alert    = pkt->ts;
            /* Reset so next window starts clean after the alert */
            t->syn_count         = 0;
            t->syn_window_start  = pkt->ts;
        }
    }
}

/* ================================================================
 * Detector: DNS anomaly
 *
 * Two independent signals, both tracked per source IP:
 *
 *   LONG_DOMAIN — a single query for a domain name exceeding
 *     THRESH_DNS_NAME_LEN characters. Long encoded subdomains are the
 *     primary indicator of DNS tunnelling (data exfiltration via QNAME).
 *     One long query is enough; no sliding window needed.
 *
 *   HIGH_FREQ — more than THRESH_DNS_FREQ_COUNT queries within
 *     THRESH_DNS_WINDOW_SECS. Indicates DNS-based C2 callbacks, domain
 *     generation algorithm (DGA) activity, or aggressive resolver behaviour.
 *
 * Both checks share the same last_dns_alert cooldown timestamp to avoid
 * producing two simultaneous alerts for the same event.
 * ================================================================ */
static void detect_dns_anomaly(const packet_info_t *pkt, ip_table_t *trackers)
{
    /* Only UDP to port 53 (queries from clients; skip responses) */
    if (pkt->proto != IPPROTO_UDP)                         return;
    if (pkt->dst_port != DNS_PORT && pkt->src_port != DNS_PORT) return;
    if (pkt->src_port == DNS_PORT)                         return;

    ip_tracker_t *t = lookup_or_create_tracker(trackers, pkt->src_ip);
    if (t == NULL) return;

    char src[INET_ADDRSTRLEN];
    ip_to_str(pkt->src_ip, src, sizeof(src));

    /* --- Signal 1: unusually long domain name -------------------------------- */
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
            }
        }
    }

    /* --- Signal 2: high query frequency ------------------------------------- */
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
            t->last_dns_alert    = pkt->ts;
            t->dns_count         = 0;
            t->dns_window_start  = pkt->ts;
        }
    }
}

/* ================================================================
 * Detector: high traffic volume
 *
 * Fires when a single bidirectional flow exceeds THRESH_HIGH_BYTES in
 * total bytes. Operates directly on the flow_entry_t (no secondary table
 * lookup). The per-flow last_alert_time prevents repeated alerts for the
 * same ongoing transfer within the cooldown window.
 * ================================================================ */
static void detect_high_traffic(flow_entry_t *flow, const packet_info_t *pkt)
{
    if (flow->total_bytes < THRESH_HIGH_BYTES) return;

    double since = timeval_diff_secs(&pkt->ts, &flow->last_alert_time);
    if (flow->last_alert_time.tv_sec != 0 && since < ALERT_COOLDOWN_SECS) return;

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    ip_to_str(flow->key.src_ip, src, sizeof(src));
    ip_to_str(flow->key.dst_ip, dst, sizeof(dst));

    printf("ALERT HIGH_TRAFFIC FLOW %s:%u <-> %s:%u BYTES=%" PRIu64 "\n",
           src, flow->key.src_port,
           dst, flow->key.dst_port,
           flow->total_bytes);
    fflush(stdout);

    flow->last_alert_time = pkt->ts;
}

/* ================================================================
 * Public API
 * ================================================================ */

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
 * check_anomalies — central dispatch, called once per packet.
 *
 * Each detector is independent. A packet may trigger multiple alerts
 * (e.g. a DNS tunnelling packet could fire both LONG_DOMAIN and HIGH_FREQ).
 * Called AFTER the flow entry has been updated so byte/packet counts are
 * current when detect_high_traffic inspects them.
 */
void check_anomalies(flow_entry_t *flow,
                     const packet_info_t *pkt,
                     ip_table_t *trackers)
{
    detect_syn_scan(pkt, trackers);
    detect_dns_anomaly(pkt, trackers);
    detect_high_traffic(flow, pkt);
}

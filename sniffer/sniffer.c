/*
 * sniffer.c — Packet Sniffer with Flow Tracking + Anomaly Detection (Phase 3)
 *
 * Extends Phase 2 (bidirectional flow tracking) with a lightweight, rule-based
 * analysis engine that detects three categories of anomalous behaviour:
 *
 *   A. SYN Scan     — many TCP SYN packets from one source with few ACKs,
 *                     indicating a port scanner probing for open services.
 *
 *   B. DNS Anomaly  — unusually long domain names (possible DNS tunnelling)
 *                     or a high query rate from one source (possible DGA/C2).
 *
 *   C. High Traffic — a single flow exceeding a byte volume threshold,
 *                     indicating a large transfer or exfiltration attempt.
 *
 * Detection uses two independent hash tables:
 *   g_flow_table  — bidirectional flows (from Phase 2), extended with TCP flag
 *                   counters and an alert cooldown timestamp.
 *   g_ip_table    — per-source-IP state for SYN and DNS frequency tracking,
 *                   which require aggregation across many flows.
 *
 * All thresholds are defined as macros at the top and can be tuned without
 * touching any logic.
 *
 * Build:
 *   gcc -Wall -std=gnu99 sniffer.c -lpcap -o sniffer
 *
 * Run:
 *   sudo ./sniffer
 *   sudo ./sniffer <interface>
 *
 * Alert output format:
 *   ALERT SYN_SCAN    SRC_IP=X.X.X.X COUNT=N
 *   ALERT DNS_ANOMALY SRC_IP=X.X.X.X DETAIL=LONG_DOMAIN|HIGH_FREQ
 *   ALERT HIGH_TRAFFIC FLOW A.B.C.D:P <-> W.X.Y.Z:Q BYTES=N
 */

/* ============================================================
 * SECTION 1 — Headers
 * ============================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <inttypes.h>

#include <pcap.h>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/time.h>

/* ============================================================
 * SECTION 2 — Tunable thresholds and constants
 *
 * All detection thresholds live here. Adjust these without touching
 * any detection logic.
 * ============================================================ */

/* --- Packet capture ---------------------------------------- */
#define SNAPLEN                 65535
#define PCAP_TIMEOUT_MS         1000

/* --- Flow table -------------------------------------------- */
#define FLOW_TABLE_SIZE         1024        /* must be power of two */
#define FLOW_TABLE_MASK         (FLOW_TABLE_SIZE - 1)
#define FLOW_TIMEOUT_SECS       60.0        /* idle flow expiry     */

/* --- Per-IP tracker table ---------------------------------- */
#define IP_TABLE_SIZE           512         /* must be power of two */
#define IP_TABLE_MASK           (IP_TABLE_SIZE - 1)

/* --- SYN scan detection ------------------------------------ */
#define THRESH_SYN_COUNT        10          /* SYNs before alert    */
#define THRESH_SYN_WINDOW_SECS  10.0        /* sliding window (s)   */

/* --- DNS anomaly detection --------------------------------- */
#define THRESH_DNS_NAME_LEN     50          /* chars in domain name */
#define THRESH_DNS_FREQ_COUNT   20          /* queries per window   */
#define THRESH_DNS_WINDOW_SECS  10.0        /* sliding window (s)   */
#define DNS_PORT                53

/* --- High traffic detection -------------------------------- */
#define THRESH_HIGH_BYTES       (1024ULL * 1024ULL)  /* 1 MB per flow */

/* --- Alert spam prevention --------------------------------- */
#define ALERT_COOLDOWN_SECS     10.0        /* min gap between same alert */

/* --- Header minimums --------------------------------------- */
#define MIN_ETHER_LEN           (int)sizeof(struct ethhdr)
#define MIN_IP_HDR_LEN          20
#define MIN_TCP_HDR_LEN         (int)sizeof(struct tcphdr)
#define MIN_UDP_HDR_LEN         (int)sizeof(struct udphdr)
#define MIN_DNS_HDR_LEN         12          /* fixed DNS header (RFC 1035) */

/* ============================================================
 * SECTION 3 — Data structures
 * ============================================================ */

/*
 * packet_info_t — parsed metadata for one captured packet.
 *
 * Populated once during parsing and threaded through the call chain so that
 * every downstream system (flow tracking, anomaly detection) can read all
 * relevant fields without re-parsing.
 *
 * transport_payload / transport_payload_len point directly into the libpcap
 * buffer — valid only for the duration of the packet_handler callback.
 */
typedef struct {
    uint32_t        src_ip;               /* host byte order */
    uint32_t        dst_ip;               /* host byte order */
    uint16_t        src_port;
    uint16_t        dst_port;
    uint8_t         proto;                /* IPPROTO_TCP or IPPROTO_UDP */
    uint8_t         tcp_flags;            /* raw TCP flags byte         */
    uint32_t        pkt_len;              /* wire length in bytes       */
    struct timeval  ts;                   /* kernel capture timestamp   */
    const u_char   *transport_payload;    /* first byte past transport hdr */
    int             transport_payload_len;
} packet_info_t;

/*
 * flow_key_t — normalised 5-tuple identifying a bidirectional flow.
 * All fields in host byte order after normalisation.
 */
typedef struct {
    uint32_t src_ip;    /* lower IP  */
    uint32_t dst_ip;    /* higher IP */
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
} flow_key_t;

/*
 * flow_entry_t — per-flow state, including Phase 3 additions.
 *
 * Phase 3 additions (marked with [P3]):
 *   syn_count       — SYN packets seen on this flow (either direction).
 *   ack_count       — ACK packets seen on this flow (either direction).
 *   last_alert_time — when the most recent HIGH_TRAFFIC alert fired;
 *                     used to suppress repeat alerts within ALERT_COOLDOWN_SECS.
 */
typedef struct flow_entry {
    flow_key_t        key;
    uint64_t          total_packets;
    uint64_t          total_bytes;
    struct timeval    start_time;
    struct timeval    last_seen;
    /* [P3] TCP flag counters */
    uint32_t          syn_count;
    uint32_t          ack_count;
    /* [P3] Per-flow alert cooldown */
    struct timeval    last_alert_time;
    struct flow_entry *next;
} flow_entry_t;

/*
 * flow_table_t — hash table of flow_entry_t nodes with separate chaining.
 */
typedef struct {
    flow_entry_t *buckets[FLOW_TABLE_SIZE];
    uint64_t      flow_count;
} flow_table_t;

/*
 * ip_tracker_t — per-source-IP state for cross-flow anomaly detection.
 *
 * A single scanner sends SYNs to many ports (many different flows) so
 * SYN scan detection requires aggregation at the source-IP level, not the
 * flow level. Similarly, DNS frequency is per querying host, not per flow.
 *
 * Sliding-window counters reset when the current time exceeds
 * window_start + THRESH_*_WINDOW_SECS.
 */
typedef struct ip_tracker {
    uint32_t        ip;                  /* source IP (host byte order)       */

    /* SYN scan tracking */
    uint32_t        syn_count;           /* SYNs in current window            */
    struct timeval  syn_window_start;    /* when the current window opened    */
    struct timeval  last_syn_alert;      /* last SYN_SCAN alert timestamp     */

    /* DNS frequency tracking */
    uint32_t        dns_count;           /* DNS queries in current window     */
    struct timeval  dns_window_start;    /* when the current window opened    */
    struct timeval  last_dns_alert;      /* last DNS_ANOMALY alert timestamp  */

    struct ip_tracker *next;
} ip_tracker_t;

/*
 * ip_table_t — hash table of ip_tracker_t nodes with separate chaining.
 */
typedef struct {
    ip_tracker_t *buckets[IP_TABLE_SIZE];
} ip_table_t;

/* ============================================================
 * SECTION 4 — Globals
 * ============================================================ */

static pcap_t      *g_handle     = NULL;
static flow_table_t g_flow_table;
static ip_table_t   g_ip_table;

/* ============================================================
 * SECTION 5 — Signal handling
 * ============================================================ */

static void handle_signal(int sig)
{
    (void)sig;
    if (g_handle != NULL) pcap_breakloop(g_handle);
}

/* ============================================================
 * SECTION 6 — Utility functions
 * ============================================================ */

/*
 * timeval_diff_secs — elapsed seconds from `earlier` to `later`.
 * Returns negative if the timestamps are inverted (clock anomaly).
 */
static double timeval_diff_secs(const struct timeval *later,
                                const struct timeval *earlier)
{
    return (double)(later->tv_sec  - earlier->tv_sec) +
           (double)(later->tv_usec - earlier->tv_usec) / 1e6;
}

/*
 * ip_to_str — convert a host-byte-order IPv4 address to a dotted-decimal
 * string in caller-supplied buffer `buf` of size `len`.
 *
 * Centralising this conversion prevents the repetitive htonl/inet_ntop
 * pattern from appearing everywhere IPs are printed.
 */
static void ip_to_str(uint32_t ip_host, char *buf, size_t len)
{
    uint32_t ip_net = htonl(ip_host);
    inet_ntop(AF_INET, &ip_net, buf, (socklen_t)len);
}

/*
 * fnv1a32 — FNV-1a 32-bit hash over an arbitrary byte sequence.
 *
 * Used by both hash tables. Provides good avalanche effect with cheap
 * XOR+multiply operations and no modulo division.
 */
static uint32_t fnv1a32(const void *data, size_t len)
{
    const uint32_t FNV_OFFSET = 2166136261u;
    const uint32_t FNV_PRIME  = 16777619u;
    uint32_t hash = FNV_OFFSET;
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < len; i++) {
        hash ^= p[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

/* ============================================================
 * SECTION 7 — Flow key operations
 * ============================================================ */

/*
 * normalize_flow_key — enforce canonical ordering so A->B and B->A
 * produce the same key. Lower IP (or lower port on equal IPs) is "src".
 */
static void normalize_flow_key(flow_key_t *key)
{
    int swap = (key->src_ip > key->dst_ip) ||
               (key->src_ip == key->dst_ip && key->src_port > key->dst_port);
    if (swap) {
        uint32_t tmp_ip   = key->src_ip;   key->src_ip   = key->dst_ip;   key->dst_ip   = tmp_ip;
        uint16_t tmp_port = key->src_port; key->src_port = key->dst_port; key->dst_port = tmp_port;
    }
}

static uint32_t hash_flow_key(const flow_key_t *key)
{
    return fnv1a32(key, sizeof(flow_key_t)) & FLOW_TABLE_MASK;
}

static int compare_flow_keys(const flow_key_t *a, const flow_key_t *b)
{
    return (a->src_ip == b->src_ip && a->dst_ip   == b->dst_ip &&
            a->src_port == b->src_port && a->dst_port == b->dst_port &&
            a->proto == b->proto);
}

/* ============================================================
 * SECTION 8 — Flow table operations
 * ============================================================ */

/*
 * expire_bucket — prune idle flows from one bucket (lazy expiry).
 * Called every time a bucket is accessed; avoids scanning the whole table.
 */
static void expire_bucket(flow_table_t *tbl, uint32_t idx,
                          const struct timeval *now)
{
    flow_entry_t *prev = NULL;
    flow_entry_t *curr = tbl->buckets[idx];
    while (curr) {
        flow_entry_t *next = curr->next;
        if (timeval_diff_secs(now, &curr->last_seen) > FLOW_TIMEOUT_SECS) {
            if (prev) prev->next = next; else tbl->buckets[idx] = next;
            free(curr);
            tbl->flow_count--;
        } else {
            prev = curr;
        }
        curr = next;
    }
}

/*
 * lookup_or_create_flow — find or allocate a flow entry, then update stats.
 * Returns NULL only on malloc failure.
 */
static flow_entry_t *lookup_or_create_flow(flow_table_t *tbl,
                                           const flow_key_t *key,
                                           const struct timeval *ts,
                                           uint32_t pkt_len)
{
    uint32_t idx = hash_flow_key(key);
    expire_bucket(tbl, idx, ts);

    for (flow_entry_t *e = tbl->buckets[idx]; e; e = e->next) {
        if (compare_flow_keys(&e->key, key)) {
            e->total_packets++;
            e->total_bytes += pkt_len;
            e->last_seen    = *ts;
            return e;
        }
    }

    /* Allocate new entry, zero all fields, then fill */
    flow_entry_t *e = (flow_entry_t *)calloc(1, sizeof(flow_entry_t));
    if (!e) { fprintf(stderr, "Error: calloc failed\n"); return NULL; }

    e->key           = *key;
    e->total_packets = 1;
    e->total_bytes   = pkt_len;
    e->start_time    = *ts;
    e->last_seen     = *ts;
    /* syn_count, ack_count, last_alert_time zeroed by calloc */

    e->next            = tbl->buckets[idx];
    tbl->buckets[idx]  = e;
    tbl->flow_count++;
    return e;
}

static void free_flow_table(flow_table_t *tbl)
{
    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        flow_entry_t *curr = tbl->buckets[i];
        while (curr) { flow_entry_t *n = curr->next; free(curr); curr = n; }
        tbl->buckets[i] = NULL;
    }
    tbl->flow_count = 0;
}

/* ============================================================
 * SECTION 9 — Per-IP tracker operations
 * ============================================================ */

/*
 * lookup_or_create_ip_tracker — find or allocate an ip_tracker_t for
 * `ip` (host byte order). Used for SYN scan and DNS frequency checks.
 * Returns NULL only on malloc failure.
 */
static ip_tracker_t *lookup_or_create_ip_tracker(ip_table_t *tbl, uint32_t ip)
{
    uint32_t idx = fnv1a32(&ip, sizeof(ip)) & IP_TABLE_MASK;

    for (ip_tracker_t *t = tbl->buckets[idx]; t; t = t->next) {
        if (t->ip == ip) return t;
    }

    ip_tracker_t *t = (ip_tracker_t *)calloc(1, sizeof(ip_tracker_t));
    if (!t) { fprintf(stderr, "Error: calloc failed for ip_tracker\n"); return NULL; }

    t->ip = ip;
    /* All counters and timestamps zeroed by calloc */

    t->next            = tbl->buckets[idx];
    tbl->buckets[idx]  = t;
    return t;
}

static void free_ip_table(ip_table_t *tbl)
{
    for (int i = 0; i < IP_TABLE_SIZE; i++) {
        ip_tracker_t *curr = tbl->buckets[i];
        while (curr) { ip_tracker_t *n = curr->next; free(curr); curr = n; }
        tbl->buckets[i] = NULL;
    }
}

/* ============================================================
 * SECTION 10 — Analysis engine
 *
 * Three detection functions, each called from check_anomalies().
 * All alert functions share the same structure:
 *   1. Retrieve or create state for this IP / flow.
 *   2. Update sliding-window counter (reset if window expired).
 *   3. Check threshold.
 *   4. If threshold exceeded AND cooldown elapsed: print alert, record time.
 * ============================================================ */

/*
 * parse_dns_qname_len — walk the QNAME field in a DNS query and return
 * the total length of the human-readable domain name (labels joined by dots).
 *
 * DNS wire format for QNAME (RFC 1035 §3.1):
 *   Each label is prefixed by a 1-byte length octet, terminated by a 0 byte.
 *   Example: 3 w w w 6 g o o g l e 3 c o m 0
 *            → "www.google.com" (14 chars)
 *
 * DNS compression pointers (top 2 bits = 11) can appear in responses but
 * are uncommon in queries. We abort if one is encountered.
 *
 * Returns the character count of the domain name, or -1 if the payload is
 * not a DNS query, is malformed, or uses unsupported compression.
 */
static int parse_dns_qname_len(const u_char *payload, int payload_len)
{
    if (payload_len < MIN_DNS_HDR_LEN) return -1;

    /*
     * DNS header flags field (bytes 2-3):
     * Bit 15 (QR): 0 = query, 1 = response.
     * We only analyse queries to detect DNS tunnelling / DGA activity.
     */
    uint16_t flags = ((uint16_t)payload[2] << 8) | payload[3];
    if (flags & 0x8000) return -1;  /* response — not a query */

    /* QDCOUNT (bytes 4-5): number of questions; must be >= 1 */
    uint16_t qdcount = ((uint16_t)payload[4] << 8) | payload[5];
    if (qdcount == 0) return -1;

    /* QNAME starts at byte 12 (after the fixed 12-byte DNS header) */
    const u_char *ptr = payload + MIN_DNS_HDR_LEN;
    int remaining = payload_len - MIN_DNS_HDR_LEN;
    int name_len  = 0;
    int first     = 1;

    while (remaining > 0) {
        uint8_t label_len = *ptr;

        /* Root label: end of QNAME */
        if (label_len == 0) break;

        /* Compression pointer (bits 7-6 both set): not expected in queries */
        if ((label_len & 0xC0) == 0xC0) break;

        /* Consume the label: 1-byte length prefix + label_len bytes */
        if (1 + label_len > (unsigned)remaining) break;  /* truncated */

        if (!first) name_len++;  /* dot separator between labels */
        name_len += label_len;
        first = 0;

        ptr       += 1 + label_len;
        remaining -= 1 + label_len;
    }

    return name_len;
}

/* ------------------------------------------------------------------
 * detect_syn_scan
 *
 * Tracks TCP SYN packets (ACK flag clear — pure connection initiations)
 * at the per-SOURCE-IP level across ALL flows from that IP.
 *
 * Why per-IP and not per-flow?
 *   A port scanner probes many destination ports, producing a separate flow
 *   entry for each. Each flow would show only 1 SYN. Aggregating at the
 *   source-IP level reveals the full scan pattern.
 *
 * Algorithm:
 *   1. Only process pure SYN packets (SYN set, ACK clear).
 *   2. Look up (or create) the ip_tracker for this source IP.
 *   3. If the current time is outside the sliding window, reset the counter.
 *   4. Increment the SYN counter.
 *   5. If counter >= THRESH_SYN_COUNT and cooldown elapsed: fire alert.
 * ------------------------------------------------------------------ */
static void detect_syn_scan(const packet_info_t *pkt)
{
    /* Only interested in pure SYN packets — connection initiations */
    if (pkt->proto != IPPROTO_TCP) return;
    if ((pkt->tcp_flags & TH_SYN) == 0) return;
    if ((pkt->tcp_flags & TH_ACK) != 0) return;

    ip_tracker_t *tracker = lookup_or_create_ip_tracker(&g_ip_table, pkt->src_ip);
    if (!tracker) return;

    /*
     * Sliding window: if the current packet arrives more than
     * THRESH_SYN_WINDOW_SECS after the window opened, reset the counter.
     * This prevents old scan traffic from permanently accumulating.
     */
    if (tracker->syn_count == 0 ||
        timeval_diff_secs(&pkt->ts, &tracker->syn_window_start) > THRESH_SYN_WINDOW_SECS) {
        tracker->syn_count        = 0;
        tracker->syn_window_start = pkt->ts;
    }

    tracker->syn_count++;

    /* Check threshold and cooldown before firing alert */
    if (tracker->syn_count >= THRESH_SYN_COUNT) {
        double since_last = timeval_diff_secs(&pkt->ts, &tracker->last_syn_alert);
        if (tracker->last_syn_alert.tv_sec == 0 || since_last >= ALERT_COOLDOWN_SECS) {
            char src_str[INET_ADDRSTRLEN];
            ip_to_str(pkt->src_ip, src_str, sizeof(src_str));
            printf("ALERT SYN_SCAN SRC_IP=%s COUNT=%u\n",
                   src_str, tracker->syn_count);
            fflush(stdout);
            tracker->last_syn_alert = pkt->ts;
            /*
             * Reset counter after alerting so the next window starts fresh.
             * Without this, we'd alert on every subsequent SYN until cooldown.
             */
            tracker->syn_count        = 0;
            tracker->syn_window_start = pkt->ts;
        }
    }
}

/* ------------------------------------------------------------------
 * detect_dns_anomaly
 *
 * Two separate DNS anomaly signals, both tracked per-source-IP:
 *
 *   LONG_DOMAIN — a single query for a domain name exceeding
 *                 THRESH_DNS_NAME_LEN characters. Long subdomains are
 *                 a hallmark of DNS tunnelling (data encoded in labels).
 *
 *   HIGH_FREQ   — more than THRESH_DNS_FREQ_COUNT queries from one source
 *                 within THRESH_DNS_WINDOW_SECS. Indicates DNS-based C2,
 *                 aggressive resolvers, or domain generation algorithm (DGA).
 *
 * Both checks fire separate ALERT lines so an analyst can distinguish them.
 * ------------------------------------------------------------------ */
static void detect_dns_anomaly(const packet_info_t *pkt)
{
    /* Only UDP packets to/from port 53 */
    if (pkt->proto != IPPROTO_UDP) return;
    if (pkt->dst_port != DNS_PORT && pkt->src_port != DNS_PORT) return;

    /* Only process queries sent TO port 53 (i.e., src_port != 53) */
    if (pkt->src_port == DNS_PORT) return;

    ip_tracker_t *tracker = lookup_or_create_ip_tracker(&g_ip_table, pkt->src_ip);
    if (!tracker) return;

    char src_str[INET_ADDRSTRLEN];
    ip_to_str(pkt->src_ip, src_str, sizeof(src_str));

    /* --- Long domain name check -------------------------------- */
    if (pkt->transport_payload && pkt->transport_payload_len >= MIN_DNS_HDR_LEN) {
        int name_len = parse_dns_qname_len(pkt->transport_payload,
                                           pkt->transport_payload_len);
        if (name_len > THRESH_DNS_NAME_LEN) {
            /*
             * One long domain is enough to alert immediately — no sliding
             * window needed. Use per-IP cooldown to avoid per-packet spam
             * for the same tunnelling session.
             */
            double since_last = timeval_diff_secs(&pkt->ts, &tracker->last_dns_alert);
            if (tracker->last_dns_alert.tv_sec == 0 || since_last >= ALERT_COOLDOWN_SECS) {
                printf("ALERT DNS_ANOMALY SRC_IP=%s DETAIL=LONG_DOMAIN LEN=%d\n",
                       src_str, name_len);
                fflush(stdout);
                tracker->last_dns_alert = pkt->ts;
            }
        }
    }

    /* --- High frequency DNS query check ----------------------- */
    if (tracker->dns_count == 0 ||
        timeval_diff_secs(&pkt->ts, &tracker->dns_window_start) > THRESH_DNS_WINDOW_SECS) {
        tracker->dns_count        = 0;
        tracker->dns_window_start = pkt->ts;
    }

    tracker->dns_count++;

    if (tracker->dns_count >= THRESH_DNS_FREQ_COUNT) {
        double since_last = timeval_diff_secs(&pkt->ts, &tracker->last_dns_alert);
        if (tracker->last_dns_alert.tv_sec == 0 || since_last >= ALERT_COOLDOWN_SECS) {
            printf("ALERT DNS_ANOMALY SRC_IP=%s DETAIL=HIGH_FREQ COUNT=%u\n",
                   src_str, tracker->dns_count);
            fflush(stdout);
            tracker->last_dns_alert = pkt->ts;
            tracker->dns_count        = 0;
            tracker->dns_window_start = pkt->ts;
        }
    }
}

/* ------------------------------------------------------------------
 * detect_high_traffic
 *
 * Fires when a single bidirectional flow exceeds THRESH_HIGH_BYTES in
 * total bytes transferred. The flow entry is passed directly — no
 * secondary lookup required.
 *
 * Per-flow cooldown (last_alert_time) prevents the alert from firing on
 * every subsequent packet once the threshold is crossed, which would
 * flood the console for a large ongoing transfer.
 * ------------------------------------------------------------------ */
static void detect_high_traffic(flow_entry_t *flow, const packet_info_t *pkt)
{
    if (flow->total_bytes < THRESH_HIGH_BYTES) return;

    double since_last = timeval_diff_secs(&pkt->ts, &flow->last_alert_time);
    if (flow->last_alert_time.tv_sec != 0 && since_last < ALERT_COOLDOWN_SECS) return;

    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];
    ip_to_str(flow->key.src_ip, src_str, sizeof(src_str));
    ip_to_str(flow->key.dst_ip, dst_str, sizeof(dst_str));

    printf("ALERT HIGH_TRAFFIC FLOW %s:%u <-> %s:%u BYTES=%" PRIu64 "\n",
           src_str, flow->key.src_port,
           dst_str, flow->key.dst_port,
           flow->total_bytes);
    fflush(stdout);

    flow->last_alert_time = pkt->ts;
}

/* ------------------------------------------------------------------
 * check_anomalies — central dispatch for all detections.
 *
 * Called once per packet after the flow entry has been updated.
 * Each individual detector is independent — a packet can trigger
 * multiple alerts simultaneously.
 * ------------------------------------------------------------------ */
static void check_anomalies(flow_entry_t *flow, const packet_info_t *pkt)
{
    detect_syn_scan(pkt);
    detect_dns_anomaly(pkt);
    detect_high_traffic(flow, pkt);
}

/* ============================================================
 * SECTION 11 — Printing
 * ============================================================ */

static const char *proto_name(uint8_t proto)
{
    switch (proto) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        default:          return "UNK";
    }
}

static void print_flow(const flow_entry_t *e)
{
    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    ip_to_str(e->key.src_ip, src_str, sizeof(src_str));
    ip_to_str(e->key.dst_ip, dst_str, sizeof(dst_str));
    printf("FLOW %s:%u <-> %s:%u | %s | PKTS=%" PRIu64 " | BYTES=%" PRIu64 "\n",
           src_str, e->key.src_port,
           dst_str, e->key.dst_port,
           proto_name(e->key.proto),
           e->total_packets, e->total_bytes);
}

static void print_flow_summary(const flow_table_t *tbl)
{
    printf("\n============================================================\n");
    printf("  Flow Table Summary -- %" PRIu64 " active flow(s)\n", tbl->flow_count);
    printf("============================================================\n");
    uint64_t printed = 0;
    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        for (const flow_entry_t *e = tbl->buckets[i]; e; e = e->next) {
            char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
            ip_to_str(e->key.src_ip, src_str, sizeof(src_str));
            ip_to_str(e->key.dst_ip, dst_str, sizeof(dst_str));
            double dur = timeval_diff_secs(&e->last_seen, &e->start_time);
            printf("  %s:%u <-> %s:%u | %s | PKTS=%" PRIu64
                   " | BYTES=%" PRIu64 " | SYN=%u | ACK=%u | DUR=%.2fs\n",
                   src_str, e->key.src_port,
                   dst_str, e->key.dst_port,
                   proto_name(e->key.proto),
                   e->total_packets, e->total_bytes,
                   e->syn_count, e->ack_count, dur);
            printed++;
        }
    }
    if (!printed) printf("  (no flows captured)\n");
    printf("============================================================\n");
}

/* ============================================================
 * SECTION 12 — Packet parsing
 * ============================================================ */

/*
 * process_transport — build the flow key, update the flow table,
 * update per-flow TCP flag counters, then run anomaly checks.
 *
 * This is the convergence point called by both parse_tcp and parse_udp
 * after they have filled in a packet_info_t.
 */
static void process_transport(const packet_info_t *pkt)
{
    flow_key_t key;
    memset(&key, 0, sizeof(key));
    key.src_ip   = pkt->src_ip;
    key.dst_ip   = pkt->dst_ip;
    key.src_port = pkt->src_port;
    key.dst_port = pkt->dst_port;
    key.proto    = pkt->proto;
    normalize_flow_key(&key);

    flow_entry_t *entry = lookup_or_create_flow(&g_flow_table, &key,
                                                 &pkt->ts, pkt->pkt_len);
    if (!entry) return;

    /*
     * Update per-flow TCP flag counters [Phase 3].
     * Note: we update BEFORE printing so the summary line reflects the flags.
     */
    if (pkt->proto == IPPROTO_TCP) {
        if (pkt->tcp_flags & TH_SYN) entry->syn_count++;
        if (pkt->tcp_flags & TH_ACK) entry->ack_count++;
    }

    print_flow(entry);
    check_anomalies(entry, pkt);
}

/*
 * parse_tcp — validate and extract TCP fields into a packet_info_t.
 *
 * th_off (data offset) gives the TCP header length in 32-bit words.
 * Multiplying by 4 and skipping that many bytes reaches the TCP payload.
 * This is important for the transport_payload pointer used by higher-level
 * protocol parsers (none currently, but preserved for Phase 4+).
 */
static void parse_tcp(const u_char *ptr, int remaining,
                      uint32_t src_ip_h, uint32_t dst_ip_h,
                      const struct timeval *ts, uint32_t pkt_len)
{
    if (remaining < MIN_TCP_HDR_LEN) return;

    const struct tcphdr *tcp = (const struct tcphdr *)ptr;

    /* TCP header length from data-offset field (in 32-bit words, × 4 for bytes) */
    int tcp_hdr_len = tcp->th_off * 4;
    if (tcp_hdr_len < MIN_TCP_HDR_LEN || tcp_hdr_len > remaining)
        tcp_hdr_len = MIN_TCP_HDR_LEN;  /* clamp on malformed header */

    packet_info_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.src_ip                = src_ip_h;
    pkt.dst_ip                = dst_ip_h;
    pkt.src_port              = ntohs(tcp->th_sport);
    pkt.dst_port              = ntohs(tcp->th_dport);
    pkt.proto                 = IPPROTO_TCP;
    pkt.tcp_flags             = tcp->th_flags;
    pkt.pkt_len               = pkt_len;
    pkt.ts                    = *ts;
    pkt.transport_payload     = ptr + tcp_hdr_len;
    pkt.transport_payload_len = remaining - tcp_hdr_len;

    process_transport(&pkt);
}

/*
 * parse_udp — validate and extract UDP fields into a packet_info_t.
 *
 * The UDP payload (transport_payload) is set to point immediately after the
 * fixed 8-byte UDP header. For DNS packets this is where the DNS message begins.
 */
static void parse_udp(const u_char *ptr, int remaining,
                      uint32_t src_ip_h, uint32_t dst_ip_h,
                      const struct timeval *ts, uint32_t pkt_len)
{
    if (remaining < MIN_UDP_HDR_LEN) return;

    const struct udphdr *udp = (const struct udphdr *)ptr;

    packet_info_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.src_ip                = src_ip_h;
    pkt.dst_ip                = dst_ip_h;
    pkt.src_port              = ntohs(udp->uh_sport);
    pkt.dst_port              = ntohs(udp->uh_dport);
    pkt.proto                 = IPPROTO_UDP;
    pkt.tcp_flags             = 0;
    pkt.pkt_len               = pkt_len;
    pkt.ts                    = *ts;
    pkt.transport_payload     = ptr + MIN_UDP_HDR_LEN;
    pkt.transport_payload_len = remaining - MIN_UDP_HDR_LEN;

    process_transport(&pkt);
}

/*
 * parse_ipv4 — validate the IP header and dispatch to parse_tcp/parse_udp.
 *
 * IPs are converted to host byte order here, once. All downstream code
 * (flow key, normalisation, hashing, printing) operates in host byte order.
 * Only ip_to_str() calls htonl() when passing to inet_ntop().
 */
static void parse_ipv4(const u_char *ip_ptr, int remaining,
                       const struct timeval *ts, uint32_t pkt_len)
{
    if (remaining < MIN_IP_HDR_LEN) return;

    const struct iphdr *ip = (const struct iphdr *)ip_ptr;
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < MIN_IP_HDR_LEN || ip_hdr_len > remaining) return;

    uint32_t src_ip_h = ntohl(ip->saddr);
    uint32_t dst_ip_h = ntohl(ip->daddr);

    const u_char *transport_ptr       = ip_ptr + ip_hdr_len;
    int           transport_remaining = remaining - ip_hdr_len;

    switch (ip->protocol) {
        case IPPROTO_TCP:
            parse_tcp(transport_ptr, transport_remaining,
                      src_ip_h, dst_ip_h, ts, pkt_len);
            break;
        case IPPROTO_UDP:
            parse_udp(transport_ptr, transport_remaining,
                      src_ip_h, dst_ip_h, ts, pkt_len);
            break;
        default:
            break;
    }
}

/*
 * packet_handler — libpcap callback invoked once per captured Ethernet frame.
 *
 * Uses caplen for bounds checking and len (wire size) for byte accounting.
 */
static void packet_handler(u_char *args,
                           const struct pcap_pkthdr *header,
                           const u_char *packet)
{
    (void)args;
    int caplen = (int)header->caplen;
    if (caplen < MIN_ETHER_LEN) return;

    const struct ethhdr *eth = (const struct ethhdr *)packet;
    if (ntohs(eth->h_proto) != ETH_P_IP) return;

    parse_ipv4(packet + MIN_ETHER_LEN, caplen - MIN_ETHER_LEN,
               &header->ts, (uint32_t)header->len);
}

/* ============================================================
 * SECTION 13 — Capture setup
 * ============================================================ */

static pcap_t *open_capture(const char *dev, char *errbuf)
{
    pcap_t *handle = pcap_open_live(dev, SNAPLEN, /*promisc=*/1,
                                    PCAP_TIMEOUT_MS, errbuf);
    if (!handle) {
        fprintf(stderr, "Error: pcap_open_live(%s): %s\n", dev, errbuf);
        return NULL;
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Error: '%s' is not an Ethernet interface (DLT=%d)\n",
                dev, pcap_datalink(handle));
        pcap_close(handle);
        return NULL;
    }
    return handle;
}

/* ============================================================
 * SECTION 14 — main
 * ============================================================ */

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *dev = NULL;

    /* Initialise both hash tables to all-NULL / zero */
    memset(&g_flow_table, 0, sizeof(g_flow_table));
    memset(&g_ip_table,   0, sizeof(g_ip_table));

    /* Resolve interface */
    if (argc >= 2) {
        dev = argv[1];
    } else {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        dev = pcap_lookupdev(errbuf);
#pragma GCC diagnostic pop
        if (!dev) {
            fprintf(stderr, "Error: no device found: %s\n", errbuf);
            fprintf(stderr, "Hint: run with sudo or pass interface as argv[1].\n");
            return EXIT_FAILURE;
        }
    }

    printf("=== Packet Sniffer -- Phase 3 (Anomaly Detection) ===\n");
    printf("Interface         : %s\n", dev);
    printf("Flow timeout      : %.0f seconds\n",   FLOW_TIMEOUT_SECS);
    printf("SYN scan thresh   : %d SYNs / %.0fs\n", THRESH_SYN_COUNT,
                                                      THRESH_SYN_WINDOW_SECS);
    printf("DNS name thresh   : %d chars\n",         THRESH_DNS_NAME_LEN);
    printf("DNS freq thresh   : %d queries / %.0fs\n", THRESH_DNS_FREQ_COUNT,
                                                         THRESH_DNS_WINDOW_SECS);
    printf("High traffic      : %" PRIu64 " bytes\n", (uint64_t)THRESH_HIGH_BYTES);
    printf("Alert cooldown    : %.0f seconds\n",      ALERT_COOLDOWN_SECS);
    printf("Press Ctrl+C to stop.\n\n");

    /* Signal handlers */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) == -1 || sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    /* Open capture */
    pcap_t *handle = open_capture(dev, errbuf);
    if (!handle) return EXIT_FAILURE;
    g_handle = handle;

    /* Capture loop */
    int rc = pcap_loop(handle, 0, packet_handler, NULL);
    if (rc == -1) fprintf(stderr, "\nCapture error: %s\n", pcap_geterr(handle));
    else          printf("\nCapture stopped.\n");

    /* Summary and cleanup */
    print_flow_summary(&g_flow_table);

    struct pcap_stat stats;
    if (pcap_stats(handle, &stats) == 0) {
        printf("\n--- libpcap Statistics ---\n");
        printf("  Packets received : %u\n", stats.ps_recv);
        printf("  Dropped (kernel) : %u\n", stats.ps_drop);
        printf("  Dropped (iface)  : %u\n", stats.ps_ifdrop);
    }

    pcap_close(handle);
    g_handle = NULL;
    free_flow_table(&g_flow_table);
    free_ip_table(&g_ip_table);

    return (rc == -1) ? EXIT_FAILURE : EXIT_SUCCESS;
}
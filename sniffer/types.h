/*
 * types.h — Shared type definitions and compile-time constants
 *
 * This header is the single source of truth for every struct and threshold
 * used across the project. No module defines its own structs for shared data.
 *
 * Include order:  types.h must be included before any other project header.
 *
 * Data flow overview:
 *   capture.c  → receives raw frames from libpcap
 *   parse.c    → fills packet_info_t from raw bytes
 *   flow.c     → manages flow_table_t keyed by flow_key_t
 *   analysis.c → manages ip_table_t; reads packet_info_t and flow_entry_t
 *   utils.c    → formatting helpers used by all modules
 */

#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <sys/time.h>   /* struct timeval */

/* ============================================================
 * Compile-time tunable thresholds
 * All values in one place — change here, recompile, done.
 * ============================================================ */

/* --- libpcap capture --------------------------------------- */
#define SNAPLEN                 65535   /* max bytes captured per packet    */
#define PCAP_TIMEOUT_MS         1000    /* read timeout passed to pcap      */

/* --- Flow hash table --------------------------------------- */
#define FLOW_TABLE_SIZE         1024    /* bucket count (must be power of 2) */
#define FLOW_TABLE_MASK         (FLOW_TABLE_SIZE - 1)
#define FLOW_TIMEOUT_SECS       60.0    /* idle flow expiry in seconds       */

/* --- Per-IP tracker table ---------------------------------- */
#define IP_TABLE_SIZE           512     /* bucket count (must be power of 2) */
#define IP_TABLE_MASK           (IP_TABLE_SIZE - 1)

/* --- SYN scan detection ------------------------------------ */
#define THRESH_SYN_COUNT        10      /* SYNs from one IP before alert    */
#define THRESH_SYN_WINDOW_SECS  10.0   /* sliding window duration (seconds) */

/* --- DNS anomaly detection --------------------------------- */
#define THRESH_DNS_NAME_LEN     50      /* max acceptable domain name length */
#define THRESH_DNS_FREQ_COUNT   20      /* max DNS queries per window        */
#define THRESH_DNS_WINDOW_SECS  10.0   /* sliding window duration (seconds) */
#define DNS_PORT                53

/* --- High traffic detection -------------------------------- */
#define THRESH_HIGH_BYTES       (1024ULL * 1024ULL)  /* 1 MB per flow       */

/* --- Alert spam prevention --------------------------------- */
#define ALERT_COOLDOWN_SECS     10.0   /* minimum gap between same alert    */

/* --- Header minimum sizes (bytes) -------------------------- */
#define MIN_ETHER_LEN           14      /* Ethernet II: 6+6+2               */
#define MIN_IP_HDR_LEN          20      /* IPv4 without options              */
#define MIN_TCP_HDR_LEN         20      /* TCP without options               */
#define MIN_UDP_HDR_LEN         8       /* UDP fixed header                  */
#define MIN_DNS_HDR_LEN         12      /* DNS fixed header (RFC 1035)       */

/* ============================================================
 * packet_info_t
 *
 * All metadata extracted from a single captured packet.
 * Populated once in parse.c and passed by pointer through the call chain.
 * transport_payload points into the libpcap buffer — valid only for the
 * duration of the packet_handler callback.
 * ============================================================ */
typedef struct {
    uint32_t        src_ip;               /* source IP, host byte order      */
    uint32_t        dst_ip;               /* destination IP, host byte order */
    uint16_t        src_port;             /* source port, host byte order    */
    uint16_t        dst_port;             /* destination port, host byte order*/
    uint8_t         proto;                /* IPPROTO_TCP or IPPROTO_UDP      */
    uint8_t         tcp_flags;            /* raw TCP flags byte              */
    uint32_t        pkt_len;              /* wire length in bytes            */
    struct timeval  ts;                   /* libpcap capture timestamp       */
    const uint8_t  *transport_payload;    /* bytes after transport header    */
    int             transport_payload_len;
} packet_info_t;

/* ============================================================
 * flow_key_t
 *
 * The normalised 5-tuple that uniquely identifies a bidirectional flow.
 * All fields stored in host byte order after normalisation.
 * Normalisation rule: lower IP (or lower port on tie) is always src.
 * ============================================================ */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
} flow_key_t;

/* ============================================================
 * flow_entry_t
 *
 * One node in the flow table's separate-chaining linked list.
 * Phase 3 additions: syn_count, ack_count, last_alert_time.
 * ============================================================ */
typedef struct flow_entry {
    flow_key_t        key;            /* normalised 5-tuple                 */
    uint64_t          total_packets;  /* packets in both directions         */
    uint64_t          total_bytes;    /* bytes in both directions           */
    struct timeval    start_time;     /* timestamp of first packet          */
    struct timeval    last_seen;      /* timestamp of most recent packet    */
    uint32_t          syn_count;      /* TCP SYN packets on this flow       */
    uint32_t          ack_count;      /* TCP ACK packets on this flow       */
    struct timeval    last_alert_time;/* for HIGH_TRAFFIC cooldown          */
    struct flow_entry *next;          /* next entry in bucket chain         */
} flow_entry_t;

/* ============================================================
 * flow_table_t — hash table of flow_entry_t nodes
 * ============================================================ */
typedef struct {
    flow_entry_t *buckets[FLOW_TABLE_SIZE];
    uint64_t      flow_count;
} flow_table_t;

/* ============================================================
 * ip_tracker_t
 *
 * Per-source-IP state for cross-flow anomaly detection.
 * SYN scans and DNS floods are per-IP phenomena — they span many flows.
 * ============================================================ */
typedef struct ip_tracker {
    uint32_t          ip;                /* source IP, host byte order      */

    /* SYN scan tracking */
    uint32_t          syn_count;         /* SYNs in current sliding window  */
    struct timeval    syn_window_start;  /* when the current window opened  */
    struct timeval    last_syn_alert;    /* timestamp of last SYN_SCAN alert*/

    /* DNS frequency tracking */
    uint32_t          dns_count;         /* DNS queries in current window   */
    struct timeval    dns_window_start;  /* when the current window opened  */
    struct timeval    last_dns_alert;    /* timestamp of last DNS alert     */

    struct ip_tracker *next;
} ip_tracker_t;

/* ============================================================
 * ip_table_t — hash table of ip_tracker_t nodes
 * ============================================================ */
typedef struct {
    ip_tracker_t *buckets[IP_TABLE_SIZE];
} ip_table_t;

#endif /* TYPES_H */

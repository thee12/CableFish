/*
 * types.h — Shared type definitions and compile-time constants
 *
 * Single source of truth for every struct, enum, and threshold used across
 * the project. Include this before any other project header.
 *
 * Phase 4 additions:
 *   alert_type_t    — enum of detectable anomaly categories
 *   packet_record_t — unified struct representing one loggable event,
 *                     passed from parse.c → output.c
 *   output_config_t — CLI-configurable output settings passed to output_init()
 *
 * Data flow:
 *   capture.c → parse.c → flow.c      (flow tracking)
 *                       → analysis.c  (anomaly detection, returns alert_type_t)
 *                       → output.c    (writes packet_record_t to JSON / CSV)
 */

#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <sys/time.h>
#include <arpa/inet.h>   /* INET_ADDRSTRLEN */

/* ============================================================
 * Compile-time tunable thresholds
 * ============================================================ */

#define SNAPLEN                 65535
#define PCAP_TIMEOUT_MS         1000

#define FLOW_TABLE_SIZE         1024
#define FLOW_TABLE_MASK         (FLOW_TABLE_SIZE - 1)
#define FLOW_TIMEOUT_SECS       60.0

#define IP_TABLE_SIZE           512
#define IP_TABLE_MASK           (IP_TABLE_SIZE - 1)

#define THRESH_SYN_COUNT        10
#define THRESH_SYN_WINDOW_SECS  10.0

#define THRESH_DNS_NAME_LEN     50
#define THRESH_DNS_FREQ_COUNT   20
#define THRESH_DNS_WINDOW_SECS  10.0
#define DNS_PORT                53

#define THRESH_HIGH_BYTES       (1024ULL * 1024ULL)

#define ALERT_COOLDOWN_SECS     10.0

#define MIN_ETHER_LEN           14
#define MIN_IP_HDR_LEN          20
#define MIN_TCP_HDR_LEN         20
#define MIN_UDP_HDR_LEN         8
#define MIN_DNS_HDR_LEN         12

/* ============================================================
 * alert_type_t  [Phase 4]
 *
 * Categorises the anomaly (if any) detected on a given packet.
 * check_anomalies() in analysis.c returns one of these values.
 * ALERT_NONE is the common case (no anomaly detected).
 *
 * Priority when multiple detectors fire simultaneously:
 *   HIGH_TRAFFIC > SYN_SCAN > DNS_ANOMALY_FREQ > DNS_ANOMALY_LONG
 * (check_anomalies returns the first non-NONE value it encounters)
 * ============================================================ */
typedef enum {
    ALERT_NONE            = 0,
    ALERT_SYN_SCAN        = 1,
    ALERT_DNS_ANOMALY_LONG= 2,
    ALERT_DNS_ANOMALY_FREQ= 3,
    ALERT_HIGH_TRAFFIC    = 4
} alert_type_t;

/* ============================================================
 * packet_record_t  [Phase 4]
 *
 * A fully-resolved, human-readable snapshot of one packet/flow event.
 * Populated in parse.c after all layers have been processed, then passed
 * to output_write() which fans it out to every enabled output target.
 *
 * Fields are pre-formatted (IP strings, timestamp string) so that
 * output.c performs no further parsing — just writing.
 *
 * packets_total / bytes_total are taken from the flow entry;
 * they are 0 for a packet that could not be associated with a flow.
 * ============================================================ */
typedef struct {
    char        timestamp[32];          /* "2026-04-02T15:32:10.123Z"         */
    char        src_ip[INET_ADDRSTRLEN];
    char        dst_ip[INET_ADDRSTRLEN];
    uint16_t    src_port;
    uint16_t    dst_port;
    uint8_t     proto;                  /* IPPROTO_TCP or IPPROTO_UDP         */
    uint32_t    length;                 /* wire length of this packet (bytes) */
    uint64_t    packets_total;          /* total packets on this flow so far  */
    uint64_t    bytes_total;            /* total bytes on this flow so far    */
    alert_type_t alert;                 /* anomaly detected on this packet    */
} packet_record_t;

/* ============================================================
 * output_config_t  [Phase 4]
 *
 * Populated from CLI arguments in main() and passed to output_init().
 * output.c copies this into its internal state so callers need not
 * keep the struct alive after output_init() returns.
 * ============================================================ */
typedef struct {
    int  json_enabled;          /* 1 = write packets.json    */
    int  csv_enabled;           /* 1 = write packets.csv     */
    char output_dir[256];       /* directory for output files */
} output_config_t;

/* ============================================================
 * packet_info_t — parsed metadata for one captured packet
 * ============================================================ */
typedef struct {
    uint32_t        src_ip;
    uint32_t        dst_ip;
    uint16_t        src_port;
    uint16_t        dst_port;
    uint8_t         proto;
    uint8_t         tcp_flags;
    uint32_t        pkt_len;
    struct timeval  ts;
    const uint8_t  *transport_payload;
    int             transport_payload_len;
} packet_info_t;

/* ============================================================
 * flow_key_t — normalised 5-tuple
 * ============================================================ */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
} flow_key_t;

/* ============================================================
 * flow_entry_t — per-flow state in the hash table
 * ============================================================ */
typedef struct flow_entry {
    flow_key_t        key;
    uint64_t          total_packets;
    uint64_t          total_bytes;
    struct timeval    start_time;
    struct timeval    last_seen;
    uint32_t          syn_count;
    uint32_t          ack_count;
    struct timeval    last_alert_time;
    struct flow_entry *next;
} flow_entry_t;

/* ============================================================
 * flow_table_t — hash table of flow_entry_t nodes
 * ============================================================ */
typedef struct {
    flow_entry_t *buckets[FLOW_TABLE_SIZE];
    uint64_t      flow_count;
} flow_table_t;

/* ============================================================
 * ip_tracker_t — per-source-IP state for anomaly detection
 * ============================================================ */
typedef struct ip_tracker {
    uint32_t          ip;
    uint32_t          syn_count;
    struct timeval    syn_window_start;
    struct timeval    last_syn_alert;
    uint32_t          dns_count;
    struct timeval    dns_window_start;
    struct timeval    last_dns_alert;
    struct ip_tracker *next;
} ip_tracker_t;

/* ============================================================
 * ip_table_t — hash table of ip_tracker_t nodes
 * ============================================================ */
typedef struct {
    ip_tracker_t *buckets[IP_TABLE_SIZE];
} ip_table_t;

#endif /* TYPES_H */
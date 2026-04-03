/*
 * parse.c — Packet parsing and output pipeline integration
 *
 * Phase 4 additions to process_transport():
 *   1. check_anomalies() now returns alert_type_t — stored in `alert`.
 *   2. build_record()    — static helper that populates a packet_record_t
 *                          from the packet_info_t, flow_entry_t, and alert.
 *   3. output_write()    — fans the record out to all enabled sinks.
 *   4. output_format_timestamp() — called from build_record() to fill the
 *                          timestamp string field.
 *
 * The console print_flow() call is preserved at the end, after the file
 * writes, so console output is unaffected by the new logging pipeline.
 *
 * Internal call chain:
 *   parse_dispatch()
 *     └─ parse_ipv4()
 *          ├─ parse_tcp()
 *          └─ parse_udp()
 *               └─ process_transport()
 *                    ├─ flow_normalize_key()
 *                    ├─ flow_lookup_or_create()   [update flow counters]
 *                    ├─ update TCP flag counters
 *                    ├─ check_anomalies()         → alert_type_t
 *                    ├─ build_record()            → packet_record_t
 *                    ├─ output_write()            → JSON / CSV files
 *                    └─ print_flow()              → console
 */

#include "parse.h"
#include "flow.h"
#include "analysis.h"
#include "output.h"
#include "utils.h"

#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

/* ----------------------------------------------------------------
 * build_record — populate a packet_record_t from all available sources.
 *
 * IPs are pulled from the normalised flow key (not the raw pkt) so the
 * log record is consistent with the console FLOW output — the same
 * canonical src/dst ordering appears in both.
 *
 * output_format_timestamp() is defined in output.c (not utils.c) because
 * timestamp formatting is an output-layer concern using <time.h>.
 * ---------------------------------------------------------------- */
static void build_record(packet_record_t      *rec,
                         const packet_info_t  *pkt,
                         const flow_entry_t   *flow,
                         alert_type_t          alert)
{
    /* Timestamp: format struct timeval into "2026-04-02T15:32:10.123Z" */
    output_format_timestamp(&pkt->ts, rec->timestamp, sizeof(rec->timestamp));

    /*
     * Use flow key IPs (normalised, lower IP is src) rather than raw pkt IPs.
     * This ensures every update to the same flow shows the same src/dst in logs.
     */
    ip_to_str(flow->key.src_ip, rec->src_ip, sizeof(rec->src_ip));
    ip_to_str(flow->key.dst_ip, rec->dst_ip, sizeof(rec->dst_ip));

    rec->src_port      = flow->key.src_port;
    rec->dst_port      = flow->key.dst_port;
    rec->proto         = pkt->proto;
    rec->length        = pkt->pkt_len;
    rec->packets_total = flow->total_packets;
    rec->bytes_total   = flow->total_bytes;
    rec->alert         = alert;
}

/* ----------------------------------------------------------------
 * process_transport — convergence point for TCP and UDP.
 * ---------------------------------------------------------------- */
static void process_transport(const packet_info_t *pkt,
                              flow_table_t        *flows,
                              ip_table_t          *trackers)
{
    /* Step 1: build and normalise the flow key */
    flow_key_t key;
    memset(&key, 0, sizeof(key));
    key.src_ip   = pkt->src_ip;
    key.dst_ip   = pkt->dst_ip;
    key.src_port = pkt->src_port;
    key.dst_port = pkt->dst_port;
    key.proto    = pkt->proto;
    flow_normalize_key(&key);

    /* Step 2: update flow counters (or create new entry) */
    flow_entry_t *entry = flow_lookup_or_create(flows, &key, &pkt->ts, pkt->pkt_len);
    if (entry == NULL) return;

    /* Step 3: update per-flow TCP flag counters */
    if (pkt->proto == IPPROTO_TCP) {
        if (pkt->tcp_flags & TH_SYN) entry->syn_count++;
        if (pkt->tcp_flags & TH_ACK) entry->ack_count++;
    }

    /* Step 4: run anomaly detection — returns highest-priority alert fired */
    alert_type_t alert = check_anomalies(entry, pkt, trackers);

    /* Step 5: build the unified log record */
    packet_record_t rec;
    build_record(&rec, pkt, entry, alert);

    /* Step 6: write to all enabled output sinks (JSON, CSV) */
    output_write(&rec);

    /* Step 7: console output — unchanged from Phase 3 */
    print_flow(entry);
}

/* ----------------------------------------------------------------
 * parse_tcp — extract TCP fields, compute payload pointer.
 * ---------------------------------------------------------------- */
static void parse_tcp(const uint8_t *ptr, int remaining,
                      uint32_t src_ip, uint32_t dst_ip,
                      const struct timeval *ts, uint32_t pkt_len,
                      flow_table_t *flows, ip_table_t *trackers)
{
    if (remaining < MIN_TCP_HDR_LEN) return;

    const struct tcphdr *tcp = (const struct tcphdr *)ptr;
    int hdrlen = tcp->th_off * 4;
    if (hdrlen < MIN_TCP_HDR_LEN || hdrlen > remaining) hdrlen = MIN_TCP_HDR_LEN;

    packet_info_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.src_ip                = src_ip;
    pkt.dst_ip                = dst_ip;
    pkt.src_port              = ntohs(tcp->th_sport);
    pkt.dst_port              = ntohs(tcp->th_dport);
    pkt.proto                 = IPPROTO_TCP;
    pkt.tcp_flags             = tcp->th_flags;
    pkt.pkt_len               = pkt_len;
    pkt.ts                    = *ts;
    pkt.transport_payload     = ptr + hdrlen;
    pkt.transport_payload_len = remaining - hdrlen;

    process_transport(&pkt, flows, trackers);
}

/* ----------------------------------------------------------------
 * parse_udp — extract UDP fields, set payload pointer for DNS parsing.
 * ---------------------------------------------------------------- */
static void parse_udp(const uint8_t *ptr, int remaining,
                      uint32_t src_ip, uint32_t dst_ip,
                      const struct timeval *ts, uint32_t pkt_len,
                      flow_table_t *flows, ip_table_t *trackers)
{
    if (remaining < MIN_UDP_HDR_LEN) return;

    const struct udphdr *udp = (const struct udphdr *)ptr;

    packet_info_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.src_ip                = src_ip;
    pkt.dst_ip                = dst_ip;
    pkt.src_port              = ntohs(udp->uh_sport);
    pkt.dst_port              = ntohs(udp->uh_dport);
    pkt.proto                 = IPPROTO_UDP;
    pkt.tcp_flags             = 0;
    pkt.pkt_len               = pkt_len;
    pkt.ts                    = *ts;
    pkt.transport_payload     = ptr + MIN_UDP_HDR_LEN;
    pkt.transport_payload_len = remaining - MIN_UDP_HDR_LEN;

    process_transport(&pkt, flows, trackers);
}

/* ----------------------------------------------------------------
 * parse_ipv4 — validate IP header, convert addresses, dispatch.
 * ---------------------------------------------------------------- */
static void parse_ipv4(const uint8_t *ip_ptr, int remaining,
                       const struct timeval *ts, uint32_t wirelen,
                       flow_table_t *flows, ip_table_t *trackers)
{
    if (remaining < MIN_IP_HDR_LEN) return;

    const struct iphdr *ip = (const struct iphdr *)ip_ptr;
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < MIN_IP_HDR_LEN || ip_hdr_len > remaining) return;

    uint32_t src_ip = ntohl(ip->saddr);
    uint32_t dst_ip = ntohl(ip->daddr);

    const uint8_t *tp = ip_ptr + ip_hdr_len;
    int            tr = remaining - ip_hdr_len;

    switch (ip->protocol) {
        case IPPROTO_TCP:
            parse_tcp(tp, tr, src_ip, dst_ip, ts, wirelen, flows, trackers);
            break;
        case IPPROTO_UDP:
            parse_udp(tp, tr, src_ip, dst_ip, ts, wirelen, flows, trackers);
            break;
        default:
            break;
    }
}

/* ----------------------------------------------------------------
 * parse_dispatch — public entry point; validates Ethernet, filters IPv4.
 * ---------------------------------------------------------------- */
void parse_dispatch(const uint8_t       *packet,
                    int                  caplen,
                    uint32_t             wirelen,
                    const struct timeval *ts,
                    flow_table_t        *flows,
                    ip_table_t          *trackers)
{
    if (caplen < MIN_ETHER_LEN) return;

    const struct ethhdr *eth = (const struct ethhdr *)packet;
    if (ntohs(eth->h_proto) != ETH_P_IP) return;

    parse_ipv4(packet + MIN_ETHER_LEN, caplen - MIN_ETHER_LEN,
               ts, wirelen, flows, trackers);
}
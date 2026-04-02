/*
 * parse.c — Packet parsing implementation
 *
 * Internal call chain (all functions except parse_dispatch are static):
 *
 *   parse_dispatch()       — validates Ethernet, filters IPv4
 *     └─ parse_ipv4()      — validates IP header, extracts src/dst IPs
 *          ├─ parse_tcp()  — extracts ports, flags, TCP payload pointer
 *          └─ parse_udp()  — extracts ports, UDP payload pointer
 *               └─ (both call) process_transport()
 *                    ├─ flow_normalize_key()
 *                    ├─ flow_lookup_or_create()
 *                    ├─ updates syn_count / ack_count on flow entry
 *                    ├─ print_flow()
 *                    └─ check_anomalies()
 *
 * Byte order contract:
 *   IPs are converted from network to host byte order in parse_ipv4(),
 *   once. All downstream code (flow keys, hashing, comparison, printing)
 *   operates in host byte order. Only ip_to_str() converts back to network
 *   order when calling inet_ntop() for display.
 *
 *   Ports are converted in parse_tcp() / parse_udp() with ntohs().
 *
 * Bounds checking:
 *   Every pointer advance is guarded by a `remaining` check before the
 *   cast, preventing out-of-bounds reads on truncated or malformed packets.
 */

#include "parse.h"
#include "flow.h"
#include "analysis.h"
#include "utils.h"

#include <string.h>

#include <netinet/if_ether.h>   /* struct ethhdr, ETH_P_IP              */
#include <netinet/ip.h>         /* struct iphdr, IPPROTO_TCP/UDP        */
#include <netinet/tcp.h>        /* struct tcphdr, TH_SYN, TH_ACK       */
#include <netinet/udp.h>        /* struct udphdr                        */
#include <arpa/inet.h>          /* ntohs(), ntohl()                     */

/* ----------------------------------------------------------------
 * process_transport — convergence point for TCP and UDP.
 *
 * Receives a fully-populated packet_info_t and:
 *   1. Builds a flow_key_t from the 5-tuple.
 *   2. Normalises the key (lower IP/port becomes src).
 *   3. Looks up or creates the flow entry; updates packet/byte counts.
 *   4. Updates TCP flag counters on the flow entry (Phase 3).
 *   5. Prints the current flow state.
 *   6. Dispatches to the anomaly detection engine.
 * ---------------------------------------------------------------- */
static void process_transport(const packet_info_t *pkt,
                              flow_table_t *flows,
                              ip_table_t   *trackers)
{
    /* Step 1 & 2: build and normalise the flow key */
    flow_key_t key;
    memset(&key, 0, sizeof(key));   /* zero padding to keep hashing stable */
    key.src_ip   = pkt->src_ip;
    key.dst_ip   = pkt->dst_ip;
    key.src_port = pkt->src_port;
    key.dst_port = pkt->dst_port;
    key.proto    = pkt->proto;
    flow_normalize_key(&key);

    /* Step 3: lookup or create; updates total_packets, total_bytes, last_seen */
    flow_entry_t *entry = flow_lookup_or_create(flows, &key, &pkt->ts, pkt->pkt_len);
    if (entry == NULL) return;  /* malloc failure: drop this packet */

    /* Step 4: update TCP flag counters on the flow entry */
    if (pkt->proto == IPPROTO_TCP) {
        if (pkt->tcp_flags & TH_SYN) entry->syn_count++;
        if (pkt->tcp_flags & TH_ACK) entry->ack_count++;
    }

    /* Step 5: log the updated flow to stdout */
    print_flow(entry);

    /* Step 6: run anomaly checks with the freshly-updated entry */
    check_anomalies(entry, pkt, trackers);
}

/* ----------------------------------------------------------------
 * parse_tcp — extract TCP fields into a packet_info_t.
 *
 * th_off (data offset) gives the TCP header length in 32-bit words.
 * Multiplied by 4 to get bytes. Valid range: 20–60 bytes.
 * transport_payload is set to the first byte of the TCP payload, making
 * it available to higher-level parsers (e.g. TLS/HTTP in a future phase).
 * ---------------------------------------------------------------- */
static void parse_tcp(const uint8_t *ptr, int remaining,
                      uint32_t src_ip, uint32_t dst_ip,
                      const struct timeval *ts, uint32_t pkt_len,
                      flow_table_t *flows, ip_table_t *trackers)
{
    if (remaining < MIN_TCP_HDR_LEN) return;

    const struct tcphdr *tcp = (const struct tcphdr *)ptr;

    /*
     * Compute the TCP header length from the data-offset field.
     * Clamp to MIN_TCP_HDR_LEN on invalid values to avoid negative
     * payload lengths; malformed packets are still flow-tracked.
     */
    int hdrlen = tcp->th_off * 4;
    if (hdrlen < MIN_TCP_HDR_LEN || hdrlen > remaining) {
        hdrlen = MIN_TCP_HDR_LEN;
    }

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
 * parse_udp — extract UDP fields into a packet_info_t.
 *
 * The UDP header is always exactly 8 bytes; no variable-length concern.
 * transport_payload points to the UDP payload, used by detect_dns_anomaly
 * to parse DNS query names.
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
    pkt.tcp_flags             = 0;       /* UDP has no flags */
    pkt.pkt_len               = pkt_len;
    pkt.ts                    = *ts;
    pkt.transport_payload     = ptr + MIN_UDP_HDR_LEN;
    pkt.transport_payload_len = remaining - MIN_UDP_HDR_LEN;

    process_transport(&pkt, flows, trackers);
}

/* ----------------------------------------------------------------
 * parse_ipv4 — validate IPv4 header and dispatch to TCP or UDP.
 *
 * ip->ihl (Internet Header Length) is in 32-bit words; multiplied by 4
 * for bytes. Valid range: 20–60 bytes (IHL 5–15). Values outside this
 * range indicate a malformed packet, which is silently dropped.
 *
 * IPs are converted from network to host byte order HERE, once.
 * All downstream code operates in host byte order.
 *
 * wirelen (passed as pkt_len) is the actual wire size, not caplen.
 * This ensures flow byte counters reflect real traffic volume even when
 * the snapshot length truncates the captured payload.
 * ---------------------------------------------------------------- */
static void parse_ipv4(const uint8_t *ip_ptr, int remaining,
                       const struct timeval *ts, uint32_t wirelen,
                       flow_table_t *flows, ip_table_t *trackers)
{
    if (remaining < MIN_IP_HDR_LEN) return;

    const struct iphdr *ip = (const struct iphdr *)ip_ptr;

    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < MIN_IP_HDR_LEN || ip_hdr_len > remaining) return;

    /* Convert to host byte order once */
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
            break;  /* ICMP, IGMP, etc. — silently ignored */
    }
}

/* ----------------------------------------------------------------
 * parse_dispatch — public entry point; validates Ethernet and filters IPv4.
 *
 * The struct ethhdr cast is safe because:
 *   (a) we validated caplen >= MIN_ETHER_LEN (14 bytes) before the cast.
 *   (b) the buffer is aligned by libpcap.
 *   (c) x86/x86-64 handles any misalignment in hardware.
 *
 * ETH_P_IP (0x0800) is compared AFTER ntohs() because h_proto is in
 * network byte order (big-endian) on the wire.
 * ---------------------------------------------------------------- */
void parse_dispatch(const uint8_t    *packet,
                    int               caplen,
                    uint32_t          wirelen,
                    const struct timeval *ts,
                    flow_table_t     *flows,
                    ip_table_t       *trackers)
{
    if (caplen < MIN_ETHER_LEN) return;

    const struct ethhdr *eth = (const struct ethhdr *)packet;
    if (ntohs(eth->h_proto) != ETH_P_IP) return;

    parse_ipv4(packet + MIN_ETHER_LEN, caplen - MIN_ETHER_LEN,
               ts, wirelen, flows, trackers);
}

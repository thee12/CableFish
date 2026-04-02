/*
 * utils.c — Shared helper function implementations
 *
 * All functions here are stateless and have no dependencies on other
 * project modules (only system headers and types.h).
 */

#include "utils.h"

#include <stdio.h>
#include <inttypes.h>    /* PRIu64      */
#include <netinet/in.h>  /* IPPROTO_TCP, IPPROTO_UDP, AF_INET */

/* ----------------------------------------------------------------
 * ip_to_str
 *
 * htonl() converts the host-byte-order uint32_t back to network byte
 * order (big-endian) as required by inet_ntop(). We store IPs in host
 * order throughout for efficient comparison and hashing, and only convert
 * back here when we need a human-readable string.
 * ---------------------------------------------------------------- */
void ip_to_str(uint32_t ip_host, char *buf, size_t len)
{
    uint32_t ip_net = htonl(ip_host);
    inet_ntop(AF_INET, &ip_net, buf, (socklen_t)len);
}

/* ----------------------------------------------------------------
 * timeval_diff_secs
 * ---------------------------------------------------------------- */
double timeval_diff_secs(const struct timeval *later,
                         const struct timeval *earlier)
{
    return (double)(later->tv_sec  - earlier->tv_sec) +
           (double)(later->tv_usec - earlier->tv_usec) / 1e6;
}

/* ----------------------------------------------------------------
 * fnv1a32
 *
 * FNV-1a (Fowler-Noll-Vo) 32-bit hash. Each byte is XOR'd into the
 * accumulator then multiplied by the FNV prime. This mixes byte position
 * into the hash, unlike plain XOR which is commutative.
 *
 * Constants are from the published FNV specification.
 * ---------------------------------------------------------------- */
uint32_t fnv1a32(const void *data, size_t len)
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

/* ----------------------------------------------------------------
 * proto_name
 * ---------------------------------------------------------------- */
const char *proto_name(uint8_t proto)
{
    switch (proto) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        default:          return "UNK";
    }
}

/* ----------------------------------------------------------------
 * print_flow
 *
 * Prints the current state of a single flow entry. Called from
 * parse.c after every flow update so live activity is visible.
 * ---------------------------------------------------------------- */
void print_flow(const flow_entry_t *e)
{
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    ip_to_str(e->key.src_ip, src, sizeof(src));
    ip_to_str(e->key.dst_ip, dst, sizeof(dst));

    printf("FLOW %s:%u <-> %s:%u | %s | PKTS=%" PRIu64 " | BYTES=%" PRIu64 "\n",
           src, e->key.src_port,
           dst, e->key.dst_port,
           proto_name(e->key.proto),
           e->total_packets,
           e->total_bytes);
}

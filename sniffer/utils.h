/*
 * utils.h — Shared helper functions
 *
 * Provides stateless utility functions used by every other module:
 *   - IP address formatting
 *   - Timestamp arithmetic
 *   - FNV-1a hashing (used by both hash tables)
 *   - Protocol name lookup
 *   - Single-flow pretty-printer
 *
 * No module-specific logic lives here; these are pure helpers.
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>      /* size_t      */
#include <sys/time.h>    /* struct timeval */
#include <arpa/inet.h>   /* INET_ADDRSTRLEN */
#include "types.h"

/*
 * ip_to_str — convert a host-byte-order IPv4 address to dotted-decimal.
 * Writes into caller-supplied buf of at least INET_ADDRSTRLEN bytes.
 */
void ip_to_str(uint32_t ip_host, char *buf, size_t len);

/*
 * timeval_diff_secs — return elapsed seconds from `earlier` to `later`.
 * Returns negative if timestamps are inverted (clock anomaly = not expired).
 */
double timeval_diff_secs(const struct timeval *later,
                         const struct timeval *earlier);

/*
 * fnv1a32 — FNV-1a 32-bit hash over `len` bytes starting at `data`.
 * Used by both the flow table and the IP tracker table.
 */
uint32_t fnv1a32(const void *data, size_t len);

/*
 * proto_name — return a static string label for an IP protocol number.
 * Returns "TCP", "UDP", or "UNK".
 */
const char *proto_name(uint8_t proto);

/*
 * print_flow — write one flow entry to stdout in the standard format:
 *   FLOW src_ip:src_port <-> dst_ip:dst_port | PROTO | PKTS=N | BYTES=N
 */
void print_flow(const flow_entry_t *entry);

#endif /* UTILS_H */

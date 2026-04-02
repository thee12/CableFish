/*
 * flow.h — Bidirectional flow tracking table (public interface)
 *
 * Manages a hash table of flow_entry_t nodes keyed by normalised 5-tuple
 * (src_ip, dst_ip, src_port, dst_port, proto).
 *
 * Normalisation ensures that A→B and B→A map to the same entry so all
 * counters (packets, bytes, TCP flags) reflect total bidirectional traffic.
 *
 * The table uses separate chaining (linked lists) for collision handling
 * and lazy expiry: stale entries are pruned when their bucket is accessed,
 * avoiding the need for a background timer or a full-table scan.
 *
 * Callers (parse.c) are responsible for normalising the key before passing
 * it to flow_lookup_or_create.
 */

#ifndef FLOW_H
#define FLOW_H

#include "types.h"

/*
 * flow_table_init — zero-initialise a flow_table_t.
 * Must be called before any other flow_* function.
 */
void flow_table_init(flow_table_t *tbl);

/*
 * flow_table_free — release all heap memory held by the table.
 * Safe to call on an already-empty table.
 */
void flow_table_free(flow_table_t *tbl);

/*
 * flow_normalize_key — enforce canonical key ordering.
 *
 * Swaps src/dst so the lower IP (or lower port on equal IPs) is always
 * stored as src. This must be called before hashing or lookup.
 */
void flow_normalize_key(flow_key_t *key);

/*
 * flow_lookup_or_create — find or allocate a flow entry, then update stats.
 *
 * Prunes expired entries in the target bucket before walking it (lazy expiry).
 * Updates total_packets, total_bytes, and last_seen on an existing entry.
 * Initialises all fields on a newly created entry.
 *
 * Returns a pointer to the entry on success, NULL on malloc failure.
 */
flow_entry_t *flow_lookup_or_create(flow_table_t *tbl,
                                    const flow_key_t *key,
                                    const struct timeval *ts,
                                    uint32_t pkt_len);

/*
 * flow_print_summary — print all live flows with full statistics to stdout.
 * Intended for the exit summary printed after the capture loop ends.
 */
void flow_print_summary(const flow_table_t *tbl);

#endif /* FLOW_H */

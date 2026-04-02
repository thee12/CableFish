/*
 * flow.c — Bidirectional flow tracking table implementation
 *
 * Implements a fixed-size hash table with separate chaining.
 * All internal helpers (hashing, key comparison, bucket expiry) are static
 * and not visible outside this translation unit.
 *
 * Key design decisions:
 *   - FNV-1a hash over the entire flow_key_t struct for good avalanche.
 *   - Field-by-field key comparison to avoid issues with struct padding.
 *   - calloc() for new entries guarantees all fields start at zero, making
 *     last_alert_time.tv_sec == 0 a reliable "never alerted" sentinel.
 *   - New entries are prepended to the bucket list (O(1)); order within a
 *     bucket is irrelevant for correctness.
 */

#include "flow.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>   /* INET_ADDRSTRLEN */

/* ----------------------------------------------------------------
 * Internal: key hashing and comparison
 * ---------------------------------------------------------------- */

/*
 * hash_key — map a normalised flow_key_t to a bucket index.
 * Hashes all bytes of the struct then masks to [0, FLOW_TABLE_SIZE).
 */
static uint32_t hash_key(const flow_key_t *key)
{
    return fnv1a32(key, sizeof(flow_key_t)) & FLOW_TABLE_MASK;
}

/*
 * keys_equal — return 1 if both keys represent the same flow, 0 otherwise.
 * Field-by-field comparison avoids undefined behaviour from struct padding.
 */
static int keys_equal(const flow_key_t *a, const flow_key_t *b)
{
    return (a->src_ip   == b->src_ip   &&
            a->dst_ip   == b->dst_ip   &&
            a->src_port == b->src_port &&
            a->dst_port == b->dst_port &&
            a->proto    == b->proto);
}

/* ----------------------------------------------------------------
 * Internal: lazy expiry
 *
 * Walk the linked list at buckets[idx] and free any entry whose
 * last_seen is older than FLOW_TIMEOUT_SECS relative to `now`.
 *
 * Uses the standard prev/curr pattern for singly-linked list deletion:
 *   - If curr is stale: update the pointer that pointed TO curr
 *     (either the bucket head or prev->next) to skip it, then free curr.
 *   - prev does NOT advance when we delete, because after deletion the
 *     slot previously occupied by curr is now occupied by curr->next.
 * ---------------------------------------------------------------- */
static void expire_bucket(flow_table_t *tbl, uint32_t idx,
                          const struct timeval *now)
{
    flow_entry_t *prev = NULL;
    flow_entry_t *curr = tbl->buckets[idx];

    while (curr != NULL) {
        flow_entry_t *next = curr->next;

        if (timeval_diff_secs(now, &curr->last_seen) > FLOW_TIMEOUT_SECS) {
            /* Unlink */
            if (prev != NULL) {
                prev->next = next;
            } else {
                tbl->buckets[idx] = next;
            }
            free(curr);
            tbl->flow_count--;
            /* prev stays — it now correctly precedes `next` */
        } else {
            prev = curr;
        }

        curr = next;
    }
}

/* ----------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------- */

void flow_table_init(flow_table_t *tbl)
{
    memset(tbl, 0, sizeof(*tbl));
}

void flow_table_free(flow_table_t *tbl)
{
    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        flow_entry_t *curr = tbl->buckets[i];
        while (curr != NULL) {
            flow_entry_t *next = curr->next;
            free(curr);
            curr = next;
        }
        tbl->buckets[i] = NULL;
    }
    tbl->flow_count = 0;
}

void flow_normalize_key(flow_key_t *key)
{
    /*
     * Canonical form: lower IP is always src.
     * If IPs are equal (e.g. loopback), lower port is src.
     * Any packet arriving in the "wrong" direction is silently flipped.
     */
    int swap = (key->src_ip > key->dst_ip) ||
               (key->src_ip == key->dst_ip && key->src_port > key->dst_port);

    if (swap) {
        uint32_t tmp_ip   = key->src_ip;
        key->src_ip       = key->dst_ip;
        key->dst_ip       = tmp_ip;

        uint16_t tmp_port = key->src_port;
        key->src_port     = key->dst_port;
        key->dst_port     = tmp_port;
    }
}

flow_entry_t *flow_lookup_or_create(flow_table_t *tbl,
                                    const flow_key_t *key,
                                    const struct timeval *ts,
                                    uint32_t pkt_len)
{
    uint32_t idx = hash_key(key);

    /* Prune idle flows in this bucket before walking it */
    expire_bucket(tbl, idx, ts);

    /* Search for an existing entry */
    for (flow_entry_t *e = tbl->buckets[idx]; e != NULL; e = e->next) {
        if (keys_equal(&e->key, key)) {
            /* Found: update counters and timestamp */
            e->total_packets++;
            e->total_bytes += pkt_len;
            e->last_seen    = *ts;
            return e;
        }
    }

    /* Not found: allocate a new entry (calloc zeros all fields) */
    flow_entry_t *e = (flow_entry_t *)calloc(1, sizeof(flow_entry_t));
    if (e == NULL) {
        fprintf(stderr, "Error: calloc failed for flow_entry_t\n");
        return NULL;
    }

    e->key           = *key;
    e->total_packets = 1;
    e->total_bytes   = pkt_len;
    e->start_time    = *ts;
    e->last_seen     = *ts;
    /* syn_count, ack_count, last_alert_time are zero from calloc */

    /* Prepend to bucket list — O(1), no tail scan needed */
    e->next           = tbl->buckets[idx];
    tbl->buckets[idx] = e;
    tbl->flow_count++;

    return e;
}

void flow_print_summary(const flow_table_t *tbl)
{
    printf("\n============================================================\n");
    printf("  Flow Table Summary -- %" PRIu64 " active flow(s)\n",
           tbl->flow_count);
    printf("============================================================\n");

    uint64_t printed = 0;

    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        for (const flow_entry_t *e = tbl->buckets[i]; e != NULL; e = e->next) {
            char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
            ip_to_str(e->key.src_ip, src, sizeof(src));
            ip_to_str(e->key.dst_ip, dst, sizeof(dst));
            double dur = timeval_diff_secs(&e->last_seen, &e->start_time);

            printf("  %s:%u <-> %s:%u | %s"
                   " | PKTS=%" PRIu64 " | BYTES=%" PRIu64
                   " | SYN=%u | ACK=%u | DUR=%.2fs\n",
                   src, e->key.src_port,
                   dst, e->key.dst_port,
                   proto_name(e->key.proto),
                   e->total_packets, e->total_bytes,
                   e->syn_count, e->ack_count, dur);
            printed++;
        }
    }

    if (printed == 0) {
        printf("  (no flows captured)\n");
    }

    printf("============================================================\n");
}

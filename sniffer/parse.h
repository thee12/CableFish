/*
 * parse.h — Packet parsing module (public interface)
 *
 * Exposes a single entry point, parse_dispatch(), which accepts a raw
 * Ethernet frame from the capture layer and peels each protocol layer:
 *
 *   Ethernet → IPv4 → TCP / UDP
 *
 * For each TCP or UDP packet, parse_dispatch:
 *   1. Fills a packet_info_t with all extracted metadata.
 *   2. Builds and normalises a flow_key_t.
 *   3. Calls flow_lookup_or_create() to update the flow table.
 *   4. Updates per-flow TCP flag counters (syn_count, ack_count).
 *   5. Calls print_flow() to log the current flow state.
 *   6. Calls check_anomalies() to run all detectors.
 *
 * This module is the integration point between the capture layer
 * (raw bytes) and the state-tracking layers (flow, analysis).
 * It contains no persistent state of its own.
 *
 * Non-IPv4 frames and non-TCP/UDP protocols are silently ignored.
 */

#ifndef PARSE_H
#define PARSE_H

#include <stdint.h>
#include <sys/time.h>
#include "types.h"

/*
 * parse_dispatch — parse one raw Ethernet frame and update all state.
 *
 * packet   — raw bytes starting at the Ethernet header (from libpcap)
 * caplen   — bytes in the capture buffer (used for bounds checking)
 * wirelen  — actual wire length (used for accurate flow byte accounting)
 * ts       — libpcap capture timestamp
 * flows    — flow hash table to update
 * trackers — per-IP tracker table for anomaly detection
 */
void parse_dispatch(const uint8_t    *packet,
                    int               caplen,
                    uint32_t          wirelen,
                    const struct timeval *ts,
                    flow_table_t     *flows,
                    ip_table_t       *trackers);

#endif /* PARSE_H */

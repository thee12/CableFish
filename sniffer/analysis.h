/*
 * analysis.h — Anomaly detection engine (public interface)
 *
 * Implements three rule-based detectors triggered once per packet:
 *
 *   SYN_SCAN    — many TCP SYN packets from one source IP across any number
 *                 of flows, with few corresponding ACKs. Tracked per source IP
 *                 because a scanner probes many ports (many flows), so the
 *                 signal only appears when aggregated at the IP level.
 *
 *   DNS_ANOMALY — either a single DNS query for an unusually long domain
 *                 (possible DNS tunnelling) or a high query rate from one
 *                 source (possible C2 or DGA). Both tracked per source IP.
 *
 *   HIGH_TRAFFIC — a single bidirectional flow whose byte total exceeds a
 *                  threshold (possible large transfer or data exfiltration).
 *                  Tracked per flow_entry_t.
 *
 * Alert spam is suppressed with per-IP and per-flow cooldown timestamps.
 * Sliding window counters reset when the current packet arrives outside the
 * previous window — O(1) per packet, no timers or full-table scans required.
 *
 * The ip_table_t (per-IP state) is owned and managed entirely within this
 * module. Callers only call analysis_init, analysis_free, and check_anomalies.
 */

#ifndef ANALYSIS_H
#define ANALYSIS_H

#include "types.h"

/*
 * analysis_init — zero-initialise the ip_tracker hash table.
 * Must be called before check_anomalies.
 */
void analysis_init(ip_table_t *tbl);

/*
 * analysis_free — release all heap memory held by the ip_tracker table.
 */
void analysis_free(ip_table_t *tbl);

/*
 * check_anomalies — run all three detectors for one packet/flow update.
 *
 * flow     — the flow entry already updated by flow_lookup_or_create.
 * pkt      — full packet metadata filled in by parse.c.
 * trackers — per-IP state table, allocated by the caller (main.c).
 *
 * Each detector is independent; a single packet can trigger multiple alerts.
 */
void check_anomalies(flow_entry_t *flow,
                     const packet_info_t *pkt,
                     ip_table_t *trackers);

#endif /* ANALYSIS_H */

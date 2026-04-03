/*
 * analysis.h — Anomaly detection engine (public interface)
 *
 * Phase 4 change: check_anomalies() now returns alert_type_t instead of void.
 * The return value is used by parse.c to populate the alert field of the
 * packet_record_t that gets written to the JSON/CSV output pipeline.
 *
 * All three detectors remain active on every call; the return value is the
 * highest-priority alert that fired (ALERT_NONE if nothing fired).
 *
 * Priority order (highest first):
 *   ALERT_HIGH_TRAFFIC > ALERT_SYN_SCAN > ALERT_DNS_ANOMALY_FREQ > ALERT_DNS_ANOMALY_LONG
 *
 * Console alerts (printf) still fire for ALL detectors that trigger,
 * regardless of which one is returned. The return value is only used to
 * populate the log record — it does not suppress any console output.
 */

#ifndef ANALYSIS_H
#define ANALYSIS_H

#include "types.h"

/*
 * analysis_init — zero-initialise the ip_tracker hash table.
 */
void analysis_init(ip_table_t *tbl);

/*
 * analysis_free — release all heap memory in the ip_tracker table.
 */
void analysis_free(ip_table_t *tbl);

/*
 * check_anomalies — run all detectors for one packet/flow event.
 *
 * Parameters:
 *   flow     — flow entry already updated by flow_lookup_or_create
 *   pkt      — full parsed packet metadata from parse.c
 *   trackers — per-IP state table (owned by main.c, passed through)
 *
 * Returns the highest-priority alert_type_t that fired, or ALERT_NONE.
 * The caller (parse.c) stores this in the packet_record_t for logging.
 */
alert_type_t check_anomalies(flow_entry_t        *flow,
                             const packet_info_t *pkt,
                             ip_table_t          *trackers);

#endif /* ANALYSIS_H */
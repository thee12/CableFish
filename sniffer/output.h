/*
 * output.h — Structured logging / export pipeline (public interface)
 *
 * Provides a pluggable output system that writes packet_record_t events
 * to one or more file-based sinks in real time:
 *
 *   JSON sink  → packets.json   (JSONL: one JSON object per line)
 *   CSV  sink  → packets.csv    (header row + one data row per event)
 *
 * Architecture:
 *
 *   parse.c calls output_write(record) after each packet is fully processed.
 *   output_write fans the record out to every enabled sink via internal
 *   log_json() and log_csv() helpers.
 *
 *   This module owns the FILE handles internally — callers see only
 *   output_init / output_write / output_close.
 *
 * Lifecycle:
 *   1. output_init()  — open files, write CSV header if file is new
 *   2. output_write() — called per packet (very frequently)
 *   3. output_close() — flush and close files cleanly at exit
 *
 * Thread safety: none (single-threaded by design).
 */

#ifndef OUTPUT_H
#define OUTPUT_H

#include "types.h"

/*
 * output_init — initialise the logging pipeline from a config struct.
 *
 * Opens output files in append mode ("a") so existing data is preserved
 * across runs. Writes the CSV header row only if the file is newly created
 * (detected by seeking to end and checking ftell == 0).
 *
 * Must be called once before any output_write() call.
 * Safe to call when both json_enabled and csv_enabled are 0 — becomes a no-op.
 */
void output_init(const output_config_t *cfg);

/*
 * output_write — write one packet_record_t to all enabled sinks.
 *
 * Called from parse.c after every processed TCP/UDP packet.
 * Internally calls log_json() and/or log_csv() depending on config.
 * Each write is followed by fflush() so data reaches the file even if
 * the process is killed (no buffered-but-unwritten records).
 *
 * Safe to call when no sinks are enabled — becomes a no-op.
 */
void output_write(const packet_record_t *rec);

/*
 * output_close — flush and close all open output files.
 *
 * Must be called before program exit (called from main.c after the
 * capture loop ends). Safe to call even if output_init was not called
 * or if no files are open.
 */
void output_close(void);

/*
 * output_format_timestamp — format a struct timeval as ISO-8601 UTC string.
 *
 * Produces: "2026-04-02T15:32:10.123Z"
 * buf must be at least 32 bytes. Called from parse.c to fill the timestamp
 * field of a packet_record_t before passing it to output_write().
 *
 * Defined in output.c (not utils.c) because timestamp formatting is an
 * output-layer concern: it uses <time.h> and produces the exact string
 * format expected by the JSON and CSV sinks.
 */
void output_format_timestamp(const struct timeval *tv, char *buf, size_t buflen);

#endif /* OUTPUT_H */
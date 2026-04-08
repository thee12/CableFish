/*
 * output.c — Structured logging / export pipeline implementation
 *
 * Internal structure:
 *
 *   g_out              — static module state (config + file handles)
 *   format_timestamp() — formats struct timeval as ISO-8601 UTC string
 *   alert_type_name()  — maps alert_type_t enum to a fixed string
 *   log_json()         — writes one JSONL record to packets.json
 *   log_csv()          — writes one CSV row to packets.csv
 *   output_init()      — opens files, writes CSV header on new files
 *   output_write()     — public dispatcher: calls log_json + log_csv
 *   output_close()     — flushes and closes all open file handles
 *
 * JSON format (one object per line, JSONL):
 *   {"timestamp":"2026-04-02T15:32:10.123Z","src_ip":"192.168.1.5",
 *    "dst_ip":"142.250.72.206","src_port":51532,"dst_port":443,
 *    "protocol":"TCP","length":1460,"packets_total":10,"bytes_total":8420,
 *    "alert":"NONE"}
 *
 * CSV format (header + data rows):
 *   timestamp,src_ip,dst_ip,src_port,dst_port,protocol,length,packets_total,bytes_total,alert
 *   2026-04-02T15:32:10.123Z,192.168.1.5,142.250.72.206,51532,443,TCP,1460,10,8420,NONE
 */

#include "output.h"
#include "ipc.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>        /* gmtime_r, strftime */
#include <inttypes.h>    /* PRIu64             */
#include <netinet/in.h>  /* IPPROTO_TCP/UDP    */

/* ============================================================
 * Module-level state
 *
 * Kept static so it is not accessible outside this translation unit.
 * Callers interact only through the three public functions.
 * ============================================================ */
typedef struct {
    output_config_t cfg;        /* copy of caller-supplied config            */
    FILE           *json_file;  /* handle for packets.json, or NULL          */
    FILE           *csv_file;   /* handle for packets.csv,  or NULL          */
} output_state_t;

static output_state_t g_out;   /* zero-initialised at program start          */

/* ============================================================
 * Internal: format_timestamp
 *
 * Converts a struct timeval to an ISO-8601 UTC string with millisecond
 * precision:  "2026-04-02T15:32:10.123Z"
 *
 * Uses gmtime_r (POSIX, available under gnu99) for reentrant UTC conversion.
 * Falls back gracefully to "1970-01-01T00:00:00.000Z" if the conversion
 * fails (should never happen in practice with a valid libpcap timestamp).
 *
 * buf must be at least 32 bytes.
 * ============================================================ */
static void format_timestamp(const struct timeval *tv, char *buf, size_t buflen)
{
    time_t   t  = (time_t)tv->tv_sec;
    struct tm tm_info;

    if (gmtime_r(&t, &tm_info) == NULL) {
        /* Safety fallback: should never occur with valid libpcap timestamps */
        snprintf(buf, buflen, "1970-01-01T00:00:00.000Z");
        return;
    }

    /* Format date and time portion: "2026-04-02T15:32:10" (19 chars) */
    char base[24];
    strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm_info);

    /* Append milliseconds and UTC suffix: ".123Z" */
    snprintf(buf, buflen, "%s.%03ldZ", base, (long)(tv->tv_usec / 1000));
}

/* ============================================================
 * Internal: log_json
 *
 * Writes one JSON object to the json_file handle, followed by a newline.
 * This produces JSONL (newline-delimited JSON), which is streamable and
 * directly parseable by tools like `jq`, Python's `json` module, etc.
 *
 * All field values are either integers or pre-validated fixed strings
 * (IP addresses from inet_ntop, protocol names, alert names, timestamp).
 * No user-controlled string content appears in the JSON, so no JSON
 * escaping of special characters is required.
 *
 * Field order follows the spec exactly; no trailing commas.
 * ============================================================ */
static void log_json(const packet_record_t *rec)
{
    if (g_out.json_file == NULL) return;

    fprintf(g_out.json_file,
        "{"
        "\"timestamp\":\"%s\","
        "\"src_ip\":\"%s\","
        "\"dst_ip\":\"%s\","
        "\"src_port\":%u,"
        "\"dst_port\":%u,"
        "\"protocol\":\"%s\","
        "\"length\":%u,"
        "\"packets_total\":%" PRIu64 ","
        "\"bytes_total\":%" PRIu64 ","
        "\"alert\":\"%s\""
        "}\n",
        rec->timestamp,
        rec->src_ip,
        rec->dst_ip,
        (unsigned)rec->src_port,
        (unsigned)rec->dst_port,
        proto_name(rec->proto),
        (unsigned)rec->length,
        rec->packets_total,
        rec->bytes_total,
        alert_type_name(rec->alert)
    );

    /*
     * Flush after every record so data reaches the file immediately.
     * Without flushing, a SIGKILL (not caught by our handlers) could
     * leave the last N records stranded in the stdio buffer.
     */
    fflush(g_out.json_file);
}

/* ============================================================
 * Internal: log_csv
 *
 * Writes one CSV data row to csv_file.
 * No quoting is needed: IP addresses never contain commas, port numbers
 * and lengths are integers, protocol/alert strings are controlled enum
 * values, and the timestamp is a fixed-format ISO-8601 string.
 *
 * Row format matches the header written in output_init():
 *   timestamp,src_ip,dst_ip,src_port,dst_port,protocol,length,packets_total,bytes_total,alert
 * ============================================================ */
static void log_csv(const packet_record_t *rec)
{
    if (g_out.csv_file == NULL) return;

    fprintf(g_out.csv_file,
        "%s,%s,%s,%u,%u,%s,%u,%" PRIu64 ",%" PRIu64 ",%s\n",
        rec->timestamp,
        rec->src_ip,
        rec->dst_ip,
        (unsigned)rec->src_port,
        (unsigned)rec->dst_port,
        proto_name(rec->proto),
        (unsigned)rec->length,
        rec->packets_total,
        rec->bytes_total,
        alert_type_name(rec->alert)
    );

    fflush(g_out.csv_file);
}

/* ============================================================
 * Internal: open_output_file
 *
 * Builds the full output path, opens the file in append mode ("a"),
 * and returns the handle. Prints an error and returns NULL on failure.
 *
 * "a" mode: if the file exists, writes are appended; if not, it is created.
 * This preserves data across multiple sniffer runs.
 * ============================================================ */
static FILE *open_output_file(const char *dir, const char *filename)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, filename);

    FILE *f = fopen(path, "a");
    if (f == NULL) {
        fprintf(stderr, "Error: cannot open output file '%s'\n", path);
    } else {
        fprintf(stderr, "Output: writing to '%s'\n", path);
    }
    return f;
}

/* ============================================================
 * Public API
 * ============================================================ */

void output_init(const output_config_t *cfg)
{
    /* Copy config into module state */
    g_out.cfg        = *cfg;
    g_out.json_file  = NULL;
    g_out.csv_file   = NULL;

    /* Open JSON file if enabled */
    if (cfg->json_enabled) {
        g_out.json_file = open_output_file(cfg->output_dir, "packets.json");
    }

    /* Open CSV file and write header if the file is new (size == 0) */
    if (cfg->csv_enabled) {
        g_out.csv_file = open_output_file(cfg->output_dir, "packets.csv");

        if (g_out.csv_file != NULL) {
            /*
             * Seek to end to measure file size. If the file was just created
             * (or was previously empty) ftell returns 0 and we write the header.
             * If the file already contains rows from a previous run, we append
             * data rows directly without duplicating the header.
             */
            fseek(g_out.csv_file, 0, SEEK_END);
            if (ftell(g_out.csv_file) == 0) {
                fprintf(g_out.csv_file,
                    "timestamp,src_ip,dst_ip,src_port,dst_port,"
                    "protocol,length,packets_total,bytes_total,alert\n");
                fflush(g_out.csv_file);
            }
        }
    }
}

/*
 * output_write — public entry point called once per processed packet.
 *
 * Before writing, pre-formats the timestamp from the struct timeval in the
 * record. The timestamp field in packet_record_t is a char array; we fill
 * it here rather than in parse.c to keep formatting concerns in this module.
 */
void output_write(const packet_record_t *rec)
{
    /*
     * Fan the record out to every enabled sink.
     * Each sink is independent — a failure in one does not affect the others.
     *
     * Sink order:
     *   1. JSON file   (log_json)     — append to packets.json
     *   2. CSV  file   (log_csv)      — append to packets.csv
     *   3. IPC stream  (ipc_send_record) — send to backend over UNIX socket [Phase 5]
     */
    if (g_out.cfg.json_enabled) log_json(rec);
    if (g_out.cfg.csv_enabled)  log_csv(rec);
    if (g_out.cfg.ipc_enabled)  ipc_send_record(rec);
}

void output_close(void)
{
    if (g_out.json_file != NULL) {
        fflush(g_out.json_file);
        fclose(g_out.json_file);
        g_out.json_file = NULL;
    }
    if (g_out.csv_file != NULL) {
        fflush(g_out.csv_file);
        fclose(g_out.csv_file);
        g_out.csv_file = NULL;
    }
}

/*
 * output_format_timestamp — utility exposed so parse.c can fill
 * the timestamp field of a packet_record_t before calling output_write.
 *
 * Defined here (not in utils.c) because timestamp formatting is an
 * output-layer concern — it uses <time.h> and produces the exact string
 * format expected by the JSON and CSV sinks.
 */
void output_format_timestamp(const struct timeval *tv, char *buf, size_t buflen)
{
    format_timestamp(tv, buf, buflen);
}
/*
 * main.c — Program entry point (Phase 4: Structured Logging)
 *
 * Phase 4 additions:
 *   - Parses three optional command-line flags:
 *       --json              enable JSON output  (packets.json)
 *       --csv               enable CSV output   (packets.csv)
 *       --output-dir <path> directory for output files (default: ".")
 *
 *   - If neither --json nor --csv is given, BOTH are enabled by default
 *     so the sniffer produces file output out of the box.
 *
 *   - Calls output_init() before the capture loop and output_close()
 *     after, ensuring all file handles are properly opened and flushed.
 *
 * Argument parsing rules:
 *   - Flags may appear in any order.
 *   - The first non-flag argument (not starting with '-') is treated as
 *     the interface name, preserving backward compatibility.
 *   - Unknown flags are silently ignored (forward compatibility).
 *
 * Full invocation examples:
 *   sudo ./sniffer
 *   sudo ./sniffer eth0
 *   sudo ./sniffer --json --csv eth0
 *   sudo ./sniffer --csv --output-dir /var/log/sniffer eth0
 *   sudo ./sniffer --json --output-dir /tmp
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>

#include <pcap.h>

#include "types.h"
#include "capture.h"
#include "flow.h"
#include "analysis.h"
#include "output.h"
#include "utils.h"

/* ----------------------------------------------------------------
 * parse_args — extract interface name and output flags from argv.
 *
 * Modifies `dev` to point to the interface name argument (or NULL if
 * not provided). Fills `out_cfg` from recognised flags.
 * ---------------------------------------------------------------- */
static void parse_args(int argc, char *argv[],
                       const char **dev,
                       output_config_t *out_cfg)
{
    int json_explicit = 0;
    int csv_explicit  = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) {
            json_explicit = 1;

        } else if (strcmp(argv[i], "--csv") == 0) {
            csv_explicit = 1;

        } else if (strcmp(argv[i], "--output-dir") == 0) {
            if (i + 1 < argc) {
                /*
                 * Copy into the fixed-size buffer with snprintf to prevent
                 * overflow. The -1 ensures NUL termination even when the
                 * path is exactly 255 characters long.
                 */
                snprintf(out_cfg->output_dir,
                         sizeof(out_cfg->output_dir) - 1,
                         "%s", argv[++i]);
            } else {
                fprintf(stderr, "Warning: --output-dir requires a path argument\n");
            }

        } else if (argv[i][0] != '-' && *dev == NULL) {
            /* First non-flag argument is the interface name */
            *dev = argv[i];

        }
        /* Unknown flags are silently skipped for forward compatibility */
    }

    /*
     * Default behaviour: if the user gave no output flags, enable both.
     * If any flag was explicitly given, respect only those flags.
     */
    if (!json_explicit && !csv_explicit) {
        out_cfg->json_enabled = 1;
        out_cfg->csv_enabled  = 1;
    } else {
        out_cfg->json_enabled = json_explicit;
        out_cfg->csv_enabled  = csv_explicit;
    }
}

/* ----------------------------------------------------------------
 * main
 * ---------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *dev = NULL;

    /* ------------------------------------------------------------------
     * 1. Initialise output config with safe defaults, then parse CLI args
     * ------------------------------------------------------------------ */
    output_config_t out_cfg;
    memset(&out_cfg, 0, sizeof(out_cfg));
    strncpy(out_cfg.output_dir, ".", sizeof(out_cfg.output_dir) - 1);

    parse_args(argc, argv, &dev, &out_cfg);

    /* ------------------------------------------------------------------
     * 2. Initialise state tables
     * ------------------------------------------------------------------ */
    flow_table_t g_flows;
    ip_table_t   g_trackers;

    flow_table_init(&g_flows);
    analysis_init(&g_trackers);

    /* ------------------------------------------------------------------
     * 3. Resolve capture interface if not given via CLI
     * ------------------------------------------------------------------ */
    if (dev == NULL) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        dev = pcap_lookupdev(errbuf);
#pragma GCC diagnostic pop
        if (dev == NULL) {
            fprintf(stderr, "Error: no capture interface found: %s\n", errbuf);
            fprintf(stderr,
                    "Hint: run with sudo, or specify: ./sniffer [--json] [--csv] "
                    "[--output-dir PATH] INTERFACE\n");
            return EXIT_FAILURE;
        }
    }

    /* ------------------------------------------------------------------
     * 4. Print active configuration
     * ------------------------------------------------------------------ */
    printf("=== Packet Sniffer -- Phase 4 (Structured Logging) ===\n");
    printf("Interface       : %s\n",   dev);
    printf("JSON output     : %s\n",   out_cfg.json_enabled ? "enabled" : "disabled");
    printf("CSV  output     : %s\n",   out_cfg.csv_enabled  ? "enabled" : "disabled");
    printf("Output dir      : %s\n",   out_cfg.output_dir);
    printf("Flow timeout    : %.0fs\n", FLOW_TIMEOUT_SECS);
    printf("SYN scan        : %d SYNs / %.0fs\n",
           THRESH_SYN_COUNT, THRESH_SYN_WINDOW_SECS);
    printf("DNS name len    : > %d chars\n", THRESH_DNS_NAME_LEN);
    printf("DNS frequency   : > %d / %.0fs\n",
           THRESH_DNS_FREQ_COUNT, THRESH_DNS_WINDOW_SECS);
    printf("High traffic    : > %" PRIu64 " bytes\n", (uint64_t)THRESH_HIGH_BYTES);
    printf("Alert cooldown  : %.0fs\n", ALERT_COOLDOWN_SECS);
    printf("Press Ctrl+C to stop.\n\n");

    /* ------------------------------------------------------------------
     * 5. Initialise output pipeline — opens files, writes CSV header
     * ------------------------------------------------------------------ */
    output_init(&out_cfg);

    /* ------------------------------------------------------------------
     * 6. Install signal handlers
     * ------------------------------------------------------------------ */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = capture_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT,  &sa, NULL) == -1 ||
        sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction");
        output_close();
        return EXIT_FAILURE;
    }

    /* ------------------------------------------------------------------
     * 7. Open capture handle
     * ------------------------------------------------------------------ */
    pcap_t *handle = capture_open(dev, errbuf);
    if (handle == NULL) {
        output_close();
        return EXIT_FAILURE;
    }

    /* ------------------------------------------------------------------
     * 8. Blocking capture loop
     * ------------------------------------------------------------------ */
    int rc = capture_run(handle, &g_flows, &g_trackers);

    if (rc == -1) {
        fprintf(stderr, "\nCapture error: %s\n", pcap_geterr(handle));
    } else {
        printf("\nCapture stopped.\n");
    }

    /* ------------------------------------------------------------------
     * 9. Flush and close output files before printing the summary so
     *    that all data is on disk before we exit.
     * ------------------------------------------------------------------ */
    output_close();

    /* ------------------------------------------------------------------
     * 10. Print flow summary and libpcap stats, then free all memory
     * ------------------------------------------------------------------ */
    flow_print_summary(&g_flows);
    capture_print_stats(handle);
    capture_close(handle);

    flow_table_free(&g_flows);
    analysis_free(&g_trackers);

    return (rc == -1) ? EXIT_FAILURE : EXIT_SUCCESS;
}
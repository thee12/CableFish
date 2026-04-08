/*
 * main.c — Program entry point (Phase 5: WebSocket Streaming Backend)
 *
 * Phase 4 flags (unchanged):
 *   --json              enable JSON file output  (packets.json)
 *   --csv               enable CSV  file output  (packets.csv)
 *   --output-dir <path> directory for output files (default: ".")
 *
 * Phase 5 flags (new):
 *   --stream            enable real-time IPC streaming to the Node.js backend
 *   --backend-path <p>  UNIX socket path (default: /tmp/sniffer.sock)
 *
 * --stream is opt-in. If not specified, file sinks behave as in Phase 4.
 * If --stream is given without --backend-path, the default socket path is used.
 *
 * Full invocation examples:
 *   sudo ./sniffer
 *   sudo ./sniffer --stream eth0
 *   sudo ./sniffer --stream --backend-path /tmp/sniffer.sock eth0
 *   sudo ./sniffer --json --csv --stream --output-dir /var/log eth0
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
#include "ipc.h"
#include "utils.h"

/* ----------------------------------------------------------------
 * parse_args — extract interface name and output/IPC flags from argv.
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
                snprintf(out_cfg->output_dir,
                         sizeof(out_cfg->output_dir) - 1,
                         "%s", argv[++i]);
            } else {
                fprintf(stderr, "Warning: --output-dir requires a path\n");
            }

        } else if (strcmp(argv[i], "--stream") == 0) {
            /* Phase 5: enable real-time IPC streaming to the Node.js backend */
            out_cfg->ipc_enabled = 1;

        } else if (strcmp(argv[i], "--backend-path") == 0) {
            /* Phase 5: override the UNIX socket path (default /tmp/sniffer.sock) */
            if (i + 1 < argc) {
                snprintf(out_cfg->ipc_socket_path,
                         sizeof(out_cfg->ipc_socket_path) - 1,
                         "%s", argv[++i]);
            } else {
                fprintf(stderr, "Warning: --backend-path requires a path\n");
            }

        } else if (argv[i][0] != '-' && *dev == NULL) {
            *dev = argv[i];
        }
    }

    /*
     * Default file-sink behaviour (unchanged from Phase 4):
     * if neither --json nor --csv is given, enable both.
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
    strncpy(out_cfg.output_dir,     ".",                    sizeof(out_cfg.output_dir) - 1);
    strncpy(out_cfg.ipc_socket_path, IPC_DEFAULT_SOCKET_PATH, sizeof(out_cfg.ipc_socket_path) - 1);

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
                    "Usage: ./sniffer [--json] [--csv] [--output-dir DIR]\n"
                    "                 [--stream] [--backend-path PATH] [IFACE]\n");
            return EXIT_FAILURE;
        }
    }

    /* ------------------------------------------------------------------
     * 4. Print active configuration
     * ------------------------------------------------------------------ */
    printf("=== Packet Sniffer -- Phase 5 (WebSocket Streaming) ===\n");
    printf("Interface       : %s\n",   dev);
    printf("JSON output     : %s\n",   out_cfg.json_enabled ? "enabled" : "disabled");
    printf("CSV  output     : %s\n",   out_cfg.csv_enabled  ? "enabled" : "disabled");
    printf("Output dir      : %s\n",   out_cfg.output_dir);
    printf("IPC streaming   : %s\n",   out_cfg.ipc_enabled  ? "enabled" : "disabled");
    if (out_cfg.ipc_enabled)
        printf("Backend socket  : %s\n", out_cfg.ipc_socket_path);
    printf("Flow timeout    : %.0fs\n", FLOW_TIMEOUT_SECS);
    printf("SYN scan        : %d SYNs / %.0fs\n",
           THRESH_SYN_COUNT, THRESH_SYN_WINDOW_SECS);
    printf("DNS name len    : > %d chars\n",   THRESH_DNS_NAME_LEN);
    printf("DNS frequency   : > %d / %.0fs\n",
           THRESH_DNS_FREQ_COUNT, THRESH_DNS_WINDOW_SECS);
    printf("High traffic    : > %" PRIu64 " bytes\n", (uint64_t)THRESH_HIGH_BYTES);
    printf("Alert cooldown  : %.0fs\n", ALERT_COOLDOWN_SECS);
    printf("Press Ctrl+C to stop.\n\n");

    /* ------------------------------------------------------------------
     * 5. Initialise output pipeline (files) and IPC stream [Phase 5]
     * ------------------------------------------------------------------ */
    output_init(&out_cfg);

    if (out_cfg.ipc_enabled) {
        ipc_init(out_cfg.ipc_socket_path);   /* non-fatal if backend is down */
    }

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
        ipc_close();
        output_close();
        return EXIT_FAILURE;
    }

    /* ------------------------------------------------------------------
     * 7. Open capture handle
     * ------------------------------------------------------------------ */
    pcap_t *handle = capture_open(dev, errbuf);
    if (handle == NULL) {
        ipc_close();
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
     * 9. Flush / close all outputs before the exit summary
     * ------------------------------------------------------------------ */
    ipc_close();
    output_close();

    /* ------------------------------------------------------------------
     * 10. Print flow summary, libpcap stats, free all memory
     * ------------------------------------------------------------------ */
    flow_print_summary(&g_flows);
    capture_print_stats(handle);
    capture_close(handle);

    flow_table_free(&g_flows);
    analysis_free(&g_trackers);

    return (rc == -1) ? EXIT_FAILURE : EXIT_SUCCESS;
}
/*
 * main.c — Program entry point
 *
 * Responsibilities:
 *   1. Declare and initialise the two shared state tables:
 *        flow_table_t  g_flows    — bidirectional flow tracking (flow.c)
 *        ip_table_t    g_trackers — per-IP anomaly state    (analysis.c)
 *   2. Resolve the capture interface (from argv or pcap_lookupdev).
 *   3. Print the active configuration to stdout.
 *   4. Install SIGINT/SIGTERM signal handlers.
 *   5. Open the capture handle (capture.c).
 *   6. Run the blocking capture loop (capture.c).
 *   7. On exit: print flow summary, libpcap stats, free all heap memory.
 *
 * main.c has NO packet-processing logic.  All of that lives in:
 *   parse.c    → protocol layer dissection
 *   flow.c     → flow table management
 *   analysis.c → anomaly detection
 *   utils.c    → formatting helpers
 *   capture.c  → libpcap I/O
 *
 * Data flow:
 *   libpcap → capture.c → parse.c → flow.c  → (stats)
 *                                 → analysis.c → (alerts)
 *                                 → utils.c    → (stdout)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>

#include <pcap.h>   /* PCAP_ERRBUF_SIZE, pcap_lookupdev, pcap_geterr */

#include "types.h"
#include "capture.h"
#include "flow.h"
#include "analysis.h"
#include "utils.h"

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *dev = NULL;

    /* ------------------------------------------------------------------
     * 1. Initialise state tables
     *
     * Both tables are stack-allocated in main() and passed by pointer to
     * every function that needs them. This keeps global state to a minimum
     * (only g_handle in capture.c is a true global).
     * ------------------------------------------------------------------ */
    flow_table_t g_flows;
    ip_table_t   g_trackers;

    flow_table_init(&g_flows);
    analysis_init(&g_trackers);

    /* ------------------------------------------------------------------
     * 2. Resolve capture interface
     *
     * pcap_lookupdev is deprecated in newer libpcap but remains the most
     * portable single-call solution for automatic selection. The pragma
     * suppresses the deprecation warning without modifying the code.
     * ------------------------------------------------------------------ */
    if (argc >= 2) {
        dev = argv[1];
    } else {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        dev = pcap_lookupdev(errbuf);
#pragma GCC diagnostic pop

        if (dev == NULL) {
            fprintf(stderr, "Error: could not find a capture interface: %s\n",
                    errbuf);
            fprintf(stderr,
                    "Hint: run with sudo, or specify an interface: "
                    "./sniffer eth0\n");
            return EXIT_FAILURE;
        }
    }

    /* ------------------------------------------------------------------
     * 3. Print active configuration
     * ------------------------------------------------------------------ */
    printf("=== Packet Sniffer — Phase 3 (Modular) ===\n");
    printf("Interface         : %s\n",   dev);
    printf("Flow timeout      : %.0fs\n", FLOW_TIMEOUT_SECS);
    printf("SYN scan          : %d SYNs / %.0fs window\n",
           THRESH_SYN_COUNT, THRESH_SYN_WINDOW_SECS);
    printf("DNS name length   : > %d chars\n", THRESH_DNS_NAME_LEN);
    printf("DNS frequency     : > %d queries / %.0fs window\n",
           THRESH_DNS_FREQ_COUNT, THRESH_DNS_WINDOW_SECS);
    printf("High traffic      : > %" PRIu64 " bytes per flow\n",
           (uint64_t)THRESH_HIGH_BYTES);
    printf("Alert cooldown    : %.0fs\n", ALERT_COOLDOWN_SECS);
    printf("Press Ctrl+C to stop and print summary.\n\n");

    /* ------------------------------------------------------------------
     * 4. Install signal handlers
     *
     * sigaction() is preferred over signal() for well-defined behaviour:
     *   - sa_flags = 0: interrupted system calls are NOT automatically
     *     restarted (pcap_loop uses select() internally; we want it to
     *     notice the break).
     *   - sigemptyset: no additional signals blocked during the handler.
     *
     * capture_signal_handler only calls pcap_breakloop() — async-signal-safe.
     * ------------------------------------------------------------------ */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = capture_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT,  &sa, NULL) == -1 ||
        sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    /* ------------------------------------------------------------------
     * 5. Open capture handle
     * ------------------------------------------------------------------ */
    pcap_t *handle = capture_open(dev, errbuf);
    if (handle == NULL) {
        return EXIT_FAILURE;
    }

    /* ------------------------------------------------------------------
     * 6. Blocking capture loop
     *
     * Returns when:
     *   rc == -2 — pcap_breakloop() was called via SIGINT/SIGTERM (normal)
     *   rc == -1 — a libpcap capture error occurred
     * ------------------------------------------------------------------ */
    int rc = capture_run(handle, &g_flows, &g_trackers);

    if (rc == -1) {
        fprintf(stderr, "\nCapture error: %s\n", pcap_geterr(handle));
    } else {
        printf("\nCapture stopped.\n");
    }

    /* ------------------------------------------------------------------
     * 7. Cleanup: summary → stats → free memory
     * ------------------------------------------------------------------ */
    flow_print_summary(&g_flows);
    capture_print_stats(handle);
    capture_close(handle);

    flow_table_free(&g_flows);
    analysis_free(&g_trackers);

    return (rc == -1) ? EXIT_FAILURE : EXIT_SUCCESS;
}

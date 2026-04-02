/*
 * capture.c — libpcap capture module implementation
 *
 * The flow and IP tracker tables are passed into capture_run() and threaded
 * through to the packet callback via libpcap's `user` pointer (u_char *args).
 * This avoids exporting them as globals while keeping the callback stateless.
 *
 * Internal structure:
 *   capture_ctx_t   — bundles the two table pointers for the callback
 *   g_handle        — file-scoped global; needed only by the signal handler
 *   packet_handler  — static libpcap callback; calls parse_dispatch()
 */

#include "capture.h"
#include "parse.h"

#include <stdio.h>
#include <string.h>

/* ----------------------------------------------------------------
 * Internal context struct
 *
 * pcap_loop accepts a single u_char* user pointer. We bundle both
 * tables into this struct and cast the pointer in the callback.
 * The struct is stack-allocated in capture_run() and valid for the
 * entire duration of the blocking pcap_loop() call.
 * ---------------------------------------------------------------- */
typedef struct {
    flow_table_t *flows;
    ip_table_t   *trackers;
} capture_ctx_t;

/* ----------------------------------------------------------------
 * g_handle — the only necessary global in the project.
 *
 * The signal handler receives only the signal number; there is no way
 * to pass context to it. The pcap handle must be reachable so we can
 * call pcap_breakloop(). All other state is passed as parameters.
 * ---------------------------------------------------------------- */
static pcap_t *g_handle = NULL;

/* ----------------------------------------------------------------
 * packet_handler — libpcap per-packet callback (static, not exported).
 *
 * libpcap guarantees this is called with:
 *   args   — the u_char* passed to pcap_loop (our capture_ctx_t*)
 *   header — pcap metadata: ts (timestamp), caplen, len (wire size)
 *   packet — raw frame bytes starting at the Ethernet header
 *
 * We use header->caplen for bounds checking (actual bytes in buffer)
 * and header->len (wire length) for flow byte accounting, so byte
 * counters reflect real traffic volume even when snaplen truncates.
 * ---------------------------------------------------------------- */
static void packet_handler(u_char *args,
                           const struct pcap_pkthdr *header,
                           const u_char *packet)
{
    capture_ctx_t *ctx = (capture_ctx_t *)args;

    parse_dispatch((const uint8_t *)packet,
                   (int)header->caplen,
                   (uint32_t)header->len,
                   &header->ts,
                   ctx->flows,
                   ctx->trackers);
}

/* ----------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------- */

pcap_t *capture_open(const char *dev, char *errbuf)
{
    /*
     * pcap_open_live arguments:
     *   device  — interface name
     *   snaplen — max bytes captured per packet (65535 = full frame)
     *   promisc — 1 = promiscuous mode: capture all frames, not just ours
     *   to_ms   — read timeout in milliseconds
     *   errbuf  — error message destination (PCAP_ERRBUF_SIZE bytes)
     */
    pcap_t *handle = pcap_open_live(dev, SNAPLEN, /*promisc=*/1,
                                    PCAP_TIMEOUT_MS, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error: pcap_open_live(%s): %s\n", dev, errbuf);
        return NULL;
    }

    /*
     * Validate Ethernet framing. DLT_EN10MB covers standard 10/100/1G
     * Ethernet. Loopback (DLT_NULL) and cooked capture (DLT_LINUX_SLL)
     * use different header formats; our parse module assumes Ethernet II.
     */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr,
                "Error: '%s' is not Ethernet (DLT=%d); "
                "try specifying an Ethernet interface.\n",
                dev, pcap_datalink(handle));
        pcap_close(handle);
        return NULL;
    }

    /* Store for the signal handler */
    g_handle = handle;
    return handle;
}

int capture_run(pcap_t *handle, flow_table_t *flows, ip_table_t *trackers)
{
    /*
     * Stack-allocate the context; it outlives pcap_loop() since the loop
     * is synchronous (blocking) — it returns before this frame is gone.
     */
    capture_ctx_t ctx = { flows, trackers };

    /*
     * pcap_loop(handle, count, callback, user)
     *   count = 0  → loop indefinitely
     *   Returns:  0 (count exhausted), -1 (error), -2 (pcap_breakloop called)
     */
    return pcap_loop(handle, /*count=*/0, packet_handler, (u_char *)&ctx);
}

void capture_print_stats(pcap_t *handle)
{
    struct pcap_stat stats;
    if (pcap_stats(handle, &stats) == 0) {
        printf("\n--- libpcap Statistics ---\n");
        printf("  Packets received : %u\n", stats.ps_recv);
        printf("  Dropped (kernel) : %u\n", stats.ps_drop);
        printf("  Dropped (iface)  : %u\n", stats.ps_ifdrop);
    }
}

void capture_close(pcap_t *handle)
{
    pcap_close(handle);
    g_handle = NULL;
}

void capture_signal_handler(int sig)
{
    (void)sig;  /* suppress unused-parameter warning */
    if (g_handle != NULL) {
        pcap_breakloop(g_handle);
    }
}

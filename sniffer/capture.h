/*
 * capture.h — libpcap capture module (public interface)
 *
 * Owns the pcap_t handle and all libpcap interactions:
 *   - Opening the interface in promiscuous mode
 *   - Validating the data link type (must be Ethernet)
 *   - Running the capture loop (blocking until signalled)
 *   - Printing libpcap statistics on exit
 *   - Closing the handle
 *   - Handling SIGINT/SIGTERM for clean shutdown
 *
 * The packet handler callback is entirely internal to capture.c.
 * It calls parse_dispatch() from parse.h, passing the flow and tracker
 * tables through libpcap's user-pointer mechanism (pcap_loop's `user` arg)
 * so no global state is needed for those tables.
 *
 * The only necessary global in capture.c is the pcap_t handle itself,
 * which must be reachable from the signal handler.
 */

#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>
#include "types.h"

/*
 * capture_open — open a live pcap capture on the named interface.
 *
 * Opens in promiscuous mode (captures all frames, not just our own MAC).
 * Validates that the interface uses Ethernet framing (DLT_EN10MB) before
 * returning — the parse module assumes this link-layer format.
 *
 * dev    — interface name (e.g. "eth0")
 * errbuf — caller-supplied buffer of PCAP_ERRBUF_SIZE bytes for errors
 *
 * Returns a pcap_t handle on success, NULL on any failure.
 * Stores the handle internally for use by capture_signal_handler.
 */
pcap_t *capture_open(const char *dev, char *errbuf);

/*
 * capture_run — start the blocking capture loop.
 *
 * Calls pcap_loop() which invokes the internal packet_handler callback
 * for every arriving frame. Returns only when:
 *   - pcap_breakloop() is called by capture_signal_handler (rc = -2)
 *   - A hard capture error occurs (rc = -1)
 *
 * flows    — passed to parse_dispatch() via pcap_loop's user pointer
 * trackers — passed to parse_dispatch() via pcap_loop's user pointer
 *
 * Returns the pcap_loop return code (-1 error, -2 clean break).
 */
int capture_run(pcap_t *handle, flow_table_t *flows, ip_table_t *trackers);

/*
 * capture_print_stats — print kernel-level capture statistics to stdout.
 * Shows packets received, dropped by kernel, and dropped by the interface.
 */
void capture_print_stats(pcap_t *handle);

/*
 * capture_close — close the capture handle and release libpcap resources.
 */
void capture_close(pcap_t *handle);

/*
 * capture_signal_handler — async-signal-safe SIGINT/SIGTERM handler.
 *
 * Calls pcap_breakloop() on the internal handle, causing capture_run()
 * to return -2. Install with sigaction() in main() before calling
 * capture_run(). pcap_breakloop() is explicitly documented as
 * async-signal-safe by libpcap.
 */
void capture_signal_handler(int sig);

#endif /* CAPTURE_H */

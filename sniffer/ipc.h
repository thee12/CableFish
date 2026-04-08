/*
 * ipc.h — UNIX domain socket IPC module (public interface)
 *
 * Streams packet_record_t events from the C sniffer to the Node.js backend
 * in real time using a UNIX domain socket (AF_UNIX, SOCK_STREAM).
 *
 * Architecture position:
 *
 *   output.c → ipc_send_record() → UNIX socket → Node.js server.js
 *                                                      ↓
 *                                              WebSocket clients
 *
 * Protocol:
 *   Each record is serialised as a single-line JSON object terminated by '\n'.
 *   Newline framing lets the Node.js server split records from the raw TCP
 *   stream without a length prefix or any other envelope overhead.
 *
 *   Example message sent over the socket:
 *     {"timestamp":"2026-04-02T15:32:10.123Z","src_ip":"192.168.1.5",...}\n
 *
 * Connection model:
 *   - ipc_init() attempts to connect. If the backend is not running, the
 *     sniffer continues normally (file/CSV sinks are unaffected).
 *   - If a send fails (backend died), the socket is closed and marked
 *     disconnected. A reconnect is attempted automatically every
 *     IPC_RECONNECT_EVERY calls to ipc_send_record().
 *   - Sends use MSG_NOSIGNAL (suppress SIGPIPE) and MSG_DONTWAIT (never
 *     block packet processing on a slow or full backend buffer).
 *
 * Lifecycle:
 *   ipc_init()        — call once after output_init()
 *   ipc_send_record() — called from output_write() for every packet
 *   ipc_close()       — call once before program exit
 */

#ifndef IPC_H
#define IPC_H

#include "types.h"

/*
 * How often to attempt reconnection when the backend is down.
 * One attempt every N calls to ipc_send_record() — avoids hammering
 * the filesystem with connect() on every high-frequency packet.
 */
#define IPC_RECONNECT_EVERY  100

/*
 * ipc_init — open the UNIX domain socket and connect to the backend.
 *
 * socket_path — path of the UNIX socket the Node.js server is listening on
 *               (typically IPC_DEFAULT_SOCKET_PATH = "/tmp/sniffer.sock")
 *
 * Prints a warning and returns -1 if the backend is not running.
 * The sniffer continues regardless; ipc_send_record() will retry.
 * Returns 0 on success.
 */
int  ipc_init(const char *socket_path);

/*
 * ipc_send_record — serialise one packet_record_t to JSON and send it.
 *
 * Builds the JSON string in a stack-allocated buffer (no heap allocation
 * per packet). Sends with MSG_NOSIGNAL | MSG_DONTWAIT so the call is
 * always non-blocking and never raises SIGPIPE.
 *
 * If the send fails or the socket is disconnected, the record is silently
 * dropped and a reconnect will be attempted on the next call after
 * IPC_RECONNECT_EVERY records. Packet capture is never interrupted.
 */
void ipc_send_record(const packet_record_t *rec);

/*
 * ipc_close — close the socket cleanly.
 *
 * Safe to call even if ipc_init() was never called or failed.
 */
void ipc_close(void);

#endif /* IPC_H */
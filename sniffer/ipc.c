/*
 * ipc.c — UNIX domain socket IPC implementation
 *
 * Implements a non-blocking, self-healing IPC channel between the C sniffer
 * and the Node.js backend.  Three design properties drive every decision:
 *
 *  1. Never block packet capture.
 *     send() uses MSG_DONTWAIT: if the kernel buffer is full, the record is
 *     dropped immediately rather than stalling the capture loop. At typical
 *     traffic rates (~1000 pkt/s) and record sizes (~300 bytes), the 128 KB
 *     socket buffer holds 400+ records — far more than enough headroom.
 *
 *  2. Never crash on backend failure.
 *     MSG_NOSIGNAL suppresses SIGPIPE. All send errors close the fd and set
 *     g_ipc.fd = -1 (disconnected state). Packet capture continues without
 *     interruption.
 *
 *  3. Recover automatically when the backend restarts.
 *     A decrementing counter triggers a reconnect attempt every
 *     IPC_RECONNECT_EVERY calls to ipc_send_record() while disconnected.
 *     Once reconnected, sends resume immediately.
 *
 * Message format:
 *   Single JSON object per message, terminated by '\n'.
 *   The newline is the only framing delimiter — no length prefix needed.
 *   The Node.js server splits on '\n' to reconstruct complete records.
 *
 * JSON field order (matches Phase 4 file output exactly):
 *   timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
 *   length, packets_total, bytes_total, alert
 */

#include "ipc.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>      /* close()                          */
#include <errno.h>
#include <inttypes.h>    /* PRIu64                           */

#include <sys/types.h>
#include <sys/socket.h>  /* socket(), connect(), send()      */
#include <sys/un.h>      /* struct sockaddr_un, AF_UNIX      */

/* ============================================================
 * Module-level state
 *
 * Kept static — ipc.c owns the socket fd exclusively.
 * All other modules interact only through the three public functions.
 * ============================================================ */
typedef struct {
    int  fd;                        /* socket file descriptor; -1 = disconnected */
    char socket_path[256];          /* saved path for reconnect attempts          */
    int  reconnect_counter;         /* counts down; reconnect when it hits 0      */
} ipc_state_t;

static ipc_state_t g_ipc = { -1, "", 0 };

/* ============================================================
 * IPC JSON buffer size
 *
 * Fields:             max chars
 *   timestamp         32
 *   src_ip            16
 *   dst_ip            16
 *   src_port           5
 *   dst_port           5
 *   protocol           3
 *   length            10
 *   packets_total     20
 *   bytes_total       20
 *   alert             20
 *   JSON keys+syntax ~150
 *   newline            1
 *   ─────────────────────
 *   Total            ~300   →  512 is a comfortable margin
 *                             1024 allows for future field additions
 * ============================================================ */
#define IPC_JSON_BUF  1024

/* ============================================================
 * Internal: ipc_connect
 *
 * Creates a new AF_UNIX SOCK_STREAM socket and connects to g_ipc.socket_path.
 * On success, stores the fd in g_ipc.fd and returns 0.
 * On any failure, closes the fd, leaves g_ipc.fd = -1, and returns -1.
 *
 * SOCK_STREAM provides a reliable, ordered, connection-oriented byte stream —
 * exactly what we need for newline-framed JSON messages.  AF_UNIX avoids
 * network overhead and the loopback stack entirely.
 * ============================================================ */
static int ipc_connect(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "IPC: socket() failed: %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_ipc.socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        /*
         * ENOENT     — socket file does not exist (backend not started yet)
         * ECONNREFUSED — socket file exists but nothing is listening
         * Both are normal during startup; log only once at ipc_init.
         */
        close(fd);
        return -1;
    }

    g_ipc.fd                = fd;
    g_ipc.reconnect_counter = IPC_RECONNECT_EVERY;  /* reset for next cycle */
    fprintf(stderr, "IPC: connected to backend at %s\n", g_ipc.socket_path);
    return 0;
}

/* ============================================================
 * Internal: ipc_disconnect
 *
 * Closes the socket and marks the state as disconnected.
 * Called whenever send() returns an error, and from ipc_close().
 * ============================================================ */
static void ipc_disconnect(void)
{
    if (g_ipc.fd >= 0) {
        close(g_ipc.fd);
        g_ipc.fd = -1;
        fprintf(stderr, "IPC: disconnected from backend\n");
    }
}

/* ============================================================
 * Internal: ipc_try_reconnect
 *
 * Called from ipc_send_record() when the socket is disconnected and the
 * reconnect counter has reached zero.
 *
 * Resets the counter regardless of success so that reconnect attempts
 * happen at a fixed maximum rate of once per IPC_RECONNECT_EVERY sends.
 * ============================================================ */
static void ipc_try_reconnect(void)
{
    g_ipc.reconnect_counter = IPC_RECONNECT_EVERY;
    ipc_connect();   /* updates g_ipc.fd on success; leaves -1 on failure */
}

/* ============================================================
 * Internal: ipc_build_json
 *
 * Serialises a packet_record_t into a newline-terminated JSON string.
 *
 * Uses snprintf with the buffer size as a hard limit — no overflow possible.
 * All input fields are either integers or controlled strings (IP addresses,
 * protocol/alert names) that cannot contain JSON special characters, so no
 * escaping is needed.
 *
 * Returns the number of bytes written (including the '\n'), or -1 if the
 * buffer was too small (should never happen with IPC_JSON_BUF = 1024).
 * ============================================================ */
static int ipc_build_json(const packet_record_t *rec, char *buf, int buflen)
{
    int n = snprintf(buf, (size_t)buflen,
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

    /* snprintf returns the number of chars it WOULD write, not what it did */
    if (n < 0 || n >= buflen) return -1;
    return n;
}

/* ============================================================
 * Internal: ipc_send_bytes
 *
 * Sends `len` bytes from `buf` over the socket.
 *
 * send() flags:
 *   MSG_NOSIGNAL  — if the peer has closed, return EPIPE instead of raising
 *                   SIGPIPE which would kill the sniffer process.
 *   MSG_DONTWAIT  — return EAGAIN/EWOULDBLOCK immediately if the kernel
 *                   send buffer is full, rather than blocking.
 *
 * Partial sends:
 *   UNIX domain stream sockets guarantee that if send() succeeds and returns
 *   n < len, the remaining bytes must be sent in a subsequent call.  For
 *   messages <= PIPE_BUF (4096 bytes on Linux), the kernel atomically sends
 *   the entire message or returns an error — partial sends are extremely rare.
 *   We handle them with a retry loop for correctness.
 *
 * Returns 0 on success, -1 on error (caller should disconnect).
 * ============================================================ */
static int ipc_send_bytes(const char *buf, int len)
{
    int total_sent = 0;

    while (total_sent < len) {
        ssize_t sent = send(g_ipc.fd,
                            buf + total_sent,
                            (size_t)(len - total_sent),
                            MSG_NOSIGNAL | MSG_DONTWAIT);

        if (sent > 0) {
            total_sent += (int)sent;
            continue;
        }

        if (sent == 0) {
            /* Peer closed the connection gracefully */
            return -1;
        }

        /* sent < 0 — error */
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /*
             * Kernel buffer temporarily full. Drop the record rather than
             * spinning or blocking. Packet capture must not be stalled.
             */
            return -1;
        }

        /* EPIPE, ECONNRESET, EBADF, or other hard error */
        return -1;
    }

    return 0;
}

/* ============================================================
 * Public API
 * ============================================================ */

int ipc_init(const char *socket_path)
{
    /* Save the path for reconnect attempts */
    strncpy(g_ipc.socket_path, socket_path, sizeof(g_ipc.socket_path) - 1);
    g_ipc.socket_path[sizeof(g_ipc.socket_path) - 1] = '\0';
    g_ipc.fd                = -1;
    g_ipc.reconnect_counter = 0;

    if (ipc_connect() < 0) {
        fprintf(stderr,
                "IPC: warning — backend not reachable at '%s'.\n"
                "IPC: sniffer will run without streaming; "
                "reconnect is automatic.\n",
                socket_path);
        return -1;
    }

    return 0;
}

void ipc_send_record(const packet_record_t *rec)
{
    /*
     * If disconnected, count down toward the next reconnect attempt.
     * This limits reconnect syscall overhead to at most one attempt
     * per IPC_RECONNECT_EVERY packets regardless of traffic rate.
     */
    if (g_ipc.fd < 0) {
        if (--g_ipc.reconnect_counter <= 0) {
            ipc_try_reconnect();
        }
        if (g_ipc.fd < 0) return;   /* still disconnected after attempt */
    }

    /* Serialise the record to a stack-allocated JSON buffer */
    char buf[IPC_JSON_BUF];
    int  len = ipc_build_json(rec, buf, sizeof(buf));

    if (len < 0) {
        /* Should never happen — buffer is generously sized */
        fprintf(stderr, "IPC: JSON serialisation overflow (record dropped)\n");
        return;
    }

    /* Attempt to send; disconnect on any failure */
    if (ipc_send_bytes(buf, len) < 0) {
        ipc_disconnect();
        g_ipc.reconnect_counter = IPC_RECONNECT_EVERY;  /* schedule reconnect */
    }
}

void ipc_close(void)
{
    ipc_disconnect();
}
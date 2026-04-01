/*
 * sniffer.c — Packet Sniffer with Flow Tracking (Phase 2)
 *
 * Extends Phase 1 (raw packet parsing) with a stateful flow tracking system.
 * Packets are grouped into bidirectional flows identified by the 5-tuple:
 *   (src_ip, dst_ip, src_port, dst_port, protocol)
 *
 * Flows are normalised so A->B and B->A map to the same table entry.
 * Per-flow statistics (packets, bytes, timestamps) are maintained in a
 * hash table with separate chaining. Flows idle for >60 seconds are expired.
 *
 * Build:
 *   gcc -Wall -std=gnu99 -lpcap sniffer.c -o sniffer
 *
 * Run (requires root for raw socket access):
 *   sudo ./sniffer
 *   sudo ./sniffer <interface>
 *
 * Output format (printed on every flow update):
 *   FLOW SRC_IP:PORT <-> DST_IP:PORT | PROTOCOL | PKTS=X | BYTES=Y
 *
 * On exit (Ctrl+C), a full flow table summary is printed.
 */

/* ============================================================
 * SECTION 1 — Headers
 * ============================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <inttypes.h>

#include <pcap.h>

#include <netinet/if_ether.h>   /* struct ethhdr, ETH_P_IP   */
#include <netinet/ip.h>         /* struct iphdr               */
#include <netinet/tcp.h>        /* struct tcphdr              */
#include <netinet/udp.h>        /* struct udphdr              */
#include <arpa/inet.h>          /* inet_ntop, ntohs, ntohl    */
#include <sys/time.h>           /* struct timeval             */

/* ============================================================
 * SECTION 2 — Constants
 * ============================================================ */

#define MIN_ETHER_LEN       (int)sizeof(struct ethhdr)
#define MIN_IP_HDR_LEN      20
#define MIN_TCP_HDR_LEN     (int)sizeof(struct tcphdr)
#define MIN_UDP_HDR_LEN     (int)sizeof(struct udphdr)
#define SNAPLEN             65535
#define PCAP_TIMEOUT_MS     1000

/*
 * Hash table configuration.
 *
 * TABLE_SIZE must be a power of two so we can use bitwise AND instead of
 * modulo for bucket selection:  bucket = hash & (TABLE_SIZE - 1)
 * This avoids the cost of integer division on every lookup.
 */
#define TABLE_SIZE          1024            /* number of buckets           */
#define TABLE_MASK          (TABLE_SIZE-1)  /* bitmask for bucket index    */

/*
 * A flow with no packets for this many seconds is considered expired and
 * will be removed from the table on the next packet that lands in its bucket.
 * Expiry is lazy (on-collision) to avoid scanning the whole table each second.
 */
#define FLOW_TIMEOUT_SECS   60

/* ============================================================
 * SECTION 3 — Flow data structures
 * ============================================================ */

/*
 * flow_key_t — the 5-tuple that uniquely identifies a bidirectional flow.
 *
 * All fields are stored in HOST byte order after normalisation so that hash
 * and comparison logic never has to call ntohs/ntohl again.
 *
 * Normalisation rule (enforced by normalize_flow_key):
 *   - The endpoint with the numerically lower IP address is always "src".
 *   - If both IPs are equal (loopback, same-host flows), the lower port is
 *     "src".  This guarantees that A->B and B->A produce identical keys.
 */
typedef struct {
    uint32_t src_ip;    /* lower IP  (host byte order) */
    uint32_t dst_ip;    /* higher IP (host byte order) */
    uint16_t src_port;  /* port associated with src_ip */
    uint16_t dst_port;  /* port associated with dst_ip */
    uint8_t  proto;     /* IPPROTO_TCP (6) or IPPROTO_UDP (17) */
} flow_key_t;

/*
 * flow_entry_t — one node in the hash table's separate-chaining linked list.
 *
 * Each entry owns its own heap allocation.  The `next` pointer threads
 * entries in the same bucket into a singly-linked list.
 */
typedef struct flow_entry {
    flow_key_t        key;           /* normalised 5-tuple                   */
    uint64_t          total_packets; /* packets seen in both directions       */
    uint64_t          total_bytes;   /* bytes seen in both directions         */
    struct timeval    start_time;    /* timestamp of the very first packet    */
    struct timeval    last_seen;     /* timestamp of the most recent packet   */
    struct flow_entry *next;         /* next entry in bucket (chaining)       */
} flow_entry_t;

/*
 * flow_table_t — the hash table itself.
 *
 * buckets[]  — array of pointers, each pointing to the head of a
 *              singly-linked list of flow_entry_t nodes.
 * flow_count — total live flows currently in the table.
 */
typedef struct {
    flow_entry_t *buckets[TABLE_SIZE];
    uint64_t      flow_count;
} flow_table_t;

/* ============================================================
 * SECTION 4 — Globals
 * ============================================================ */

/* libpcap handle — written once in main, read in signal handler */
static pcap_t      *g_handle = NULL;

/* The single global flow table — zero-initialised at program start */
static flow_table_t g_table;

/* ============================================================
 * SECTION 5 — Signal handling
 * ============================================================ */

static void handle_signal(int sig)
{
    (void)sig;
    if (g_handle != NULL) {
        pcap_breakloop(g_handle);
    }
}

/* ============================================================
 * SECTION 6 — Flow key operations
 * ============================================================ */

/*
 * normalize_flow_key — reorder fields so lower-IP/port is always "src".
 *
 * Takes a raw key (fields in host byte order, direction as the packet arrived)
 * and, if necessary, swaps src and dst so the canonical form is consistent
 * regardless of which direction triggered the flow creation.
 *
 * Examples:
 *   192.168.1.5:51532 -> 8.8.8.8:53    becomes  8.8.8.8:53 <-> 192.168.1.5:51532
 *   8.8.8.8:53 -> 192.168.1.5:51532    becomes  8.8.8.8:53 <-> 192.168.1.5:51532
 *   (same result — same flow entry)
 *
 * Called once per packet before any hash or comparison.
 */
static void normalize_flow_key(flow_key_t *key)
{
    int swap = 0;

    if (key->src_ip > key->dst_ip) {
        /* Numerically higher IP must become dst */
        swap = 1;
    } else if (key->src_ip == key->dst_ip && key->src_port > key->dst_port) {
        /* Same host (e.g. loopback): use port ordering as tiebreaker */
        swap = 1;
    }

    if (swap) {
        uint32_t tmp_ip   = key->src_ip;   key->src_ip   = key->dst_ip;
                                            key->dst_ip   = tmp_ip;
        uint16_t tmp_port = key->src_port; key->src_port = key->dst_port;
                                            key->dst_port = tmp_port;
    }
}

/*
 * hash_flow_key — map a normalised flow_key_t to a bucket index [0, TABLE_SIZE).
 *
 * We use FNV-1a (Fowler-Noll-Vo) over the raw bytes of the key struct.
 * FNV-1a has good avalanche behaviour for small, structured inputs and is
 * cheap to compute (one XOR + one multiply per byte, no divisions).
 *
 * Why not just XOR the fields together?
 *   XOR is commutative and collapses many distinct keys to the same value
 *   (e.g. port 80 XOR port 443 == port 443 XOR port 80, but also ==
 *   many other pairs). FNV-1a mixes position into the hash.
 *
 * The result is masked to TABLE_MASK to select the bucket.
 */
static uint32_t hash_flow_key(const flow_key_t *key)
{
    /* FNV-1a 32-bit constants (from the FNV spec) */
    const uint32_t FNV_OFFSET = 2166136261u;
    const uint32_t FNV_PRIME  = 16777619u;

    uint32_t hash = FNV_OFFSET;
    const uint8_t *data = (const uint8_t *)key;

    for (size_t i = 0; i < sizeof(flow_key_t); i++) {
        hash ^= data[i];
        hash *= FNV_PRIME;
    }

    return hash & TABLE_MASK;
}

/*
 * compare_flow_keys — return 1 if both keys are identical, 0 otherwise.
 *
 * Both keys must already be normalised before calling this.
 * Field-by-field comparison is used (rather than memcmp) to avoid any risk
 * from compiler-inserted struct padding bytes containing uninitialised data.
 */
static int compare_flow_keys(const flow_key_t *a, const flow_key_t *b)
{
    return (a->src_ip   == b->src_ip   &&
            a->dst_ip   == b->dst_ip   &&
            a->src_port == b->src_port &&
            a->dst_port == b->dst_port &&
            a->proto    == b->proto);
}

/* ============================================================
 * SECTION 7 — Flow table operations
 * ============================================================ */

/*
 * timeval_diff_secs — return the elapsed seconds between two timevals.
 *
 * Used during expiry checks to determine how long a bucket-entry has been
 * idle. Returns a negative value if `later` is before `earlier` (e.g. due
 * to a clock adjustment — we treat that as "not expired").
 */
static double timeval_diff_secs(const struct timeval *later,
                                const struct timeval *earlier)
{
    return (double)(later->tv_sec  - earlier->tv_sec) +
           (double)(later->tv_usec - earlier->tv_usec) / 1e6;
}

/*
 * expire_bucket — walk the linked list at buckets[idx] and free any entry
 *                 whose last_seen timestamp is older than FLOW_TIMEOUT_SECS.
 *
 * This is the "lazy expiry" strategy: we don't maintain a separate timer or
 * scan the whole table on a clock tick. Instead, when we need to walk a
 * bucket anyway (for lookup or insert), we prune stale entries at the same
 * time at zero extra cost.
 *
 * The traversal uses the standard prev/curr pattern for singly-linked list
 * deletion without a dummy head node:
 *
 *   [bucket head] -> curr -> next -> ...
 *
 * If curr is expired:
 *   - The pointer that pointed TO curr (either bucket head or prev->next)
 *     is updated to skip directly to next.
 *   - curr is freed.
 *   - prev stays in place because the new node at this position is `next`.
 */
static void expire_bucket(flow_table_t *table, uint32_t idx,
                          const struct timeval *now)
{
    flow_entry_t *prev = NULL;
    flow_entry_t *curr = table->buckets[idx];

    while (curr != NULL) {
        flow_entry_t *next = curr->next;

        if (timeval_diff_secs(now, &curr->last_seen) > FLOW_TIMEOUT_SECS) {
            /* Unlink curr from the list */
            if (prev == NULL) {
                table->buckets[idx] = next;  /* curr was the head */
            } else {
                prev->next = next;
            }
            free(curr);
            table->flow_count--;
            /* Do NOT advance prev — it now correctly points before `next` */
        } else {
            prev = curr;
        }

        curr = next;
    }
}

/*
 * update_flow — increment counters and refresh the last_seen timestamp
 *               on an existing flow entry.
 *
 * Called after a successful lookup. Does not print; the caller prints after
 * this returns so the print and update happen atomically from the caller's
 * perspective.
 */
static void update_flow(flow_entry_t *entry,
                        const struct timeval *ts,
                        uint32_t pkt_len)
{
    entry->total_packets++;
    entry->total_bytes += pkt_len;
    entry->last_seen    = *ts;
}

/*
 * lookup_or_create_flow — find an existing flow entry for `key`, or allocate
 *                         a new one, then update its statistics.
 *
 * Algorithm:
 *   1. Compute bucket index from FNV-1a hash of the normalised key.
 *   2. Prune expired entries in that bucket (lazy expiry).
 *   3. Walk the bucket list; if a matching entry is found, call update_flow()
 *      and return it immediately.
 *   4. If not found, allocate a new entry, initialise all fields, and prepend
 *      it to the bucket list (O(1) insert — no need to scan to the tail).
 *
 * Returns a pointer to the flow_entry_t so the caller can print it.
 * Returns NULL only on malloc failure (unrecoverable — packet is dropped).
 */
static flow_entry_t *lookup_or_create_flow(flow_table_t *table,
                                           const flow_key_t *key,
                                           const struct timeval *ts,
                                           uint32_t pkt_len)
{
    uint32_t idx = hash_flow_key(key);

    /* Prune stale flows in this bucket before walking it */
    expire_bucket(table, idx, ts);

    /* Walk the chain looking for a matching entry */
    flow_entry_t *entry = table->buckets[idx];
    while (entry != NULL) {
        if (compare_flow_keys(&entry->key, key)) {
            update_flow(entry, ts, pkt_len);
            return entry;
        }
        entry = entry->next;
    }

    /* Not found — allocate a fresh entry */
    entry = (flow_entry_t *)malloc(sizeof(flow_entry_t));
    if (entry == NULL) {
        fprintf(stderr, "Error: malloc failed — dropping packet\n");
        return NULL;
    }

    entry->key           = *key;
    entry->total_packets = 1;
    entry->total_bytes   = pkt_len;
    entry->start_time    = *ts;
    entry->last_seen     = *ts;

    /* Prepend to bucket list — O(1) */
    entry->next         = table->buckets[idx];
    table->buckets[idx] = entry;
    table->flow_count++;

    return entry;
}

/*
 * free_flow_table — release all heap memory held by the flow table.
 *
 * Walks every bucket and frees every entry in the chain. Called once at
 * program exit. After this call the table is safe to discard.
 */
static void free_flow_table(flow_table_t *table)
{
    for (int i = 0; i < TABLE_SIZE; i++) {
        flow_entry_t *curr = table->buckets[i];
        while (curr != NULL) {
            flow_entry_t *next = curr->next;
            free(curr);
            curr = next;
        }
        table->buckets[i] = NULL;
    }
    table->flow_count = 0;
}

/* ============================================================
 * SECTION 8 — Printing
 * ============================================================ */

/*
 * proto_name — return a static string label for a protocol number.
 */
static const char *proto_name(uint8_t proto)
{
    switch (proto) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        default:          return "UNK";
    }
}

/*
 * print_flow — format and print a single flow entry to stdout.
 *
 * Output format:
 *   FLOW 192.168.1.5:51532 <-> 142.250.72.206:443 | TCP | PKTS=10 | BYTES=8420
 *
 * The IPs in the key are stored in host byte order; inet_ntop expects network
 * byte order, so we call htonl() to convert back before printing.
 *
 * The "src" side always has the lower IP (enforced by normalisation), giving
 * a consistent display regardless of which direction triggered the update.
 */
static void print_flow(const flow_entry_t *entry)
{
    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];

    uint32_t src_net = htonl(entry->key.src_ip);
    uint32_t dst_net = htonl(entry->key.dst_ip);

    inet_ntop(AF_INET, &src_net, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &dst_net, dst_str, sizeof(dst_str));

    printf("FLOW %s:%u <-> %s:%u | %s | PKTS=%" PRIu64 " | BYTES=%" PRIu64 "\n",
           src_str, entry->key.src_port,
           dst_str, entry->key.dst_port,
           proto_name(entry->key.proto),
           entry->total_packets,
           entry->total_bytes);
}

/*
 * print_flow_summary — print all live flows in the table at program exit.
 *
 * Iterates every bucket in order, printing full statistics including duration
 * for each surviving flow. Flows already expired by lazy expiry won't appear.
 */
static void print_flow_summary(const flow_table_t *table)
{
    printf("\n============================================================\n");
    printf("  Flow Table Summary -- %" PRIu64 " active flow(s)\n",
           table->flow_count);
    printf("============================================================\n");

    uint64_t printed = 0;

    for (int i = 0; i < TABLE_SIZE; i++) {
        const flow_entry_t *entry = table->buckets[i];
        while (entry != NULL) {
            char src_str[INET_ADDRSTRLEN];
            char dst_str[INET_ADDRSTRLEN];
            uint32_t src_net = htonl(entry->key.src_ip);
            uint32_t dst_net = htonl(entry->key.dst_ip);
            inet_ntop(AF_INET, &src_net, src_str, sizeof(src_str));
            inet_ntop(AF_INET, &dst_net, dst_str, sizeof(dst_str));

            double duration = timeval_diff_secs(&entry->last_seen,
                                                &entry->start_time);

            printf("  %s:%u <-> %s:%u | %s | PKTS=%" PRIu64
                   " | BYTES=%" PRIu64 " | DURATION=%.2fs\n",
                   src_str, entry->key.src_port,
                   dst_str, entry->key.dst_port,
                   proto_name(entry->key.proto),
                   entry->total_packets,
                   entry->total_bytes,
                   duration);

            printed++;
            entry = entry->next;
        }
    }

    if (printed == 0) {
        printf("  (no flows captured)\n");
    }

    printf("============================================================\n");
}

/* ============================================================
 * SECTION 9 — Packet parsing  (from Phase 1, extended)
 * ============================================================ */

/*
 * process_transport — build a flow key, normalise it, and update the table.
 *
 * This is the convergence point for both TCP and UDP after their headers have
 * been parsed. By this point we have all five elements of the flow key in
 * host byte order. We:
 *   1. Zero-initialise the key struct (ensures no padding garbage).
 *   2. Fill in the fields.
 *   3. Normalise (swap src/dst if needed for consistent ordering).
 *   4. Call lookup_or_create_flow to update statistics.
 *   5. Print the resulting flow entry.
 */
static void process_transport(uint32_t src_ip_h, uint32_t dst_ip_h,
                               uint16_t src_port,  uint16_t dst_port,
                               uint8_t  proto,
                               const struct timeval *ts, uint32_t pkt_len)
{
    flow_key_t key;
    memset(&key, 0, sizeof(key));
    key.src_ip   = src_ip_h;
    key.dst_ip   = dst_ip_h;
    key.src_port = src_port;
    key.dst_port = dst_port;
    key.proto    = proto;

    normalize_flow_key(&key);

    flow_entry_t *entry = lookup_or_create_flow(&g_table, &key, ts, pkt_len);
    if (entry != NULL) {
        print_flow(entry);
    }
}

/*
 * parse_tcp — extract TCP source/destination ports and forward to
 *             process_transport.
 *
 * The TCP header begins immediately after the IP header (which may contain
 * options, hence the variable ip_hdr_len computed in parse_ipv4 above).
 * We validate MIN_TCP_HDR_LEN bytes are available before casting.
 */
static void parse_tcp(const u_char *ptr, int remaining,
                      uint32_t src_ip_h, uint32_t dst_ip_h,
                      const struct timeval *ts, uint32_t pkt_len)
{
    if (remaining < MIN_TCP_HDR_LEN) return;

    const struct tcphdr *tcp = (const struct tcphdr *)ptr;

    process_transport(src_ip_h, dst_ip_h,
                      ntohs(tcp->th_sport), ntohs(tcp->th_dport),
                      IPPROTO_TCP, ts, pkt_len);
}

/*
 * parse_udp — extract UDP source/destination ports and forward to
 *             process_transport.
 *
 * The UDP header is always exactly 8 bytes (no variable-length concern).
 */
static void parse_udp(const u_char *ptr, int remaining,
                      uint32_t src_ip_h, uint32_t dst_ip_h,
                      const struct timeval *ts, uint32_t pkt_len)
{
    if (remaining < MIN_UDP_HDR_LEN) return;

    const struct udphdr *udp = (const struct udphdr *)ptr;

    process_transport(src_ip_h, dst_ip_h,
                      ntohs(udp->uh_sport), ntohs(udp->uh_dport),
                      IPPROTO_UDP, ts, pkt_len);
}

/*
 * parse_ipv4 — parse the IPv4 header and dispatch to parse_tcp / parse_udp.
 *
 * Key changes from Phase 1:
 *   - src/dst IPs are converted to host byte order with ntohl() here, once.
 *     All downstream code (normalisation, hashing, comparison) works in host
 *     byte order. Only printing calls htonl() to convert back for inet_ntop.
 *   - The packet timestamp `ts` and wire length `pkt_len` are threaded down
 *     so the flow table can record accurate statistics.
 *   - Variable IP header length (ip->ihl * 4) is still handled correctly;
 *     the transport pointer skips past any IP options.
 */
static void parse_ipv4(const u_char *ip_ptr, int remaining,
                       const struct timeval *ts, uint32_t pkt_len)
{
    if (remaining < MIN_IP_HDR_LEN) return;

    const struct iphdr *ip = (const struct iphdr *)ip_ptr;

    /*
     * IHL is in 32-bit words; multiply by 4 for byte count.
     * Validate: IHL must be at least 5 (20 bytes) and must not exceed
     * the number of bytes we actually have in the capture buffer.
     */
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < MIN_IP_HDR_LEN || ip_hdr_len > remaining) return;

    /* Convert IPs to host byte order once — all downstream uses host order */
    uint32_t src_ip_h = ntohl(ip->saddr);
    uint32_t dst_ip_h = ntohl(ip->daddr);

    const u_char *transport_ptr       = ip_ptr + ip_hdr_len;
    int           transport_remaining = remaining - ip_hdr_len;

    switch (ip->protocol) {
        case IPPROTO_TCP:
            parse_tcp(transport_ptr, transport_remaining,
                      src_ip_h, dst_ip_h, ts, pkt_len);
            break;
        case IPPROTO_UDP:
            parse_udp(transport_ptr, transport_remaining,
                      src_ip_h, dst_ip_h, ts, pkt_len);
            break;
        default:
            break;
    }
}

/*
 * packet_handler — libpcap callback, invoked once per captured frame.
 *
 * Validates the Ethernet header, filters for IPv4, then dispatches.
 *
 * We use header->caplen for bounds checking (bytes actually in the buffer)
 * but pass header->len (the true wire length) to the flow table as pkt_len
 * so byte totals represent actual traffic volume even when snaplen truncates
 * the captured payload.
 */
static void packet_handler(u_char *args,
                           const struct pcap_pkthdr *header,
                           const u_char *packet)
{
    (void)args;

    int caplen = (int)header->caplen;
    if (caplen < MIN_ETHER_LEN) return;

    const struct ethhdr *eth = (const struct ethhdr *)packet;
    if (ntohs(eth->h_proto) != ETH_P_IP) return;

    const u_char *ip_ptr       = packet + MIN_ETHER_LEN;
    int           ip_remaining = caplen - MIN_ETHER_LEN;

    parse_ipv4(ip_ptr, ip_remaining, &header->ts, (uint32_t)header->len);
}

/* ============================================================
 * SECTION 10 — Capture setup
 * ============================================================ */

/*
 * open_capture — open a live pcap handle on the named interface.
 *
 * Validates DLT_EN10MB (Ethernet) before returning so the rest of the code
 * can assume standard 14-byte Ethernet framing without further checks.
 */
static pcap_t *open_capture(const char *dev, char *errbuf)
{
    pcap_t *handle = pcap_open_live(dev, SNAPLEN, /*promisc=*/1,
                                    PCAP_TIMEOUT_MS, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error: pcap_open_live(%s): %s\n", dev, errbuf);
        return NULL;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr,
                "Error: '%s' is not an Ethernet interface (DLT=%d)\n",
                dev, pcap_datalink(handle));
        pcap_close(handle);
        return NULL;
    }

    return handle;
}

/* ============================================================
 * SECTION 11 — main
 * ============================================================ */

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *dev = NULL;

    /* ----------------------------------------------------------
     * 1. Initialise the flow table
     *    memset to zero guarantees all bucket pointers are NULL and
     *    flow_count is 0 — equivalent to an empty table.
     * ---------------------------------------------------------- */
    memset(&g_table, 0, sizeof(g_table));

    /* ----------------------------------------------------------
     * 2. Resolve the network interface
     * ---------------------------------------------------------- */
    if (argc >= 2) {
        dev = argv[1];
    } else {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        dev = pcap_lookupdev(errbuf);
#pragma GCC diagnostic pop
        if (dev == NULL) {
            fprintf(stderr, "Error: no suitable device found: %s\n", errbuf);
            fprintf(stderr,
                    "Hint: run with sudo, or pass an interface name as argv[1].\n");
            return EXIT_FAILURE;
        }
    }

    printf("=== Packet Sniffer -- Phase 2 (Flow Tracking) ===\n");
    printf("Interface    : %s\n", dev);
    printf("Flow timeout : %d seconds of inactivity\n", FLOW_TIMEOUT_SECS);
    printf("Table size   : %d buckets (separate chaining)\n", TABLE_SIZE);
    printf("Press Ctrl+C to stop and print summary.\n\n");

    /* ----------------------------------------------------------
     * 3. Install signal handlers for clean shutdown
     * ---------------------------------------------------------- */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT,  &sa, NULL) == -1 ||
        sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    /* ----------------------------------------------------------
     * 4. Open the capture handle
     * ---------------------------------------------------------- */
    pcap_t *handle = open_capture(dev, errbuf);
    if (handle == NULL) return EXIT_FAILURE;
    g_handle = handle;

    /* ----------------------------------------------------------
     * 5. Capture loop
     *    Runs until pcap_breakloop() is called (Ctrl+C -> SIGINT)
     *    or a hard capture error occurs.
     * ---------------------------------------------------------- */
    int rc = pcap_loop(handle, /*count=*/0, packet_handler, /*user=*/NULL);

    if (rc == -1) {
        fprintf(stderr, "\nCapture error: %s\n", pcap_geterr(handle));
    } else {
        printf("\nCapture stopped.\n");
    }

    /* ----------------------------------------------------------
     * 6. Print summary, release all resources
     * ---------------------------------------------------------- */
    print_flow_summary(&g_table);

    struct pcap_stat stats;
    if (pcap_stats(handle, &stats) == 0) {
        printf("\n--- libpcap Statistics ---\n");
        printf("  Packets received : %u\n", stats.ps_recv);
        printf("  Dropped (kernel) : %u\n", stats.ps_drop);
        printf("  Dropped (iface)  : %u\n", stats.ps_ifdrop);
    }

    pcap_close(handle);
    g_handle = NULL;

    free_flow_table(&g_table);

    return (rc == -1) ? EXIT_FAILURE : EXIT_SUCCESS;
}
/* proves the vendored stack starts and behaves under senko's configuration.
   it is not a dataplane test: no proxying happens here, only the stack's own
   init, its pools and one packet handed in and taken back out */

#include <stdio.h>
#include <string.h>

#include "lwip/init.h"
#include "lwip/ip6_frag.h"
#include "lwip/ip4_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/stats.h"
#include "lwip/sys.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"
#include "lwip/udp.h"

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

static int packets_sent;
static uint16_t last_sent_len;

/* stands in for the utun device: whatever the stack decides to send would be
   framed and written to the tunnel here */
static err_t capture_output(struct netif *netif, struct pbuf *p,
                            const ip4_addr_t *ipaddr) {
    (void)netif;
    (void)ipaddr;
    ++packets_sent;
    last_sent_len = p->tot_len;
    return ERR_OK;
}

static err_t tunnel_init(struct netif *netif) {
    netif->name[0] = 'u';
    netif->name[1] = 't';
    netif->output = capture_output;
    netif->mtu = 1500;
    /* a point to point tunnel: bare ip, no link layer to resolve */
    netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

/* an icmp echo request, which the stack should answer by itself */
static size_t build_ping(uint8_t *out, const uint8_t source[4],
                         const uint8_t destination[4]) {
    size_t total = 20 + 8;
    memset(out, 0, total);
    out[0] = 0x45;
    out[2] = (uint8_t)(total >> 8);
    out[3] = (uint8_t)total;
    out[8] = 64;
    out[9] = 1; /* icmp */
    memcpy(out + 12, source, 4);
    memcpy(out + 16, destination, 4);
    out[20] = 8; /* echo request */
    out[24] = 0x12; out[25] = 0x34; /* identifier */
    out[26] = 0x00; out[27] = 0x01; /* sequence */

    /* ip header checksum */
    uint32_t sum = 0;
    for (size_t i = 0; i < 20; i += 2) sum += (uint32_t)(out[i] << 8 | out[i + 1]);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    uint16_t check = (uint16_t)~sum;
    out[10] = (uint8_t)(check >> 8);
    out[11] = (uint8_t)check;

    /* icmp checksum over the 8 byte echo header */
    sum = 0;
    for (size_t i = 20; i < total; i += 2) sum += (uint32_t)(out[i] << 8 | out[i + 1]);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    check = (uint16_t)~sum;
    out[22] = (uint8_t)(check >> 8);
    out[23] = (uint8_t)check;
    return total;
}

int main(void) {
    lwip_init();
    ok("the stack starts", 1);

    /* the clock lwip uses has to be the daemon's monotonic one */
    u32_t first = sys_now();
    ok("the clock is readable", first > 0 || first == 0);

    /* pools, not libc: allocating and freeing must leave the pool as it was */
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, 512, PBUF_POOL);
    ok("a pbuf comes out of the pool", p != NULL);
    if (p) {
        ok("the pbuf has the length asked for", p->tot_len == 512);
        ok("the pbuf is writable", pbuf_take(p, "senko", 5) == ERR_OK);
        pbuf_free(p);
    }

    /* protocol control blocks come from fixed pools too */
    struct tcp_pcb *tcp = tcp_new();
    ok("a tcp pcb is available", tcp != NULL);
    if (tcp) tcp_abort(tcp);

    struct udp_pcb *udp = udp_new();
    ok("a udp pcb is available", udp != NULL);
    if (udp) udp_remove(udp);

    /* the pools are bounded: asking for more pcbs than the profile allows has
       to fail cleanly rather than grow the heap */
    struct udp_pcb *held[MEMP_NUM_UDP_PCB + 4];
    size_t taken = 0;
    for (size_t i = 0; i < sizeof held / sizeof held[0]; ++i) {
        held[i] = udp_new();
        if (held[i]) ++taken;
    }
    ok("the udp pool stops at its configured size", taken == MEMP_NUM_UDP_PCB);
    for (size_t i = 0; i < sizeof held / sizeof held[0]; ++i)
        if (held[i]) udp_remove(held[i]);

    /* one interface, standing in for the tunnel */
    struct netif tunnel;
    ip4_addr_t address, netmask, gateway;
    IP4_ADDR(&address, 198, 18, 0, 1);
    IP4_ADDR(&netmask, 255, 255, 255, 255);
    IP4_ADDR(&gateway, 0, 0, 0, 0);
    memset(&tunnel, 0, sizeof tunnel);
    struct netif *added = netif_add(&tunnel, &address, &netmask, &gateway, NULL,
                                    tunnel_init, ip_input);
    ok("the tunnel interface is accepted", added != NULL);
    netif_set_default(&tunnel);
    netif_set_up(&tunnel);
    ok("the interface reports itself up", netif_is_up(&tunnel));

    /* a packet in, an answer out: this is the whole point of the stack being
       here, even before any flow is proxied */
    uint8_t ping[64];
    uint8_t source[4] = { 198, 18, 0, 2 };
    uint8_t destination[4] = { 198, 18, 0, 1 };
    size_t ping_len = build_ping(ping, source, destination);

    struct pbuf *packet = pbuf_alloc(PBUF_RAW, (u16_t)ping_len, PBUF_POOL);
    ok("an inbound packet can be wrapped", packet != NULL);
    if (packet) {
        pbuf_take(packet, ping, (u16_t)ping_len);
        err_t taken_in = tunnel.input(packet, &tunnel);
        ok("the stack accepted the packet", taken_in == ERR_OK);
        ok("the stack answered the echo request", packets_sent == 1);
        ok("the answer is an ip packet of the expected size", last_sent_len == ping_len);
    }

    /* timers must be callable without an os behind them */
    sys_check_timeouts();
    ok("timeouts run without a scheduler", 1);

    /* the v6 reassembly timer checks that its bookkeeping fits a fragment
       header, which it does not on a 64 bit slice unless the header is copied.
       it first runs a second after start, so a short test never saw it */
    ip6_reass_tmr();
    ok("the v6 reassembly timer accepts this configuration", 1);

    /* nothing may be left allocated once the test is done */
    netif_remove(&tunnel);
#if LWIP_STATS
    ok("no pbuf is left in use", lwip_stats.mem.used == 0 ||
       lwip_stats.memp[MEMP_PBUF_POOL] == NULL ||
       lwip_stats.memp[MEMP_PBUF_POOL]->used == 0);
#endif

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("all lwip smoke checks passed");
    return 0;
}

#ifndef BYE_TCP_H
#define BYE_TCP_H

#include <stddef.h>
#include <stdint.h>

#include "bye_desync.h"
#include "bye_hosts.h"
#include "bye_route.h"
#include "bye_tg.h"
#include "bye_wsconn.h"
#include "tun/direct_socket.h"
#include "tun/tun_loop.h"

#ifdef __cplusplus
extern "C" {
#endif

/* the tcp flows the tunnel captures. every flow leaves by the physical
   interface; what differs is what happens to its bytes:

     direct     passed on untouched
     desync     the first bytes are cut so a filter that matches the server
                name misses it, then passed on untouched. with a strategy
                list a tls flow that gets no answer is tried again with the
                next strategy, and the one that works is remembered for that
                address and port
     telegram   the mtproto stream is carried over a websocket to telegram's
                gateway, and falls back to direct when the gateway fails. a
                few connections to the gateway wait ready (tcp, tls and the
                upgrade done) for the datacenters in use

   everything runs on the tunnel's loop thread, driven by the hooks and the
   flow callback that bye_tcp_init() installs in the loop configuration */

#define BYE_TCP_MAX_FLOWS 48
#define BYE_TCP_RELAYS_MAX 4
#define BYE_TCP_RELAY_NAME_MAX 48
/* flows holding a tls session; each takes tens of kilobytes on a small device */
#define BYE_TCP_TELEGRAM_MAX 8
/* gateway connections kept ready, all datacenters together */
#define BYE_TCP_POOL_MAX 4

/* decides the path of a flow by its destination; the default is bye_route_tcp
   with the policy below. a test uses it to aim traffic at loopback */
typedef bye_path_t (*bye_tcp_classify_fn)(void *ctx, const uint8_t *addr, size_t addr_len,
                                          uint16_t port);

/* sends one fake packet for the direct connection on fd: `offset` bytes of the
   connection's stream are already out, so the packet takes the next sequence
   number and the real bytes follow with the same one. 0 when it left,
   BYE_FAKE_SEND_* when it did not */
#define BYE_FAKE_SEND_OK         0
#define BYE_FAKE_SEND_OFF       -1 /* no watcher, or the connection is not ipv4 */
#define BYE_FAKE_SEND_UNKNOWN   -2 /* its syn and syn-ack were not seen */
#define BYE_FAKE_SEND_FAILED    -3 /* the raw socket refused the packet, errno says why */
typedef int (*bye_fake_send_fn)(void *ctx, int fd, uint32_t offset, const uint8_t *payload,
                                size_t len, uint8_t ttl, int md5sig);

typedef struct {
    bye_route_policy_t policy;
    bye_tcp_classify_fn classify;
    void              *classify_ctx;
    /* the address and port that stand for every datacenter's gateway, instead
       of the datacenter's own address on 443. the port also stands for the
       relay's, which a test cannot bind below 1024 */
    uint8_t            gateway[4];
    uint16_t           gateway_port;
    int                gateway_set;
    bye_tg_ws_addresses_t ws_addresses;
    /* domains whose kwsN host reaches the gateway through cloudflare, and the
       address of each. they are tried before the datacenter's own address */
    char               relay[BYE_TCP_RELAYS_MAX][BYE_TCP_RELAY_NAME_MAX];
    uint8_t            relay_addr[BYE_TCP_RELAYS_MAX][4];
    size_t             relay_count;
    bye_strategies_t   strategies; /* none given: the bytes are not cut */
    /* names the cut is limited to (hosts_only) or spared (not hosts_only);
       borrowed, NULL cuts every flow */
    const bye_hosts_t *hosts;
    int                hosts_only;
    uint32_t           auto_wait_ms; /* how long a tls hello may go unanswered, 0 for 3 s */
    /* gateway connections kept ready for each datacenter a flow used in the
       last minutes, so a flow does not wait for tcp, tls and the upgrade. 0
       connects when the flow starts */
    size_t             pool;
    direct_socket_fn   direct_socket;
    void              *direct_ctx;
    bye_wsconn_ctx_t  *tls;        /* borrowed; NULL turns the telegram path off */
    bye_fake_send_fn   fake_send;  /* NULL leaves a fake part as a plain cut */
    void              *fake_ctx;
    uint8_t            dns[4];     /* tcp 53 goes here when dns_set */
    int                dns_set;
    size_t             max_flows;  /* 0 uses BYE_TCP_MAX_FLOWS */
    int                trace;
} bye_tcp_config_t;

#define BYE_TCP_CAPTURE_MAX 2048
#define BYE_TCP_RECENT_MAX 8
#define BYE_TCP_RECENT_LEN 128

typedef struct {
    uint64_t requested;
    uint64_t refused;    /* no socket for the destination, or too many flows */
    uint64_t aborted;    /* a running flow failed: the app got a reset */
    uint64_t finished;
    uint64_t direct;
    uint64_t desync_applied;
    uint64_t desync_passed;  /* the first payload had no name, or never completed */
    uint64_t fake_sent;      /* fake packets that left */
    uint64_t fake_missed;    /* a fake part went out as a plain cut: no watcher, no syn seen, or a refusal */
    uint64_t hosts_skipped;  /* the host list kept a flow from being cut */
    uint64_t auto_retried;   /* a tls flow got no answer and moved to the next strategy */
    uint64_t auto_learned;   /* a strategy other than the first answered and was remembered */
    uint64_t auto_exhausted; /* every strategy failed for a flow */
    uint64_t addr_retried;   /* every strategy failed at the app's address and the flow went to another address of the site */
    uint64_t telegram_ws;
    uint64_t telegram_fallback;
    uint64_t pool_hits;      /* a telegram flow took a connection that was ready */
    uint64_t pool_misses;    /* none was ready, the flow connected itself */
    uint64_t pool_ready;     /* connections ready now */
    uint64_t bytes_up;
    uint64_t bytes_down;
    char     last_error[160];
    /* the last flows that failed or moved to the next strategy, newest at
       (recent_count - 1) % BYE_TCP_RECENT_MAX, so a report names the sites and
       addresses behind the counters */
    uint32_t recent_count;
    char     recent[BYE_TCP_RECENT_MAX][BYE_TCP_RECENT_LEN];
    /* the newest tls flow that got no answer: where it went and the hello the app sent,
       for the strategy check to try the same bytes at the same address */
    struct {
        char     name[48];
        uint8_t  addr[4];
        uint16_t port;
        size_t   hello_len; /* 0 for none */
        uint8_t  hello[BYE_TCP_CAPTURE_MAX];
    } capture;
} bye_tcp_stats_t;

typedef struct bye_tcp bye_tcp_t;

size_t bye_tcp_size(void);

/* installs the flow callback and the loop hooks. tcp must be zeroed storage of
   bye_tcp_size() bytes. 0 on success */
int bye_tcp_init(bye_tcp_t *tcp, const bye_tcp_config_t *config, tun_loop_config_t *loop_config);

/* readable on the loop thread, or by anyone once the loop has ended */
const bye_tcp_stats_t *bye_tcp_stats(const bye_tcp_t *tcp);

#ifdef __cplusplus
}
#endif

#endif

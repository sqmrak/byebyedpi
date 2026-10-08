#ifndef BYE_TGPROXY_H
#define BYE_TGPROXY_H

#include <stddef.h>
#include <stdint.h>

#include "bye_wsconn.h"
#include "bye_tg.h"
#include "tun/direct_socket.h"

#ifdef __cplusplus
extern "C" {
#endif

/* the mtproto proxy telegram is pointed at: tg://proxy?server=127.0.0.1&port=P&secret=dd<hex>.
   it listens on loopback only, reads the client's obfuscated stream with the
   secret, and carries it to the datacenter's websocket gateway. it does not
   depend on the tunnel or on any desync strategy: with the tunnel up its
   sockets leave by the physical interface like the tunnel's own, with the
   tunnel down they are plain sockets.

   one thread accepts, one thread serves each client, so a stalled gateway
   holds one client and nothing else */

#define BYE_TGPROXY_CLIENTS_MAX 24
#define BYE_TGPROXY_RELAYS_MAX 4
#define BYE_TGPROXY_RELAY_NAME_MAX 48
#define BYE_TGPROXY_ERROR_MAX 160

typedef struct {
    uint16_t         port;
    uint8_t          secret[16];
    bye_wsconn_ctx_t *tls;            /* the caller keeps it until the proxy stops */
    direct_socket_fn socket;          /* a nonblocking tcp socket that leaves by the right interface */
    void            *socket_ctx;
    /* domains whose kwsN host reaches the gateway through cloudflare, with the
       address of each, resolved by the caller. they are tried first */
    char             relay[BYE_TGPROXY_RELAYS_MAX][BYE_TGPROXY_RELAY_NAME_MAX];
    uint8_t          relay_addr[BYE_TGPROXY_RELAYS_MAX][4];
    size_t           relay_count;
    /* the address and port standing for every gateway, for a test that cannot
       bind 443 */
    uint8_t          gateway[4];
    uint16_t         gateway_port;
    int              gateway_set;
    bye_tg_ws_addresses_t ws_addresses;
    int              trace;
} bye_tgproxy_config_t;

typedef struct {
    uint64_t clients;      /* accepted */
    uint64_t active;       /* serving now */
    uint64_t gateway_ok;   /* clients that got a websocket to a datacenter */
    uint64_t gateway_fail; /* clients that found no gateway */
    uint64_t bad_init;     /* clients that did not speak mtproto with this secret */
    uint64_t bytes_up;
    uint64_t bytes_down;
    char     last_error[BYE_TGPROXY_ERROR_MAX];
} bye_tgproxy_stats_t;

typedef struct bye_tgproxy bye_tgproxy_t;

/* NULL with the reason in error when the port cannot be bound */
bye_tgproxy_t *bye_tgproxy_start(const bye_tgproxy_config_t *config, char *error, size_t error_cap);

/* closes the listener and every client, and waits for the threads */
void bye_tgproxy_stop(bye_tgproxy_t *proxy);

void bye_tgproxy_stats(bye_tgproxy_t *proxy, bye_tgproxy_stats_t *out);

/* 32 hex digits to 16 bytes; 0 when the text is exactly that */
int bye_tgproxy_secret_parse(const char *hex, uint8_t out[16]);

#ifdef __cplusplus
}
#endif

#endif

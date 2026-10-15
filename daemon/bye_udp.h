#ifndef BYE_UDP_H
#define BYE_UDP_H

#include <stddef.h>
#include <stdint.h>

#include "tun/direct_socket.h"
#include "tun/tun_loop.h"

#ifdef __cplusplus
extern "C" {
#endif

/* the udp datagrams the tunnel captures. each tuple gets one socket bound to
   the physical interface, answers go back from the destination the app
   addressed. udp 443 is refused with icmp port unreachable when asked to:
   quic would carry the server name in a packet no cut can reach, and an app
   falls back to tcp when quic is refused */

#define BYE_UDP_ASSOC_MAX 32

typedef struct {
    direct_socket_fn direct_socket;
    void            *direct_ctx;
    int              block_quic;
    uint8_t          dns[4]; /* dns queries go here over tcp when dns_set */
    uint16_t         dns_port; /* the port that carries dns, 0 for 53 */
    int              dns_set;
    int              trace;
} bye_udp_config_t;

typedef struct {
    uint64_t received;
    uint64_t sent;       /* answers handed back to the app */
    uint64_t refused;    /* datagrams that could not be relayed */
    uint64_t expired;
    uint64_t evicted;    /* an idle tuple gave way to a new one */
    uint64_t quic_dropped;
    uint64_t full_socket; /* a socket with no room, the datagram was lost */
    char     last_error[160];
} bye_udp_stats_t;

typedef struct bye_udp bye_udp_t;

size_t bye_udp_size(void);

/* installs beside bye_tcp: call it after bye_tcp_init, on the same loop
   configuration, so the hooks chain. tcp must be zeroed storage of
   bye_udp_size() bytes. 0 on success */
int bye_udp_init(bye_udp_t *udp, const bye_udp_config_t *config, tun_loop_config_t *loop_config);

const bye_udp_stats_t *bye_udp_stats(const bye_udp_t *udp);

#ifdef __cplusplus
}
#endif

#endif

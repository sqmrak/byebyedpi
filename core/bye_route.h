#ifndef BYE_ROUTE_H
#define BYE_ROUTE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* where a captured tcp flow goes. the flow always leaves by the physical
   interface; the path only says what is done to its bytes on the way */

typedef enum {
    BYE_PATH_DIRECT = 0, /* untouched */
    BYE_PATH_DESYNC,     /* the first bytes are cut, then untouched */
    BYE_PATH_TELEGRAM    /* an mtproto stream carried over a websocket */
} bye_path_t;

typedef struct {
    int telegram; /* carry telegram over the websocket gateway */
} bye_route_policy_t;

/* the destination is 4 or 16 address bytes */
bye_path_t bye_route_tcp(const bye_route_policy_t *policy, const uint8_t *addr,
                         size_t addr_len, uint16_t port);

/* an address that never leaves the local network or the device */
int bye_route_is_local(const uint8_t *addr, size_t addr_len);

/* tunnel names need their owner checked before being used as the uplink */
int bye_route_is_tunnel_ifname(const char *ifname);

/* the kernel path must match the interface and router published by brighton_netd */
int bye_route_brighton_link_matches(const char *ifname, const uint8_t *gateway4,
                                    const char *service_ifname, const char *service_router);

#ifdef __cplusplus
}
#endif

#endif

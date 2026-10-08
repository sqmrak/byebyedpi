#ifndef BYE_TG_H
#define BYE_TG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* what the bridge needs to know about telegram: its address ranges, its
   datacenters and the hosts of the websocket gateway. the ranges are the list
   telegram publishes at core.telegram.org/resources/cidr.txt */

/* datacenter 203 is the cdn one: it is served by the gateway of datacenter 2 */
#define BYE_TG_DC_CDN 203
#define BYE_TG_WS_VARIANTS 2
#define BYE_TG_WS_HOST_MAX 40
#define BYE_TG_WS_PATH "/apiws"
#define BYE_TG_WS_DCS 5
#define BYE_TG_GATEWAYS_MAX 4

typedef struct {
    uint8_t address[4];
    int valid;
} bye_tg_ws_address_t;

typedef struct {
    bye_tg_ws_address_t dc[BYE_TG_WS_DCS][BYE_TG_WS_VARIANTS];
} bye_tg_ws_addresses_t;

typedef struct {
    char host[BYE_TG_WS_HOST_MAX];
    uint8_t address[4];
} bye_tg_gateway_t;

int bye_tg_dc_known(int dc);

/* a pinned mtproto address, used when the websocket host cannot be reached */
int bye_tg_dc_address(int dc, uint8_t out[4]);

/* resolved websocket hosts first, then pinned addresses, without duplicate pairs */
size_t bye_tg_gateways(int dc, int is_media, const bye_tg_ws_addresses_t *resolved,
                       bye_tg_gateway_t *out, size_t cap);

/* after a tcp failure, skip hosts on the same address */
size_t bye_tg_gateway_next(const bye_tg_gateway_t *gateways, size_t count,
                           size_t current, int tcp_failed);

/* the host names to try, in order. returns 0, or -1 once the variants run out */
int bye_tg_ws_host(int dc, int is_media, unsigned variant, char *out, size_t cap);

/* whether an ipv4 (4 bytes) or ipv6 (16 bytes) address belongs to telegram */
int bye_tg_is_address(const uint8_t *addr, size_t addr_len);

#ifdef __cplusplus
}
#endif

#endif

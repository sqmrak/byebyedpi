#ifndef SENKO_TUN_FLOW_H
#define SENKO_TUN_FLOW_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* the flow key and the flow table caps from senko's core/tun_flow.h. the flow
   table itself stays out: byebyedpi keeps its own per-flow state beside the
   stack, so only the types the capture layer shares are kept */

/* compile-time hard caps hold the worst case the arm64 build may reach */
#define TUN_FLOW_MAX_TCP 64
#define TUN_FLOW_MAX_UDP 128

typedef enum {
    TUN_FLOW_TCP = 0,
    TUN_FLOW_UDP
} tun_flow_proto_t;

typedef struct {
    uint8_t  source[16];
    uint8_t  destination[16];
    uint16_t source_port;
    uint16_t destination_port;
    uint8_t  address_len; /* 4 or 16 */
    uint8_t  protocol;    /* tun_flow_proto_t */
} tun_flow_key_t;

#ifdef __cplusplus
}
#endif

#endif

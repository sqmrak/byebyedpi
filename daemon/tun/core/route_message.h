#ifndef SENKO_ROUTE_MESSAGE_H
#define SENKO_ROUTE_MESSAGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* builds and reads darwin routing socket messages as plain bytes, with no
   syscalls and no system headers, so the wire layout can be checked on the
   host. daemon/utun_route.c is the adapter that writes these to AF_ROUTE.

   the struct layout is asserted against the real sdk headers by
   tests/route_layout_check.c, which is compiled for both slices */

/* a request this daemon builds: a header, a destination, a gateway and a
   netmask, and nothing else */
#define ROUTE_MESSAGE_MAX 256
/* a reply is not bounded by what we send. an RTM_GET answer carries the
   address list the kernel chose to report, so it gets its own larger cap */
#define ROUTE_REPLY_MAX 2048
#define ROUTE_MESSAGE_HEADER_LEN 92
#define ROUTE_MESSAGE_VERSION 5
/* RTAX_MAX on darwin: the address list has eight slots, not thirty two */
#define ROUTE_ADDRESS_SLOTS 8

typedef enum {
    ROUTE_MESSAGE_ADD    = 1, /* RTM_ADD */
    ROUTE_MESSAGE_DELETE = 2, /* RTM_DELETE */
    ROUTE_MESSAGE_GET    = 4  /* RTM_GET */
} route_message_type_t;

typedef enum {
    /* a next hop address: the packet is handed to a router on the link */
    ROUTE_TARGET_GATEWAY = 0,
    /* the link itself, addressed by interface index. link local, multicast
       and the tunnel's own split defaults have no next hop */
    ROUTE_TARGET_INTERFACE
} route_target_t;

typedef struct {
    route_message_type_t type;
    uint8_t  destination[16];
    uint8_t  address_len; /* 4 or 16 */
    uint8_t  prefix;      /* a full length prefix builds a host route */
    route_target_t target;
    uint8_t  gateway[16];     /* used when target is ROUTE_TARGET_GATEWAY */
    uint16_t interface_index; /* used when target is ROUTE_TARGET_INTERFACE */
    int32_t  pid;
    int32_t  seq;
    int      want_interface; /* ask the kernel to report RTA_IFP in the reply */
} route_message_spec_t;

typedef struct {
    int32_t  pid;
    int32_t  seq;
    int      kernel_errno; /* rtm_errno, 0 when the kernel accepted it */
    int      has_gateway;
    uint8_t  gateway[16];
    uint8_t  gateway_len;
    int      gateway_is_link; /* the next hop is the link, not an address */
    int      has_interface;
    char     ifname[16];
    uint16_t interface_index;
} route_message_reply_t;

typedef enum {
    ROUTE_MESSAGE_OK          =  0,
    ROUTE_MESSAGE_ERR_ARG     = -1,
    ROUTE_MESSAGE_ERR_SPACE   = -2,
    ROUTE_MESSAGE_ERR_TRUNCATED = -3,
    ROUTE_MESSAGE_ERR_VERSION = -4,
    /* the reply belongs to another writer on the shared routing socket */
    ROUTE_MESSAGE_ERR_FOREIGN = -5,
    ROUTE_MESSAGE_ERR_KERNEL  = -6 /* the kernel reported rtm_errno */
} route_message_status_t;

route_message_status_t route_message_build(const route_message_spec_t *spec,
                                           uint8_t *out, size_t cap, size_t *out_len);

/* every writer on AF_ROUTE sees every other writer's replies, so a reply that
   does not carry our pid and sequence is someone else's and must not be read
   as an answer to our request */
route_message_status_t route_message_parse(const uint8_t *reply, size_t len,
                                           int32_t expect_pid, int32_t expect_seq,
                                           route_message_reply_t *out);

const char *route_message_status_name(route_message_status_t status);

#ifdef __cplusplus
}
#endif

#endif

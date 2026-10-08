#ifndef SENKO_TUN_PLAN_H
#define SENKO_TUN_PLAN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* portable route plan builder: turns an interface, a gateway and a set of
   endpoints/policies into a bounded, ordered list of add/delete operations.
   no syscalls happen here, see daemon/utun_route.c for the privileged
   adapter that actually sends routing socket messages */

#define TUN_PLAN_MAX_ENDPOINTS 16
#define TUN_PLAN_MAX_POLICIES  64
/* endpoints + policies + 2 reserved v4 nets + 2 reserved v6 nets + 4 split defaults */
#define TUN_PLAN_MAX_OPS (TUN_PLAN_MAX_ENDPOINTS + TUN_PLAN_MAX_POLICIES + 8)

typedef struct {
    uint8_t address[16];
    uint8_t address_len; /* 4 or 16, 0 = unset */
} tun_plan_addr_t;

typedef struct {
    uint8_t address[16];
    uint8_t address_len; /* 4 or 16, 0 = unset */
    uint8_t prefix;
} tun_plan_cidr_t;

typedef struct {
    char ifname[16];          /* the utun interface */
    char physical_ifname[16]; /* the interface the default route leaves by */

    int     have_gateway4;
    uint8_t gateway4[4];
    int     have_gateway6;
    uint8_t gateway6[16];
    /* cellular links can have no IP next hop, but still need a physical pin */
    int     route_ipv4;

    tun_plan_addr_t endpoints[TUN_PLAN_MAX_ENDPOINTS];
    size_t          endpoint_count;

    tun_plan_cidr_t direct_policies[TUN_PLAN_MAX_POLICIES];
    size_t          direct_policy_count;

    /* the caller found a usable physical v6 route, with or without a gateway */
    int enable_ipv6;
} tun_plan_input_t;

typedef enum {
    TUN_PLAN_OP_ADD = 0,
    TUN_PLAN_OP_DELETE
} tun_plan_op_t;

typedef enum {
    TUN_PLAN_VIA_TUNNEL = 0, /* interface route out of the utun interface */
    TUN_PLAN_VIA_GATEWAY,    /* route through the physical gateway address */
    /* interface route out of the physical interface, with no gateway. link
       local and multicast have no next hop to be sent to, so a gateway route
       for them would either be refused or send them somewhere wrong */
    TUN_PLAN_VIA_PHYSICAL
} tun_plan_via_t;

typedef enum {
    TUN_PLAN_KIND_ENDPOINT_PIN = 0,
    TUN_PLAN_KIND_DIRECT_POLICY,
    TUN_PLAN_KIND_RESERVED_BYPASS,
    TUN_PLAN_KIND_SPLIT_DEFAULT
} tun_plan_kind_t;

typedef struct {
    tun_plan_op_t   op;
    tun_plan_kind_t kind;
    uint8_t         address[16];
    uint8_t         address_len;
    uint8_t         prefix;
    tun_plan_via_t  via;
    uint8_t         gateway[16];
    /* the interface this operation belongs to, so an executor never has to
       guess which of the two names applies */
    char            ifname[16];
    char            label[32]; /* diagnostic tag, e.g. "endpoint[0]" */
    /* set while applying: the kernel already routed this bypass net off the
       tunnel, so the route is not ours to delete */
    int             preexisting;
} tun_plan_op_entry_t;

typedef struct {
    char                 ifname[16];
    char                 physical_ifname[16];
    tun_plan_op_entry_t  ops[TUN_PLAN_MAX_OPS];
    size_t               count;
} tun_plan_t;

typedef enum {
    TUN_PLAN_OK           = 0,
    TUN_PLAN_ERR_ARG      = -1,
    TUN_PLAN_ERR_FULL     = -2,
    TUN_PLAN_ERR_ADDRESS  = -3,
    TUN_PLAN_ERR_PREFIX   = -4,
    TUN_PLAN_ERR_DUPLICATE = -5,
    TUN_PLAN_ERR_NO_GATEWAY = -6
} tun_plan_status_t;

/* build the add sequence: endpoint pins first, then direct policies, then
   the reserved bypass nets, then the split defaults last, so nothing can
   transiently route server or policy traffic into the tunnel it depends on */
tun_plan_status_t tun_plan_build(const tun_plan_input_t *input, tun_plan_t *out_plan);

/* the exact reverse of plan, as delete operations, for teardown and for
   rollback of a partially applied plan */
tun_plan_status_t tun_plan_rollback(const tun_plan_t *plan, tun_plan_t *out_rollback);

/* one line per operation, truncated to fit cap; returns the number of bytes
   that would have been written, like snprintf */
int tun_plan_render(const tun_plan_t *plan, char *buf, size_t cap);

/* the routes that outlive a killed daemon: pins, direct policies and bypass
   nets it added itself. tunnel routes die with the interface and are left out.
   returns the length written, or -1 when cap is too small */
int tun_plan_save_leftovers(const tun_plan_t *plan, char *buf, size_t cap);

/* reads what save wrote back into a plan that utun_route_revert can undo.
   anything malformed, torn or unknown is refused as a whole */
tun_plan_status_t tun_plan_load_leftovers(const char *text, size_t len,
                                          tun_plan_t *out);

#ifdef __cplusplus
}
#endif

#endif

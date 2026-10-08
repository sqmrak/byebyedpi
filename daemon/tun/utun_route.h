#ifndef SENKO_UTUN_ROUTE_H
#define SENKO_UTUN_ROUTE_H

#include <stddef.h>
#include <stdint.h>

#include "core/tun_plan.h"
#include "route_socket.h"

#ifdef __cplusplus
extern "C" {
#endif

/* applies a plan built by core/tun_plan.c and undoes exactly what it applied.
   every syscall goes through an executor so the ordering, the rollback and
   the recursion check can be tested on the host against a fake table */

typedef enum {
    UTUN_ROUTE_OK          =  0,
    UTUN_ROUTE_ERR_ARG     = -1,
    UTUN_ROUTE_ERR_APPLY   = -2, /* an operation failed, see result.failed_index */
    UTUN_ROUTE_ERR_VERIFY  = -3, /* routes applied but lookup disagrees */
    UTUN_ROUTE_ERR_RECURSION = -4 /* an endpoint resolves back into the tunnel */
} utun_route_status_t;

/* what went wrong with one route operation, in a form that can be logged or
   shown as is. the message is a finished sentence naming the route, the cause
   and the exact code */
typedef struct {
    int  code; /* errno, or 0 when there was none */
    char message[ROUTE_ERROR_MAX];
} utun_route_error_t;

typedef struct {
    char ifname[16];
    int  via_gateway;
    uint8_t gateway[16];
    uint8_t address_len;
} utun_route_path_t;

/* snapshot the physical path before split defaults are installed. a link-level
   or absent gateway pins the server on the interface itself */
int utun_route_path_from_reply(uint8_t address_len,
                               const route_message_reply_t *reply,
                               utun_route_path_t *out_path,
                               utun_route_error_t *out_error);

int utun_route_system_path(const uint8_t *address, uint8_t address_len,
                           utun_route_path_t *out_path,
                           utun_route_error_t *out_error);

typedef struct {
    /* 0 on success, -1 on failure with the reason in *out_error. a delete of
       a route that is already gone reports success: a rollback that runs
       after a partial apply, and a cleanup after a crash, both hit that */
    int (*apply)(void *ctx, const tun_plan_op_entry_t *op, const char *ifname,
                 utun_route_error_t *out_error);
    /* which interface the kernel would actually send this destination out of.
       returns 0 and fills ifname_out, or -1 with the reason in *out_error */
    int (*lookup)(void *ctx, const uint8_t *address, uint8_t address_len,
                  char *ifname_out, size_t ifname_cap,
                  utun_route_error_t *out_error);
    void *ctx;
} utun_route_executor_t;

typedef struct {
    size_t applied;      /* operations that succeeded before any failure */
    size_t failed_index; /* index of the failing operation, SIZE_MAX when none */
    int    failed_errno;
    /* the failure in plain words, ready to log or show. empty on success */
    char   failed_message[ROUTE_ERROR_MAX];
    size_t rolled_back;      /* operations undone after the failure */
    size_t rollback_failures; /* undo operations the kernel refused */
    /* the first refused undo, which is the one worth showing: the rest of the
       teardown keeps going regardless */
    char   rollback_message[ROUTE_ERROR_MAX];
} utun_route_result_t;

/* apply in plan order, and on the first failure undo everything already
   applied in reverse order. the result says how far it got either way */
utun_route_status_t utun_route_apply(tun_plan_t *plan,
                                     const utun_route_executor_t *executor,
                                     utun_route_result_t *out_result);

/* route installation is not committed until every endpoint still leaves by
   the physical link; a failed lookup or recursive pin undoes the whole plan */
utun_route_status_t utun_route_apply_verified(tun_plan_t *plan,
                                              const utun_route_executor_t *executor,
                                              utun_route_result_t *out_result);

/* undo a fully applied plan. keeps going past a refused delete so one stale
   route cannot strand the rest, and reports how many were refused */
utun_route_status_t utun_route_revert(const tun_plan_t *plan,
                                      const utun_route_executor_t *executor,
                                      utun_route_result_t *out_result);

/* every endpoint pin in the plan must resolve to something other than the
   tunnel interface, otherwise the server socket would route into the tunnel
   that depends on it. out_error explains a failure in the same words the
   apply path uses */
utun_route_status_t utun_route_verify_endpoints(const tun_plan_t *plan,
                                                const utun_route_executor_t *executor,
                                                size_t *out_failed_index,
                                                utun_route_error_t *out_error);

/* the darwin executor, backed by the routing socket. on a host build every
   call fails with ENOTSUP rather than touching the machine's routes */
const utun_route_executor_t *utun_route_system_executor(void);

const char *utun_route_status_name(utun_route_status_t status);

#ifdef __cplusplus
}
#endif

#endif

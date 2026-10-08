#include "utun_route.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

const char *utun_route_status_name(utun_route_status_t status) {
    switch (status) {
    case UTUN_ROUTE_OK:            return "ok";
    case UTUN_ROUTE_ERR_ARG:       return "arg";
    case UTUN_ROUTE_ERR_APPLY:     return "apply";
    case UTUN_ROUTE_ERR_VERIFY:    return "verify";
    case UTUN_ROUTE_ERR_RECURSION: return "recursion";
    }
    return "unknown";
}

static void result_init(utun_route_result_t *result) {
    memset(result, 0, sizeof *result);
    result->failed_index = SIZE_MAX;
}

int utun_route_path_from_reply(uint8_t address_len,
                               const route_message_reply_t *reply,
                               utun_route_path_t *out_path,
                               utun_route_error_t *out_error) {
    if (out_path) memset(out_path, 0, sizeof *out_path);
    if (out_error) memset(out_error, 0, sizeof *out_error);
    if (!reply || !out_path || !out_error ||
        (address_len != 4 && address_len != 16)) return -1;
    if (!reply->has_interface || !reply->ifname[0] ||
        !memchr(reply->ifname, '\0', sizeof reply->ifname)) {
        out_error->code = ENXIO;
        snprintf(out_error->message, sizeof out_error->message,
                 "the kernel did not name a usable physical interface for this route");
        return -1;
    }
    snprintf(out_path->ifname, sizeof out_path->ifname, "%s", reply->ifname);
    out_path->address_len = address_len;
    if (reply->has_gateway && !reply->gateway_is_link) {
        if (reply->gateway_len != address_len) {
            out_error->code = EAFNOSUPPORT;
            snprintf(out_error->message, sizeof out_error->message,
                     "the route's gateway address family differs from its destination");
            memset(out_path, 0, sizeof *out_path);
            return -1;
        }
        out_path->via_gateway = 1;
        memcpy(out_path->gateway, reply->gateway, address_len);
    }
    return 0;
}

/* undo ops[0 .. upto) in reverse, counting what the kernel refused instead of
   stopping: a refused delete usually means the route is already gone, and
   giving up there would strand every earlier operation */
static void undo_prefix(const tun_plan_t *plan, const utun_route_executor_t *executor,
                        size_t upto, utun_route_result_t *result) {
    for (size_t i = upto; i > 0; --i) {
        if (plan->ops[i - 1].preexisting) continue;
        tun_plan_op_entry_t undo = plan->ops[i - 1];
        undo.op = TUN_PLAN_OP_DELETE;
        utun_route_error_t error;
        memset(&error, 0, sizeof error);
        if (executor->apply(executor->ctx, &undo, plan->ifname, &error) == 0) {
            ++result->rolled_back;
            continue;
        }
        if (result->rollback_failures == 0)
            snprintf(result->rollback_message, sizeof result->rollback_message,
                     "%s", error.message);
        ++result->rollback_failures;
    }
}

utun_route_status_t utun_route_apply(tun_plan_t *plan,
                                     const utun_route_executor_t *executor,
                                     utun_route_result_t *out_result) {
    utun_route_result_t local;
    result_init(&local);
    if (out_result) *out_result = local;
    if (!plan || !executor || !executor->apply) return UTUN_ROUTE_ERR_ARG;

    for (size_t i = 0; i < plan->count; ++i) plan->ops[i].preexisting = 0;
    for (size_t i = 0; i < plan->count; ++i) {
        tun_plan_op_entry_t op = plan->ops[i];
        op.op = TUN_PLAN_OP_ADD;
        utun_route_error_t error;
        memset(&error, 0, sizeof error);
        if (executor->apply(executor->ctx, &op, plan->ifname, &error) == 0) {
            ++local.applied;
            continue;
        }
        /* ios 5 already routes 169.254/16 on the wifi interface, which is
           exactly what the bypass wants. any other route that exists is an error */
        if (error.code == EEXIST && op.kind == TUN_PLAN_KIND_RESERVED_BYPASS) {
            plan->ops[i].preexisting = 1;
            continue;
        }
        local.failed_index = i;
        local.failed_errno = error.code;
        snprintf(local.failed_message, sizeof local.failed_message, "%s",
                 error.message);
        undo_prefix(plan, executor, i, &local);
        if (out_result) *out_result = local;
        return UTUN_ROUTE_ERR_APPLY;
    }

    if (out_result) *out_result = local;
    return UTUN_ROUTE_OK;
}

utun_route_status_t utun_route_revert(const tun_plan_t *plan,
                                      const utun_route_executor_t *executor,
                                      utun_route_result_t *out_result) {
    utun_route_result_t local;
    result_init(&local);
    if (out_result) *out_result = local;
    if (!plan || !executor || !executor->apply) return UTUN_ROUTE_ERR_ARG;

    undo_prefix(plan, executor, plan->count, &local);
    if (out_result) *out_result = local;
    return local.rollback_failures ? UTUN_ROUTE_ERR_APPLY : UTUN_ROUTE_OK;
}

utun_route_status_t utun_route_verify_endpoints(const tun_plan_t *plan,
                                                const utun_route_executor_t *executor,
                                                size_t *out_failed_index,
                                                utun_route_error_t *out_error) {
    if (out_failed_index) *out_failed_index = SIZE_MAX;
    if (out_error) {
        out_error->code = 0;
        out_error->message[0] = '\0';
    }
    if (!plan || !executor || !executor->lookup) return UTUN_ROUTE_ERR_ARG;

    for (size_t i = 0; i < plan->count; ++i) {
        const tun_plan_op_entry_t *op = &plan->ops[i];
        if (op->kind != TUN_PLAN_KIND_ENDPOINT_PIN) continue;
        char ifname[16];
        memset(ifname, 0, sizeof ifname);
        utun_route_error_t error;
        memset(&error, 0, sizeof error);
        if (executor->lookup(executor->ctx, op->address, op->address_len,
                             ifname, sizeof ifname, &error) != 0) {
            if (out_failed_index) *out_failed_index = i;
            if (out_error) *out_error = error;
            return UTUN_ROUTE_ERR_VERIFY;
        }
        if (strcmp(ifname, plan->ifname) == 0) {
            if (out_failed_index) *out_failed_index = i;
            if (out_error) {
                out_error->code = 0;
                snprintf(out_error->message, sizeof out_error->message,
                         "the server address in %s is routed back into the tunnel"
                         " on %s, which would make its own connection depend on"
                         " itself", op->label, ifname);
            }
            return UTUN_ROUTE_ERR_RECURSION;
        }
        if (strcmp(ifname, op->ifname) != 0) {
            if (out_failed_index) *out_failed_index = i;
            if (out_error) {
                out_error->code = 0;
                snprintf(out_error->message, sizeof out_error->message,
                         "the server address in %s leaves by %s instead of the"
                         " pinned physical interface %s",
                         op->label, ifname, op->ifname);
            }
            return UTUN_ROUTE_ERR_VERIFY;
        }
    }
    return UTUN_ROUTE_OK;
}

utun_route_status_t utun_route_apply_verified(tun_plan_t *plan,
                                              const utun_route_executor_t *executor,
                                              utun_route_result_t *out_result) {
    utun_route_result_t result;
    utun_route_status_t status = utun_route_apply(plan, executor, &result);
    if (status != UTUN_ROUTE_OK) {
        if (out_result) *out_result = result;
        return status;
    }

    utun_route_error_t error;
    size_t failed_index = SIZE_MAX;
    status = utun_route_verify_endpoints(plan, executor, &failed_index, &error);
    if (status == UTUN_ROUTE_OK) {
        if (out_result) *out_result = result;
        return UTUN_ROUTE_OK;
    }

    result.failed_index = failed_index;
    result.failed_errno = error.code;
    snprintf(result.failed_message, sizeof result.failed_message, "%s",
             error.message[0] ? error.message : "endpoint route verification failed");
    utun_route_result_t rollback;
    (void)utun_route_revert(plan, executor, &rollback);
    result.rolled_back = rollback.rolled_back;
    result.rollback_failures = rollback.rollback_failures;
    snprintf(result.rollback_message, sizeof result.rollback_message, "%s",
             rollback.rollback_message);
    if (out_result) *out_result = result;
    return status;
}

#if defined(__APPLE__)

/* sys/socket.h comes first on purpose: net/if.h in the iphoneos 5 sdk uses
   struct sockaddr without declaring it, so the usual alphabetical order fails
   to compile the armv7 slice */
#include <sys/socket.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/select.h>
#include <unistd.h>

#include "core/senko_time.h"

typedef struct {
    int fd;
} route_fd_t;

static long darwin_write(void *ctx, const uint8_t *data, size_t len, int *out_errno) {
    route_fd_t *socket_ctx = ctx;
    *out_errno = 0;
    ssize_t wrote = write(socket_ctx->fd, data, len);
    if (wrote < 0) {
        *out_errno = errno;
        return -1;
    }
    return (long)wrote;
}

/* wait for a reply no longer than the deadline allows, so a kernel that never
   answers costs a bounded wait instead of the whole connect attempt */
static long darwin_read(void *ctx, uint8_t *buf, size_t cap, int64_t deadline_ms,
                        int *out_errno) {
    route_fd_t *socket_ctx = ctx;
    *out_errno = 0;

    int64_t remaining = deadline_ms - senko_now_ms();
    if (remaining <= 0) return 0;

    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(socket_ctx->fd, &readable);
    struct timeval timeout;
    timeout.tv_sec = (time_t)(remaining / 1000);
    timeout.tv_usec = (suseconds_t)((remaining % 1000) * 1000);

    int ready = select(socket_ctx->fd + 1, &readable, NULL, NULL, &timeout);
    if (ready < 0) {
        *out_errno = errno;
        return -1;
    }
    if (ready == 0) return 0;

    ssize_t got = read(socket_ctx->fd, buf, cap);
    if (got < 0) {
        *out_errno = errno;
        return -1;
    }
    return (long)got;
}

static int64_t darwin_now(void *ctx) {
    (void)ctx;
    return senko_now_ms();
}

/* one socket per request: a short lived socket cannot accumulate replies to
   requests this daemon has already given up on */
static route_socket_status_t run_route_request(const route_message_spec_t *spec,
                                               route_message_reply_t *out_reply,
                                               route_error_t *out_error) {
    route_fd_t socket_ctx;
    socket_ctx.fd = socket(AF_ROUTE, SOCK_RAW, 0);
    if (socket_ctx.fd < 0) {
        int opened = errno;
        if (out_error) {
            /* only a permission failure is about root. blaming root for a
               descriptor or memory limit would send the reader looking in
               the wrong place */
            const char *why =
                opened == EPERM || opened == EACCES
                    ? "byedpid has to run as root to change routes"
                    : opened == EMFILE || opened == ENFILE
                        ? "this process has no free file descriptors left"
                        : opened == ENOMEM || opened == ENOBUFS
                            ? "the kernel had no memory for another socket"
                            : opened == EAFNOSUPPORT
                                ? "this kernel has no routing socket support"
                                : "the system refused it";
            out_error->status = ROUTE_SOCKET_ERR_WRITE;
            out_error->kernel_errno = opened;
            snprintf(out_error->message, sizeof out_error->message,
                     "cannot open the routing socket: %s (errno %d %s)",
                     why, opened, route_errno_name(opened));
        }
        return ROUTE_SOCKET_ERR_WRITE;
    }

    route_io_t io;
    memset(&io, 0, sizeof io);
    io.write_message = darwin_write;
    io.read_message = darwin_read;
    io.now_ms = darwin_now;
    io.ctx = &socket_ctx;
    io.pid = (int32_t)getpid();

    route_socket_status_t status = route_socket_transact(&io, spec,
        ROUTE_SOCKET_DEFAULT_TIMEOUT_MS, out_reply, out_error);
    close(socket_ctx.fd);
    return status;
}

int utun_route_system_path(const uint8_t *address, uint8_t address_len,
                           utun_route_path_t *out_path,
                           utun_route_error_t *out_error) {
    if (out_path) memset(out_path, 0, sizeof *out_path);
    if (out_error) memset(out_error, 0, sizeof *out_error);
    if (!address || !out_path || !out_error ||
        (address_len != 4 && address_len != 16)) return -1;

    route_message_spec_t spec;
    memset(&spec, 0, sizeof spec);
    spec.type = ROUTE_MESSAGE_GET;
    spec.address_len = address_len;
    spec.prefix = address_len == 4 ? 32 : 128;
    spec.want_interface = 1;
    memcpy(spec.destination, address, address_len);

    route_message_reply_t reply;
    route_error_t error;
    memset(&error, 0, sizeof error);
    if (run_route_request(&spec, &reply, &error) != ROUTE_SOCKET_OK) {
        out_error->code = error.kernel_errno;
        snprintf(out_error->message, sizeof out_error->message, "%s", error.message);
        return -1;
    }
    return utun_route_path_from_reply(address_len, &reply, out_path, out_error);
}

/* an interface index the kernel will accept: zero means the name is gone, and
   the routing message only carries sixteen bits of it */
static int index_for(const char *ifname, uint16_t *out_index,
                     utun_route_error_t *out_error) {
    unsigned index = if_nametoindex(ifname);
    if (index == 0 || index > 0xffffu) {
        if (out_error) {
            out_error->code = index == 0 ? ENXIO : ERANGE;
            snprintf(out_error->message, sizeof out_error->message,
                     index == 0
                        ? "interface \"%s\" does not exist any more, so no route"
                          " can point at it (if_nametoindex returned 0)"
                        : "interface \"%s\" has index %u, which does not fit a"
                          " routing message",
                     ifname, index);
        }
        return -1;
    }
    *out_index = (uint16_t)index;
    return 0;
}

static int system_apply(void *ctx, const tun_plan_op_entry_t *op, const char *ifname,
                        utun_route_error_t *out_error) {
    (void)ctx;
    if (out_error) {
        out_error->code = 0;
        out_error->message[0] = '\0';
    }
    if (!op || !out_error) return -1;

    route_message_spec_t spec;
    memset(&spec, 0, sizeof spec);
    spec.type = op->op == TUN_PLAN_OP_ADD ? ROUTE_MESSAGE_ADD : ROUTE_MESSAGE_DELETE;
    spec.address_len = op->address_len;
    spec.prefix = op->prefix;
    memcpy(spec.destination, op->address, op->address_len);

    if (op->via == TUN_PLAN_VIA_GATEWAY) {
        spec.target = ROUTE_TARGET_GATEWAY;
        memcpy(spec.gateway, op->gateway, op->address_len);
    } else {
        const char *target = op->ifname[0] ? op->ifname : ifname;
        if (!target || !target[0]) {
            out_error->code = EINVAL;
            snprintf(out_error->message, sizeof out_error->message,
                     "route %s has no interface to leave by", op->label);
            return -1;
        }
        spec.target = ROUTE_TARGET_INTERFACE;
        /* the kernel drops every route of an interface that goes away, so a
           delete for a vanished one, e.g. pdp_ip0 after leaving cellular, is done */
        if (op->op == TUN_PLAN_OP_DELETE && if_nametoindex(target) == 0) return 0;
        if (index_for(target, &spec.interface_index, out_error) != 0) return -1;
    }

    route_error_t error;
    memset(&error, 0, sizeof error);
    route_socket_status_t status = run_route_request(&spec, NULL, &error);

    /* the route is absent either way, which is what a delete asked for */
    if (status == ROUTE_SOCKET_OK || status == ROUTE_SOCKET_ALREADY_GONE) return 0;

    out_error->code = error.kernel_errno;
    snprintf(out_error->message, sizeof out_error->message, "%s", error.message);
    return -1;
}

/* which interface the kernel picks for this destination right now. the plan
   pins endpoints through the physical gateway, so seeing the tunnel name here
   is what route recursion looks like */
static int system_lookup(void *ctx, const uint8_t *address, uint8_t address_len,
                         char *ifname_out, size_t ifname_cap,
                         utun_route_error_t *out_error) {
    (void)ctx;
    if (out_error) {
        out_error->code = 0;
        out_error->message[0] = '\0';
    }
    if (!address || !ifname_out || ifname_cap == 0 || !out_error) return -1;
    if (address_len != 4 && address_len != 16) {
        out_error->code = EINVAL;
        snprintf(out_error->message, sizeof out_error->message,
                 "cannot look up a route for an address that is neither 4 nor 16"
                 " bytes long");
        return -1;
    }
    ifname_out[0] = '\0';

    utun_route_path_t path;
    if (utun_route_system_path(address, address_len, &path, out_error) != 0) return -1;
    if (strlen(path.ifname) >= ifname_cap) {
        out_error->code = ENOSPC;
        snprintf(out_error->message, sizeof out_error->message,
                 "the route interface name does not fit the lookup output");
        return -1;
    }
    snprintf(ifname_out, ifname_cap, "%s", path.ifname);
    return 0;
}

static const utun_route_executor_t SYSTEM_EXECUTOR = {
    system_apply, system_lookup, NULL
};

#else

int utun_route_system_path(const uint8_t *address, uint8_t address_len,
                           utun_route_path_t *out_path,
                           utun_route_error_t *out_error) {
    (void)address;
    (void)address_len;
    if (out_path) memset(out_path, 0, sizeof *out_path);
    if (out_error) {
        out_error->code = ENOTSUP;
        snprintf(out_error->message, sizeof out_error->message,
                 "physical route lookup is unavailable on this host build");
    }
    return -1;
}

static int host_apply(void *ctx, const tun_plan_op_entry_t *op, const char *ifname,
                      utun_route_error_t *out_error) {
    (void)ctx;
    (void)ifname;
    if (!out_error) return -1;
    out_error->code = ENOTSUP;
    snprintf(out_error->message, sizeof out_error->message,
             "route %s was not applied: this build has no kernel routing, which"
             " is expected on a host test and never on a device",
             op && op->label[0] ? op->label : "request");
    return -1;
}

static int host_lookup(void *ctx, const uint8_t *address, uint8_t address_len,
                       char *ifname_out, size_t ifname_cap,
                       utun_route_error_t *out_error) {
    (void)ctx;
    (void)address;
    (void)address_len;
    if (ifname_out && ifname_cap) ifname_out[0] = '\0';
    if (out_error) {
        out_error->code = ENOTSUP;
        snprintf(out_error->message, sizeof out_error->message,
                 "route lookup is not available: this build has no kernel"
                 " routing, which is expected on a host test and never on a"
                 " device");
    }
    return -1;
}

static const utun_route_executor_t SYSTEM_EXECUTOR = {
    host_apply, host_lookup, NULL
};

#endif

const utun_route_executor_t *utun_route_system_executor(void) {
    return &SYSTEM_EXECUTOR;
}

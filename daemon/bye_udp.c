#include "bye_udp.h"

#include "tun/core/senko_time.h"
#include "tun/route_socket.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define IDLE_MS 30000
/* resolvers send each query from a new port and want one answer */
#define DNS_IDLE_MS 8000
#define READ_BATCH 16

typedef struct {
    int            used;
    tun_flow_key_t key;
    int            fd;
    int64_t        touched_ms;
} assoc_t;

struct bye_udp {
    bye_udp_config_t     config;
    tun_stack_t         *stack;
    tun_loop_hooks_t     previous;
    bye_udp_stats_t      stats;
    assoc_t              assocs[BYE_UDP_ASSOC_MAX];
    uint8_t              buf[TUN_STACK_PACKET_MAX];
};

size_t bye_udp_size(void) {
    return sizeof(struct bye_udp);
}

const bye_udp_stats_t *bye_udp_stats(const bye_udp_t *udp) {
    return udp ? &udp->stats : NULL;
}

static void set_error(bye_udp_t *udp, const char *text) {
    snprintf(udp->stats.last_error, sizeof udp->stats.last_error, "%s", text);
}

static int key_equal(const tun_flow_key_t *a, const tun_flow_key_t *b) {
    return a->address_len == b->address_len && a->source_port == b->source_port &&
           a->destination_port == b->destination_port &&
           memcmp(a->source, b->source, a->address_len) == 0 &&
           memcmp(a->destination, b->destination, a->address_len) == 0;
}

static int64_t idle_for(const assoc_t *assoc) {
    return assoc->key.destination_port == 53 ? DNS_IDLE_MS : IDLE_MS;
}

static void close_assoc(assoc_t *assoc) {
    if (assoc->fd >= 0) close(assoc->fd);
    memset(assoc, 0, sizeof *assoc);
    assoc->fd = -1;
}

static int open_assoc(bye_udp_t *udp, assoc_t *assoc, const tun_flow_key_t *key) {
    char error[160];
    int family = key->address_len == 4 ? AF_INET : AF_INET6;
    int fd = udp->config.direct_socket
        ? udp->config.direct_socket(udp->config.direct_ctx, family, SOCK_DGRAM, error, sizeof error)
        : -1;
    if (fd < 0) {
        set_error(udp, udp->config.direct_socket ? error
                       : "direct udp has no physical interface to leave by");
        return -1;
    }
    if (fd >= FD_SETSIZE) {
        close(fd);
        set_error(udp, "the descriptor cannot be watched by select");
        return -1;
    }
    const uint8_t *address = key->destination;
    if (key->destination_port == 53 && udp->config.dns_set && family == AF_INET)
        address = udp->config.dns;

    struct sockaddr_storage to;
    socklen_t to_len;
    memset(&to, 0, sizeof to);
    if (family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)&to;
#ifdef __APPLE__
        in->sin_len = sizeof *in;
#endif
        in->sin_family = AF_INET;
        in->sin_port = htons(key->destination_port);
        memcpy(&in->sin_addr, address, 4);
        to_len = sizeof *in;
    } else {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&to;
#ifdef __APPLE__
        in6->sin6_len = sizeof *in6;
#endif
        in6->sin6_family = AF_INET6;
        in6->sin6_port = htons(key->destination_port);
        memcpy(&in6->sin6_addr, address, 16);
        to_len = sizeof *in6;
    }
    if (connect(fd, (struct sockaddr *)&to, to_len) != 0) {
        char why[128];
        snprintf(why, sizeof why, "the udp destination is unreachable");
        route_errno_append(why, sizeof why, errno);
        set_error(udp, why);
        close(fd);
        return -1;
    }
    assoc->used = 1;
    assoc->key = *key;
    assoc->fd = fd;
    assoc->touched_ms = senko_now_ms();
    return 0;
}

/* a free slot, or the one idle longest: a new lookup beats an old tuple */
static assoc_t *slot_for_new(bye_udp_t *udp) {
    assoc_t *oldest = NULL;
    for (size_t i = 0; i < BYE_UDP_ASSOC_MAX; ++i) {
        assoc_t *assoc = &udp->assocs[i];
        if (!assoc->used) return assoc;
        if (!oldest || assoc->touched_ms < oldest->touched_ms) oldest = assoc;
    }
    ++udp->stats.evicted;
    close_assoc(oldest);
    return oldest;
}

static int on_udp(void *ctx, const tun_flow_key_t *key, const uint8_t *payload, size_t len) {
    bye_udp_t *udp = ctx;
    if (!key || (key->address_len != 4 && key->address_len != 16) || !payload || len == 0) {
        ++udp->stats.refused;
        set_error(udp, "a udp datagram is empty or malformed");
        return -1;
    }
    ++udp->stats.received;
    if (udp->config.block_quic && key->destination_port == 443) {
        ++udp->stats.quic_dropped;
        /* a silent drop leaves chrome and cfnetwork waiting out a quic
           handshake timeout before they fall back to tcp */
        tun_stack_status_t sent = tun_stack_udp_unreachable(udp->stack, key, len);
        if (sent != TUN_STACK_OK && sent != TUN_STACK_QUEUED) {
            ++udp->stats.refused;
            set_error(udp, "the tunnel output queue refused a quic refusal");
        }
        return 0;
    }
    assoc_t *assoc = NULL;
    for (size_t i = 0; i < BYE_UDP_ASSOC_MAX; ++i)
        if (udp->assocs[i].used && key_equal(&udp->assocs[i].key, key)) {
            assoc = &udp->assocs[i];
            break;
        }
    if (!assoc) {
        assoc = slot_for_new(udp);
        if (open_assoc(udp, assoc, key) != 0) {
            ++udp->stats.refused;
            return -1;
        }
    }
    assoc->touched_ms = senko_now_ms();
    ssize_t sent;
    do {
        sent = send(assoc->fd, payload, len, 0);
    } while (sent < 0 && errno == EINTR);
    if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)) {
        /* udp is allowed to lose a datagram, and the app sends it again */
        ++udp->stats.full_socket;
        return 0;
    }
    if (sent < 0) {
        char why[128];
        snprintf(why, sizeof why, "a udp send failed");
        route_errno_append(why, sizeof why, errno);
        set_error(udp, why);
        ++udp->stats.refused;
        close_assoc(assoc);
        return -1;
    }
    return 0;
}

static int on_start(void *ctx, tun_stack_t *stack, char *error, size_t error_cap) {
    bye_udp_t *udp = ctx;
    udp->stack = stack;
    if (udp->previous.start) return udp->previous.start(udp->previous.ctx, stack, error, error_cap);
    return 0;
}

static void lower_wait(uint32_t *wait_ms, int64_t now, int64_t due) {
    int64_t left = due - now;
    if (left < 0) left = 0;
    if ((uint64_t)left < *wait_ms) *wait_ms = (uint32_t)left;
}

static void on_prepare(void *ctx, fd_set *readable, fd_set *writable, int *highest,
                       uint32_t *wait_ms) {
    bye_udp_t *udp = ctx;
    if (udp->previous.prepare)
        udp->previous.prepare(udp->previous.ctx, readable, writable, highest, wait_ms);
    int64_t now = senko_now_ms();
    for (size_t i = 0; i < BYE_UDP_ASSOC_MAX; ++i) {
        const assoc_t *assoc = &udp->assocs[i];
        if (!assoc->used) continue;
        FD_SET(assoc->fd, readable);
        if (assoc->fd > *highest) *highest = assoc->fd;
        lower_wait(wait_ms, now, assoc->touched_ms + idle_for(assoc));
    }
}

static void receive(bye_udp_t *udp, assoc_t *assoc) {
    for (int i = 0; i < READ_BATCH; ++i) {
        ssize_t got = recv(assoc->fd, udp->buf, sizeof udp->buf, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        /* an icmp unreachable for the connected socket: the app just waits */
        if (got < 0 && errno == ECONNREFUSED) return;
        if (got < 0) {
            char why[128];
            snprintf(why, sizeof why, "a udp receive failed");
            route_errno_append(why, sizeof why, errno);
            set_error(udp, why);
            close_assoc(assoc);
            return;
        }
        tun_stack_status_t replied = tun_stack_udp_reply(udp->stack, &assoc->key, udp->buf,
                                                         (size_t)got);
        if (replied == TUN_STACK_OK || replied == TUN_STACK_QUEUED) {
            ++udp->stats.sent;
        } else {
            ++udp->stats.refused;
            set_error(udp, "the tunnel output queue refused a udp answer");
        }
        assoc->touched_ms = senko_now_ms();
    }
}

static void on_dispatch(void *ctx, const fd_set *readable, const fd_set *writable) {
    bye_udp_t *udp = ctx;
    if (udp->previous.dispatch) udp->previous.dispatch(udp->previous.ctx, readable, writable);
    int64_t now = senko_now_ms();
    for (size_t i = 0; i < BYE_UDP_ASSOC_MAX; ++i) {
        assoc_t *assoc = &udp->assocs[i];
        if (!assoc->used) continue;
        if (FD_ISSET(assoc->fd, readable)) receive(udp, assoc);
        if (assoc->used && now - assoc->touched_ms >= idle_for(assoc)) {
            ++udp->stats.expired;
            close_assoc(assoc);
        }
    }
}

static void on_stop(void *ctx) {
    bye_udp_t *udp = ctx;
    for (size_t i = 0; i < BYE_UDP_ASSOC_MAX; ++i)
        if (udp->assocs[i].used) close_assoc(&udp->assocs[i]);
    if (udp->previous.stop) udp->previous.stop(udp->previous.ctx);
}

int bye_udp_init(bye_udp_t *udp, const bye_udp_config_t *config, tun_loop_config_t *loop_config) {
    if (!udp || !config || !loop_config || !config->direct_socket || loop_config->stack.udp_packet)
        return -1;
    memset(udp, 0, sizeof *udp);
    udp->config = *config;
    udp->previous = loop_config->hooks;
    for (size_t i = 0; i < BYE_UDP_ASSOC_MAX; ++i) udp->assocs[i].fd = -1;
    loop_config->stack.udp_packet = on_udp;
    loop_config->stack.udp_ctx = udp;
    loop_config->hooks.start = on_start;
    loop_config->hooks.prepare = on_prepare;
    loop_config->hooks.dispatch = on_dispatch;
    loop_config->hooks.stop = on_stop;
    loop_config->hooks.ctx = udp;
    return 0;
}

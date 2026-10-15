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
/* the largest datagram that crosses the tunnel without fragmenting */
#define DNS_MSG_MAX 1232
#define DNS_HEADER_LEN 12

typedef struct {
    int            used;
    tun_flow_key_t key;
    int            fd;
    int64_t        touched_ms;
    /* a lookup carried over tcp: one query, one answer */
    int            stream;
    int            connecting;
    size_t         out_len;
    size_t         out_sent;
    size_t         in_len;
    uint8_t        out[2 + DNS_MSG_MAX];
    uint8_t        in[2 + DNS_MSG_MAX];
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
    return assoc->stream ? DNS_IDLE_MS : IDLE_MS;
}

/* the network forges udp answers for some names (nxdomain for youtube) even
   when they are addressed to a public resolver, while tcp reaches the
   resolver unchanged, so a resolver the user picked is asked over tcp */
static int is_dns_stream(const bye_udp_t *udp, const tun_flow_key_t *key) {
    return udp->config.dns_set && key->address_len == 4 &&
           key->destination_port == (udp->config.dns_port ? udp->config.dns_port : 53);
}

static void close_assoc(assoc_t *assoc) {
    if (assoc->fd >= 0) close(assoc->fd);
    memset(assoc, 0, sizeof *assoc);
    assoc->fd = -1;
}

static int open_assoc(bye_udp_t *udp, assoc_t *assoc, const tun_flow_key_t *key) {
    char error[160];
    int family = key->address_len == 4 ? AF_INET : AF_INET6;
    int stream = is_dns_stream(udp, key);
    int fd = udp->config.direct_socket
        ? udp->config.direct_socket(udp->config.direct_ctx, family,
                                    stream ? SOCK_STREAM : SOCK_DGRAM, error, sizeof error)
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
    if (stream) address = udp->config.dns;

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
    if (connect(fd, (struct sockaddr *)&to, to_len) != 0 && !(stream && errno == EINPROGRESS)) {
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
    assoc->stream = stream;
    assoc->connecting = stream;
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

static void flush_query(bye_udp_t *udp, assoc_t *assoc) {
    while (assoc->out_sent < assoc->out_len) {
        ssize_t sent = send(assoc->fd, assoc->out + assoc->out_sent,
                            assoc->out_len - assoc->out_sent, 0);
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (sent < 0) {
            char why[128];
            snprintf(why, sizeof why, "a dns query over tcp failed to send");
            route_errno_append(why, sizeof why, errno);
            set_error(udp, why);
            ++udp->stats.refused;
            close_assoc(assoc);
            return;
        }
        assoc->out_sent += (size_t)sent;
    }
}

static int start_lookup(bye_udp_t *udp, const tun_flow_key_t *key,
                        const uint8_t *payload, size_t len) {
    if (len < DNS_HEADER_LEN || len > DNS_MSG_MAX) {
        ++udp->stats.refused;
        set_error(udp, "a dns query is shorter than a header or longer than a datagram");
        return -1;
    }
    assoc_t *assoc = slot_for_new(udp);
    if (open_assoc(udp, assoc, key) != 0) {
        ++udp->stats.refused;
        return -1;
    }
    assoc->out[0] = (uint8_t)(len >> 8);
    assoc->out[1] = (uint8_t)len;
    memcpy(assoc->out + 2, payload, len);
    assoc->out_len = 2 + len;
    return 0;
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
    if (assoc && assoc->stream) {
        /* a resolver repeating a query from the same port gets a new
           connection, so one tcp stream never carries two ids */
        close_assoc(assoc);
        assoc = NULL;
    }
    if (is_dns_stream(udp, key)) return start_lookup(udp, key, payload, len);
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
        if (assoc->stream && (assoc->connecting || assoc->out_sent < assoc->out_len))
            FD_SET(assoc->fd, writable);
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

/* offset just past the first question, 0 when the name is malformed */
static size_t question_end(const uint8_t *query, size_t len) {
    size_t at = DNS_HEADER_LEN;
    while (at < len && query[at] != 0) {
        if (query[at] > 63) return 0;
        at += 1u + query[at];
    }
    at += 5;
    return at <= len ? at : 0;
}

/* an answer that cannot cross the tunnel whole becomes a truncated reply to
   the stored query, so the app repeats the lookup over tcp itself */
static void reply_truncated(bye_udp_t *udp, assoc_t *assoc) {
    const uint8_t *query = assoc->out + 2;
    size_t end = question_end(query, assoc->out_len - 2);
    if (end == 0) {
        ++udp->stats.refused;
        set_error(udp, "a dns query has a malformed question");
        return;
    }
    memcpy(udp->buf, query, end);
    /* qr and tc set, the question kept, no records */
    udp->buf[2] = (uint8_t)(0x82 | (query[2] & 0x01));
    udp->buf[3] = 0x80;
    udp->buf[4] = 0;
    udp->buf[5] = 1;
    memset(udp->buf + 6, 0, 6);
    tun_stack_status_t replied = tun_stack_udp_reply(udp->stack, &assoc->key, udp->buf, end);
    if (replied == TUN_STACK_OK || replied == TUN_STACK_QUEUED) {
        ++udp->stats.sent;
    } else {
        ++udp->stats.refused;
        set_error(udp, "the tunnel output queue refused a udp answer");
    }
}

static void receive_stream(bye_udp_t *udp, assoc_t *assoc) {
    if (assoc->connecting) return;
    for (;;) {
        size_t want = 2;
        if (assoc->in_len >= 2) {
            size_t answer = ((size_t)assoc->in[0] << 8) | assoc->in[1];
            if (answer > DNS_MSG_MAX) {
                reply_truncated(udp, assoc);
                close_assoc(assoc);
                return;
            }
            want = 2 + answer;
        }
        if (assoc->in_len >= want) break;
        ssize_t got = recv(assoc->fd, assoc->in + assoc->in_len, want - assoc->in_len, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (got <= 0) {
            char why[128];
            snprintf(why, sizeof why, got == 0 ? "the resolver closed the tcp connection"
                                                : "a dns answer over tcp failed to arrive");
            if (got < 0) route_errno_append(why, sizeof why, errno);
            set_error(udp, why);
            ++udp->stats.refused;
            close_assoc(assoc);
            return;
        }
        assoc->in_len += (size_t)got;
    }
    size_t answer_len = assoc->in_len - 2;
    if (answer_len < DNS_HEADER_LEN) {
        set_error(udp, "a dns answer over tcp is shorter than a header");
        ++udp->stats.refused;
        close_assoc(assoc);
        return;
    }
    tun_stack_status_t replied = tun_stack_udp_reply(udp->stack, &assoc->key, assoc->in + 2,
                                                     answer_len);
    if (replied == TUN_STACK_OK || replied == TUN_STACK_QUEUED) {
        ++udp->stats.sent;
    } else {
        ++udp->stats.refused;
        set_error(udp, "the tunnel output queue refused a udp answer");
    }
    close_assoc(assoc);
}

static void dispatch_stream(bye_udp_t *udp, assoc_t *assoc, const fd_set *readable,
                            const fd_set *writable) {
    if (assoc->connecting && FD_ISSET(assoc->fd, writable)) {
        int value = 0;
        socklen_t value_len = sizeof value;
        if (getsockopt(assoc->fd, SOL_SOCKET, SO_ERROR, &value, &value_len) != 0) value = errno;
        if (value != 0) {
            char why[128];
            snprintf(why, sizeof why, "the dns resolver is unreachable over tcp");
            route_errno_append(why, sizeof why, value);
            set_error(udp, why);
            ++udp->stats.refused;
            close_assoc(assoc);
            return;
        }
        assoc->connecting = 0;
    }
    if (!assoc->connecting && assoc->out_sent < assoc->out_len) flush_query(udp, assoc);
    if (assoc->used && FD_ISSET(assoc->fd, readable)) receive_stream(udp, assoc);
}

static void on_dispatch(void *ctx, const fd_set *readable, const fd_set *writable) {
    bye_udp_t *udp = ctx;
    if (udp->previous.dispatch) udp->previous.dispatch(udp->previous.ctx, readable, writable);
    int64_t now = senko_now_ms();
    for (size_t i = 0; i < BYE_UDP_ASSOC_MAX; ++i) {
        assoc_t *assoc = &udp->assocs[i];
        if (!assoc->used) continue;
        if (assoc->stream) dispatch_stream(udp, assoc, readable, writable);
        else if (FD_ISSET(assoc->fd, readable)) receive(udp, assoc);
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

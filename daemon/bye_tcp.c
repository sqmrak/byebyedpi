#include "bye_tcp.h"

#include "bye_altaddr.h"
#include "bye_mtp.h"
#include "bye_tg.h"
#include "tun/core/senko_time.h"
#include "tun/route_socket.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define HOLD_MAX 4096
/* a tls record body is at most 16384 bytes, and the plan may add record
   headers and one urgent byte */
#define FIRST_MAX (16384 + 5 + BYE_DESYNC_GROWTH_MAX)
#define FIRST_WAIT_MS 1500
#define CONNECT_MS 8000
#define HANDSHAKE_MS 8000
#define TG_INIT_MS 10000
#define TG_PING_MS 30000
#define TG_IDLE_MS 120000
#define TG_FAIL_MS 30000
#define UP_STEP 16384
#define PASSES 8
/* a tls server answers a hello in well under this, or the strategy is dropped */
/* a ready gateway connection is dropped after this, the gateway closes idle
   ones on its own schedule */
#define POOL_MAX_AGE_MS 40000
#define POOL_PING_MS 15000
/* a datacenter nobody used for this long stops being kept ready */
#define POOL_IDLE_MS (5 * 60 * 1000)
/* a connection that failed to come up is not tried again before this */
#define POOL_RETRY_MS 10000
#define POOL_CHECK_MS 1000
#define AUTO_WAIT_MS 3000
/* the most a probing flow keeps for a retry: one tls record and its header */
#define REPLAY_MAX FIRST_MAX
#define AUTO_CACHE_MAX 64
#define SITE_HINT_MAX 16
#define AUTO_LEARNED_MS (60 * 60 * 1000)
/* after every strategy failed the next flows to that address are not retried
   for a while, so a blocked address does not cost each of them every wait */
#define AUTO_EXHAUSTED_MS (30 * 1000)
#define AUTO_EXHAUSTED 0xffu
/* other addresses of a server name tried after every strategy failed at the first one */
#define ALT_TRY_MAX 3
#define REDIRECT_MAX 16

typedef enum {
    R_FREE = 0,
    R_CONNECTING,   /* a direct socket is connecting, the flow may be held or open */
    R_ACCEPTED,     /* connected and accepted, waiting for the app's handshake */
    R_RUNNING,      /* bytes pass both ways */
    R_TG_INIT,      /* accepted, collecting the 64 byte client init */
    R_TG_CONNECT,   /* tcp to the datacenter's gateway */
    R_TG_HANDSHAKE, /* tls and the websocket upgrade */
    R_TG_RUNNING,
    R_TG_POOLED     /* upgraded and idle, waiting for a flow to take it */
} state_t;

typedef struct {
    state_t        state;
    uint64_t       flow_id;
    tun_flow_key_t key;
    bye_path_t     path;
    uint8_t        dest[16];
    uint8_t        dest_len;
    uint16_t       dest_port;
    int            fd;
    int            accepted;  /* the app's handshake was answered */
    int            app_eof;
    int            server_write_shut;
    int            app_fin_sent;
    int            blocked;   /* the socket took no more bytes */
    int64_t        started_ms;
    int64_t        deadline_ms; /* the current step must finish by then, 0 for none */

    uint8_t        hold[HOLD_MAX]; /* server bytes the app's window could not take */
    size_t         hold_off;
    size_t         hold_len;

    /* desync */
    int            first_done;
    int64_t        first_since_ms;
    int            strategy_set; /* strategy and strategy_start were chosen */
    unsigned       strategy;     /* the index in use */
    unsigned       strategy_start; /* where this flow began, the cache decides */
    unsigned       attempt;      /* the step of the strategy cycle in use, 0 for the first */
    int            no_probe;     /* the flow is not retried: the host list or the cache says so */
    int            probing;      /* the first bytes are out and nothing came back yet */
    int            probe_done;   /* an answer arrived during this pass: run the upload again */
    uint8_t       *replay;       /* collected first bytes, kept while a retry is possible */
    size_t         replay_len;
    size_t         replay_cap;
    int            probe_replay; /* the next first payload comes from replay, not the stack */
    int64_t        probe_due_ms; /* the answer must come by then, 0 on the last strategy */
    uint8_t       *pending;   /* planned bytes the socket has not taken yet */
    size_t         pending_off;
    size_t         pending_len;

    /* telegram */
    bye_mtp_t        *mtp;
    bye_wsconn_t     *ws;
    bye_mtp_route_t   route;
    uint8_t           relay_init[BYE_MTP_INIT_LEN];
    unsigned          variant;
    int               ws_wait_write;
    int               ping_sent;
    int64_t           last_rx_ms;
    int               counted_tg; /* holds one of the telegram slots */
    int               pooled;     /* a gateway connection for the pool, not a flow */
    int64_t           pool_since_ms; /* when the upgrade finished */
    int               again;      /* a pass ended with work left: run it again */

    char           name[256]; /* the complete sni, so site hints keep the suffix */
    unsigned       alt_used;   /* addresses other than the app's that this flow moved to */
    uint8_t        seen[BYE_ALT_ADDRS_MAX + 1][4]; /* the app's address and those tried since */
    unsigned       seen_count;

    uint64_t       up;
    uint64_t       down;
} relay_t;

typedef struct {
    uint8_t  addr[16];
    uint8_t  len;
    uint16_t port;
    uint8_t  index;       /* the strategy that answered, or AUTO_EXHAUSTED */
    int64_t  expires_ms;  /* 0 for an empty slot */
} learned_t;

/* cdn names use many addresses; reuse a passing strategy so each address avoids the same failed attempts */
typedef struct {
    char    site[32];
    uint8_t index;
    int64_t expires_ms;
} site_hint_t;

/* a name whose own address answered no cut, and the address of the same site that did */
typedef struct {
    char    name[256];
    uint8_t addr[4];
    int64_t expires_ms;
} redirect_t;

struct bye_tcp {
    bye_tcp_config_t config;
    tun_stack_t     *stack;
    bye_tcp_stats_t  stats;
    size_t           tg_active;
    int64_t          tg_fail_until[2 * 8]; /* by datacenter and media, see fail_slot */
    size_t           relay_first;   /* the relay that worked last */
    int64_t          pool_use_ms[2 * 8];   /* the last flow, by datacenter and media */
    int64_t          pool_retry_ms[2 * 8]; /* a failed connection waits until then */
    int64_t          pool_check_ms;
    relay_t          pool[BYE_TCP_POOL_MAX];
    learned_t        learned[AUTO_CACHE_MAX];
    size_t           learned_next;
    site_hint_t      hint[SITE_HINT_MAX];
    size_t           hint_next;
    redirect_t       redirect[REDIRECT_MAX];
    size_t           redirect_next;
    uint8_t          scratch[FIRST_MAX];
    relay_t          relays[TUN_NAT_TCP_MAX];
};

size_t bye_tcp_size(void) {
    return sizeof(struct bye_tcp);
}

const bye_tcp_stats_t *bye_tcp_stats(const bye_tcp_t *tcp) {
    return tcp ? &tcp->stats : NULL;
}

static void set_error(bye_tcp_t *tcp, const char *text) {
    snprintf(tcp->stats.last_error, sizeof tcp->stats.last_error, "%s", text);
}

static void trace(bye_tcp_t *tcp, const relay_t *relay, const char *what, const char *why) {
    char ip[INET6_ADDRSTRLEN] = "?";
    (void)inet_ntop(relay->dest_len == 4 ? AF_INET : AF_INET6, relay->dest, ip, sizeof ip);
    const char *path = relay->path == BYE_PATH_TELEGRAM ? "telegram"
                     : relay->path == BYE_PATH_DESYNC ? "desync" : "direct";
    if (relay->path != BYE_PATH_TELEGRAM && strcmp(what, "closed") != 0) {
        bye_tcp_stats_t *stats = &tcp->stats;
        snprintf(stats->recent[stats->recent_count++ % BYE_TCP_RECENT_MAX], BYE_TCP_RECENT_LEN,
                 "%.47s %s:%u %s %s%s%s", relay->name[0] ? relay->name : ip, ip,
                 (unsigned)relay->dest_port, path, what,
                 why ? ": " : "", why ? why : "");
    }
    if (!tcp->config.trace) return;
    fprintf(stderr, "byedpid: tcp %s%s%u %s %s up %llu down %llu%s%s\n", ip,
            relay->dest_len == 4 ? ":" : " port ", (unsigned)relay->dest_port, path, what,
            (unsigned long long)relay->up, (unsigned long long)relay->down,
            why ? ": " : "", why ? why : "");
}

/* the capture slot is the low byte of a flow id, so a flow maps to its relay
   without a search; the full id is compared before anything is trusted */
static relay_t *relay_for(bye_tcp_t *tcp, uint64_t flow_id) {
    size_t slot = (size_t)(flow_id & 0xffu);
    return slot < TUN_NAT_TCP_MAX ? &tcp->relays[slot] : NULL;
}

static void close_fd(relay_t *relay) {
    if (relay->fd >= 0) close(relay->fd);
    relay->fd = -1;
}

static void release(bye_tcp_t *tcp, relay_t *relay) {
    if (relay->ws) bye_wsconn_free(relay->ws);
    if (relay->mtp) bye_mtp_close(relay->mtp);
    close_fd(relay);
    free(relay->pending);
    free(relay->replay);
    if (relay->counted_tg && tcp->tg_active) --tcp->tg_active;
    /* the relay init holds key material */
    memset(relay->relay_init, 0, sizeof relay->relay_init);
    memset(relay, 0, sizeof *relay);
    relay->fd = -1;
}

/* a flow that failed after the app connected gets a reset, never a clean fin,
   so the app does not take a cut transfer for a complete one */
static void abort_flow(bye_tcp_t *tcp, relay_t *relay, const char *why) {
    uint64_t id = relay->flow_id;
    int accepted = relay->accepted;
    ++tcp->stats.aborted;
    set_error(tcp, why);
    trace(tcp, relay, "reset", why);
    release(tcp, relay);
    if (accepted) (void)tun_stack_flow_abort(tcp->stack, id);
    else (void)tun_stack_flow_reject(tcp->stack, id);
}

static void refuse_flow(bye_tcp_t *tcp, relay_t *relay, const char *why) {
    ++tcp->stats.refused;
    set_error(tcp, why);
    trace(tcp, relay, "refused", why);
    uint64_t id = relay->flow_id;
    int accepted = relay->accepted;
    release(tcp, relay);
    if (accepted) (void)tun_stack_flow_abort(tcp->stack, id);
    else (void)tun_stack_flow_reject(tcp->stack, id);
}

static void finish_flow(bye_tcp_t *tcp, relay_t *relay) {
    uint64_t id = relay->flow_id;
    ++tcp->stats.finished;
    trace(tcp, relay, "closed", NULL);
    release(tcp, relay);
    (void)tun_stack_flow_close(tcp->stack, id);
}

static int probe_retry(bye_tcp_t *tcp, relay_t *relay, uint32_t kind, const char *why);

/* a failed send or receive on a flow that has had no answer yet may be the
   filter cutting the connection, and then the next strategy gets its turn */
static void abort_errno(bye_tcp_t *tcp, relay_t *relay, const char *what, int value) {
    char why[128];
    snprintf(why, sizeof why, "%s", what);
    route_errno_append(why, sizeof why, value);
    if (relay->probing && probe_retry(tcp, relay, BYE_TRIGGER_TORST, why)) return;
    abort_flow(tcp, relay, why);
}


static int dial(bye_tcp_t *tcp, relay_t *relay, int family, const uint8_t *addr,
                uint16_t port, int nodelay, char *why, size_t why_cap) {
    char error[160];
    int fd = tcp->config.direct_socket
        ? tcp->config.direct_socket(tcp->config.direct_ctx, family, SOCK_STREAM, error, sizeof error)
        : -1;
    if (fd < 0) {
        snprintf(why, why_cap, "%s", tcp->config.direct_socket ? error
                                      : "direct tcp has no physical interface to leave by");
        return -1;
    }
    if (fd >= FD_SETSIZE) {
        close(fd);
        snprintf(why, why_cap, "the descriptor cannot be watched by select");
        return -1;
    }
    /* without it the kernel joins the planned segments back into one */
    if (nodelay) (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &(int){ 1 }, sizeof(int));

    struct sockaddr_storage to;
    socklen_t to_len;
    memset(&to, 0, sizeof to);
    if (family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)&to;
#ifdef __APPLE__
        in->sin_len = sizeof *in;
#endif
        in->sin_family = AF_INET;
        in->sin_port = htons(port);
        memcpy(&in->sin_addr, addr, 4);
        to_len = sizeof *in;
    } else {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&to;
#ifdef __APPLE__
        in6->sin6_len = sizeof *in6;
#endif
        in6->sin6_family = AF_INET6;
        in6->sin6_port = htons(port);
        memcpy(&in6->sin6_addr, addr, 16);
        to_len = sizeof *in6;
    }
    if (connect(fd, (struct sockaddr *)&to, to_len) != 0 && errno != EINPROGRESS) {
        snprintf(why, why_cap, "the %s connection was refused", family == AF_INET ? "ipv4" : "ipv6");
        route_errno_append(why, why_cap, errno);
        close(fd);
        return -1;
    }
    relay->fd = fd;
    return 0;
}

/* 1 once connected, 0 while waiting, -1 with errno in *error */
static int connect_result(const relay_t *relay, int *error) {
    int value = 0;
    socklen_t len = sizeof value;
    if (getsockopt(relay->fd, SOL_SOCKET, SO_ERROR, &value, &len) != 0) value = errno;
    *error = value;
    return value == 0 ? 1 : -1;
}


static void start_direct(bye_tcp_t *tcp, relay_t *relay) {
    char why[160];
    int family = relay->dest_len == 4 ? AF_INET : AF_INET6;
    if (dial(tcp, relay, family, relay->dest, relay->dest_port,
             relay->path == BYE_PATH_DESYNC, why, sizeof why) != 0) {
        refuse_flow(tcp, relay, why);
        return;
    }
    relay->state = R_CONNECTING;
    relay->deadline_ms = senko_now_ms() + CONNECT_MS;
}

static int flush_hold(bye_tcp_t *tcp, relay_t *relay) {
    while (relay->hold_off < relay->hold_len) {
        size_t accepted = 0;
        if (tun_stack_flow_write(tcp->stack, relay->flow_id, relay->hold + relay->hold_off,
                                 relay->hold_len - relay->hold_off, &accepted) != TUN_STACK_OK)
            return -1;
        if (accepted == 0) return 1; /* the app's window is full */
        relay->hold_off += accepted;
        tcp->stats.bytes_down += accepted;
        relay->down += accepted;
    }
    relay->hold_off = relay->hold_len = 0;
    return 0;
}

/* planned bytes the socket refused earlier go first. 0 once empty, 1 while
   the socket is full, -1 after the flow was torn down */
static int flush_pending(bye_tcp_t *tcp, relay_t *relay) {
    while (relay->pending_off < relay->pending_len) {
        ssize_t sent = send(relay->fd, relay->pending + relay->pending_off,
                            relay->pending_len - relay->pending_off, 0);
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            relay->blocked = 1;
            return 1;
        }
        if (sent <= 0) {
            abort_errno(tcp, relay, "the destination refused the app's bytes", errno);
            return -1;
        }
        relay->pending_off += (size_t)sent;
    }
    free(relay->pending);
    relay->pending = NULL;
    relay->pending_off = relay->pending_len = 0;
    return 0;
}

/* keeps what the socket did not take, so a full socket cuts the plan short but
   loses nothing */
static int stash_pending(bye_tcp_t *tcp, relay_t *relay, const uint8_t *data, size_t len) {
    relay->pending = malloc(len);
    if (!relay->pending) {
        abort_flow(tcp, relay, "not enough memory to hold the first bytes");
        return -1;
    }
    memcpy(relay->pending, data, len);
    relay->pending_off = 0;
    relay->pending_len = len;
    relay->blocked = 1;
    return 0;
}

static int ttl_get(int fd, int family) {
    int value = 0;
    socklen_t len = sizeof value;
    int level = family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
    int name = family == AF_INET ? IP_TTL : IPV6_UNICAST_HOPS;
    return getsockopt(fd, level, name, &value, &len) == 0 ? value : -1;
}

static int ttl_set(int fd, int family, int value) {
    int level = family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
    int name = family == AF_INET ? IP_TTL : IPV6_UNICAST_HOPS;
    return setsockopt(fd, level, name, &value, sizeof value);
}

/* a fake that cannot leave is no reason to drop the flow: its part still goes
   out as a plain cut, and the counters and the trace say it happened */
static void send_fake(bye_tcp_t *tcp, relay_t *relay, const bye_desync_t *group,
                      const bye_plan_t *plan, const bye_op_t *op, uint32_t wire) {
    uint8_t payload[BYE_FAKE_PAYLOAD_MAX];
    int tls = plan->has_name ? plan->tls : (plan->total > 0 && tcp->scratch[0] == 0x16);
    size_t n = bye_desync_fake(group, tls, tcp->scratch, plan->total, op->len, payload, sizeof payload);
    int status = BYE_FAKE_SEND_OFF;
    if (n && tcp->config.fake_send)
        status = tcp->config.fake_send(tcp->config.fake_ctx, relay->fd, wire, payload, n,
                                       group->fake_ttl ? group->fake_ttl : BYE_FAKE_TTL_DEFAULT,
                                       group->md5sig);
    if (status == BYE_FAKE_SEND_OK) {
        ++tcp->stats.fake_sent;
        return;
    }
    ++tcp->stats.fake_missed;
    trace(tcp, relay, status == BYE_FAKE_SEND_UNKNOWN ? "fake not sent, the syn of this connection was not seen"
                    : status == BYE_FAKE_SEND_FAILED ? "fake not sent, the raw socket refused it"
                    : "fake not sent, there is no watcher or no fake bytes", NULL);
}

/* ttl 1 forces retransmission after later segments; restore it before sending those segments
   partial writes remain in pending; -1 means the flow was closed */
static int send_plan(bye_tcp_t *tcp, relay_t *relay, const bye_desync_t *group, const bye_plan_t *plan) {
    int family = relay->dest_len == 4 ? AF_INET : AF_INET6;
    /* bytes the socket has taken, urgent ones included: the next fake takes the
       sequence number that follows them */
    uint32_t wire = 0;
    for (size_t i = 0; i < plan->count; ++i) {
        const bye_op_t *op = &plan->ops[i];
        uint8_t *seg = tcp->scratch + op->off;
        size_t len = op->len, done = 0;
        int failed = 0;
        int restore = 0;
        if (op->flags & BYE_OP_FAKE) send_fake(tcp, relay, group, plan, op, wire);
        if (op->flags & BYE_OP_TTL1) {
            restore = tcp->config.strategies.def_ttl ? tcp->config.strategies.def_ttl
                                                     : ttl_get(relay->fd, family);
            if (restore < 2 || ttl_set(relay->fd, family, 1) != 0) {
                abort_errno(tcp, relay, "the ttl of the destination socket could not be set", errno);
                return -1;
            }
        }
        if (op->flags & BYE_OP_OOB) {
            /* the urgent byte takes the place of the next app byte, which the next
               segment sends again. the scratch buffer has one spare byte for the last */
            uint8_t kept = seg[len];
            seg[len] = plan->oob_char;
            ssize_t sent;
            do sent = send(relay->fd, seg, len + 1, MSG_OOB);
            while (sent < 0 && errno == EINTR);
            seg[len] = kept;
            if (sent > 0) wire += (uint32_t)sent;
            if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) sent = 0;
            if (sent < 0) failed = errno;
            else done = (size_t)sent > len ? len : (size_t)sent;
        } else {
            while (done < len) {
                ssize_t sent = send(relay->fd, seg + done, len - done, 0);
                if (sent < 0 && errno == EINTR) continue;
                if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
                if (sent <= 0) {
                    failed = sent < 0 ? errno : ECONNRESET;
                    break;
                }
                done += (size_t)sent;
                wire += (uint32_t)sent;
            }
        }
        if (restore) {
            int back = ttl_set(relay->fd, family, restore);
            int back_errno = errno;
            if (back != 0 && !failed) failed = back_errno;
        }
        if (failed) {
            abort_errno(tcp, relay, "the destination refused the app's bytes", failed);
            return -1;
        }
        if (done < len) {
            return stash_pending(tcp, relay, seg + done, plan->total - op->off - done);
        }
        if (op->oob_after) {
            static const uint8_t byte = BYE_DESYNC_OOB_BYTE;
            ssize_t sent = send(relay->fd, &byte, 1, MSG_OOB);
            /* the urgent byte is only a decoy: a full socket may skip it */
            if (sent > 0) wire += (uint32_t)sent;
            if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS &&
                errno != EINTR) {
                abort_errno(tcp, relay, "the destination refused the urgent byte", errno);
                return -1;
            }
        }
    }
    return 0;
}

static unsigned strategy_count(const bye_tcp_t *tcp) {
    return tcp->config.strategies.count ? (unsigned)tcp->config.strategies.count : 1u;
}

static const bye_desync_t *strategy_at(const bye_tcp_t *tcp, unsigned index) {
    static const bye_desync_t none;
    return index < tcp->config.strategies.count ? &tcp->config.strategies.item[index] : &none;
}

static learned_t *learned_find(bye_tcp_t *tcp, const relay_t *relay, int64_t now) {
    for (size_t i = 0; i < AUTO_CACHE_MAX; ++i) {
        learned_t *entry = &tcp->learned[i];
        if (entry->expires_ms > now && entry->len == relay->dest_len &&
            entry->port == relay->dest_port && memcmp(entry->addr, relay->dest, relay->dest_len) == 0)
            return entry;
    }
    return NULL;
}

static void learned_store(bye_tcp_t *tcp, const relay_t *relay, unsigned index, int64_t ttl_ms) {
    int64_t now = senko_now_ms();
    learned_t *entry = learned_find(tcp, relay, now);
    if (!entry) {
        entry = &tcp->learned[tcp->learned_next];
        tcp->learned_next = (tcp->learned_next + 1) % AUTO_CACHE_MAX;
        memset(entry, 0, sizeof *entry);
        entry->len = relay->dest_len;
        entry->port = relay->dest_port;
        memcpy(entry->addr, relay->dest, relay->dest_len);
    }
    entry->index = (uint8_t)index;
    entry->expires_ms = now + ttl_ms;
}

/* the last two labels of a name, "googlevideo.com" for "rr1---sn-x.googlevideo.com", or NULL */
static const char *site_of(const char *name) {
    size_t len = strlen(name);
    const char *dot = NULL;
    for (size_t i = len; i-- > 0;) {
        if (name[i] != '.') continue;
        if (dot) return name + i + 1;
        dot = name + i;
    }
    return dot ? name : NULL;
}

static site_hint_t *hint_find(bye_tcp_t *tcp, const relay_t *relay, int64_t now) {
    const char *site = site_of(relay->name);
    if (!site || strlen(site) >= sizeof tcp->hint[0].site) return NULL;
    for (size_t i = 0; i < SITE_HINT_MAX; ++i)
        if (tcp->hint[i].expires_ms > now && strcmp(tcp->hint[i].site, site) == 0)
            return &tcp->hint[i];
    return NULL;
}

static void hint_store(bye_tcp_t *tcp, const relay_t *relay, unsigned index) {
    const char *site = site_of(relay->name);
    if (!site || strlen(site) >= sizeof tcp->hint[0].site) return;
    int64_t now = senko_now_ms();
    site_hint_t *entry = hint_find(tcp, relay, now);
    if (!entry) {
        entry = &tcp->hint[tcp->hint_next];
        tcp->hint_next = (tcp->hint_next + 1) % SITE_HINT_MAX;
        snprintf(entry->site, sizeof entry->site, "%s", site);
    }
    entry->index = (uint8_t)index;
    entry->expires_ms = now + AUTO_LEARNED_MS;
}

/* the strategy this flow starts with: the one that last answered for its
   destination, then for its site, or the first */
static void choose_strategy(bye_tcp_t *tcp, relay_t *relay) {
    relay->strategy_set = 1;
    relay->strategy = relay->strategy_start = 0;
    relay->attempt = 0;
    if (strategy_count(tcp) < 2) return;
    learned_t *entry = learned_find(tcp, relay, senko_now_ms());
    if (!entry) {
        site_hint_t *hint = hint_find(tcp, relay, senko_now_ms());
        if (hint) relay->strategy = relay->strategy_start = hint->index % strategy_count(tcp);
        return;
    }
    if (entry->index == AUTO_EXHAUSTED) relay->no_probe = 1;
    else relay->strategy = relay->strategy_start = entry->index % strategy_count(tcp);
}

/* 1 when the host list says this name is not cut */
static int host_skipped(const bye_tcp_t *tcp, const uint8_t *data, const bye_plan_t *plan) {
    if (!tcp->config.hosts || !plan->has_name) return 0;
    int listed = bye_hosts_match(tcp->config.hosts, (const char *)data + plan->name_off,
                                 plan->name_len);
    return tcp->config.hosts_only ? !listed : listed;
}

static void replay_drop(relay_t *relay) {
    free(relay->replay);
    relay->replay = NULL;
    relay->replay_len = relay->replay_cap = 0;
}

/* a hello larger than the replay buffer cannot be retried without truncation */
static int replay_append(relay_t *relay, const uint8_t *data, size_t len) {
    if (relay->replay_len + len > REPLAY_MAX) return -1;
    if (relay->replay_len + len > relay->replay_cap) {
        size_t cap = relay->replay_cap ? relay->replay_cap : 2048;
        while (cap < relay->replay_len + len) cap *= 2;
        if (cap > REPLAY_MAX) cap = REPLAY_MAX;
        uint8_t *grown = realloc(relay->replay, cap);
        if (!grown) return -1;
        relay->replay = grown;
        relay->replay_cap = cap;
    }
    memcpy(relay->replay + relay->replay_len, data, len);
    relay->replay_len += len;
    return 0;
}

static void probe_keep(relay_t *relay, const uint8_t *data, size_t len) {
    if (replay_append(relay, data, len) == 0) return;
    relay->probing = 0;
    relay->probe_due_ms = 0;
    replay_drop(relay);
}

static redirect_t *redirect_find(bye_tcp_t *tcp, const char *name, int64_t now) {
    for (size_t i = 0; i < REDIRECT_MAX; ++i)
        if (tcp->redirect[i].expires_ms > now && strcmp(tcp->redirect[i].name, name) == 0)
            return &tcp->redirect[i];
    return NULL;
}

static void redirect_store(bye_tcp_t *tcp, const relay_t *relay) {
    int64_t now = senko_now_ms();
    redirect_t *entry = redirect_find(tcp, relay->name, now);
    if (!entry) {
        entry = &tcp->redirect[tcp->redirect_next];
        tcp->redirect_next = (tcp->redirect_next + 1) % REDIRECT_MAX;
    }
    snprintf(entry->name, sizeof entry->name, "%s", relay->name);
    memcpy(entry->addr, relay->dest, 4);
    entry->expires_ms = now + AUTO_LEARNED_MS;
}

static int seen_has(const relay_t *relay, const uint8_t *addr) {
    for (unsigned i = 0; i < relay->seen_count; ++i)
        if (memcmp(relay->seen[i], addr, 4) == 0) return 1;
    return 0;
}

static void seen_add(relay_t *relay, const uint8_t *addr) {
    if (relay->seen_count < sizeof relay->seen / sizeof relay->seen[0])
        memcpy(relay->seen[relay->seen_count++], addr, 4);
}

/* an ipv4 flow with a server name may be moved to another address of the site */
static int alt_possible(const relay_t *relay) {
    return relay->name[0] && strlen(relay->name) < BYE_ALT_NAME_MAX &&
           relay->dest_len == 4 && relay->alt_used < ALT_TRY_MAX;
}

/* points the flow at an address of its site that it has not used. 0 when the lookup is
   not done or has nothing new */
static int alt_next(relay_t *relay) {
    uint8_t found[BYE_ALT_ADDRS_MAX][4];
    size_t count = 0;
    if (!alt_possible(relay) || !bye_altaddr_get(relay->name, found, BYE_ALT_ADDRS_MAX, &count)) return 0;
    if (!relay->seen_count) seen_add(relay, relay->dest);
    for (size_t i = 0; i < count; ++i) {
        if (seen_has(relay, found[i])) continue;
        memcpy(relay->dest, found[i], 4);
        seen_add(relay, found[i]);
        ++relay->alt_used;
        return 1;
    }
    return 0;
}

/* retries the collected hello on a fresh destination socket, so the app's
   tcp connection survives a failed strategy or address */
static int redial(bye_tcp_t *tcp, relay_t *relay) {
    close_fd(relay);
    free(relay->pending);
    relay->pending = NULL;
    relay->pending_off = relay->pending_len = 0;
    relay->hold_off = relay->hold_len = 0;
    relay->first_done = 0;
    relay->first_since_ms = 0;
    relay->blocked = 0;
    relay->probe_replay = 1;
    relay->probe_due_ms = 0;
    char error[160];
    int family = relay->dest_len == 4 ? AF_INET : AF_INET6;
    if (dial(tcp, relay, family, relay->dest, relay->dest_port, 1, error, sizeof error) != 0) {
        abort_flow(tcp, relay, error);
        return 1;
    }
    relay->state = R_CONNECTING;
    relay->deadline_ms = senko_now_ms() + CONNECT_MS;
    return 1;
}

/* a probe needs the complete hello; a truncated record cannot complete a handshake */
static void capture_flow(bye_tcp_t *tcp, const relay_t *relay) {
    if (!relay->name[0] || relay->dest_len != 4 || relay->replay_len < 5 ||
        relay->replay_len > BYE_TCP_CAPTURE_MAX || relay->replay[0] != 0x16 ||
        strlen(relay->name) >= sizeof tcp->stats.capture.name)
        return;
    size_t record = 5u + (((size_t)relay->replay[3] << 8) | relay->replay[4]);
    if (relay->replay_len < record) return;
    tcp->stats.capture.hello_len = 0;
    memcpy(tcp->stats.capture.name, relay->name, strlen(relay->name) + 1);
    memcpy(tcp->stats.capture.addr, relay->dest, 4);
    tcp->stats.capture.port = relay->dest_port;
    memcpy(tcp->stats.capture.hello, relay->replay, relay->replay_len);
    tcp->stats.capture.hello_len = relay->replay_len;
}

static int probe_retry(bye_tcp_t *tcp, relay_t *relay, uint32_t kind, const char *why) {
    if (!relay->probing) return 0;
    capture_flow(tcp, relay);
    /* the lookup runs while the strategies are tried, so the addresses are ready by the time
       the last one has failed */
    if (alt_possible(relay)) bye_altaddr_request(relay->name);
    relay->probing = 0;
    unsigned count = strategy_count(tcp);
    size_t step = bye_strategies_after(&tcp->config.strategies, relay->strategy_start,
                                       relay->attempt, kind);
    if (step == 0) {
        /* a filter may block only some of a site's addresses, so try another after all strategies fail */
        if (alt_next(relay)) {
            ++tcp->stats.addr_retried;
            trace(tcp, relay, "no answer, next address", why);
            choose_strategy(tcp, relay);
            return redial(tcp, relay);
        }
        /* the address a flow was sent to on an earlier success is not trusted any more */
        redirect_t *entry = redirect_find(tcp, relay->name, senko_now_ms());
        if (entry) entry->expires_ms = 0;
        learned_store(tcp, relay, AUTO_EXHAUSTED, AUTO_EXHAUSTED_MS);
        ++tcp->stats.auto_exhausted;
        replay_drop(relay);
        return 0;
    }
    relay->attempt = (unsigned)step;
    relay->strategy = (relay->strategy_start + relay->attempt) % count;
    ++tcp->stats.auto_retried;
    trace(tcp, relay, "no answer, next strategy", why);
    return redial(tcp, relay);
}

/* the destination answered the first bytes: the copy is not needed, and the
   strategy that got through is kept for the next flow to this address */
static void probe_success(bye_tcp_t *tcp, relay_t *relay) {
    relay->probing = 0;
    relay->probe_due_ms = 0;
    replay_drop(relay);
    relay->probe_done = 1;
    if (relay->alt_used > 0) redirect_store(tcp, relay);
    if (relay->strategy == 0) {
        learned_t *entry = learned_find(tcp, relay, senko_now_ms());
        if (entry) entry->expires_ms = 0;
        site_hint_t *hint = hint_find(tcp, relay, senko_now_ms());
        if (hint) hint->expires_ms = 0;
        return;
    }
    hint_store(tcp, relay, relay->strategy);
    learned_t *entry = learned_find(tcp, relay, senko_now_ms());
    if (!entry || entry->index != relay->strategy) ++tcp->stats.auto_learned;
    learned_store(tcp, relay, relay->strategy, AUTO_LEARNED_MS);
}

/* the first payload of a desync flow. 0 when done, 1 to wait for more bytes,
   -1 once the flow was torn down */
static int first_payload(bye_tcp_t *tcp, relay_t *relay) {
    bye_plan_t plan;
    bye_desync_status_t built;
    const size_t limit = FIRST_MAX - BYE_DESYNC_GROWTH_MAX;
    for (;;) {
        size_t len = 0;
        int eof = 0;
        if (!relay->probe_replay) {
            const uint8_t *data;
            if (tun_stack_flow_peek(tcp->stack, relay->flow_id, &data, &len, &eof) != TUN_STACK_OK)
                return 1;
            size_t room = limit - relay->replay_len;
            size_t take = len < room ? len : room;
            if (take) {
                /* peek exposes one pbuf, not the whole hello. consume the copy so a
                   hello larger than the app's tcp window can finish arriving */
                if (replay_append(relay, data, take) != 0) {
                    abort_flow(tcp, relay, "not enough memory to collect the first bytes");
                    return -1;
                }
                if (tun_stack_flow_consume(tcp->stack, relay->flow_id, take) != TUN_STACK_OK) {
                    abort_flow(tcp, relay, "the ip stack refused the first bytes");
                    return -1;
                }
                tcp->stats.bytes_up += take;
                relay->up += take;
            }
        }
        if (relay->replay_len == 0) {
            if (eof) relay->first_done = 1;
            return relay->first_done ? 0 : 1;
        }
        built = bye_desync_build(strategy_at(tcp, relay->strategy), relay->replay,
                                 relay->replay_len, tcp->scratch, sizeof tcp->scratch, &plan);
        /* sni may precede the end of a hello. keep the whole record before a reset
           can trigger a retry, or the retry would send a truncated handshake */
        if (built == BYE_DESYNC_OK && plan.tls &&
            relay->replay_len < 5u + (((size_t)relay->replay[3] << 8) | relay->replay[4]))
            built = BYE_DESYNC_NEED_MORE;
        if (built != BYE_DESYNC_NEED_MORE) break;
        int64_t now = senko_now_ms();
        if (!relay->first_since_ms) relay->first_since_ms = now;
        if (!eof && relay->replay_len < limit && now - relay->first_since_ms < FIRST_WAIT_MS) {
            if (len) continue;
            return 1;
        }
        /* an incomplete prefix leaves unchanged once its time or size budget ends */
        memcpy(tcp->scratch, relay->replay, relay->replay_len);
        memset(&plan, 0, sizeof plan);
        plan.count = 1;
        plan.total = plan.ops[0].len = relay->replay_len;
        relay->no_probe = 1;
        built = BYE_DESYNC_OK;
        break;
    }
    if (built != BYE_DESYNC_OK) {
        abort_flow(tcp, relay, "the first bytes could not be planned");
        return -1;
    }
    if (plan.has_name && !relay->name[0] && plan.name_len < sizeof relay->name) {
        memcpy(relay->name, relay->replay + plan.name_off, plan.name_len);
        relay->name[plan.name_len] = '\0';
    }
    /* the site cache needs the name before it can choose a strategy */
    if (!relay->strategy_set) {
        choose_strategy(tcp, relay);
        if (!relay->no_probe && relay->strategy && bye_desync_build(strategy_at(tcp, relay->strategy),
                relay->replay, relay->replay_len, tcp->scratch, sizeof tcp->scratch, &plan) != BYE_DESYNC_OK) {
            abort_flow(tcp, relay, "the cached strategy could not be planned");
            return -1;
        }
    }
    if (host_skipped(tcp, relay->replay, &plan)) {
        static const bye_desync_t none;
        if (bye_desync_build(&none, relay->replay, relay->replay_len,
                             tcp->scratch, sizeof tcp->scratch, &plan) != BYE_DESYNC_OK) {
            abort_flow(tcp, relay, "the untouched first bytes could not be planned");
            return -1;
        }
        relay->no_probe = 1;
        if (relay->attempt == 0) ++tcp->stats.hosts_skipped;
    }
    if (!relay->probe_replay && !relay->no_probe && relay->alt_used == 0 && plan.tls && alt_possible(relay)) {
        redirect_t *entry = redirect_find(tcp, relay->name, senko_now_ms());
        if (entry && memcmp(entry->addr, relay->dest, 4) != 0) {
            seen_add(relay, relay->dest);
            memcpy(relay->dest, entry->addr, 4);
            seen_add(relay, relay->dest);
            ++relay->alt_used;
            trace(tcp, relay, "to the address that answered before", NULL);
            choose_strategy(tcp, relay);
            (void)redial(tcp, relay);
            return 1;
        }
    }
    if (relay->attempt == 0) {
        if (plan.applied) ++tcp->stats.desync_applied;
        else ++tcp->stats.desync_passed;
    }
    relay->first_done = 1;
    relay->probe_replay = 0;
    if (strategy_count(tcp) > 1 && !relay->no_probe && plan.has_name && plan.tls) {
        relay->probing = 1;
        /* the final strategy still waits when another address can be tried */
        relay->probe_due_ms = bye_strategies_after(&tcp->config.strategies, relay->strategy_start,
                                                   relay->attempt, BYE_TRIGGER_TORST) || alt_possible(relay)
            ? senko_now_ms() + (tcp->config.strategies.timeout_ms ? tcp->config.strategies.timeout_ms
                                : tcp->config.auto_wait_ms ? tcp->config.auto_wait_ms : AUTO_WAIT_MS)
            : 0;
    } else {
        replay_drop(relay);
    }
    return send_plan(tcp, relay, strategy_at(tcp, relay->strategy), &plan) != 0 ? -1 : 0;
}

static int app_to_server(bye_tcp_t *tcp, relay_t *relay) {
    relay->blocked = 0;
    int pending = flush_pending(tcp, relay);
    if (pending < 0) return -1;
    if (pending > 0) return 0;
    for (;;) {
        if (relay->path == BYE_PATH_DESYNC && !relay->first_done) {
            int first = first_payload(tcp, relay);
            if (first < 0) return -1;
            if (first > 0) return 0;
            if (relay->pending) return 0;
            continue;
        }
        const uint8_t *data;
        size_t len;
        int eof;
        if (tun_stack_flow_peek(tcp->stack, relay->flow_id, &data, &len, &eof) != TUN_STACK_OK)
            return 0;
        if (len == 0) {
            if (eof && !relay->server_write_shut) {
                relay->app_eof = 1;
                shutdown(relay->fd, SHUT_WR);
                relay->server_write_shut = 1;
            }
            return 0;
        }
        ssize_t sent = send(relay->fd, data, len, 0);
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            relay->blocked = 1;
            return 0;
        }
        if (sent <= 0) {
            abort_errno(tcp, relay, "the destination refused the app's bytes", errno);
            return -1;
        }
        if (relay->probing) probe_keep(relay, data, (size_t)sent);
        tun_stack_flow_consume(tcp->stack, relay->flow_id, (size_t)sent);
        tcp->stats.bytes_up += (uint64_t)sent;
        relay->up += (uint64_t)sent;
    }
}

static void server_to_app(bye_tcp_t *tcp, relay_t *relay) {
    for (;;) {
        int held = flush_hold(tcp, relay);
        if (held < 0) {
            abort_flow(tcp, relay, "the ip stack refused bytes for the app");
            return;
        }
        if (held > 0 || relay->app_fin_sent) return;
        size_t room = tun_stack_flow_writable(tcp->stack, relay->flow_id);
        if (room == 0) return;
        if (room > sizeof relay->hold) room = sizeof relay->hold;
        ssize_t got = recv(relay->fd, relay->hold, room, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (got < 0) {
            abort_errno(tcp, relay, "the destination connection failed", errno);
            return;
        }
        if (got == 0) {
            if (probe_retry(tcp, relay, BYE_TRIGGER_TORST, "the destination closed without an answer")) return;
            relay->app_fin_sent = 1;
            (void)tun_stack_flow_shutdown(tcp->stack, relay->flow_id);
            if (relay->app_eof) finish_flow(tcp, relay);
            return;
        }
        if (relay->probing) {
            /* a non-handshake response can trigger another strategy; the final attempt must forward it */
            if (relay->hold[0] != 0x16 &&
                bye_strategies_after(&tcp->config.strategies, relay->strategy_start,
                                     relay->attempt, BYE_TRIGGER_TLSERR) &&
                probe_retry(tcp, relay, BYE_TRIGGER_TLSERR,
                            "the destination answered a hello with something else"))
                return;
            probe_success(tcp, relay);
        }
        relay->hold_len = (size_t)got;
        relay->hold_off = 0;
    }
}

static void direct_service(bye_tcp_t *tcp, relay_t *relay) {
    if (app_to_server(tcp, relay) != 0) return;
    /* the first payload may have sent the flow to another address, which connects first */
    if (relay->state != R_RUNNING) return;
    /* the destination may have finished first; the app's fin ends it then */
    if (relay->app_eof && relay->app_fin_sent && relay->hold_len == 0) {
        finish_flow(tcp, relay);
        return;
    }
    server_to_app(tcp, relay);
    /* the answer released the first bytes, and the app may have sent more */
    if (relay->state == R_RUNNING && relay->probe_done) {
        relay->probe_done = 0;
        (void)app_to_server(tcp, relay);
    }
}


/* one slot for each datacenter and kind; datacenter 203 shares slot 6 */
static size_t fail_slot(int dc, int is_media) {
    size_t base = dc == BYE_TG_DC_CDN ? 6 : (size_t)dc;
    return base * 2 + (is_media ? 1 : 0);
}

static size_t tg_gateways(const bye_tcp_t *tcp, const relay_t *relay,
                          bye_tg_gateway_t *out, size_t cap) {
    size_t count = bye_tg_gateways(relay->route.dc, relay->route.is_media,
        tcp->config.gateway_set ? NULL : &tcp->config.ws_addresses, out, cap);
    if (tcp->config.gateway_set)
        for (size_t i = 0; i < count; ++i) memcpy(out[i].address, tcp->config.gateway, 4);
    return count;
}

static unsigned tg_variants(const bye_tcp_t *tcp, const relay_t *relay) {
    bye_tg_gateway_t gateways[BYE_TG_GATEWAYS_MAX];
    return (unsigned)tg_gateways(tcp, relay, gateways, BYE_TG_GATEWAYS_MAX) + (unsigned)tcp->config.relay_count;
}

/* the relay this attempt uses, or -1 once the attempts pass to the datacenter */
static int tg_relay_index(const bye_tcp_t *tcp, const relay_t *relay) {
    size_t count = tcp->config.relay_count;
    if (relay->variant >= count) return -1;
    return (int)((tcp->relay_first + relay->variant) % count);
}

static void tg_connect(bye_tcp_t *tcp, relay_t *relay);
static void tg_unreachable(bye_tcp_t *tcp, relay_t *relay, const char *why);

static int pool_adopt(bye_tcp_t *tcp, relay_t *relay);

/* a pool connection is closed. failed holds the next try off for a while */
static void pool_release(bye_tcp_t *tcp, relay_t *entry, int failed) {
    size_t slot = fail_slot(entry->route.dc, entry->route.is_media);
    if (failed) tcp->pool_retry_ms[slot] = senko_now_ms() + POOL_RETRY_MS;
    if (entry->state == R_TG_POOLED && tcp->stats.pool_ready) --tcp->stats.pool_ready;
    release(tcp, entry);
}

/* the gateway cannot be used: the flow goes to the datacenter as it is. the
   app's bytes were not consumed, so they are sent unchanged */
static void tg_fallback(bye_tcp_t *tcp, relay_t *relay, const char *why) {
    /* a pool connection has no app waiting: it is just dropped */
    if (relay->pooled) {
        pool_release(tcp, relay, 1);
        return;
    }
    set_error(tcp, why);
    if (tcp->config.trace) trace(tcp, relay, "telegram gateway unusable", why);
    ++tcp->stats.telegram_fallback;
    if (relay->ws) bye_wsconn_free(relay->ws);
    relay->ws = NULL;
    if (relay->mtp) bye_mtp_close(relay->mtp);
    relay->mtp = NULL;
    memset(relay->relay_init, 0, sizeof relay->relay_init);
    close_fd(relay);
    if (relay->counted_tg && tcp->tg_active) --tcp->tg_active;
    relay->counted_tg = 0;
    /* a tls hello or a request to a telegram address (the web client, an
       unobfuscated app) gets the same cut as any other web flow */
    relay->path = relay->dest_port == 443 || relay->dest_port == 80
        ? BYE_PATH_DESYNC : BYE_PATH_DIRECT;
    char error[160];
    int family = relay->dest_len == 4 ? AF_INET : AF_INET6;
    if (dial(tcp, relay, family, relay->dest, relay->dest_port, 1, error, sizeof error) != 0) {
        abort_flow(tcp, relay, error);
        return;
    }
    relay->state = R_CONNECTING;
    relay->deadline_ms = senko_now_ms() + CONNECT_MS;
}

/* the datacenter's gateway failed: skip it for a while and go direct */
static void tg_giveup(bye_tcp_t *tcp, relay_t *relay, const char *why) {
    size_t slot = fail_slot(relay->route.dc, relay->route.is_media);
    int64_t now = senko_now_ms();
    /* flows that were already dialing when the first one failed end here
       too: only the first one logs and starts the cooldown */
    if (tcp->tg_fail_until[slot] <= now) {
        fprintf(stderr, "byedpid: telegram dc%d gateway unusable for %d s: %s%s\n",
                relay->route.dc, TG_FAIL_MS / 1000, why,
                tcp->config.relay_count ? "" : " (no relay is set)");
        tcp->tg_fail_until[slot] = now + TG_FAIL_MS;
    }
    tg_fallback(tcp, relay, why);
}

/* the tls or websocket step failed: the other host of the datacenter may
   answer, and after that the gateway is given up */
static void tg_try_next(bye_tcp_t *tcp, relay_t *relay, const char *why) {
    fprintf(stderr, "byedpid: telegram gateway step %u failed: %s\n", relay->variant, why);
    if (relay->ws) bye_wsconn_free(relay->ws);
    relay->ws = NULL;
    close_fd(relay);
    if (++relay->variant < tg_variants(tcp, relay)) {
        tg_connect(tcp, relay);
        return;
    }
    tg_giveup(tcp, relay, why);
}

/* a tcp timeout cannot be cured by another host name on the same address */
static void tg_unreachable(bye_tcp_t *tcp, relay_t *relay, const char *why) {
    close_fd(relay);
    int index = tg_relay_index(tcp, relay);
    if (index >= 0) {
        fprintf(stderr, "byedpid: telegram relay %s unreachable: %s\n",
                tcp->config.relay[index], why);
        ++relay->variant;
        tg_connect(tcp, relay);
        return;
    }
    bye_tg_gateway_t gateways[BYE_TG_GATEWAYS_MAX];
    size_t count = tg_gateways(tcp, relay, gateways, BYE_TG_GATEWAYS_MAX);
    size_t next = bye_tg_gateway_next(gateways, count,
        relay->variant - tcp->config.relay_count, 1);
    if (next < count) {
        fprintf(stderr, "byedpid: telegram dc%d address unreachable: %s, trying another address\n",
                relay->route.dc, why);
        relay->variant = (unsigned)(tcp->config.relay_count + next);
        tg_connect(tcp, relay);
        return;
    }
    tg_giveup(tcp, relay, why);
}

/* the name the certificate must match and the host header carry */
static int tg_host(const bye_tcp_t *tcp, const relay_t *relay, char *host, size_t cap) {
    int index = tg_relay_index(tcp, relay);
    if (index >= 0) {
        int gateway = relay->route.dc == BYE_TG_DC_CDN ? 2 : relay->route.dc;
        int n = snprintf(host, cap, "kws%d.%s", gateway, tcp->config.relay[index]);
        return n > 0 && (size_t)n < cap ? 0 : -1;
    }
    bye_tg_gateway_t gateways[BYE_TG_GATEWAYS_MAX];
    size_t count = tg_gateways(tcp, relay, gateways, BYE_TG_GATEWAYS_MAX);
    size_t variant = relay->variant - tcp->config.relay_count;
    if (variant >= count) return -1;
    int n = snprintf(host, cap, "%s", gateways[variant].host);
    return n > 0 && (size_t)n < cap ? 0 : -1;
}

static void tg_connect(bye_tcp_t *tcp, relay_t *relay) {
    uint8_t address[4];
    uint16_t port = 443;
    char why[160];
    int index = tg_relay_index(tcp, relay);
    if (index >= 0) {
        memcpy(address, tcp->config.relay_addr[index], 4);
        if (tcp->config.gateway_set && tcp->config.gateway_port) port = tcp->config.gateway_port;
    } else {
        bye_tg_gateway_t gateways[BYE_TG_GATEWAYS_MAX];
        size_t count = tg_gateways(tcp, relay, gateways, BYE_TG_GATEWAYS_MAX);
        size_t variant = relay->variant - tcp->config.relay_count;
        if (variant >= count) {
            tg_fallback(tcp, relay, "no gateway address for the datacenter");
            return;
        }
        memcpy(address, gateways[variant].address, 4);
        if (tcp->config.gateway_port) port = tcp->config.gateway_port;
    }
    char host[BYE_TG_WS_HOST_MAX + BYE_TCP_RELAY_NAME_MAX], text[INET_ADDRSTRLEN];
    if (tg_host(tcp, relay, host, sizeof host) == 0 &&
        inet_ntop(AF_INET, address, text, sizeof text))
        trace(tcp, relay, host, text);
    if (dial(tcp, relay, AF_INET, address, port, 1, why, sizeof why) != 0) {
        tg_unreachable(tcp, relay, why);
        return;
    }
    relay->state = R_TG_CONNECT;
    relay->deadline_ms = senko_now_ms() + CONNECT_MS;
}

static void tg_init(bye_tcp_t *tcp, relay_t *relay) {
    const uint8_t *data;
    size_t len;
    int eof;
    if (tun_stack_flow_peek(tcp->stack, relay->flow_id, &data, &len, &eof) != TUN_STACK_OK)
        return;
    if (len < BYE_MTP_INIT_LEN) {
        /* the client closed before it said anything */
        if (eof && len == 0) finish_flow(tcp, relay);
        else if (eof) tg_fallback(tcp, relay, "the client closed inside its init");
        return;
    }
    bye_mtp_status_t opened = bye_mtp_open(&relay->mtp, NULL, 0, data, &relay->route,
                                           relay->relay_init);
    if (opened != BYE_MTP_OK) {
        /* a client that does not use the obfuscated transport, or the http one */
        tg_fallback(tcp, relay, opened == BYE_MTP_ERR_HTTP ? "http transport"
                                                           : "not an obfuscated mtproto stream");
        return;
    }
    if (!bye_tg_dc_known(relay->route.dc)) {
        tg_fallback(tcp, relay, "unknown datacenter");
        return;
    }
    if (tcp->tg_fail_until[fail_slot(relay->route.dc, relay->route.is_media)] > senko_now_ms()) {
        tg_fallback(tcp, relay, "the gateway failed a moment ago");
        return;
    }
    size_t slot = fail_slot(relay->route.dc, relay->route.is_media);
    tcp->pool_use_ms[slot] = senko_now_ms();
    if (tcp->config.pool) {
        if (pool_adopt(tcp, relay)) return;
        ++tcp->stats.pool_misses;
    }
    relay->variant = 0;
    tg_connect(tcp, relay);
}

static void tg_drive_handshake(bye_tcp_t *tcp, relay_t *relay);

static void tg_connected(bye_tcp_t *tcp, relay_t *relay) {
    char host[BYE_TG_WS_HOST_MAX];
    if (tg_host(tcp, relay, host, sizeof host) != 0) {
        tg_try_next(tcp, relay, "no gateway host for the datacenter");
        return;
    }
    relay->ws = bye_wsconn_new(tcp->config.tls, relay->fd, host, BYE_TG_WS_PATH);
    if (!relay->ws) {
        tg_try_next(tcp, relay, "cannot start the tls session");
        return;
    }
    relay->state = R_TG_HANDSHAKE;
    relay->deadline_ms = senko_now_ms() + HANDSHAKE_MS;
    tg_drive_handshake(tcp, relay);
}

static int tg_emit(void *ctx, const uint8_t *msg, size_t len) {
    relay_t *relay = ctx;
    return bye_wsconn_send(relay->ws, msg, len);
}

static void tg_service(bye_tcp_t *tcp, relay_t *relay);

/* the gateway carries websocket frames: the datacenter gets its init, and the
   flow runs */
static void tg_established(bye_tcp_t *tcp, relay_t *relay) {
    /* the datacenter expects its own init first, in a message of its own */
    if (bye_wsconn_send(relay->ws, relay->relay_init, sizeof relay->relay_init) != 0) {
        tg_try_next(tcp, relay, "cannot queue the datacenter init");
        return;
    }
    memset(relay->relay_init, 0, sizeof relay->relay_init);
    tun_stack_flow_consume(tcp->stack, relay->flow_id, BYE_MTP_INIT_LEN);
    tcp->stats.bytes_up += BYE_MTP_INIT_LEN;
    relay->up += BYE_MTP_INIT_LEN;
    int used = tg_relay_index(tcp, relay);
    if (used >= 0) tcp->relay_first = (size_t)used;
    relay->state = R_TG_RUNNING;
    relay->deadline_ms = 0;
    relay->last_rx_ms = senko_now_ms();
    ++tcp->stats.telegram_ws;
    trace(tcp, relay, "gateway open", NULL);
    tg_service(tcp, relay);
}

static void tg_drive_handshake(bye_tcp_t *tcp, relay_t *relay) {
    bye_wsconn_status_t status = bye_wsconn_handshake(relay->ws);
    if (status == BYE_WSCONN_WANT_READ || status == BYE_WSCONN_WANT_WRITE) {
        relay->ws_wait_write = status == BYE_WSCONN_WANT_WRITE;
        return;
    }
    if (status != BYE_WSCONN_OK) {
        char why[BYE_WSCONN_ERROR_MAX + 32];
        snprintf(why, sizeof why, "%s", status == BYE_WSCONN_ERR ? bye_wsconn_error(relay->ws)
                                                                  : "the gateway closed");
        tg_try_next(tcp, relay, why);
        return;
    }
    if (relay->pooled) {
        /* nothing is sent yet: the init belongs to the flow that takes it */
        relay->state = R_TG_POOLED;
        relay->deadline_ms = 0;
        relay->ws_wait_write = 0;
        relay->pool_since_ms = relay->last_rx_ms = senko_now_ms();
        relay->ping_sent = 0;
        ++tcp->stats.pool_ready;
        return;
    }
    tg_established(tcp, relay);
}

/* a connection that is still open at the other end: a closed or reset socket
   shows as end of file or an error, an idle one as nothing to read */
static int pool_alive(const relay_t *entry) {
    char byte;
    ssize_t got;
    do {
        got = recv(entry->fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
    } while (got < 0 && errno == EINTR);
    if (got == 0) return 0;
    return got > 0 || errno == EAGAIN || errno == EWOULDBLOCK;
}

/* gives a flow the ready connection of its datacenter, if there is one */
static int pool_adopt(bye_tcp_t *tcp, relay_t *relay) {
    int64_t now = senko_now_ms();
    for (size_t i = 0; i < BYE_TCP_POOL_MAX; ++i) {
        relay_t *entry = &tcp->pool[i];
        if (entry->state != R_TG_POOLED || entry->route.dc != relay->route.dc ||
            entry->route.is_media != relay->route.is_media)
            continue;
        if (now - entry->pool_since_ms >= POOL_MAX_AGE_MS || !pool_alive(entry)) {
            pool_release(tcp, entry, 0);
            continue;
        }
        relay->fd = entry->fd;
        relay->ws = entry->ws;
        relay->variant = entry->variant;
        entry->fd = -1;
        entry->ws = NULL;
        pool_release(tcp, entry, 0);
        ++tcp->stats.pool_hits;
        relay->state = R_TG_HANDSHAKE;
        tg_established(tcp, relay);
        return 1;
    }
    return 0;
}

static void pool_service(bye_tcp_t *tcp, relay_t *entry, const fd_set *readable, int64_t now) {
    if (now - entry->pool_since_ms >= POOL_MAX_AGE_MS) {
        pool_release(tcp, entry, 0);
        return;
    }
    if (FD_ISSET(entry->fd, readable) || bye_wsconn_buffered(entry->ws)) {
        uint8_t sink[64];
        size_t got = 0;
        bye_wsconn_status_t status = bye_wsconn_read(entry->ws, sink, sizeof sink, &got);
        /* an idle gateway sends control frames only; anything else, or an end,
           makes the connection useless */
        if (got > 0 || status == BYE_WSCONN_ERR || status == BYE_WSCONN_CLOSED) {
            pool_release(tcp, entry, 0);
            return;
        }
    }
    if (!entry->ping_sent && now - entry->last_rx_ms >= POOL_PING_MS) {
        entry->ping_sent = 1;
        if (bye_wsconn_ping(entry->ws) != 0) {
            pool_release(tcp, entry, 0);
            return;
        }
    }
    if (bye_wsconn_pending(entry->ws) > 0) {
        bye_wsconn_status_t flushed = bye_wsconn_flush(entry->ws);
        if (flushed == BYE_WSCONN_ERR || flushed == BYE_WSCONN_CLOSED) pool_release(tcp, entry, 0);
    }
}

/* one connection per pass is started for a datacenter that lacks its share */
static void pool_maintain(bye_tcp_t *tcp, int64_t now) {
    if (!tcp->config.pool || !tcp->config.tls || now < tcp->pool_check_ms) return;
    tcp->pool_check_ms = now + POOL_CHECK_MS;
    size_t want = tcp->config.pool > 2 ? 2 : tcp->config.pool;
    for (size_t slot = 2; slot < 16; ++slot) {
        if (!tcp->pool_use_ms[slot] || now - tcp->pool_use_ms[slot] >= POOL_IDLE_MS ||
            now < tcp->pool_retry_ms[slot] || tcp->tg_fail_until[slot] > now)
            continue;
        size_t have = 0;
        relay_t *free_entry = NULL;
        for (size_t i = 0; i < BYE_TCP_POOL_MAX; ++i) {
            relay_t *entry = &tcp->pool[i];
            if (entry->state == R_FREE) {
                if (!free_entry) free_entry = entry;
            } else if (fail_slot(entry->route.dc, entry->route.is_media) == slot) {
                ++have;
            }
        }
        if (have >= want || !free_entry) continue;
        memset(free_entry, 0, sizeof *free_entry);
        free_entry->fd = -1;
        free_entry->pooled = 1;
        size_t base = slot / 2;
        free_entry->route.dc = base == 6 ? BYE_TG_DC_CDN : (int)base;
        free_entry->route.is_media = (int)(slot & 1u);
        free_entry->started_ms = now;
        tg_connect(tcp, free_entry);
        return;
    }
}

static void tg_close_ws_side(bye_tcp_t *tcp, relay_t *relay) {
    if (relay->app_fin_sent) return;
    relay->app_fin_sent = 1;
    (void)tun_stack_flow_shutdown(tcp->stack, relay->flow_id);
}

/* the app to the gateway. 0 while the flow lives, -1 once it was torn down */
static int tg_up(bye_tcp_t *tcp, relay_t *relay) {
    for (int pass = 0; pass < PASSES; ++pass) {
        bye_wsconn_status_t flushed = bye_wsconn_flush(relay->ws);
        if (flushed == BYE_WSCONN_ERR || flushed == BYE_WSCONN_CLOSED) {
            abort_flow(tcp, relay, flushed == BYE_WSCONN_ERR ? bye_wsconn_error(relay->ws)
                                                              : "the gateway closed");
            return -1;
        }
        relay->ws_wait_write = flushed == BYE_WSCONN_WANT_WRITE || flushed == BYE_WSCONN_WANT_READ;
        if (bye_wsconn_pending(relay->ws) > 0) return 0;

        const uint8_t *data;
        size_t len;
        int eof;
        if (tun_stack_flow_peek(tcp->stack, relay->flow_id, &data, &len, &eof) != TUN_STACK_OK)
            return 0;
        if (len == 0) {
            if (eof && !relay->app_eof) {
                relay->app_eof = 1;
                if (bye_mtp_up_flush(relay->mtp, tg_emit, relay) != BYE_MTP_OK) {
                    abort_flow(tcp, relay, "cannot queue the last bytes");
                    return -1;
                }
            }
            return 0;
        }
        size_t take = len < UP_STEP ? len : UP_STEP;
        memcpy(tcp->scratch, data, take);
        bye_mtp_status_t up = bye_mtp_up(relay->mtp, tcp->scratch, take, tg_emit, relay);
        if (up != BYE_MTP_OK) {
            abort_flow(tcp, relay, up == BYE_MTP_ERR_PACKET ? "an mtproto packet is too large"
                                                             : "cannot queue the app's bytes");
            return -1;
        }
        tun_stack_flow_consume(tcp->stack, relay->flow_id, take);
        tcp->stats.bytes_up += take;
        relay->up += take;
        relay->last_rx_ms = senko_now_ms();
    }
    relay->again = 1;
    return 0;
}

/* the gateway to the app. 0 while the flow lives, -1 once it was torn down */
static int tg_down(bye_tcp_t *tcp, relay_t *relay) {
    for (int pass = 0; pass < PASSES; ++pass) {
        int held = flush_hold(tcp, relay);
        if (held < 0) {
            abort_flow(tcp, relay, "the ip stack refused bytes for the app");
            return -1;
        }
        if (held > 0 || relay->app_fin_sent) return 0;
        size_t room = tun_stack_flow_writable(tcp->stack, relay->flow_id);
        if (room == 0) return 0;
        if (room > sizeof relay->hold) room = sizeof relay->hold;
        size_t got = 0;
        bye_wsconn_status_t status = bye_wsconn_read(relay->ws, relay->hold, room, &got);
        if (got > 0) {
            if (bye_mtp_down(relay->mtp, relay->hold, got) != BYE_MTP_OK) {
                abort_flow(tcp, relay, "cannot decrypt the gateway's bytes");
                return -1;
            }
            relay->hold_len = got;
            relay->hold_off = 0;
            relay->last_rx_ms = senko_now_ms();
            relay->ping_sent = 0;
            continue;
        }
        if (status == BYE_WSCONN_ERR) {
            abort_flow(tcp, relay, bye_wsconn_error(relay->ws));
            return -1;
        }
        if (status == BYE_WSCONN_CLOSED) {
            tg_close_ws_side(tcp, relay);
            return 0;
        }
        return 0;
    }
    relay->again = 1;
    return 0;
}

static void tg_service(bye_tcp_t *tcp, relay_t *relay) {
    relay->again = 0;
    if (tg_up(tcp, relay) != 0) return;
    if (tg_down(tcp, relay) != 0) return;
    /* a pong queued by the read has to leave without waiting for the app */
    if (bye_wsconn_pending(relay->ws) > 0) {
        bye_wsconn_status_t flushed = bye_wsconn_flush(relay->ws);
        if (flushed == BYE_WSCONN_ERR) {
            abort_flow(tcp, relay, bye_wsconn_error(relay->ws));
            return;
        }
        relay->ws_wait_write = flushed != BYE_WSCONN_OK;
    }
    /* telegram ends both directions together */
    if (relay->app_fin_sent && relay->hold_len == 0 && bye_wsconn_pending(relay->ws) == 0) {
        finish_flow(tcp, relay);
        return;
    }
    if (relay->app_eof && bye_wsconn_pending(relay->ws) == 0) finish_flow(tcp, relay);
}

static void tg_timers(bye_tcp_t *tcp, relay_t *relay, int64_t now) {
    if (now - relay->last_rx_ms >= TG_IDLE_MS) {
        abort_flow(tcp, relay, "the gateway was silent for too long");
        return;
    }
    if (!relay->ping_sent && now - relay->last_rx_ms >= TG_PING_MS) {
        relay->ping_sent = 1;
        if (bye_wsconn_ping(relay->ws) != 0) {
            abort_flow(tcp, relay, "cannot queue a ping");
            return;
        }
        tg_service(tcp, relay);
    }
}


static size_t active_relays(const bye_tcp_t *tcp) {
    size_t active = 0;
    for (size_t i = 0; i < TUN_NAT_TCP_MAX; ++i)
        if (tcp->relays[i].state != R_FREE) ++active;
    return active;
}

static void start_flow(bye_tcp_t *tcp, relay_t *relay) {
    if (relay->path == BYE_PATH_TELEGRAM &&
        (!tcp->config.tls || tcp->tg_active >= BYE_TCP_TELEGRAM_MAX))
        relay->path = BYE_PATH_DIRECT;
    if (relay->path == BYE_PATH_TELEGRAM) {
        relay->state = R_TG_INIT;
        relay->counted_tg = 1;
        ++tcp->tg_active;
        relay->deadline_ms = senko_now_ms() + TG_INIT_MS;
        relay->accepted = 1;
        if (tun_stack_flow_accept(tcp->stack, relay->flow_id) != TUN_STACK_OK)
            release(tcp, relay);
        return;
    }
    ++tcp->stats.direct;
    start_direct(tcp, relay);
}

static void on_flow(void *ctx, tun_stack_flow_event_t event, uint64_t flow_id,
                    const tun_flow_key_t *key) {
    bye_tcp_t *tcp = ctx;
    relay_t *relay = relay_for(tcp, flow_id);
    if (!relay) return;

    switch (event) {
    case TUN_STACK_FLOW_REQUESTED: {
        ++tcp->stats.requested;
        if (relay->state != R_FREE) release(tcp, relay);
        relay->flow_id = flow_id;
        relay->key = *key;
        relay->fd = -1;
        relay->started_ms = senko_now_ms();
        relay->dest_len = key->address_len;
        memcpy(relay->dest, key->destination, key->address_len);
        relay->dest_port = key->destination_port;
        relay->path = tcp->config.classify
            ? tcp->config.classify(tcp->config.classify_ctx, key->destination, key->address_len,
                                   key->destination_port)
            : bye_route_tcp(&tcp->config.policy, key->destination, key->address_len,
                            key->destination_port);
        /* the resolver the user picked answers every dns query over tcp too */
        if (key->destination_port == 53 && tcp->config.dns_set && key->address_len == 4) {
            memcpy(relay->dest, tcp->config.dns, 4);
            relay->path = BYE_PATH_DIRECT;
        }
        size_t limit = tcp->config.max_flows ? tcp->config.max_flows : BYE_TCP_MAX_FLOWS;
        if (active_relays(tcp) >= limit) {
            refuse_flow(tcp, relay, "too many flows are open");
            return;
        }
        start_flow(tcp, relay);
        return;
    }
    case TUN_STACK_FLOW_OPEN:
        if (relay->flow_id != flow_id || relay->state != R_ACCEPTED) return;
        relay->state = R_RUNNING;
        direct_service(tcp, relay);
        return;
    case TUN_STACK_FLOW_READABLE:
    case TUN_STACK_FLOW_WRITABLE:
        if (relay->flow_id != flow_id) return;
        if (relay->state == R_RUNNING) direct_service(tcp, relay);
        else if (relay->state == R_TG_INIT) tg_init(tcp, relay);
        else if (relay->state == R_TG_RUNNING) tg_service(tcp, relay);
        return;
    case TUN_STACK_FLOW_CLOSED:
        if (relay->flow_id == flow_id && relay->state != R_FREE) release(tcp, relay);
        return;
    }
}

static int on_start(void *ctx, tun_stack_t *stack, char *error, size_t error_cap) {
    bye_tcp_t *tcp = ctx;
    (void)error;
    (void)error_cap;
    tcp->stack = stack;
    return 0;
}

static void lower_wait(uint32_t *wait_ms, int64_t now, int64_t due) {
    int64_t left = due - now;
    if (left < 0) left = 0;
    if ((uint64_t)left < *wait_ms) *wait_ms = (uint32_t)left;
}

static void watch(relay_t *relay, fd_set *readable, fd_set *writable, int *highest,
                  int want_read, int want_write) {
    if (relay->fd < 0) return;
    if (want_read) FD_SET(relay->fd, readable);
    if (want_write) FD_SET(relay->fd, writable);
    if (relay->fd > *highest) *highest = relay->fd;
}

static void on_prepare(void *ctx, fd_set *readable, fd_set *writable, int *highest,
                       uint32_t *wait_ms) {
    bye_tcp_t *tcp = ctx;
    int64_t now = senko_now_ms();
    if (tcp->config.pool && tcp->config.tls) lower_wait(wait_ms, now, tcp->pool_check_ms);
    for (size_t i = 0; i < TUN_NAT_TCP_MAX + BYE_TCP_POOL_MAX; ++i) {
        relay_t *relay = i < TUN_NAT_TCP_MAX ? &tcp->relays[i] : &tcp->pool[i - TUN_NAT_TCP_MAX];
        switch (relay->state) {
        case R_FREE:
        case R_ACCEPTED:
            break;
        case R_CONNECTING:
        case R_TG_CONNECT:
            watch(relay, readable, writable, highest, 0, 1);
            lower_wait(wait_ms, now, relay->deadline_ms);
            break;
        case R_RUNNING:
            /* bytes wait in hold for the app's window before more are read */
            watch(relay, readable, writable, highest,
                  relay->hold_len == 0 && !relay->app_fin_sent &&
                      tun_stack_flow_writable(tcp->stack, relay->flow_id) > 0,
                  relay->blocked || relay->pending_len > 0);
            if (relay->path == BYE_PATH_DESYNC && !relay->first_done && relay->first_since_ms)
                lower_wait(wait_ms, now, relay->first_since_ms + FIRST_WAIT_MS);
            if (relay->probing && relay->probe_due_ms)
                lower_wait(wait_ms, now, relay->probe_due_ms);
            break;
        case R_TG_INIT:
            lower_wait(wait_ms, now, relay->deadline_ms);
            break;
        case R_TG_HANDSHAKE:
            watch(relay, readable, writable, highest, !relay->ws_wait_write, relay->ws_wait_write);
            lower_wait(wait_ms, now, relay->deadline_ms);
            break;
        case R_TG_POOLED:
            watch(relay, readable, writable, highest, 1, bye_wsconn_pending(relay->ws) > 0);
            if (bye_wsconn_buffered(relay->ws)) *wait_ms = 0;
            lower_wait(wait_ms, now, relay->pool_since_ms + POOL_MAX_AGE_MS);
            if (!relay->ping_sent) lower_wait(wait_ms, now, relay->last_rx_ms + POOL_PING_MS);
            break;
        case R_TG_RUNNING:
            watch(relay, readable, writable, highest,
                  relay->hold_len == 0 && !relay->app_fin_sent,
                  relay->ws_wait_write || bye_wsconn_pending(relay->ws) > 0);
            /* decrypted bytes the tls layer holds do not wake the socket */
            if (relay->again || (relay->hold_len == 0 && bye_wsconn_buffered(relay->ws)))
                *wait_ms = 0;
            lower_wait(wait_ms, now,
                       relay->last_rx_ms + (relay->ping_sent ? TG_IDLE_MS : TG_PING_MS));
            break;
        }
    }
}

static void dispatch_connecting(bye_tcp_t *tcp, relay_t *relay, const fd_set *writable, int64_t now) {
    if (!FD_ISSET(relay->fd, writable)) {
        if (now >= relay->deadline_ms) {
            if (relay->accepted) abort_flow(tcp, relay, "the destination did not answer in time");
            else refuse_flow(tcp, relay, "the destination did not answer in time");
        }
        return;
    }
    int error = 0;
    if (connect_result(relay, &error) < 0) {
        char why[128];
        snprintf(why, sizeof why, "the destination refused the connection");
        route_errno_append(why, sizeof why, error);
        if (relay->accepted) abort_flow(tcp, relay, why);
        else refuse_flow(tcp, relay, why);
        return;
    }
    if (relay->accepted) {
        /* a gateway fallback: the app is already waiting */
        relay->state = R_RUNNING;
        direct_service(tcp, relay);
        return;
    }
    relay->state = R_ACCEPTED;
    relay->accepted = 1;
    if (tun_stack_flow_accept(tcp->stack, relay->flow_id) != TUN_STACK_OK) release(tcp, relay);
}

static void on_dispatch(void *ctx, const fd_set *readable, const fd_set *writable) {
    bye_tcp_t *tcp = ctx;
    int64_t now = senko_now_ms();
    pool_maintain(tcp, now);
    for (size_t i = 0; i < TUN_NAT_TCP_MAX + BYE_TCP_POOL_MAX; ++i) {
        relay_t *relay = i < TUN_NAT_TCP_MAX ? &tcp->relays[i] : &tcp->pool[i - TUN_NAT_TCP_MAX];
        switch (relay->state) {
        case R_FREE:
        case R_ACCEPTED:
            break;
        case R_CONNECTING:
            dispatch_connecting(tcp, relay, writable, now);
            break;
        case R_RUNNING:
            if (relay->probing && relay->probe_due_ms && now >= relay->probe_due_ms &&
                !FD_ISSET(relay->fd, readable)) {
                if (probe_retry(tcp, relay, BYE_TRIGGER_TORST, "the destination did not answer in time")) break;
            }
            /* another flow's ack can free a shared segment for bytes parked in hold */
            if (FD_ISSET(relay->fd, readable) || FD_ISSET(relay->fd, writable) ||
                (relay->hold_len > 0 && tun_stack_flow_writable(tcp->stack, relay->flow_id) > 0) ||
                (relay->path == BYE_PATH_DESYNC && !relay->first_done && relay->first_since_ms))
                direct_service(tcp, relay);
            break;
        case R_TG_INIT:
            if (now >= relay->deadline_ms) tg_fallback(tcp, relay, "the client sent no init");
            break;
        case R_TG_CONNECT:
            if (FD_ISSET(relay->fd, writable)) {
                int error = 0;
                if (connect_result(relay, &error) < 0) {
                    char why[128];
                    snprintf(why, sizeof why, "the gateway refused the connection");
                    route_errno_append(why, sizeof why, error);
                    tg_unreachable(tcp, relay, why);
                } else {
                    tg_connected(tcp, relay);
                }
            } else if (now >= relay->deadline_ms) {
                tg_unreachable(tcp, relay, "the gateway did not answer in time");
            }
            break;
        case R_TG_HANDSHAKE:
            if (now >= relay->deadline_ms)
                tg_try_next(tcp, relay, "the gateway handshake took too long");
            else if (FD_ISSET(relay->fd, readable) || FD_ISSET(relay->fd, writable))
                tg_drive_handshake(tcp, relay);
            break;
        case R_TG_POOLED:
            pool_service(tcp, relay, readable, now);
            break;
        case R_TG_RUNNING:
            if (FD_ISSET(relay->fd, readable) || FD_ISSET(relay->fd, writable) ||
                relay->again || (relay->hold_len == 0 && bye_wsconn_buffered(relay->ws)))
                tg_service(tcp, relay);
            if (relay->state == R_TG_RUNNING) tg_timers(tcp, relay, now);
            break;
        }
    }
}

static void on_stop(void *ctx) {
    bye_tcp_t *tcp = ctx;
    for (size_t i = 0; i < TUN_NAT_TCP_MAX; ++i)
        if (tcp->relays[i].state != R_FREE) release(tcp, &tcp->relays[i]);
    for (size_t i = 0; i < BYE_TCP_POOL_MAX; ++i)
        if (tcp->pool[i].state != R_FREE) pool_release(tcp, &tcp->pool[i], 0);
}

int bye_tcp_init(bye_tcp_t *tcp, const bye_tcp_config_t *config, tun_loop_config_t *loop_config) {
    if (!tcp || !config || !loop_config || !config->direct_socket) return -1;
    if (config->max_flows > TUN_NAT_TCP_MAX) return -1;
    memset(tcp, 0, sizeof *tcp);
    tcp->config = *config;
    for (size_t i = 0; i < TUN_NAT_TCP_MAX; ++i) tcp->relays[i].fd = -1;
    for (size_t i = 0; i < BYE_TCP_POOL_MAX; ++i) tcp->pool[i].fd = -1;

    loop_config->stack.flow_event = on_flow;
    loop_config->stack.flow_ctx = tcp;
    loop_config->hooks.start = on_start;
    loop_config->hooks.prepare = on_prepare;
    loop_config->hooks.dispatch = on_dispatch;
    loop_config->hooks.stop = on_stop;
    loop_config->hooks.ctx = tcp;
    return 0;
}

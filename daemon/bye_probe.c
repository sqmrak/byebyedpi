#define _DEFAULT_SOURCE
#include "bye_probe.h"

#include "bye_ciadpi.h"

#include "tun/core/senko_time.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define HELLO_MAX 4096

/* the strategies tried after the configured ones, from the mildest cut to the
   plain hello last: a site that rejects any cut answers that one. the options
   of ciadpi carry the disorder, which the spec syntax has no word for: a filter
   that rebuilds the stream by order of arrival is only beaten by it */
static const char *const BUILTIN[] = {
    "tlsrec=name+1;split=1,name+1",
    "tlsrec=name+1",
    "tlsrec=mid;split=1,mid",
    "split=1,name+1",
    "split=1",
    "split=2",
    "split=1,name+1;oob=1",
    "oob=1",
    "-d1",
    "-d3+s",
    "-d1 -d3+s -s6+s -r1+s",
    "none"
};

/* every strategy a flow tries costs it one wait for an answer, so a suggested
   list stays short */
#define SUGGEST_MAX 4

typedef struct {
    char         spec[BYE_PROBE_SPEC_MAX];
    bye_desync_t plan;
    unsigned     tried;
    unsigned     ok;
    uint64_t     ms;
} candidate_t;

struct bye_probe {
    pthread_mutex_t lock;
    pthread_t       thread;
    int             started; /* the thread was created and not joined */
    int             running;
    int             cancel;
    int             stopped; /* the last run was cancelled */
    bye_probe_request_t request;
    candidate_t     candidates[BYE_PROBE_CANDIDATES_MAX];
    size_t          candidate_count;
    size_t          configured_count;
    uint8_t         addrs[BYE_PROBE_NAMES_MAX][4];
    int             resolved[BYE_PROBE_NAMES_MAX];
    char            unresolved[BYE_PROBE_NAMES_MAX][BYE_PROBE_NAME_MAX];
    char            resolve_error[BYE_PROBE_NAMES_MAX][160];
    size_t          unresolved_count;
    unsigned        total;
    unsigned        done;
    /* what each strategy did with the app's own hello [0] and with this library's hello [1]
       at the app's address; 0xff for not tried */
    uint8_t         app_result[2][BYE_PROBE_CANDIDATES_MAX];
    uint32_t        app_ms[2][BYE_PROBE_CANDIDATES_MAX];
    /* the app's hello at an address of the same site that the app did not use, to tell a
       blocked address from a blocked cut; alt_name is empty when there is none */
    char            alt_name[BYE_PROBE_NAME_MAX];
    uint8_t         alt_addr[4];
    uint8_t         alt_result[BYE_PROBE_CANDIDATES_MAX];
    uint32_t        alt_ms[BYE_PROBE_CANDIDATES_MAX];
};

/* 1 when name is the site or a host of the site, as "www.youtube.com" is of "youtube.com" */
static int same_site(const char *host, const char *site) {
    size_t host_len = strlen(host), site_len = strlen(site);
    if (host_len < site_len) return 0;
    if (strcmp(host + host_len - site_len, site) != 0) return 0;
    return host_len == site_len || host[host_len - site_len - 1] == '.';
}

size_t bye_probe_size(void) {
    return sizeof(struct bye_probe);
}

void bye_probe_init(bye_probe_t *probe) {
    memset(probe, 0, sizeof *probe);
    pthread_mutex_init(&probe->lock, NULL);
}


int bye_probe_hello(const char *host, uint8_t *out, size_t cap, size_t *len) {
    if (len) *len = 0;
    if (!host || !host[0] || !out || !len) return -1;
    int result = -1;
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = ctx ? SSL_new(ctx) : NULL;
    BIO *rbio = BIO_new(BIO_s_mem());
    BIO *wbio = BIO_new(BIO_s_mem());
    if (!ssl || !rbio || !wbio) {
        BIO_free(rbio);
        BIO_free(wbio);
        goto done;
    }
    /* the ssl object owns both ends from here */
    SSL_set_bio(ssl, rbio, wbio);
    SSL_set_connect_state(ssl);
    if (SSL_set_tlsext_host_name(ssl, host) != 1) goto done;
    /* nothing answers the hello, so this ends asking for more input */
    (void)SSL_do_handshake(ssl);
    int pending = (int)BIO_pending(wbio);
    if (pending < 6 || (size_t)pending > cap) goto done;
    if (BIO_read(wbio, out, pending) != pending || out[0] != 0x16) goto done;
    *len = (size_t)pending;
    result = 0;
done:
    ERR_clear_error();
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return result;
}


int bye_probe_plain_socket(void *ctx, int family, int type, char *error, size_t error_cap) {
    (void)ctx;
    int fd = socket(family, type, 0);
    if (fd < 0) {
        if (error && error_cap) snprintf(error, error_cap, "cannot open a socket (errno %d)", errno);
        return -1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 ||
        fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        close(fd);
        if (error && error_cap) snprintf(error, error_cap, "cannot set up a socket (errno %d)", errno);
        return -1;
    }
    return fd;
}

/* 1 when the descriptor is ready, 0 on timeout, -1 on a poll failure */
static int wait_for(int fd, short events, int64_t deadline_ms) {
    for (;;) {
        int64_t left = deadline_ms - senko_now_ms();
        if (left < 0) left = 0;
        struct pollfd item = { fd, events, 0 };
        int ready = poll(&item, 1, (int)left);
        if (ready < 0 && errno == EINTR) continue;
        return ready;
    }
}

/* the whole buffer, or the reason it was not */
static bye_probe_result_t send_all(int fd, const uint8_t *data, size_t len, int flags,
                                   int64_t deadline_ms) {
    size_t at = 0;
    while (at < len) {
        ssize_t sent = send(fd, data + at, len - at, flags);
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            int ready = wait_for(fd, POLLOUT, deadline_ms);
            if (ready < 0) return BYE_PROBE_FAILED;
            if (ready == 0) return BYE_PROBE_SILENT;
            continue;
        }
        if (sent <= 0) return BYE_PROBE_RESET;
        at += (size_t)sent;
    }
    return BYE_PROBE_ANSWERED;
}

bye_probe_result_t bye_probe_attempt(const bye_probe_request_t *request, const uint8_t *addr,
                                     const char *host, const bye_desync_t *strategy,
                                     uint32_t *ms) {
    if (ms) *ms = 0;
    if (!request || !addr || !host || !strategy) return BYE_PROBE_FAILED;
    uint8_t hello[HELLO_MAX];
    size_t hello_len = 0;
    if (bye_probe_hello(host, hello, sizeof hello, &hello_len) != 0) return BYE_PROBE_FAILED;
    return bye_probe_attempt_hello(request, addr, hello, hello_len, strategy, ms);
}

bye_probe_result_t bye_probe_attempt_hello(const bye_probe_request_t *request, const uint8_t *addr,
                                           const uint8_t *hello, size_t hello_len,
                                           const bye_desync_t *strategy, uint32_t *ms) {
    int64_t started = senko_now_ms();
    if (ms) *ms = 0;
    if (!request || !addr || !hello || !hello_len || hello_len > HELLO_MAX || !strategy)
        return BYE_PROBE_FAILED;
    uint32_t wait = request->wait_ms ? request->wait_ms : BYE_PROBE_WAIT_MS;
    int64_t deadline = started + wait;

    uint8_t out[HELLO_MAX + BYE_DESYNC_GROWTH_MAX];
    bye_plan_t plan;
    if (bye_desync_build(strategy, hello, hello_len, out, sizeof out, &plan) != BYE_DESYNC_OK)
        return BYE_PROBE_FAILED;

    char error[96];
    int fd = request->bound
        ? direct_socket_bound((void *)&request->iface, AF_INET, SOCK_STREAM, error, sizeof error)
        : bye_probe_plain_socket(NULL, AF_INET, SOCK_STREAM, error, sizeof error);
    if (fd < 0) return BYE_PROBE_FAILED;
    /* without it the kernel joins the planned segments back into one */
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &(int){ 1 }, sizeof(int));

    bye_probe_result_t result = BYE_PROBE_FAILED;
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
#ifdef __APPLE__
    to.sin_len = sizeof to;
#endif
    to.sin_family = AF_INET;
    to.sin_port = htons(request->port ? request->port : 443);
    memcpy(&to.sin_addr, addr, 4);
    if (connect(fd, (struct sockaddr *)&to, sizeof to) != 0 && errno != EINPROGRESS) {
        result = BYE_PROBE_UNREACHABLE;
        goto done;
    }
    int ready = wait_for(fd, POLLOUT, deadline);
    if (ready < 0) goto done;
    if (ready == 0) {
        result = BYE_PROBE_UNREACHABLE;
        goto done;
    }
    int value = 0;
    socklen_t value_len = sizeof value;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &value_len) != 0 || value != 0) {
        result = BYE_PROBE_UNREACHABLE;
        goto done;
    }

    for (size_t i = 0; i < plan.count; ++i) {
        const bye_op_t *op = &plan.ops[i];
        uint8_t *seg = out + op->off;
        int restore = 0;
        if (op->flags & BYE_OP_TTL1) {
            /* the first router drops it and the kernel sends it again behind the next part */
            socklen_t ttl_len = sizeof restore;
            if (getsockopt(fd, IPPROTO_IP, IP_TTL, &restore, &ttl_len) != 0 || restore < 2 ||
                setsockopt(fd, IPPROTO_IP, IP_TTL, &(int){ 1 }, sizeof(int)) != 0) {
                result = BYE_PROBE_FAILED;
                goto done;
            }
        }
        if (op->flags & BYE_OP_OOB) {
            /* the urgent byte takes the place of the next hello byte, which the next part sends again */
            uint8_t kept = seg[op->len];
            seg[op->len] = plan.oob_char;
            ssize_t sent;
            do sent = send(fd, seg, op->len + 1, MSG_OOB);
            while (sent < 0 && errno == EINTR);
            seg[op->len] = kept;
            result = sent == (ssize_t)(op->len + 1) ? BYE_PROBE_ANSWERED : BYE_PROBE_RESET;
        } else {
            result = send_all(fd, seg, op->len, 0, deadline);
        }
        if (restore && setsockopt(fd, IPPROTO_IP, IP_TTL, &restore, sizeof restore) != 0)
            result = BYE_PROBE_FAILED;
        if (result != BYE_PROBE_ANSWERED) goto done;
        if (op->oob_after) {
            static const uint8_t byte = BYE_DESYNC_OOB_BYTE;
            /* the urgent byte is only a decoy: a full socket may skip it */
            ssize_t sent = send(fd, &byte, 1, MSG_OOB);
            if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS &&
                errno != EINTR) {
                result = BYE_PROBE_RESET;
                goto done;
            }
        }
    }

    for (;;) {
        ready = wait_for(fd, POLLIN, deadline);
        if (ready < 0) {
            result = BYE_PROBE_FAILED;
            goto done;
        }
        if (ready == 0) {
            result = BYE_PROBE_SILENT;
            goto done;
        }
        uint8_t first[8];
        ssize_t got = recv(fd, first, sizeof first, 0);
        if (got < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (got <= 0) {
            result = BYE_PROBE_RESET;
            goto done;
        }
        result = first[0] == 0x16 ? BYE_PROBE_ANSWERED : BYE_PROBE_OTHER;
        goto done;
    }
done:
    close(fd);
    if (ms) *ms = (uint32_t)(senko_now_ms() - started);
    return result;
}


static void add_candidate(bye_probe_t *probe, const char *spec) {
    if (probe->candidate_count == BYE_PROBE_CANDIDATES_MAX) return;
    for (size_t i = 0; i < probe->candidate_count; ++i)
        if (strcmp(probe->candidates[i].spec, spec) == 0) return;
    candidate_t *item = &probe->candidates[probe->candidate_count];
    memset(item, 0, sizeof *item);
    snprintf(item->spec, sizeof item->spec, "%s", spec);
    if (spec[0] == '-') {
        /* the first group stands for the text, the groups behind it only answer failures */
        bye_strategies_t groups;
        if (bye_ciadpi_parse(spec, &groups, NULL, 0) != BYE_DESYNC_OK || groups.count == 0) return;
        item->plan = groups.item[0];
    } else if (bye_desync_parse(strcmp(spec, "none") == 0 ? "" : spec, &item->plan, NULL, 0) !=
               BYE_DESYNC_OK) {
        /* "none" is a word of the list syntax, and an empty spec to the parser */
        return;
    }
    ++probe->candidate_count;
}

static void build_candidates(bye_probe_t *probe, const char *configured) {
    const char *p = configured;
    while (p && (*p == ' ' || *p == '\t')) ++p;
    /* auto is the daemon's own list, so the check tries what the tunnel would */
    if (p && strcmp(p, BYE_STRATEGIES_DEFAULT) == 0) p = BYE_STRATEGIES_AUTO_LIST;
    if (p && *p == '-') {
        add_candidate(probe, p);
        p = NULL;
    }
    while (p && *p) {
        const char *end = strchr(p, '|');
        if (!end) end = p + strlen(p);
        while (p < end && (*p == ' ' || *p == '\t')) ++p;
        const char *stop = end;
        while (stop > p && (stop[-1] == ' ' || stop[-1] == '\t')) --stop;
        char spec[BYE_PROBE_SPEC_MAX];
        size_t n = (size_t)(stop - p);
        if (n > 0 && n < sizeof spec) {
            memcpy(spec, p, n);
            spec[n] = '\0';
            add_candidate(probe, spec);
        }
        p = *end ? end + 1 : end;
    }
    probe->configured_count = probe->candidate_count;
    for (size_t i = 0; i < sizeof BUILTIN / sizeof BUILTIN[0]; ++i) add_candidate(probe, BUILTIN[i]);
}

static int resolve_v4(const char *name, uint8_t *addr, char *error, size_t error_cap) {
    struct addrinfo hints, *found = NULL;
    memset(addr, 0, 4);
    if (error && error_cap) error[0] = '\0';
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int code = getaddrinfo(name, NULL, &hints, &found);
    int saved_errno = errno;
    if (code != 0) {
        const char *message = gai_strerror(code);
        if (error && error_cap) {
            if (code == EAI_SYSTEM)
                snprintf(error, error_cap, "getaddrinfo(%d), errno=%d: %s", code,
                         saved_errno, strerror(saved_errno));
            else
                snprintf(error, error_cap, "getaddrinfo(%d): %s", code,
                         message ? message : "DNS lookup failed");
        }
        if (found) freeaddrinfo(found);
        return -1;
    }
    int result = -1;
    for (struct addrinfo *item = found; item; item = item->ai_next) {
        if (item->ai_family != AF_INET || !item->ai_addr ||
            item->ai_addrlen < sizeof(struct sockaddr_in)) continue;
        memcpy(addr, &((struct sockaddr_in *)item->ai_addr)->sin_addr, 4);
        result = 0;
        break;
    }
    if (found) freeaddrinfo(found);
    if (result != 0 && error && error_cap)
        snprintf(error, error_cap, "no IPv4 address in DNS answer");
    return result;
}

static int cancelled(bye_probe_t *probe) {
    pthread_mutex_lock(&probe->lock);
    int value = probe->cancel;
    pthread_mutex_unlock(&probe->lock);
    return value;
}

static void *run(void *arg) {
    bye_probe_t *probe = arg;
    uint8_t (*addrs)[4] = probe->addrs;
    int *resolved = probe->resolved;
    size_t names = probe->request.name_count;
    unsigned usable = 0;
    for (size_t i = 0; i < names && !cancelled(probe); ++i) {
        uint8_t found[4];
        char error[160];
        int ok = resolve_v4(probe->request.names[i], found, error, sizeof error) == 0;
        if (!ok)
            fprintf(stderr, "byedpid: probe dns %s: %s\n", probe->request.names[i], error);
        pthread_mutex_lock(&probe->lock);
        if (ok) memcpy(addrs[i], found, 4);
        resolved[i] = ok;
        if (resolved[i]) ++usable;
        else {
            size_t index = probe->unresolved_count++;
            snprintf(probe->unresolved[index], BYE_PROBE_NAME_MAX, "%s", probe->request.names[i]);
            snprintf(probe->resolve_error[index], sizeof probe->resolve_error[index], "%s", error);
        }
        pthread_mutex_unlock(&probe->lock);
    }
    pthread_mutex_lock(&probe->lock);
    probe->total = usable * (unsigned)probe->candidate_count;
    ssize_t alt = -1;
    if (probe->request.app_hello_len) {
        probe->total += 2u * (unsigned)probe->candidate_count;
        for (size_t i = 0; i < names; ++i) {
            if (!resolved[i] || memcmp(addrs[i], probe->request.app_addr, 4) == 0 ||
                !same_site(probe->request.app_name, probe->request.names[i]))
                continue;
            alt = (ssize_t)i;
            memcpy(probe->alt_addr, addrs[i], 4);
            snprintf(probe->alt_name, sizeof probe->alt_name, "%s", probe->request.names[i]);
            probe->total += (unsigned)probe->candidate_count;
            break;
        }
    }
    pthread_mutex_unlock(&probe->lock);

    for (size_t n = 0; n < names; ++n) {
        if (!resolved[n]) continue;
        for (size_t c = 0; c < probe->candidate_count; ++c) {
            if (cancelled(probe)) goto finished;
            uint32_t ms = 0;
            bye_probe_result_t result = bye_probe_attempt(&probe->request, addrs[n],
                                                          probe->request.names[n],
                                                          &probe->candidates[c].plan, &ms);
            pthread_mutex_lock(&probe->lock);
            ++probe->candidates[c].tried;
            if (result == BYE_PROBE_ANSWERED) {
                ++probe->candidates[c].ok;
                probe->candidates[c].ms += ms;
            }
            ++probe->done;
            pthread_mutex_unlock(&probe->lock);
        }
    }
    for (size_t kind = 0; kind < 2 && probe->request.app_hello_len; ++kind) {
        uint8_t own[HELLO_MAX];
        size_t own_len = 0;
        if (kind == 1 && bye_probe_hello(probe->request.app_name, own, sizeof own, &own_len) != 0) own_len = 0;
        for (size_t c = 0; c < probe->candidate_count; ++c) {
            if (cancelled(probe)) goto finished;
            uint32_t ms = 0;
            bye_probe_result_t result = kind == 0
                ? bye_probe_attempt_hello(&probe->request, probe->request.app_addr, probe->request.app_hello,
                                          probe->request.app_hello_len, &probe->candidates[c].plan, &ms)
                : bye_probe_attempt_hello(&probe->request, probe->request.app_addr, own, own_len,
                                          &probe->candidates[c].plan, &ms);
            pthread_mutex_lock(&probe->lock);
            probe->app_result[kind][c] = (uint8_t)result;
            probe->app_ms[kind][c] = ms;
            ++probe->done;
            pthread_mutex_unlock(&probe->lock);
        }
    }
    for (size_t c = 0; alt >= 0 && c < probe->candidate_count; ++c) {
        if (cancelled(probe)) goto finished;
        uint32_t ms = 0;
        bye_probe_result_t result = bye_probe_attempt_hello(&probe->request, probe->alt_addr,
                                                            probe->request.app_hello, probe->request.app_hello_len,
                                                            &probe->candidates[c].plan, &ms);
        pthread_mutex_lock(&probe->lock);
        probe->alt_result[c] = (uint8_t)result;
        probe->alt_ms[c] = ms;
        ++probe->done;
        pthread_mutex_unlock(&probe->lock);
    }
finished:
    pthread_mutex_lock(&probe->lock);
    probe->stopped = probe->cancel;
    probe->running = 0;
    pthread_mutex_unlock(&probe->lock);
    return NULL;
}

int bye_probe_start(bye_probe_t *probe, const bye_probe_request_t *request, char *error,
                    size_t error_cap) {
    if (error && error_cap) error[0] = '\0';
    if (!probe || !request || request->name_count == 0 ||
        request->name_count > BYE_PROBE_NAMES_MAX) {
        if (error && error_cap) snprintf(error, error_cap, "give one to %d names", BYE_PROBE_NAMES_MAX);
        return -1;
    }
    pthread_mutex_lock(&probe->lock);
    int busy = probe->running;
    pthread_mutex_unlock(&probe->lock);
    if (busy) {
        if (error && error_cap) snprintf(error, error_cap, "a probe is already running");
        return -1;
    }
    if (probe->started) {
        pthread_join(probe->thread, NULL);
        probe->started = 0;
    }
    pthread_mutex_lock(&probe->lock);
    probe->request = *request;
    probe->cancel = probe->stopped = 0;
    probe->candidate_count = probe->configured_count = 0;
    probe->unresolved_count = 0;
    memset(probe->resolved, 0, sizeof probe->resolved);
    probe->total = probe->done = 0;
    memset(probe->app_result, 0xff, sizeof probe->app_result);
    memset(probe->alt_result, 0xff, sizeof probe->alt_result);
    probe->alt_name[0] = '\0';
    build_candidates(probe, request->configured);
    probe->running = 1;
    pthread_mutex_unlock(&probe->lock);
    if (pthread_create(&probe->thread, NULL, run, probe) != 0) {
        pthread_mutex_lock(&probe->lock);
        probe->running = 0;
        pthread_mutex_unlock(&probe->lock);
        if (error && error_cap) snprintf(error, error_cap, "cannot start the probe thread");
        return -1;
    }
    probe->started = 1;
    return 0;
}

void bye_probe_cancel(bye_probe_t *probe) {
    if (!probe) return;
    pthread_mutex_lock(&probe->lock);
    probe->cancel = 1;
    pthread_mutex_unlock(&probe->lock);
}

void bye_probe_destroy(bye_probe_t *probe) {
    if (!probe) return;
    bye_probe_cancel(probe);
    if (probe->started) pthread_join(probe->thread, NULL);
    probe->started = 0;
    pthread_mutex_destroy(&probe->lock);
}

int bye_probe_running(bye_probe_t *probe) {
    pthread_mutex_lock(&probe->lock);
    int value = probe->running;
    pthread_mutex_unlock(&probe->lock);
    return value;
}

size_t bye_probe_report(bye_probe_t *probe, char *out, size_t cap) {
    if (!out || cap == 0) return 0;
    size_t at = 0;
#define PUT(...) do { \
        int w = snprintf(out + at, cap - at, __VA_ARGS__); \
        if (w < 0 || (size_t)w >= cap - at) { out[at] = '\0'; goto full; } \
        at += (size_t)w; \
    } while (0)
    pthread_mutex_lock(&probe->lock);
    const char *state = probe->running ? "running"
                      : probe->candidate_count == 0 ? "idle"
                      : probe->stopped ? "stopped" : "done";
    PUT("state=%s\n", state);
    PUT("progress=%u/%u\n", probe->done, probe->total);
    PUT("configured=%zu\n", probe->configured_count);
    /* dns failures must stay visible even when a long strategy fills the report */
    for (size_t i = 0; i < probe->unresolved_count; ++i) {
        PUT("unresolved=%s\n", probe->unresolved[i]);
        PUT("unresolved.error=%s %s\n", probe->unresolved[i], probe->resolve_error[i]);
    }
    for (size_t i = 0; i < probe->candidate_count; ++i) {
        const candidate_t *c = &probe->candidates[i];
        PUT("candidate.%zu=%u/%u %ums %s\n", i, c->ok, c->tried,
            c->ok ? (unsigned)(c->ms / c->ok) : 0u, c->spec);
    }
    for (size_t i = 0; i < probe->request.name_count; ++i) {
        if (!probe->resolved[i]) continue;
        char text[INET_ADDRSTRLEN];
        PUT("address.%zu=%s %s\n", i, probe->request.names[i],
            inet_ntop(AF_INET, probe->addrs[i], text, sizeof text) ? text : "?");
    }

    /* the working specs, those that answered most often first, in list order
       among equals; the list a config can take as it is */
    size_t order[BYE_PROBE_CANDIDATES_MAX];
    size_t count = 0;
    for (size_t i = 0; i < probe->candidate_count; ++i)
        if (probe->candidates[i].ok) order[count++] = i;
    for (size_t i = 1; i < count; ++i) {
        size_t held = order[i];
        size_t j = i;
        while (j > 0 && probe->candidates[order[j - 1]].ok < probe->candidates[held].ok) {
            order[j] = order[j - 1];
            --j;
        }
        order[j] = held;
    }
    if (count > SUGGEST_MAX) count = SUGGEST_MAX;
    PUT("suggest=");
    for (size_t i = 0; i < count; ++i) PUT("%s%s", i ? "|" : "", probe->candidates[order[i]].spec);
    PUT("\n");
    if (probe->request.app_hello_len) {
        static const char *const names[] = { "answered", "reset", "silent", "other", "unreachable", "failed" };
        char text[INET_ADDRSTRLEN];
        PUT("app=%s %s %zu bytes\n", probe->request.app_name,
            inet_ntop(AF_INET, probe->request.app_addr, text, sizeof text) ? text : "?",
            probe->request.app_hello_len);
        /* "the app's hello | this library's hello", for the candidate of the same number */
        for (size_t i = 0; i < probe->candidate_count; ++i) {
            char parts[2][32];
            for (size_t kind = 0; kind < 2; ++kind) {
                unsigned code = probe->app_result[kind][i];
                if (code == 0xff) snprintf(parts[kind], sizeof parts[kind], "-");
                else snprintf(parts[kind], sizeof parts[kind], "%s %ums",
                              code < sizeof names / sizeof names[0] ? names[code] : "?", (unsigned)probe->app_ms[kind][i]);
            }
            PUT("app.%zu=%s | %s\n", i, parts[0], parts[1]);
        }
        if (probe->alt_name[0]) {
            PUT("alt=%s %s\n", probe->alt_name,
                inet_ntop(AF_INET, probe->alt_addr, text, sizeof text) ? text : "?");
            for (size_t i = 0; i < probe->candidate_count; ++i) {
                unsigned code = probe->alt_result[i];
                if (code == 0xff) PUT("alt.%zu=-\n", i);
                else PUT("alt.%zu=%s %ums\n", i, code < sizeof names / sizeof names[0] ? names[code] : "?",
                         (unsigned)probe->alt_ms[i]);
            }
        }
    }
full:
    pthread_mutex_unlock(&probe->lock);
    return at;
#undef PUT
}

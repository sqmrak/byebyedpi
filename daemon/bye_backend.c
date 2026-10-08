#define _DEFAULT_SOURCE

#include "bye_backend.h"

#include "bye_badge.h"
#include "bye_hostsfile.h"
#include "bye_paths.h"
#include "bye_resolver.h"
#include "tun/core/senko_time.h"
#include "tun/legacy_ios.h"
#include "tun/route_socket.h"
#include "tun/utun_route.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define LEFTOVERS_MAX 16384
#define START_WAIT_SEC 8
#define CMD_SNAPSHOT (TUN_LOOP_CMD_OWNER + 1)

/* the tunnel's own private range, apart from the one senko uses so the two
   can be told apart in ifconfig */
static const uint8_t LOCAL4[4] = { 198, 19, 0, 1 };
static const uint8_t PEER4[4] = { 198, 19, 0, 2 };
static const uint8_t ULA6_PREFIX[4] = { 0xfd, 0x00, 0xbd, 0x91 };

static void reason_set(char *out, size_t cap, const char *why) {
    if (out && cap) snprintf(out, cap, "%s", why);
}

static void deadline_in_ms(struct timespec *deadline, int ms) {
    struct timeval now;
    gettimeofday(&now, NULL);
    long long ns = (long long)now.tv_usec * 1000LL + (long long)(ms % 1000) * 1000000LL;
    deadline->tv_sec = now.tv_sec + ms / 1000 + (time_t)(ns / 1000000000LL);
    deadline->tv_nsec = (long)(ns % 1000000000LL);
}

static void fail_with_errno(char *out, size_t cap, const char *what, int value) {
    reason_set(out, cap, what);
    if (out && cap) route_errno_append(out, cap, value);
}


static void leftovers_save(const tun_plan_t *plan) {
    char text[LEFTOVERS_MAX];
    int len = tun_plan_save_leftovers(plan, text, sizeof text);
    const char *tmp = BYE_LEFTOVERS_PATH ".new";
    int fd = len > 0 ? open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600) : -1;
    int ok = fd >= 0 && write(fd, text, (size_t)len) == (ssize_t)len;
    if (fd >= 0 && close(fd) != 0) ok = 0;
    if (ok && rename(tmp, BYE_LEFTOVERS_PATH) == 0) return;
    int saved = errno;
    (void)unlink(tmp);
    fprintf(stderr, "byedpid: cannot record the routes for crash cleanup in %s (errno %d %s)\n",
            BYE_LEFTOVERS_PATH, saved, strerror(saved));
}

static void leftovers_forget(void) {
    if (unlink(BYE_LEFTOVERS_PATH) != 0 && errno != ENOENT)
        fprintf(stderr, "byedpid: cannot remove %s (errno %d %s)\n", BYE_LEFTOVERS_PATH,
                errno, strerror(errno));
}

static void leftovers_undo(void) {
    int fd = open(BYE_LEFTOVERS_PATH, O_RDONLY);
    if (fd < 0) return;
    char text[LEFTOVERS_MAX];
    ssize_t len = read(fd, text, sizeof text);
    close(fd);
    tun_plan_t plan;
    if (len <= 0 || (size_t)len >= sizeof text ||
        tun_plan_load_leftovers(text, (size_t)len, &plan) != TUN_PLAN_OK) {
        fprintf(stderr, "byedpid: ignoring an unreadable %s from a previous run\n",
                BYE_LEFTOVERS_PATH);
        leftovers_forget();
        return;
    }
    utun_route_result_t result;
    if (utun_route_revert(&plan, utun_route_system_executor(), &result) != UTUN_ROUTE_OK) {
        fprintf(stderr, "byedpid: %zu route(s) left by a previous run could not be removed: %s\n",
                result.rollback_failures, result.rollback_message);
        return;
    }
    fprintf(stderr, "byedpid: removed %zu route(s) left by a previous run\n", result.rolled_back);
    leftovers_forget();
}


#define RESOLVE_WAIT_MS 6000
#define RESOLVE_JOBS_MAX (BYE_TG_WS_DCS * BYE_TG_WS_VARIANTS + BYE_TCP_RELAYS_MAX)

/* timed-out libc lookups can outlive a restart, so all starts share this bound */
static pthread_mutex_t resolve_lock = PTHREAD_MUTEX_INITIALIZER;
static size_t resolve_jobs;

static void resolve_slot_release(void) {
    pthread_mutex_lock(&resolve_lock);
    --resolve_jobs;
    pthread_mutex_unlock(&resolve_lock);
}

/* a lookup runs on its own thread and is abandoned when it takes too long, so
   a resolver that never answers cannot hold the control socket. whoever
   finishes last frees the job */
typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t  done;
    int             finished;
    int             refs;
    int             found;
    uint8_t         address[4];
    char            host[128];
} resolve_job_t;

static void resolve_unref(resolve_job_t *job) {
    pthread_mutex_lock(&job->lock);
    int last = --job->refs == 0;
    pthread_mutex_unlock(&job->lock);
    if (!last) return;
    pthread_cond_destroy(&job->done);
    pthread_mutex_destroy(&job->lock);
    free(job);
}

static void *resolve_main(void *arg) {
    resolve_job_t *job = arg;
    struct addrinfo hints, *list = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int found = 0;
    uint8_t address[4] = { 0 };
    if (getaddrinfo(job->host, "443", &hints, &list) == 0 && list) {
        memcpy(address, &((struct sockaddr_in *)list->ai_addr)->sin_addr, 4);
        found = 1;
    }
    if (list) freeaddrinfo(list);
    pthread_mutex_lock(&job->lock);
    memcpy(job->address, address, 4);
    job->found = found;
    job->finished = 1;
    pthread_cond_broadcast(&job->done);
    pthread_mutex_unlock(&job->lock);
    resolve_unref(job);
    resolve_slot_release();
    return NULL;
}

/* starts the lookup of host on its own thread. NULL when it could not start */
static resolve_job_t *resolve_start(const char *host) {
    pthread_mutex_lock(&resolve_lock);
    int full = resolve_jobs >= RESOLVE_JOBS_MAX;
    if (!full) ++resolve_jobs;
    pthread_mutex_unlock(&resolve_lock);
    if (full) return NULL;
    resolve_job_t *job = calloc(1, sizeof *job);
    if (!job) {
        resolve_slot_release();
        return NULL;
    }
    if (strlen(host) >= sizeof job->host) {
        free(job);
        resolve_slot_release();
        return NULL;
    }
    snprintf(job->host, sizeof job->host, "%s", host);
    if (pthread_mutex_init(&job->lock, NULL) != 0) {
        free(job);
        resolve_slot_release();
        return NULL;
    }
    if (pthread_cond_init(&job->done, NULL) != 0) {
        pthread_mutex_destroy(&job->lock);
        free(job);
        resolve_slot_release();
        return NULL;
    }
    job->refs = 2;
    pthread_t thread;
    if (pthread_create(&thread, NULL, resolve_main, job) != 0) {
        job->refs = 1;
        resolve_unref(job);
        resolve_slot_release();
        return NULL;
    }
    pthread_detach(thread);
    return job;
}

/* 0 with the first ipv4 address of the job's host, -1 when the lookup failed
   or is still running at the deadline. consumes the job */
static int resolve_finish(resolve_job_t *job, const struct timespec *deadline, uint8_t out[4]) {
    if (!job) return -1;
    pthread_mutex_lock(&job->lock);
    while (!job->finished)
        if (pthread_cond_timedwait(&job->done, &job->lock, deadline) != 0) break;
    int ok = job->finished && job->found;
    if (ok) memcpy(out, job->address, 4);
    pthread_mutex_unlock(&job->lock);
    resolve_unref(job);
    return ok ? 0 : -1;
}

/* a name that does not resolve is left out and named in warning. returns how many
   of the domains in list (a config relay value) have an address */
size_t bye_resolve_relays(const char *list, char names[][BYE_TCP_RELAY_NAME_MAX],
                          uint8_t addrs[][4], size_t max, char *warning, size_t warning_cap) {
    resolve_job_t *jobs[BYE_TCP_RELAYS_MAX] = { NULL };
    char domains[BYE_TCP_RELAYS_MAX][BYE_TCP_RELAY_NAME_MAX];
    size_t total = 0, found = 0;
    if (max > BYE_TCP_RELAYS_MAX) max = BYE_TCP_RELAYS_MAX;
    const char *p = list;
    while (*p && total < max) {
        const char *comma = strchr(p, ',');
        size_t n = comma ? (size_t)(comma - p) : strlen(p);
        if (n >= sizeof domains[0]) break;
        memcpy(domains[total], p, n);
        domains[total][n] = '\0';
        char name[BYE_TCP_RELAY_NAME_MAX + 8];
        snprintf(name, sizeof name, "kws2.%.47s", domains[total]);
        jobs[total++] = resolve_start(name);
        if (!comma) break;
        p = comma + 1;
    }
    struct timespec deadline;
    deadline_in_ms(&deadline, RESOLVE_WAIT_MS);
    for (size_t i = 0; i < total; ++i) {
        uint8_t address[4];
        if (resolve_finish(jobs[i], &deadline, address) == 0) {
            char text[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, address, text, sizeof text);
            fprintf(stderr, "byedpid: telegram relay kws2.%s is %s\n", domains[i], text);
            snprintf(names[found], BYE_TCP_RELAY_NAME_MAX, "%.47s", domains[i]);
            memcpy(addrs[found], address, 4);
            ++found;
        } else if (warning && warning_cap) {
            snprintf(warning, warning_cap, "telegram relay %.100s did not resolve and is left out",
                     domains[i]);
            fprintf(stderr, "byedpid: %s\n", warning);
        }
    }
    return found;
}

void bye_resolve_gateways(bye_tg_ws_addresses_t *out) {
    if (!out) return;
    resolve_job_t *jobs[BYE_TG_WS_DCS][BYE_TG_WS_VARIANTS];
    memset(out, 0, sizeof *out);
    memset(jobs, 0, sizeof jobs);
    for (int dc = 1; dc <= BYE_TG_WS_DCS; ++dc) {
        for (unsigned media = 0; media < BYE_TG_WS_VARIANTS; ++media) {
            char host[BYE_TG_WS_HOST_MAX];
            if (bye_tg_ws_host(dc, (int)media, 0, host, sizeof host) == 0)
                jobs[dc - 1][media] = resolve_start(host);
        }
    }
    struct timespec deadline;
    deadline_in_ms(&deadline, RESOLVE_WAIT_MS);
    for (int dc = 1; dc <= BYE_TG_WS_DCS; ++dc) {
        for (unsigned media = 0; media < BYE_TG_WS_VARIANTS; ++media) {
            bye_tg_ws_address_t *entry = &out->dc[dc - 1][media];
            entry->valid = resolve_finish(jobs[dc - 1][media], &deadline, entry->address) == 0;
            char host[BYE_TG_WS_HOST_MAX], address[INET_ADDRSTRLEN];
            bye_tg_ws_host(dc, (int)media, 0, host, sizeof host);
            if (entry->valid && inet_ntop(AF_INET, entry->address, address, sizeof address))
                fprintf(stderr, "byedpid: telegram gateway %s is %s\n", host, address);
            else
                fprintf(stderr, "byedpid: telegram gateway %s did not resolve, using pinned addresses\n", host);
        }
    }
}


static int physical_path(tun_plan_input_t *input, char *reason, size_t cap) {
    static const uint8_t probe4[4] = { 1, 1, 1, 1 };
    static const uint8_t probe6[16] = {
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88
    };
    utun_route_path_t path;
    utun_route_error_t error;
    memset(input, 0, sizeof *input);
    if (utun_route_system_path(probe4, 4, &path, &error) != 0) {
        reason_set(reason, cap, error.message);
        return -1;
    }
    /* brighton's utun is the guest's network link, not another vpn */
    int brighton = bye_route_is_tunnel_ifname(path.ifname) &&
        bye_iface_brighton_link(path.ifname, path.via_gateway ? path.gateway : NULL);
    if (bye_route_is_tunnel_ifname(path.ifname) && !brighton) {
        char text[160];
        snprintf(text, sizeof text,
                 "another tunnel (%s) already carries the default route, turn it off and start again",
                 path.ifname);
        reason_set(reason, cap, text);
        return -1;
    }
    snprintf(input->physical_ifname, sizeof input->physical_ifname, "%s", path.ifname);
    input->route_ipv4 = 1;
    input->have_gateway4 = path.via_gateway;
    if (path.via_gateway) memcpy(input->gateway4, path.gateway, 4);

    /* brighton_netd carries only ipv4, so ipv6 bypass routes have no uplink there */
    input->enable_ipv6 = !brighton;
    utun_route_path_t path6;
    /* an ipv4-only carrier can still carry ipv6 app packets through the tunnel */
    if (utun_route_system_path(probe6, 16, &path6, &error) == 0) {
        if (strcmp(path6.ifname, input->physical_ifname) != 0) {
            reason_set(reason, cap, "IPv4 and IPv6 leave through different physical interfaces");
            return -1;
        }
        input->enable_ipv6 = 1;
        input->have_gateway6 = path6.via_gateway;
        if (path6.via_gateway) memcpy(input->gateway6, path6.gateway, 16);
    }
    return 0;
}

static void ula_address(uint8_t out[16], uint8_t last) {
    memset(out, 0, 16);
    memcpy(out, ULA6_PREFIX, sizeof ULA6_PREFIX);
    out[15] = last;
}

/* 1 when another interface already holds one of the tunnel's addresses */
static int address_in_use(void) {
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) != 0) return -1;
    uint8_t local6[16], peer6[16];
    ula_address(local6, 1);
    ula_address(peer6, 2);
    int conflict = 0;
    for (struct ifaddrs *item = interfaces; item; item = item->ifa_next) {
        if (!item->ifa_addr) continue;
        if (item->ifa_addr->sa_family == AF_INET) {
            const struct sockaddr_in *a = (const struct sockaddr_in *)item->ifa_addr;
            if (memcmp(&a->sin_addr, LOCAL4, 4) == 0 || memcmp(&a->sin_addr, PEER4, 4) == 0)
                conflict = 1;
        } else if (item->ifa_addr->sa_family == AF_INET6) {
            const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)item->ifa_addr;
            if (memcmp(&a->sin6_addr, local6, 16) == 0 || memcmp(&a->sin6_addr, peer6, 16) == 0)
                conflict = 1;
        }
    }
    freeifaddrs(interfaces);
    return conflict;
}


static void take_snapshot(bye_backend_t *backend, tun_stack_t *stack) {
    bye_backend_snapshot_t snap;
    memset(&snap, 0, sizeof snap);
    snap.tcp = *bye_tcp_stats(backend->tcp);
    snap.udp = *bye_udp_stats(backend->udp);
    snap.stack = *tun_stack_stats(stack);
    pthread_mutex_lock(&backend->lock);
    backend->snapshot = snap;
    ++backend->snapshot_seq;
    pthread_cond_broadcast(&backend->changed);
    pthread_mutex_unlock(&backend->lock);
}

static void on_command(void *ctx, tun_stack_t *stack, const tun_loop_command_t *command) {
    bye_backend_t *backend = ctx;
    if (command->type == CMD_SNAPSHOT) take_snapshot(backend, stack);
}

static int post(bye_backend_t *backend, int type) {
    if (!backend || !backend->initialized || !backend->active || !backend->loop) return -1;
    tun_loop_command_t command;
    command.type = type;
    command.generation = backend->generation;
    command.argument = 0;
    return tun_loop_post(backend->loop, &command) == TUN_LOOP_OK ? 0 : -1;
}

static void deadline_in(struct timespec *deadline, int seconds) {
    struct timeval now;
    gettimeofday(&now, NULL);
    deadline->tv_sec = now.tv_sec + seconds;
    deadline->tv_nsec = (long)now.tv_usec * 1000L;
}

int bye_backend_snapshot(bye_backend_t *backend, bye_backend_snapshot_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof *out);
    if (!bye_backend_running(backend)) return -1;
    pthread_mutex_lock(&backend->lock);
    uint64_t wanted = backend->snapshot_seq + 1;
    pthread_mutex_unlock(&backend->lock);
    if (post(backend, CMD_SNAPSHOT) != 0) return -1;
    struct timespec deadline;
    deadline_in(&deadline, 1);
    pthread_mutex_lock(&backend->lock);
    while (backend->snapshot_seq < wanted && !backend->ended)
        if (pthread_cond_timedwait(&backend->changed, &backend->lock, &deadline) == ETIMEDOUT)
            break;
    int ok = backend->snapshot_seq >= wanted;
    if (ok) *out = backend->snapshot;
    pthread_mutex_unlock(&backend->lock);
    return ok ? 0 : -1;
}


static void ready(void *ctx) {
    bye_backend_t *backend = ctx;
    pthread_mutex_lock(&backend->lock);
    backend->ready = 1;
    pthread_cond_broadcast(&backend->changed);
    pthread_mutex_unlock(&backend->lock);
}

static void *run(void *ctx) {
    bye_backend_t *backend = ctx;
    tun_loop_result_t result;
    tun_loop_status_t status = tun_loop_run(backend->loop, &result);
    pthread_mutex_lock(&backend->lock);
    backend->result = result;
    backend->ended = 1;
    if (status != TUN_LOOP_OK) snprintf(backend->error, sizeof backend->error, "%s", result.message);
    pthread_cond_broadcast(&backend->changed);
    pthread_mutex_unlock(&backend->lock);
    ssize_t wrote;
    do {
        wrote = write(backend->ended_pipe[1], "e", 1);
    } while (wrote < 0 && errno == EINTR);
    /* a full pipe already holds the wakeup */
    return NULL;
}

static int open_ended_pipe(int fds[2]) {
    if (pipe(fds) != 0) return -1;
    for (int i = 0; i < 2; ++i) {
        int flags = fcntl(fds[i], F_GETFL, 0);
        if (flags < 0 || fcntl(fds[i], F_SETFL, flags | O_NONBLOCK) != 0 ||
            fcntl(fds[i], F_SETFD, FD_CLOEXEC) != 0) {
            close(fds[0]);
            close(fds[1]);
            fds[0] = fds[1] = -1;
            return -1;
        }
    }
    return 0;
}

int bye_backend_ended_fd(const bye_backend_t *backend) {
    return backend && backend->initialized ? backend->ended_pipe[0] : -1;
}

void bye_backend_drain_ended(bye_backend_t *backend) {
    if (!backend || !backend->initialized) return;
    char sink[16];
    ssize_t got;
    do {
        got = read(backend->ended_pipe[0], sink, sizeof sink);
    } while (got > 0 || (got < 0 && errno == EINTR));
}

void bye_backend_end_reason(bye_backend_t *backend, char *out, size_t cap) {
    if (!out || !cap) return;
    out[0] = '\0';
    if (!backend || !backend->initialized) return;
    pthread_mutex_lock(&backend->lock);
    if (backend->ended) snprintf(out, cap, "%s", backend->result.message);
    pthread_mutex_unlock(&backend->lock);
}

int bye_backend_init(bye_backend_t *backend) {
    if (!backend) return -1;
    memset(backend, 0, sizeof *backend);
    backend->ended_pipe[0] = backend->ended_pipe[1] = -1;
    utun_device_init(&backend->device);
    utun_dns_init(&backend->dns);
    if (open_ended_pipe(backend->ended_pipe) != 0) return -1;
    if (pthread_mutex_init(&backend->lock, NULL) != 0) goto fail_pipe;
    if (pthread_cond_init(&backend->changed, NULL) != 0) goto fail_lock;
    backend->initialized = 1;
    leftovers_undo();
    return 0;
fail_lock:
    pthread_mutex_destroy(&backend->lock);
fail_pipe:
    close(backend->ended_pipe[0]);
    close(backend->ended_pipe[1]);
    backend->ended_pipe[0] = backend->ended_pipe[1] = -1;
    return -1;
}

void bye_backend_stop(bye_backend_t *backend) {
    if (!backend || !backend->initialized) return;
    utun_dns_withdraw(&backend->dns);
    backend->dns_state[0] = '\0';
    if (backend->thread_started) {
        tun_loop_request_stop(backend->loop);
        pthread_join(backend->thread, NULL);
        backend->thread_started = 0;
    }
    if (backend->active) {
        bye_badge_off();
        utun_route_result_t result;
        if (utun_route_revert(&backend->plan, utun_route_system_executor(), &result) != UTUN_ROUTE_OK)
            /* the record stays, so the next start tries the routes again */
            fprintf(stderr, "byedpid: route cleanup failed: %s\n",
                    result.rollback_message[0] ? result.rollback_message : result.failed_message);
        else
            leftovers_forget();
        backend->active = 0;
    }
    /* a zeroed loop that never ran tun_loop_init reads its wake pipe as fd 0
       and has no device, so it must not be torn down as a loop */
    if (backend->loop_initialized) tun_loop_destroy(backend->loop);
    utun_device_close(&backend->device);
    memset(&backend->iface, 0, sizeof backend->iface);
    backend->loop_initialized = 0;
    free(backend->loop);
    free(backend->tcp);
    free(backend->udp);
    backend->loop = NULL;
    backend->tcp = NULL;
    backend->udp = NULL;
    bye_wsconn_ctx_free(backend->tls);
    backend->tls = NULL;
    bye_hosts_free(backend->hosts);
    backend->hosts = NULL;
    backend->ready = 0;
    backend->ended = 0;
}

void bye_backend_destroy(bye_backend_t *backend) {
    if (!backend || !backend->initialized) return;
    bye_backend_stop(backend);
    pthread_cond_destroy(&backend->changed);
    pthread_mutex_destroy(&backend->lock);
    close(backend->ended_pipe[0]);
    close(backend->ended_pipe[1]);
    backend->ended_pipe[0] = backend->ended_pipe[1] = -1;
    backend->initialized = 0;
}

int bye_backend_running(bye_backend_t *backend) {
    if (!backend || !backend->initialized || !backend->active) return 0;
    pthread_mutex_lock(&backend->lock);
    int running = backend->ready && !backend->ended;
    pthread_mutex_unlock(&backend->lock);
    return running;
}

int bye_backend_direct(const bye_backend_t *backend, direct_socket_iface_t *out) {
    if (!backend || !out || !backend->initialized || !backend->active) return -1;
    *out = backend->direct;
    return 0;
}

int bye_backend_external_interface(const bye_backend_t *backend, char *out, size_t cap,
                                    char *reason, size_t reason_cap) {
    if (out && cap) out[0] = '\0';
    if (reason && reason_cap) reason[0] = '\0';
    if (!backend || !out || !cap) {
        reason_set(reason, reason_cap, "invalid external interface output");
        return -1;
    }
    const char *name;
    utun_route_path_t path;
    if (backend->active) {
        /* split defaults point at utun, so querying them now would report ourselves */
        name = backend->direct.ifname;
    } else {
        static const uint8_t probe4[4] = { 1, 1, 1, 1 };
        utun_route_error_t error;
        if (utun_route_system_path(probe4, 4, &path, &error) != 0) {
            reason_set(reason, reason_cap, error.message);
            return -1;
        }
        name = path.ifname;
    }
    const char *end = memchr(name, '\0', sizeof path.ifname);
    size_t len = end ? (size_t)(end - name) : sizeof path.ifname;
    if (!len || len == sizeof path.ifname || len >= cap) {
        reason_set(reason, reason_cap, "the external interface name is missing or does not fit");
        return -1;
    }
    memcpy(out, name, len + 1);
    return 0;
}

int bye_backend_network_ok(const bye_backend_t *backend) {
    if (!backend || !backend->direct.ifname[0]) return 0;
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) != 0) return 1; /* cannot tell: leave the tunnel alone */
    int up = 0, addressed = 0;
    for (struct ifaddrs *item = interfaces; item; item = item->ifa_next) {
        if (!item->ifa_addr || strcmp(item->ifa_name, backend->direct.ifname) != 0) continue;
        if ((item->ifa_flags & IFF_UP) && (item->ifa_flags & IFF_RUNNING)) up = 1;
        if (item->ifa_addr->sa_family == AF_INET || item->ifa_addr->sa_family == AF_INET6)
            addressed = 1;
    }
    freeifaddrs(interfaces);
    return up && addressed;
}

const char *bye_backend_warning(const bye_backend_t *backend) {
    return backend ? backend->warning : "";
}

const char *bye_backend_dns_state(const bye_backend_t *backend) {
    return backend ? backend->dns_state : "";
}

const char *bye_backend_ifname(const bye_backend_t *backend) {
    return backend ? backend->iface.ifname : "";
}

static void stack_addresses(tun_stack_config_t *stack, const char *ifname) {
    stack->mtu = BYE_TUN_MTU;
    stack->have_ipv4 = stack->have_ipv6 = 1;
    memcpy(stack->address4, LOCAL4, 4);
    memset(stack->netmask4, 255, 4);
    memcpy(stack->synthetic4, PEER4, 4);
    ula_address(stack->address6, 1);
    ula_address(stack->synthetic6, 2);
    snprintf(stack->ifname, sizeof stack->ifname, "%s", ifname);
}

int bye_backend_start(bye_backend_t *backend, const bye_backend_options_t *options,
                      char *reason, size_t reason_cap) {
    if (reason && reason_cap) reason[0] = '\0';
    if (!backend || !backend->initialized || !options) return -1;
    bye_backend_stop(backend);
    backend->error[0] = backend->warning[0] = '\0';
    const bye_config_t *config = &options->config;

    tun_plan_input_t input;
    if (physical_path(&input, reason, reason_cap) != 0) return -1;
    int conflict = address_in_use();
    if (conflict != 0) {
        reason_set(reason, reason_cap, conflict > 0
            ? "the tunnel address is already in use on another interface"
            : "device interface addresses could not be inspected");
        return -1;
    }
    if (config->hosts[0]) {
        char hosts_reason[160];
        backend->hosts = bye_hostsfile_load(options->hosts_dir ? options->hosts_dir : BYE_HOSTS_DIR,
                                            config->hosts, hosts_reason, sizeof hosts_reason);
        if (!backend->hosts) {
            reason_set(reason, reason_cap, hosts_reason);
            return -1;
        }
    }
    memset(&backend->direct, 0, sizeof backend->direct);
    snprintf(backend->direct.ifname, sizeof backend->direct.ifname, "%s", input.physical_ifname);
    backend->direct.ifindex = if_nametoindex(input.physical_ifname);
    /* an iphone 7 plus on ios 15.8.3 refused every direct connect with ENETUNREACH, and the
       log did not say which interface they were bound to */
    fprintf(stderr, "byedpid: direct traffic leaves by %s (index %u), ipv4 gateway %s, ipv6 %s\n",
            input.physical_ifname, backend->direct.ifindex, input.have_gateway4 ? "yes" : "none",
            input.have_gateway6 ? "gateway" : "no gateway");

    if (config->telegram) {
        char tls_error[BYE_WSCONN_ERROR_MAX];
        backend->tls = bye_wsconn_ctx_new(options->ca_file, tls_error, sizeof tls_error);
        if (!backend->tls) {
            /* the rest still works, and the status says why telegram does not */
            snprintf(backend->warning, sizeof backend->warning,
                     "telegram gateway is off: %.150s", tls_error);
            fprintf(stderr, "byedpid: %s\n", backend->warning);
        }
    }

    /* the lookups go out together before the routes change, by the network's
       own resolver */
    size_t relay_count = 0;
    char relay_names[BYE_TCP_RELAYS_MAX][BYE_TCP_RELAY_NAME_MAX];
    uint8_t relay_addrs[BYE_TCP_RELAYS_MAX][4];
    bye_tg_ws_addresses_t ws_addresses;
    memset(&ws_addresses, 0, sizeof ws_addresses);
    if (config->telegram && backend->tls) bye_resolve_gateways(&ws_addresses);
    if (config->telegram && backend->tls && config->relay[0])
        relay_count = bye_resolve_relays(config->relay, relay_names, relay_addrs, BYE_TCP_RELAYS_MAX,
                                         backend->warning, sizeof backend->warning);

    if (utun_device_open(&backend->device, 0) != UTUN_DEVICE_OK) {
        fail_with_errno(backend->error, sizeof backend->error, "cannot open a utun device",
                        backend->device.last_errno);
        goto failed;
    }
    snprintf(input.ifname, sizeof input.ifname, "%s", backend->device.ifname);
    if (tun_plan_build(&input, &backend->plan) != TUN_PLAN_OK) {
        reason_set(backend->error, sizeof backend->error, "the route plan is invalid");
        goto failed;
    }

    snprintf(backend->iface.ifname, sizeof backend->iface.ifname, "%s", input.ifname);
    inet_ntop(AF_INET, LOCAL4, backend->iface.local4, sizeof backend->iface.local4);
    inet_ntop(AF_INET, PEER4, backend->iface.peer4, sizeof backend->iface.peer4);
    uint8_t local6[16];
    ula_address(local6, 1);
    inet_ntop(AF_INET6, local6, backend->iface.local6, sizeof backend->iface.local6);
    backend->iface.mtu = BYE_TUN_MTU;
    if (bye_iface_up(&backend->iface) != 0) {
        int saved = errno;
        snprintf(backend->error, sizeof backend->error, "cannot give %s its address", input.ifname);
        route_errno_append(backend->error, sizeof backend->error, saved);
        goto failed;
    }

    backend->loop = calloc(1, tun_loop_size());
    backend->tcp = calloc(1, bye_tcp_size());
    backend->udp = calloc(1, bye_udp_size());
    if (!backend->loop || !backend->tcp || !backend->udp) {
        reason_set(backend->error, sizeof backend->error, "not enough memory for the tunnel");
        goto failed;
    }

    tun_loop_config_t loop_config;
    memset(&loop_config, 0, sizeof loop_config);
    loop_config.generation = ++backend->generation;
    stack_addresses(&loop_config.stack, input.ifname);
    loop_config.on_ready = ready;
    loop_config.ready_ctx = backend;
    loop_config.on_command = on_command;
    loop_config.command_ctx = backend;
    loop_config.retain_device_until_destroy = 1;

    bye_tcp_config_t tcp;
    memset(&tcp, 0, sizeof tcp);
    tcp.policy.telegram = config->telegram && backend->tls != NULL;
    tcp.ws_addresses = ws_addresses;
    tcp.strategies = config->desync_strategies;
    tcp.hosts = backend->hosts;
    tcp.hosts_only = config->hosts_only;
    tcp.pool = (size_t)config->pool;
    tcp.direct_socket = direct_socket_bound;
    tcp.direct_ctx = &backend->direct;
    tcp.tls = backend->tls;
    tcp.trace = options->trace;
    for (size_t i = 0; i < relay_count; ++i) {
        snprintf(tcp.relay[i], sizeof tcp.relay[i], "%.47s", relay_names[i]);
        memcpy(tcp.relay_addr[i], relay_addrs[i], 4);
    }
    tcp.relay_count = relay_count;
    bye_udp_config_t udp;
    memset(&udp, 0, sizeof udp);
    udp.direct_socket = direct_socket_bound;
    udp.direct_ctx = &backend->direct;
    udp.block_quic = config->block_quic;
    udp.trace = options->trace;
    if (config->dns[0]) {
        if (inet_pton(AF_INET, config->dns, tcp.dns) != 1) {
            reason_set(backend->error, sizeof backend->error, "the dns address is not an ipv4 address");
            goto failed;
        }
        memcpy(udp.dns, tcp.dns, 4);
        tcp.dns_set = udp.dns_set = 1;
    }
    if (bye_tcp_init(backend->tcp, &tcp, &loop_config) != 0 ||
        bye_udp_init(backend->udp, &udp, &loop_config) != 0 ||
        tun_loop_init(backend->loop, &loop_config, &backend->device) != TUN_LOOP_OK) {
        reason_set(backend->error, sizeof backend->error, "the packet loop could not start");
        goto failed;
    }
    backend->loop_initialized = 1;
    if (pthread_create(&backend->thread, NULL, run, backend) != 0) {
        reason_set(backend->error, sizeof backend->error, "the packet thread could not start");
        goto failed;
    }
    backend->thread_started = 1;

    struct timespec deadline;
    deadline_in(&deadline, START_WAIT_SEC);
    pthread_mutex_lock(&backend->lock);
    while (!backend->ready && !backend->ended)
        if (pthread_cond_timedwait(&backend->changed, &backend->lock, &deadline) == ETIMEDOUT)
            break;
    int started = backend->ready && !backend->ended;
    pthread_mutex_unlock(&backend->lock);
    if (!started) {
        snprintf(backend->error, sizeof backend->error, "%s",
                 backend->result.message[0] ? backend->result.message
                                            : "the packet loop did not become ready");
        goto failed;
    }

    utun_route_result_t routes;
    if (utun_route_apply_verified(&backend->plan, utun_route_system_executor(), &routes) !=
        UTUN_ROUTE_OK) {
        snprintf(backend->error, sizeof backend->error, "%.255s",
                 routes.failed_message[0] ? routes.failed_message : "route installation failed");
        goto failed;
    }
    leftovers_save(&backend->plan);
    backend->active = 1;

    /* ios before 12 needs a configd service for sockets bound to the original interface
       (EADDRNOTAVAIL on ios 5.1.1); reuse the current resolver unless another was chosen */
    char system_dns[INET_ADDRSTRLEN] = "";
    const char *dns_server = config->dns[0] ? config->dns : NULL;
    int service_needed = senko_ios_major() < 12;
    if (!dns_server && service_needed) {
        bye_resolver_status_t found = bye_resolver_system(system_dns, sizeof system_dns);
        /* ios 9.3.6 supplied no resolver through configd, so try the ipv4 router */
        if (found == BYE_RESOLVER_NONE && input.have_gateway4 &&
            inet_ntop(AF_INET, input.gateway4, system_dns, sizeof system_dns)) {
            fprintf(stderr, "byedpid: configd lists no dns server, using the router %s\n", system_dns);
            found = BYE_RESOLVER_FOUND;
        }
        if (found != BYE_RESOLVER_FOUND) {
            reason_set(backend->error, sizeof backend->error,
                       found == BYE_RESOLVER_IPV6_ONLY
                           ? "the system resolver is ipv6 only, give an ipv4 one with: byebyectl set dns ADDRESS"
                           : "cannot find the system resolver, give one with: byebyectl set dns ADDRESS");
            goto failed;
        }
        dns_server = system_dns;
    }
    if (dns_server) {
        char dns_reason[160];
        if (utun_dns_publish(&backend->dns, input.ifname, backend->iface.local4, backend->iface.peer4,
                             dns_server, dns_reason, sizeof dns_reason) == 0) {
            snprintf(backend->dns_state, sizeof backend->dns_state,
                     config->dns[0] ? "system dns is %s through %s"
                                    : "system dns stays %s, kept by a configd entry on %s",
                     dns_server, input.ifname);
        } else {
            snprintf(backend->dns_state, sizeof backend->dns_state,
                     "system dns stays outside the tunnel: %.150s", dns_reason);
            fprintf(stderr, "byedpid: %s\n", backend->dns_state);
            reason_set(backend->error, sizeof backend->error, backend->dns_state);
            goto failed;
        }
    }
    bye_badge_on(backend->direct.ifname);
    return 0;
failed:
    reason_set(reason, reason_cap, backend->error);
    bye_backend_stop(backend);
    return -1;
}

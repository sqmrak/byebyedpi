#define _DEFAULT_SOURCE

#include "bye_tgproxy.h"

#include "bye_mtp.h"
#include "bye_tg.h"
#include "tun/core/senko_time.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef MSG_NOSIGNAL
#define SEND_FLAGS MSG_NOSIGNAL
#else
#define SEND_FLAGS 0
#endif

#define INIT_WAIT_MS 10000
#define CONNECT_WAIT_MS 8000
#define HANDSHAKE_WAIT_MS 8000
#define WRITE_WAIT_MS 30000
#define SLICE_MS 200
#define PING_MS 30000
#define IDLE_MS 120000
#define STEP 16384
/* the client is not read while this much waits for the gateway */
#define QUEUE_HIGH (256u * 1024u)
#define STACK_SIZE (512u * 1024u)
/* a datacenter whose gateways all failed is refused at once for this long, or every
   client telegram opens waits out the connect timeouts and fills the client slots */
#define FAIL_MS 20000
#define FAIL_SLOTS 16

struct bye_tgproxy {
    bye_tgproxy_config_t config;
    int             listen_fd;
    int             wake[2];
    pthread_t       accept_thread;
    pthread_mutex_t lock;
    pthread_cond_t  idle;
    size_t          active;
    int             stopping;
    int64_t         fail_until[FAIL_SLOTS]; /* by datacenter and media, see fail_slot */
    bye_tgproxy_stats_t stats;
};

typedef struct {
    bye_tgproxy_t *proxy;
    int            fd;
} client_t;

static size_t fail_slot(const bye_mtp_route_t *route) {
    size_t dc = route->dc == BYE_TG_DC_CDN ? 6 : (size_t)route->dc;
    return (dc % (FAIL_SLOTS / 2)) * 2 + (route->is_media ? 1 : 0);
}

static void note_error(bye_tgproxy_t *proxy, const char *why) {
    pthread_mutex_lock(&proxy->lock);
    snprintf(proxy->stats.last_error, sizeof proxy->stats.last_error, "%s", why);
    pthread_mutex_unlock(&proxy->lock);
    fprintf(stderr, "byedpid: telegram proxy: %s\n", why);
}

static int is_stopping(bye_tgproxy_t *proxy) {
    pthread_mutex_lock(&proxy->lock);
    int stopping = proxy->stopping;
    pthread_mutex_unlock(&proxy->lock);
    return stopping;
}

/* 1 when the socket is ready, 0 on timeout, -1 when the proxy is stopping or
   the poll failed. an error or hangup counts as ready so the caller's own
   read, write or SO_ERROR names it */
static int wait_io(bye_tgproxy_t *proxy, int fd, short events, int64_t deadline_ms) {
    for (;;) {
        if (is_stopping(proxy)) return -1;
        int64_t left = deadline_ms - senko_now_ms();
        if (left <= 0) return 0;
        struct pollfd item = { fd, events, 0 };
        int ready = poll(&item, 1, left < SLICE_MS ? (int)left : SLICE_MS);
        if (ready < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (ready > 0) return 1;
    }
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 ? 0 : -1;
}

/* 0 when all of it left, -1 when the client is gone or too slow */
static int write_all(bye_tgproxy_t *proxy, int fd, const uint8_t *data, size_t len) {
    int64_t deadline = senko_now_ms() + WRITE_WAIT_MS;
    while (len) {
        ssize_t n = send(fd, data, len, SEND_FLAGS);
        if (n > 0) {
            data += n;
            len -= (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (wait_io(proxy, fd, POLLOUT, deadline) != 1) return -1;
            continue;
        }
        return -1;
    }
    return 0;
}

/* reads exactly len bytes. 0 done, 1 the client closed first, -1 timeout or error */
static int read_exact(bye_tgproxy_t *proxy, int fd, uint8_t *out, size_t len, int64_t deadline) {
    size_t have = 0;
    while (have < len) {
        ssize_t n = recv(fd, out + have, len - have, 0);
        if (n > 0) {
            have += (size_t)n;
            continue;
        }
        if (n == 0) return 1;
        if (errno == EINTR) continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK) return -1;
        if (wait_io(proxy, fd, POLLIN, deadline) != 1) return -1;
    }
    return 0;
}

/* a connected tcp socket to the gateway address, or -1 with the reason */
static int gateway_dial(bye_tgproxy_t *proxy, const uint8_t addr[4], uint16_t port, char *why,
                        size_t why_cap) {
    char error[160];
    int fd = proxy->config.socket
        ? proxy->config.socket(proxy->config.socket_ctx, AF_INET, SOCK_STREAM, error, sizeof error)
        : -1;
    if (fd < 0) {
        snprintf(why, why_cap, "%s", proxy->config.socket ? error : "no socket source for the gateway");
        return -1;
    }
    /* the websocket frames are small and the client waits for each answer */
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &(int){ 1 }, sizeof(int));
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
#ifdef __APPLE__
    to.sin_len = sizeof to;
#endif
    to.sin_family = AF_INET;
    to.sin_port = htons(port);
    memcpy(&to.sin_addr, addr, 4);
    if (connect(fd, (struct sockaddr *)&to, sizeof to) != 0 && errno != EINPROGRESS) {
        snprintf(why, why_cap, "connect failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    if (wait_io(proxy, fd, POLLOUT, senko_now_ms() + CONNECT_WAIT_MS) != 1) {
        snprintf(why, why_cap, "the gateway did not accept the connection in time");
        close(fd);
        return -1;
    }
    int value = 0;
    socklen_t value_len = sizeof value;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &value_len) != 0) value = errno;
    if (value != 0) {
        snprintf(why, why_cap, "connect failed: %s", strerror(value));
        close(fd);
        return -1;
    }
    return fd;
}

/* tls and the upgrade. 0 once the socket carries websocket frames */
static int ws_open(bye_tgproxy_t *proxy, bye_wsconn_t *ws, int fd, char *why, size_t why_cap) {
    int64_t deadline = senko_now_ms() + HANDSHAKE_WAIT_MS;
    for (;;) {
        bye_wsconn_status_t status = bye_wsconn_handshake(ws);
        if (status == BYE_WSCONN_OK) return 0;
        if (status != BYE_WSCONN_WANT_READ && status != BYE_WSCONN_WANT_WRITE) {
            snprintf(why, why_cap, "%s", status == BYE_WSCONN_ERR ? bye_wsconn_error(ws)
                                                                  : "the gateway closed");
            return -1;
        }
        if (wait_io(proxy, fd, status == BYE_WSCONN_WANT_WRITE ? POLLOUT : POLLIN, deadline) != 1) {
            snprintf(why, why_cap, "the gateway handshake did not finish in time");
            return -1;
        }
    }
}

static int emit_ws(void *ctx, const uint8_t *msg, size_t len) {
    return bye_wsconn_send(ctx, msg, len);
}

/* a gateway for the datacenter: relays first, then the datacenter's own
   address, like the tunnel's telegram path. 0 with a ready websocket */
static int gateway_open(bye_tgproxy_t *proxy, const bye_mtp_route_t *route, int *out_fd,
                        bye_wsconn_t **out_ws) {
    const bye_tgproxy_config_t *config = &proxy->config;
    int gateway = route->dc == BYE_TG_DC_CDN ? 2 : route->dc;
    char why[BYE_WSCONN_ERROR_MAX + 64] = "no gateway for the datacenter";
    bye_tg_gateway_t gateways[BYE_TG_GATEWAYS_MAX];
    size_t count = bye_tg_gateways(route->dc, route->is_media,
        config->gateway_set ? NULL : &config->ws_addresses, gateways, BYE_TG_GATEWAYS_MAX);
    if (config->gateway_set)
        for (size_t i = 0; i < count; ++i) memcpy(gateways[i].address, config->gateway, 4);
    size_t total = config->relay_count + count;
    for (size_t variant = 0; variant < total; ++variant) {
        char host[BYE_TG_WS_HOST_MAX + BYE_TGPROXY_RELAY_NAME_MAX];
        uint8_t address[4];
        uint16_t port = 443;
        if (variant < config->relay_count) {
            snprintf(host, sizeof host, "kws%d.%s", gateway, config->relay[variant]);
            memcpy(address, config->relay_addr[variant], 4);
        } else {
            size_t index = variant - config->relay_count;
            snprintf(host, sizeof host, "%s", gateways[index].host);
            memcpy(address, gateways[index].address, 4);
        }
        if (config->gateway_set) {
            memcpy(address, config->gateway, 4);
        }
        if (config->gateway_port) port = config->gateway_port;
        int fd = gateway_dial(proxy, address, port, why, sizeof why);
        if (fd < 0) {
            char text[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, address, text, sizeof text))
                fprintf(stderr, "byedpid: telegram proxy: %s at %s: %s\n", host, text, why);
            if (is_stopping(proxy)) return -1;
            if (variant >= config->relay_count) {
                size_t next = bye_tg_gateway_next(gateways, count, variant - config->relay_count, 1);
                variant = config->relay_count + next - 1;
            }
            continue;
        }
        bye_wsconn_t *ws = bye_wsconn_new(config->tls, fd, host, BYE_TG_WS_PATH);
        if (!ws) {
            snprintf(why, sizeof why, "cannot start the tls session");
            close(fd);
            continue;
        }
        if (ws_open(proxy, ws, fd, why, sizeof why) == 0) {
            *out_fd = fd;
            *out_ws = ws;
            return 0;
        }
        bye_wsconn_free(ws);
        close(fd);
        if (is_stopping(proxy)) return -1;
        if (config->trace) fprintf(stderr, "byedpid: telegram proxy: dc%d via %s: %s\n", route->dc, host, why);
    }
    char line[BYE_TGPROXY_ERROR_MAX];
    snprintf(line, sizeof line, "dc%d has no reachable gateway for %d s: %.90s", route->dc, FAIL_MS / 1000, why);
    note_error(proxy, line);
    return -1;
}

static void add_bytes(bye_tgproxy_t *proxy, uint64_t up, uint64_t down) {
    pthread_mutex_lock(&proxy->lock);
    proxy->stats.bytes_up += up;
    proxy->stats.bytes_down += down;
    pthread_mutex_unlock(&proxy->lock);
}

/* moves the stream both ways until either side ends */
static void pump(bye_tgproxy_t *proxy, int client_fd, int ws_fd, bye_wsconn_t *ws, bye_mtp_t *mtp) {
    uint8_t buf[STEP];
    int64_t last_rx = senko_now_ms();
    int ping_sent = 0, client_eof = 0, ws_closed = 0;
    for (;;) {
        if (is_stopping(proxy)) return;
        int ws_want_write = 0;
        bye_wsconn_status_t flushed = bye_wsconn_flush(ws);
        if (flushed == BYE_WSCONN_ERR || flushed == BYE_WSCONN_CLOSED) return;
        if (flushed == BYE_WSCONN_WANT_WRITE) ws_want_write = 1;
        size_t queued = bye_wsconn_pending(ws);
        if (queued) ws_want_write = 1;
        if (client_eof && queued == 0) return;

        /* what the gateway already delivered is read before the next poll */
        int ws_ready = bye_wsconn_buffered(ws);
        struct pollfd fds[2];
        fds[0].fd = client_fd;
        fds[0].events = !client_eof && queued < QUEUE_HIGH ? POLLIN : 0;
        fds[0].revents = 0;
        fds[1].fd = ws_fd;
        fds[1].events = (ws_closed ? 0 : POLLIN) | (ws_want_write ? POLLOUT : 0);
        fds[1].revents = 0;
        int ready = ws_ready ? 0 : poll(fds, 2, SLICE_MS);
        if (ready < 0 && errno != EINTR) return;
        if (ready < 0) continue;

        int64_t now = senko_now_ms();
        if (ws_ready || (fds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            for (;;) {
                size_t got = 0;
                bye_wsconn_status_t status = bye_wsconn_read(ws, buf, sizeof buf, &got);
                if (got > 0) {
                    if (bye_mtp_down(mtp, buf, got) != BYE_MTP_OK ||
                        write_all(proxy, client_fd, buf, got) != 0)
                        return;
                    add_bytes(proxy, 0, got);
                    last_rx = now;
                    ping_sent = 0;
                    continue;
                }
                if (status == BYE_WSCONN_ERR) return;
                if (status == BYE_WSCONN_CLOSED) ws_closed = 1;
                break;
            }
            /* telegram ends both directions together */
            if (ws_closed) return;
        }
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = recv(client_fd, buf, sizeof buf, 0);
            if (n > 0) {
                if (bye_mtp_up(mtp, buf, (size_t)n, emit_ws, ws) != BYE_MTP_OK) return;
                add_bytes(proxy, (uint64_t)n, 0);
                last_rx = now;
            } else if (n == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) {
                client_eof = 1;
                if (bye_mtp_up_flush(mtp, emit_ws, ws) != BYE_MTP_OK) return;
            }
        }
        if (now - last_rx >= IDLE_MS) return;
        if (!ping_sent && now - last_rx >= PING_MS) {
            ping_sent = 1;
            if (bye_wsconn_ping(ws) != 0) return;
        }
    }
}

static void serve(bye_tgproxy_t *proxy, int client_fd) {
    uint8_t init[BYE_MTP_INIT_LEN], relay_init[BYE_MTP_INIT_LEN];
    if (set_nonblocking(client_fd) != 0) return;
#ifdef SO_NOSIGPIPE
    (void)setsockopt(client_fd, SOL_SOCKET, SO_NOSIGPIPE, &(int){ 1 }, sizeof(int));
#endif
    (void)setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &(int){ 1 }, sizeof(int));
    int got = read_exact(proxy, client_fd, init, sizeof init, senko_now_ms() + INIT_WAIT_MS);
    if (got != 0) return;

    bye_mtp_t *mtp = NULL;
    bye_mtp_route_t route;
    memset(&route, 0, sizeof route);
    if (bye_mtp_open(&mtp, proxy->config.secret, sizeof proxy->config.secret, init, &route,
                     relay_init) != BYE_MTP_OK) {
        pthread_mutex_lock(&proxy->lock);
        ++proxy->stats.bad_init;
        pthread_mutex_unlock(&proxy->lock);
        note_error(proxy, "a client did not speak mtproto with this secret");
        return;
    }
    memset(init, 0, sizeof init);
    if (!bye_tg_dc_known(route.dc)) {
        char line[BYE_TGPROXY_ERROR_MAX];
        snprintf(line, sizeof line, "a client asked for the unknown datacenter %d", route.dc);
        note_error(proxy, line);
        bye_mtp_close(mtp);
        return;
    }

    size_t slot = fail_slot(&route);
    pthread_mutex_lock(&proxy->lock);
    int recent = proxy->fail_until[slot] > senko_now_ms();
    if (recent) ++proxy->stats.gateway_fail;
    pthread_mutex_unlock(&proxy->lock);
    if (recent) {
        bye_mtp_close(mtp);
        return;
    }
    int ws_fd = -1;
    bye_wsconn_t *ws = NULL;
    if (gateway_open(proxy, &route, &ws_fd, &ws) != 0) {
        pthread_mutex_lock(&proxy->lock);
        ++proxy->stats.gateway_fail;
        proxy->fail_until[slot] = senko_now_ms() + FAIL_MS;
        pthread_mutex_unlock(&proxy->lock);
        bye_mtp_close(mtp);
        return;
    }
    pthread_mutex_lock(&proxy->lock);
    ++proxy->stats.gateway_ok;
    pthread_mutex_unlock(&proxy->lock);
    if (proxy->config.trace) fprintf(stderr, "byedpid: telegram proxy: dc%d open\n", route.dc);

    /* the datacenter expects its own init first, in a message of its own */
    if (bye_wsconn_send(ws, relay_init, sizeof relay_init) == 0)
        pump(proxy, client_fd, ws_fd, ws, mtp);
    memset(relay_init, 0, sizeof relay_init);
    bye_wsconn_free(ws);
    close(ws_fd);
    bye_mtp_close(mtp);
}

static void *client_main(void *arg) {
    client_t *client = arg;
    bye_tgproxy_t *proxy = client->proxy;
    serve(proxy, client->fd);
    close(client->fd);
    free(client);
    pthread_mutex_lock(&proxy->lock);
    --proxy->stats.active;
    --proxy->active;
    pthread_cond_broadcast(&proxy->idle);
    pthread_mutex_unlock(&proxy->lock);
    return NULL;
}

static void *accept_main(void *arg) {
    bye_tgproxy_t *proxy = arg;
    for (;;) {
        struct pollfd fds[2] = { { proxy->listen_fd, POLLIN, 0 }, { proxy->wake[0], POLLIN, 0 } };
        if (poll(fds, 2, -1) < 0) {
            if (errno == EINTR) continue;
            return NULL;
        }
        if (fds[1].revents) return NULL;
        if (!(fds[0].revents & POLLIN)) continue;
        int fd = accept(proxy->listen_fd, NULL, NULL);
        if (fd < 0) continue;
        (void)fcntl(fd, F_SETFD, FD_CLOEXEC);

        pthread_mutex_lock(&proxy->lock);
        int full = proxy->active >= BYE_TGPROXY_CLIENTS_MAX;
        if (!full) {
            ++proxy->active;
            ++proxy->stats.active;
            ++proxy->stats.clients;
        }
        pthread_mutex_unlock(&proxy->lock);
        client_t *client = full ? NULL : malloc(sizeof *client);
        pthread_t thread;
        pthread_attr_t attr;
        int started = 0;
        if (client) {
            client->proxy = proxy;
            client->fd = fd;
            if (pthread_attr_init(&attr) == 0) {
                (void)pthread_attr_setstacksize(&attr, STACK_SIZE);
                (void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                started = pthread_create(&thread, &attr, client_main, client) == 0;
                pthread_attr_destroy(&attr);
            }
        }
        if (started) continue;
        if (!full) {
            pthread_mutex_lock(&proxy->lock);
            --proxy->active;
            --proxy->stats.active;
            pthread_mutex_unlock(&proxy->lock);
        }
        if (!full) note_error(proxy, "cannot start a client thread");
        free(client);
        close(fd);
    }
}

int bye_tgproxy_secret_parse(const char *hex, uint8_t out[16]) {
    if (!hex || strlen(hex) != 32) return -1;
    for (size_t i = 0; i < 16; ++i) {
        int value = 0;
        for (size_t j = 0; j < 2; ++j) {
            char c = hex[i * 2 + j];
            int digit = c >= '0' && c <= '9' ? c - '0'
                      : c >= 'a' && c <= 'f' ? c - 'a' + 10
                      : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
            if (digit < 0) return -1;
            value = value * 16 + digit;
        }
        out[i] = (uint8_t)value;
    }
    return 0;
}

bye_tgproxy_t *bye_tgproxy_start(const bye_tgproxy_config_t *config, char *error, size_t error_cap) {
    if (error && error_cap) error[0] = '\0';
    if (!config || !config->tls || !config->socket || config->port == 0) {
        if (error && error_cap) snprintf(error, error_cap, "the proxy has no port, tls or socket source");
        return NULL;
    }
    bye_tgproxy_t *proxy = calloc(1, sizeof *proxy);
    if (!proxy) {
        if (error && error_cap) snprintf(error, error_cap, "not enough memory");
        return NULL;
    }
    proxy->config = *config;
    proxy->listen_fd = proxy->wake[0] = proxy->wake[1] = -1;
    if (pthread_mutex_init(&proxy->lock, NULL) != 0) {
        free(proxy);
        return NULL;
    }
    if (pthread_cond_init(&proxy->idle, NULL) != 0) {
        pthread_mutex_destroy(&proxy->lock);
        free(proxy);
        return NULL;
    }

    const char *what = NULL;
    int saved = 0;
    proxy->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy->listen_fd < 0) {
        what = "cannot open the listening socket";
        goto fail;
    }
    (void)fcntl(proxy->listen_fd, F_SETFD, FD_CLOEXEC);
    (void)setsockopt(proxy->listen_fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
    struct sockaddr_in local;
    memset(&local, 0, sizeof local);
#ifdef __APPLE__
    local.sin_len = sizeof local;
#endif
    local.sin_family = AF_INET;
    local.sin_port = htons(config->port);
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(proxy->listen_fd, (struct sockaddr *)&local, sizeof local) != 0) {
        what = "cannot bind 127.0.0.1";
        goto fail;
    }
    if (listen(proxy->listen_fd, 16) != 0) {
        what = "cannot listen";
        goto fail;
    }
    if (pipe(proxy->wake) != 0) {
        what = "cannot open the wake pipe";
        goto fail;
    }
    (void)fcntl(proxy->wake[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(proxy->wake[1], F_SETFD, FD_CLOEXEC);
    if (pthread_create(&proxy->accept_thread, NULL, accept_main, proxy) != 0) {
        what = "cannot start the accept thread";
        goto fail;
    }
    return proxy;
fail:
    saved = errno;
    if (error && error_cap)
        snprintf(error, error_cap, "%s (port %u): %s", what, (unsigned)config->port, strerror(saved));
    if (proxy->listen_fd >= 0) close(proxy->listen_fd);
    if (proxy->wake[0] >= 0) close(proxy->wake[0]);
    if (proxy->wake[1] >= 0) close(proxy->wake[1]);
    pthread_cond_destroy(&proxy->idle);
    pthread_mutex_destroy(&proxy->lock);
    free(proxy);
    return NULL;
}

void bye_tgproxy_stop(bye_tgproxy_t *proxy) {
    if (!proxy) return;
    pthread_mutex_lock(&proxy->lock);
    proxy->stopping = 1;
    pthread_mutex_unlock(&proxy->lock);
    if (write(proxy->wake[1], "x", 1) < 0) {
        /* a full pipe already holds a wakeup */
    }
    pthread_join(proxy->accept_thread, NULL);
    close(proxy->listen_fd);
    close(proxy->wake[0]);
    close(proxy->wake[1]);
    pthread_mutex_lock(&proxy->lock);
    while (proxy->active) pthread_cond_wait(&proxy->idle, &proxy->lock);
    pthread_mutex_unlock(&proxy->lock);
    pthread_cond_destroy(&proxy->idle);
    pthread_mutex_destroy(&proxy->lock);
    free(proxy);
}

void bye_tgproxy_stats(bye_tgproxy_t *proxy, bye_tgproxy_stats_t *out) {
    if (!out) return;
    memset(out, 0, sizeof *out);
    if (!proxy) return;
    pthread_mutex_lock(&proxy->lock);
    *out = proxy->stats;
    pthread_mutex_unlock(&proxy->lock);
}

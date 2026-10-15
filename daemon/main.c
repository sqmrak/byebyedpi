#define _DEFAULT_SOURCE

#include "bye_backend.h"
#include "bye_badge.h"
#include "bye_config.h"
#include "bye_ctl.h"
#include "bye_paths.h"
#include "bye_probe.h"
#include "bye_tgproxy.h"
#include "bye_tls_owner.h"
#include "tun/legacy_ios.h"
#include "tun/core/senko_time.h"
#include "tun/proc_detach.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define PATH_MAX_LEN 256
#define NETWORK_CHECK_MS 3000
#define RETRY_MS 5000
#define RETRY_MAX 12

typedef struct {
    bye_backend_t backend;
    bye_probe_t  *probe;        /* made by the first probe command */
    bye_config_t  config;
    char          config_path[PATH_MAX_LEN];
    char          ca_file[PATH_MAX_LEN];
    char          token_path[PATH_MAX_LEN];
    int           trace;
    int           managed; /* launchd started the process */
    int           wanted;       /* the user asked for a tunnel, keep trying to hold one */
    int           attempts;     /* tries since the tunnel last worked */
    int64_t       next_try_ms;
    int64_t       next_check_ms;
    int64_t       started_ms;
    char          last_error[256];
    char          config_error[BYE_CONFIG_ERROR_MAX];
    char          running_spec[BYE_CONFIG_SPEC_MAX]; /* what the running tunnel was started with */
    bye_tgproxy_t *proxy;
    bye_wsconn_ctx_t *proxy_tls;
    char          proxy_error[BYE_TGPROXY_ERROR_MAX];
    int           tls_switch;
    int           tls_restart;
    char          tls_error[256];
    /* the physical interface the tunnel leaves by, for the proxy's sockets, which
       are made on other threads than the one that starts and stops the tunnel */
    pthread_mutex_t direct_lock;
    direct_socket_iface_t direct;
    int           direct_valid;
} daemon_t;

static int signal_pipe[2] = { -1, -1 };

static void on_signal(int sig) {
    int saved = errno;
    unsigned char byte = (unsigned char)sig;
    if (write(signal_pipe[1], &byte, 1) < 0) {
        /* a full pipe already holds a wakeup */
    }
    errno = saved;
}

static void usage(void) {
    fprintf(stderr,
            "usage: byedpid [--ctl PATH] [--config PATH] [--ca PATH] [--trace] [--managed]\n"
            "       byedpid --restore-tls\n");
}


static int read_file(const char *path, char *buf, size_t cap, size_t *len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return errno == ENOENT ? 1 : -1;
    ssize_t got = read(fd, buf, cap);
    int saved = errno;
    close(fd);
    if (got < 0) {
        errno = saved;
        return -1;
    }
    *len = (size_t)got;
    return 0;
}

/* the options of ciadpi the config names but this system leaves out */
static void log_notes(const bye_config_t *config) {
    const char *notes = config->desync_strategies.notes;
    while (*notes) {
        const char *end = strchr(notes, '\n');
        size_t n = end ? (size_t)(end - notes) : strlen(notes);
        fprintf(stderr, "byedpid: desync.spec: %.*s\n", (int)n, notes);
        notes += n + (end ? 1 : 0);
    }
}

static int save_config(const daemon_t *d);

static void load_config(daemon_t *d) {
    char text[BYE_CONFIG_FILE_MAX + 2];
    size_t len = 0;
    bye_config_t loaded;
    d->config_error[0] = '\0';
    bye_config_defaults(&loaded);
    int read_status = read_file(d->config_path, text, sizeof text, &len);
    if (read_status == 0) loaded.version = 1;
    if (read_status < 0) {
        snprintf(d->config_error, sizeof d->config_error, "cannot read the file (errno %d)", errno);
    } else if (read_status == 0 &&
               bye_config_parse(text, len, &loaded, d->config_error, sizeof d->config_error) !=
                   BYE_CONFIG_OK) {
        bye_config_defaults(&loaded);
    }
    int migrated = read_status == 0 && !d->config_error[0] && bye_config_migrate(&loaded);
    if (d->config_error[0])
        fprintf(stderr, "byedpid: %s: %s\n", d->config_path, d->config_error);
    d->config = loaded;
    if (migrated && save_config(d) != 0)
        fprintf(stderr, "byedpid: cannot write the migrated config file\n");
    if (d->config.spec_reduced)
        fprintf(stderr, "byedpid: desync.spec held a list split by |, only its first strategy is used\n");
    log_notes(&d->config);
}

static int save_config(const daemon_t *d) {
    char text[BYE_CONFIG_FILE_MAX];
    if (bye_config_render(&d->config, text, sizeof text) != 0) return -1;
    char tmp[PATH_MAX_LEN + 8];
    if (snprintf(tmp, sizeof tmp, "%s.new", d->config_path) >= (int)sizeof tmp) return -1;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    size_t len = strlen(text);
    int ok = write(fd, text, len) == (ssize_t)len && fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    if (!ok || rename(tmp, d->config_path) != 0) {
        (void)unlink(tmp);
        return -1;
    }
    return 0;
}


static int tls_owner(daemon_t *d, int enabled) {
    if (!d->tls_switch) return 0;
    int changed = 0;
    int result = bye_tls_owner_set(enabled, &changed, d->tls_error, sizeof d->tls_error);
    if (changed) {
        d->tls_restart = 1;
        fprintf(stderr, "byedpid: %s tlsfix, restart apps to reload their tls hooks\n",
                enabled ? "disabled" : "restored");
    }
    if (result != 0) fprintf(stderr, "byedpid: %s\n", d->tls_error);
    return result;
}

static int tunnel_start(daemon_t *d, char *reason, size_t cap) {
    bye_backend_options_t options;
    memset(&options, 0, sizeof options);
    options.config = d->config;
    options.ca_file = d->ca_file;
    options.trace = d->trace;
    if (tls_owner(d, 1) != 0) {
        snprintf(reason, cap, "%s", d->tls_error);
        tls_owner(d, 0);
        return -1;
    }
    if (bye_backend_start(&d->backend, &options, reason, cap) != 0) {
        tls_owner(d, 0);
        return -1;
    }
    pthread_mutex_lock(&d->direct_lock);
    d->direct_valid = bye_backend_direct(&d->backend, &d->direct) == 0;
    pthread_mutex_unlock(&d->direct_lock);
    snprintf(d->running_spec, sizeof d->running_spec, "%s", d->config.desync_spec);
    d->started_ms = senko_now_ms();
    d->last_error[0] = '\0';
    fprintf(stderr, "byedpid: tunnel up on %s\n", bye_backend_ifname(&d->backend));
    return 0;
}

static void tunnel_stop(daemon_t *d) {
    tls_owner(d, 0);
    if (!bye_backend_running(&d->backend) && !d->backend.active) return;
    pthread_mutex_lock(&d->direct_lock);
    d->direct_valid = 0;
    pthread_mutex_unlock(&d->direct_lock);
    bye_backend_stop(&d->backend);
    d->running_spec[0] = '\0';
    d->started_ms = 0;
    fprintf(stderr, "byedpid: tunnel stopped\n");
}

static void remember_error(daemon_t *d, const char *why) {
    snprintf(d->last_error, sizeof d->last_error, "%s", why);
    fprintf(stderr, "byedpid: %s\n", why);
}


/* the proxy's sockets leave by the physical interface while the tunnel is up,
   or the kernel would send them back into utun, and are plain sockets while it
   is down */
static int proxy_socket(void *ctx, int family, int type, char *error, size_t error_cap) {
    daemon_t *d = ctx;
    direct_socket_iface_t iface;
    pthread_mutex_lock(&d->direct_lock);
    int bound = d->direct_valid;
    iface = d->direct;
    pthread_mutex_unlock(&d->direct_lock);
    if (bound) return direct_socket_bound(&iface, family, type, error, error_cap);
    int fd = socket(family, type, 0);
    int flags = fd >= 0 ? fcntl(fd, F_GETFL, 0) : -1;
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        snprintf(error, error_cap, "cannot open a socket (errno %d)", errno);
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}

static void proxy_stop(daemon_t *d) {
    bye_tgproxy_stop(d->proxy);
    d->proxy = NULL;
    bye_wsconn_ctx_free(d->proxy_tls);
    d->proxy_tls = NULL;
}

/* 16 random bytes as 32 lowercase hex digits. 0 on success */
static int draw_secret(char out[BYE_CONFIG_SECRET_LEN + 1]) {
    uint8_t raw[BYE_CONFIG_SECRET_LEN / 2];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t have = 0;
    while (have < sizeof raw) {
        ssize_t n = read(fd, raw + have, sizeof raw - have);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        have += (size_t)n;
    }
    close(fd);
    if (have != sizeof raw) return -1;
    for (size_t i = 0; i < sizeof raw; ++i) snprintf(out + i * 2, 3, "%02x", raw[i]);
    return 0;
}

/* makes the proxy match the config: stopped when it is off, restarted otherwise */
static void proxy_apply(daemon_t *d) {
    proxy_stop(d);
    d->proxy_error[0] = '\0';
    if (!d->config.proxy) return;
    if (!d->config.proxy_secret[0]) {
        bye_config_t next = d->config;
        if (draw_secret(next.proxy_secret) != 0) {
            snprintf(d->proxy_error, sizeof d->proxy_error, "cannot draw a secret from /dev/urandom");
            fprintf(stderr, "byedpid: telegram proxy: %s\n", d->proxy_error);
            return;
        }
        bye_config_t previous = d->config;
        d->config = next;
        if (save_config(d) != 0) {
            d->config = previous;
            snprintf(d->proxy_error, sizeof d->proxy_error, "cannot write the config file");
            fprintf(stderr, "byedpid: telegram proxy: %s\n", d->proxy_error);
            return;
        }
    }
    bye_tgproxy_config_t config;
    memset(&config, 0, sizeof config);
    config.port = (uint16_t)d->config.proxy_port;
    if (bye_tgproxy_secret_parse(d->config.proxy_secret, config.secret) != 0) {
        snprintf(d->proxy_error, sizeof d->proxy_error, "the proxy secret is not 32 hex digits");
        return;
    }
    char tls_error[BYE_WSCONN_ERROR_MAX];
    d->proxy_tls = bye_wsconn_ctx_new(d->ca_file, tls_error, sizeof tls_error);
    if (!d->proxy_tls) {
        snprintf(d->proxy_error, sizeof d->proxy_error, "tls is not available: %.120s", tls_error);
        fprintf(stderr, "byedpid: telegram proxy: %s\n", d->proxy_error);
        return;
    }
    config.tls = d->proxy_tls;
    config.socket = proxy_socket;
    config.socket_ctx = d;
    config.trace = d->trace;
    bye_resolve_gateways(&config.ws_addresses);
    if (d->config.relay[0]) {
        char names[BYE_TGPROXY_RELAYS_MAX][BYE_TGPROXY_RELAY_NAME_MAX];
        uint8_t addrs[BYE_TGPROXY_RELAYS_MAX][4];
        char warning[160] = "";
        size_t found = bye_resolve_relays(d->config.relay, names, addrs, BYE_TGPROXY_RELAYS_MAX,
                                          warning, sizeof warning);
        for (size_t i = 0; i < found; ++i) {
            memcpy(config.relay[i], names[i], sizeof config.relay[i]);
            memcpy(config.relay_addr[i], addrs[i], 4);
        }
        config.relay_count = found;
    }
    d->proxy = bye_tgproxy_start(&config, d->proxy_error, sizeof d->proxy_error);
    if (!d->proxy) {
        fprintf(stderr, "byedpid: telegram proxy: %s\n", d->proxy_error);
        bye_wsconn_ctx_free(d->proxy_tls);
        d->proxy_tls = NULL;
        return;
    }
    fprintf(stderr, "byedpid: telegram proxy on 127.0.0.1:%d\n", d->config.proxy_port);
}


static size_t emit(char *out, size_t cap, size_t at, const char *fmt, ...) __attribute__((format(printf, 4, 5)));

static size_t emit(char *out, size_t cap, size_t at, const char *fmt, ...) {
    if (at >= cap) return at;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out + at, cap - at, fmt, ap);
    va_end(ap);
    if (n < 0) return at;
    return at + (size_t)n < cap ? at + (size_t)n : cap - 1;
}

static size_t reply_line(char *out, size_t cap, const char *status, const char *detail) {
    return (size_t)snprintf(out, cap, "%s%s%s\n.\n", status, detail && detail[0] ? " " : "",
                            detail ? detail : "");
}

static size_t status_reply(daemon_t *d, char *out, size_t cap) {
    bye_backend_snapshot_t snap;
    int have = bye_backend_snapshot(&d->backend, &snap) == 0;
    int running = bye_backend_running(&d->backend);
    char ended[256];
    bye_backend_end_reason(&d->backend, ended, sizeof ended);
    size_t at = emit(out, cap, 0, "OK\n");
    at = emit(out, cap, at, "running=%d\n", running);
    at = emit(out, cap, at, "wanted=%d\n", d->wanted);
    at = emit(out, cap, at, "interface=%s\n", bye_backend_ifname(&d->backend));
    char external[sizeof d->backend.direct.ifname], external_error[sizeof d->last_error];
    if (bye_backend_external_interface(&d->backend, external, sizeof external,
                                       external_error, sizeof external_error) == 0)
        at = emit(out, cap, at, "external_interface=%s\n", external);
    else
        at = emit(out, cap, at, "external_interface=\nexternal_interface.error=%s\n", external_error);
    at = emit(out, cap, at, "seconds=%lld\n",
              running && d->started_ms ? (long long)((senko_now_ms() - d->started_ms) / 1000) : 0LL);
    at = emit(out, cap, at, "attempts=%d\n", d->attempts);
    at = emit(out, cap, at, "error=%s\n", d->last_error);
    at = emit(out, cap, at, "ended=%s\n", ended);
    at = emit(out, cap, at, "warning=%s\n", bye_backend_warning(&d->backend));
    at = emit(out, cap, at, "tls.restart_required=%d\ntls.error=%s\n", d->tls_restart, d->tls_error);
    at = emit(out, cap, at, "config_error=%s\n", d->config_error);
    at = emit(out, cap, at, "dns=%s\n", bye_backend_dns_state(&d->backend));
    at = emit(out, cap, at, "configd=%s\n", d->backend.dns.diagnostic);
    at = emit(out, cap, at, "strategy=%s\n", d->running_spec);
    at = emit(out, cap, at, "proxy=%d\n", d->proxy != NULL);
    at = emit(out, cap, at, "proxy.error=%s\n", d->proxy_error);
    if (d->proxy) {
        bye_tgproxy_stats_t ps;
        bye_tgproxy_stats(d->proxy, &ps);
        at = emit(out, cap, at, "proxy.clients=%llu\n", (unsigned long long)ps.clients);
        at = emit(out, cap, at, "proxy.active=%llu\n", (unsigned long long)ps.active);
        at = emit(out, cap, at, "proxy.gateway_ok=%llu\n", (unsigned long long)ps.gateway_ok);
        at = emit(out, cap, at, "proxy.gateway_fail=%llu\n", (unsigned long long)ps.gateway_fail);
        at = emit(out, cap, at, "proxy.bad_init=%llu\n", (unsigned long long)ps.bad_init);
        at = emit(out, cap, at, "proxy.up=%llu\n", (unsigned long long)ps.bytes_up);
        at = emit(out, cap, at, "proxy.down=%llu\n", (unsigned long long)ps.bytes_down);
        at = emit(out, cap, at, "proxy.last_error=%s\n", ps.last_error);
    }
    if (have) {
        at = emit(out, cap, at, "tcp.requested=%llu\n", (unsigned long long)snap.tcp.requested);
        at = emit(out, cap, at, "tcp.direct=%llu\n", (unsigned long long)snap.tcp.direct);
        at = emit(out, cap, at, "tcp.desync=%llu\n", (unsigned long long)snap.tcp.desync_applied);
        at = emit(out, cap, at, "tcp.desync_passed=%llu\n", (unsigned long long)snap.tcp.desync_passed);
        at = emit(out, cap, at, "tcp.fake_sent=%llu\n", (unsigned long long)snap.tcp.fake_sent);
        at = emit(out, cap, at, "tcp.fake_missed=%llu\n", (unsigned long long)snap.tcp.fake_missed);
        at = emit(out, cap, at, "tcp.telegram=%llu\n", (unsigned long long)snap.tcp.telegram_ws);
        at = emit(out, cap, at, "tcp.telegram_fallback=%llu\n",
                  (unsigned long long)snap.tcp.telegram_fallback);
        at = emit(out, cap, at, "tcp.pool_hits=%llu\n", (unsigned long long)snap.tcp.pool_hits);
        at = emit(out, cap, at, "tcp.pool_misses=%llu\n", (unsigned long long)snap.tcp.pool_misses);
        at = emit(out, cap, at, "tcp.pool_ready=%llu\n", (unsigned long long)snap.tcp.pool_ready);
        at = emit(out, cap, at, "tcp.hosts_skipped=%llu\n", (unsigned long long)snap.tcp.hosts_skipped);
        at = emit(out, cap, at, "tcp.auto_retried=%llu\n", (unsigned long long)snap.tcp.auto_retried);
        at = emit(out, cap, at, "tcp.auto_learned=%llu\n", (unsigned long long)snap.tcp.auto_learned);
        at = emit(out, cap, at, "tcp.auto_exhausted=%llu\n", (unsigned long long)snap.tcp.auto_exhausted);
        at = emit(out, cap, at, "tcp.addr_retried=%llu\n", (unsigned long long)snap.tcp.addr_retried);
        at = emit(out, cap, at, "tcp.refused=%llu\n", (unsigned long long)snap.tcp.refused);
        at = emit(out, cap, at, "tcp.aborted=%llu\n", (unsigned long long)snap.tcp.aborted);
        at = emit(out, cap, at, "tcp.up=%llu\n", (unsigned long long)snap.tcp.bytes_up);
        at = emit(out, cap, at, "tcp.down=%llu\n", (unsigned long long)snap.tcp.bytes_down);
        at = emit(out, cap, at, "tcp.last_error=%s\n", snap.tcp.last_error);
        uint32_t shown = snap.tcp.recent_count < BYE_TCP_RECENT_MAX ? snap.tcp.recent_count : BYE_TCP_RECENT_MAX;
        for (uint32_t i = 0; i < shown; ++i)
            at = emit(out, cap, at, "tcp.recent.%u=%s\n", (unsigned)i,
                      snap.tcp.recent[(snap.tcp.recent_count - 1 - i) % BYE_TCP_RECENT_MAX]);
        at = emit(out, cap, at, "udp.received=%llu\n", (unsigned long long)snap.udp.received);
        at = emit(out, cap, at, "udp.sent=%llu\n", (unsigned long long)snap.udp.sent);
        at = emit(out, cap, at, "udp.quic_dropped=%llu\n", (unsigned long long)snap.udp.quic_dropped);
        at = emit(out, cap, at, "udp.last_error=%s\n", snap.udp.last_error);
    }
    at = emit(out, cap, at, ".\n");
    return at;
}

static size_t config_reply(const daemon_t *d, char *out, size_t cap) {
    char text[BYE_CONFIG_FILE_MAX];
    if (bye_config_render(&d->config, text, sizeof text) != 0)
        return reply_line(out, cap, "ERR", "cannot render the config");
    size_t at = emit(out, cap, 0, "OK\n%s.\n", text);
    return at;
}

static size_t set_reply(daemon_t *d, const char *args, char *out, size_t cap) {
    const char *space = strchr(args, ' ');
    if (!space || space == args || !space[1]) return reply_line(out, cap, "ERR", "usage: set KEY VALUE");
    if (strncmp(args, "desync ", 7) == 0)
        return reply_line(out, cap, "ERR", "the bypass is always on, set desync.spec to change the strategy");
    char line[BYE_CTL_LINE_MAX + 8];
    snprintf(line, sizeof line, "%.*s = %s\n", (int)(space - args), args, space + 1);
    bye_config_t next = d->config;
    char error[BYE_CONFIG_ERROR_MAX];
    if (bye_config_parse(line, strlen(line), &next, error, sizeof error) != BYE_CONFIG_OK)
        return reply_line(out, cap, "ERR", error);
    if (next.spec_reduced)
        return reply_line(out, cap, "ERR", "desync.spec is one strategy, a list split by | is not accepted");
    bye_config_t previous = d->config;
    d->config = next;
    if (save_config(d) != 0) {
        d->config = previous;
        return reply_line(out, cap, "ERR", "cannot write the config file");
    }
    d->config_error[0] = '\0';
    log_notes(&d->config);
    /* the proxy follows its own keys at once, the tunnel waits for a restart */
    int proxy_key = strncmp(args, "proxy", 5) == 0 && (args[5] == ' ' || args[5] == '.');
    if (proxy_key || (strncmp(args, "relay ", 6) == 0 && d->proxy)) proxy_apply(d);
    int tunnel_key = !proxy_key;
    return reply_line(out, cap, "OK", tunnel_key && bye_backend_running(&d->backend) ? "restart to apply" : "");
}

/* "probe NAME..." starts the strategy check, "probe" reads its report and
   "probe stop" ends it early */
static size_t probe_reply(daemon_t *d, const char *args, char *out, size_t cap) {
    while (*args == ' ') ++args;
    if (!d->probe) {
        d->probe = calloc(1, bye_probe_size());
        if (!d->probe) return reply_line(out, cap, "ERR", "not enough memory");
        bye_probe_init(d->probe);
    }
    if (strcmp(args, "stop") == 0) {
        bye_probe_cancel(d->probe);
        return reply_line(out, cap, "OK", "");
    }
    if (*args) {
        bye_probe_request_t request;
        memset(&request, 0, sizeof request);
        while (*args) {
            const char *end = strchr(args, ' ');
            size_t n = end ? (size_t)(end - args) : strlen(args);
            if (request.name_count == BYE_PROBE_NAMES_MAX || n >= BYE_PROBE_NAME_MAX)
                return reply_line(out, cap, "ERR", "usage: probe NAME... (up to four plain domain names)");
            for (size_t i = 0; i < n; ++i) {
                char c = args[i];
                request.names[request.name_count][i] = c >= 'A' && c <= 'Z' ? (char)(c + 32) : c;
            }
            request.names[request.name_count][n] = '\0';
            if (!bye_hosts_name_ok(request.names[request.name_count], n))
                return reply_line(out, cap, "ERR", "usage: probe NAME... (up to four plain domain names)");
            ++request.name_count;
            args += n;
            while (*args == ' ') ++args;
        }
        snprintf(request.configured, sizeof request.configured, "%s", d->config.desync_spec);
        bye_backend_snapshot_t snap;
        if (bye_backend_snapshot(&d->backend, &snap) == 0 && snap.tcp.capture.hello_len &&
            snap.tcp.capture.port == 443) {
            snprintf(request.app_name, sizeof request.app_name, "%s", snap.tcp.capture.name);
            memcpy(request.app_addr, snap.tcp.capture.addr, 4);
            memcpy(request.app_hello, snap.tcp.capture.hello, snap.tcp.capture.hello_len);
            request.app_hello_len = snap.tcp.capture.hello_len;
        }
        request.bound = bye_backend_direct(&d->backend, &request.iface) == 0;
        char error[160];
        if (bye_probe_start(d->probe, &request, error, sizeof error) != 0)
            return reply_line(out, cap, "ERR", error);
        return reply_line(out, cap, "OK", "started");
    }
    size_t at = emit(out, cap, 0, "OK\n");
    at += bye_probe_report(d->probe, out + at, cap > at ? cap - at : 0);
    return emit(out, cap, at, ".\n");
}

static size_t handle(void *ctx, const char *line, char *out, size_t cap) {
    daemon_t *d = ctx;
    char reason[256];
    if (strcmp(line, "status") == 0) return status_reply(d, out, cap);
    if (strcmp(line, "config") == 0) return config_reply(d, out, cap);
    if (strncmp(line, "set ", 4) == 0) return set_reply(d, line + 4, out, cap);
    if (strcmp(line, "probe") == 0 || strncmp(line, "probe ", 6) == 0)
        return probe_reply(d, line + 5, out, cap);
    if (strcmp(line, "reload") == 0) {
        load_config(d);
        proxy_apply(d);
        return reply_line(out, cap, d->config_error[0] ? "ERR" : "OK", d->config_error);
    }
    if (strcmp(line, "start") == 0 || strcmp(line, "restart") == 0) {
        tunnel_stop(d);
        d->wanted = 1;
        d->attempts = 0;
        if (tunnel_start(d, reason, sizeof reason) != 0) {
            /* an explicit start that fails is the user's to see, not to retry */
            d->wanted = 0;
            remember_error(d, reason);
            return reply_line(out, cap, "ERR", reason);
        }
        return reply_line(out, cap, "OK", bye_backend_ifname(&d->backend));
    }
    if (strcmp(line, "stop") == 0) {
        d->wanted = 0;
        tunnel_stop(d);
        if (d->tls_error[0]) return reply_line(out, cap, "ERR", d->tls_error);
        return reply_line(out, cap, "OK", "");
    }
    return reply_line(out, cap, "ERR", "unknown command");
}


/* the tunnel ended on its own, or the network it leaves by is gone. a wanted
   tunnel is started again a bounded number of times: a join to another wifi
   or a move to the cellular link is normal, a dead end is not */
static void supervise(daemon_t *d, int64_t now) {
    if (!d->wanted) return;
    int running = bye_backend_running(&d->backend);
    if (running) {
        if (now < d->next_check_ms) return;
        d->next_check_ms = now + NETWORK_CHECK_MS;
        if (bye_backend_network_ok(&d->backend)) {
            d->attempts = 0;
            return;
        }
        remember_error(d, "the network interface went away");
        tunnel_stop(d);
        d->next_try_ms = now;
    } else if (d->backend.active || d->backend.thread_started) {
        char why[256];
        bye_backend_end_reason(&d->backend, why, sizeof why);
        remember_error(d, why[0] ? why : "the tunnel ended");
        tunnel_stop(d);
        d->next_try_ms = now;
    }
    if (bye_backend_running(&d->backend) || now < d->next_try_ms) return;
    if (d->attempts >= RETRY_MAX) {
        d->wanted = 0;
        remember_error(d, "giving up after repeated failures to start the tunnel");
        return;
    }
    ++d->attempts;
    char reason[256];
    if (tunnel_start(d, reason, sizeof reason) != 0) {
        remember_error(d, reason);
        d->next_try_ms = now + RETRY_MS;
    }
}

static int parse_args(daemon_t *d, int argc, char **argv, char *ctl_path, size_t ctl_cap) {
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        int has_value = i + 1 < argc;
        if (strcmp(arg, "--ctl") == 0 && has_value) {
            snprintf(ctl_path, ctl_cap, "%s", argv[++i]);
        } else if (strcmp(arg, "--config") == 0 && has_value) {
            snprintf(d->config_path, sizeof d->config_path, "%s", argv[++i]);
        } else if (strcmp(arg, "--ca") == 0 && has_value) {
            snprintf(d->ca_file, sizeof d->ca_file, "%s", argv[++i]);
        } else if (strcmp(arg, "--trace") == 0) {
            d->trace = 1;
        } else if (strcmp(arg, "--managed") == 0) {
            /* launchd owns the process, so main leaves its session alone */
            d->managed = 1;
        } else {
            usage();
            return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    static daemon_t d;
    if (argc == 2 && strcmp(argv[1], "--restore-tls") == 0) {
        char error[256];
        if (geteuid() != 0) return 1;
        if (bye_tls_owner_set(0, NULL, error, sizeof error) == 0) return 0;
        fprintf(stderr, "byedpid: %s\n", error);
        return 1;
    }
    char ctl_path[PATH_MAX_LEN] = BYE_CTL_SOCKET;
    snprintf(d.config_path, sizeof d.config_path, "%s", BYE_CONFIG_PATH);
    snprintf(d.ca_file, sizeof d.ca_file, "%s", BYE_CA_BUNDLE);
    if (parse_args(&d, argc, argv, ctl_path, sizeof ctl_path) != 0) return 2;
    if (snprintf(d.token_path, sizeof d.token_path, "%.*s.token",
                 (int)(strlen(ctl_path) > 5 && strcmp(ctl_path + strlen(ctl_path) - 5, ".sock") == 0
                           ? strlen(ctl_path) - 5 : strlen(ctl_path)), ctl_path) >= (int)sizeof d.token_path)
        return 2;

    /* launchd keeps its job in the session it made for it. ios 8 and 9 do not
       make the job a session leader, so detaching there moved the daemon out
       of that session, and it was then left without a bootstrap port: configd
       could not be reached at all */
    if (!d.managed) senko_proc_detach();
    senko_raise_memory_limit();
    signal(SIGPIPE, SIG_IGN);
    if (pipe(signal_pipe) != 0 || fcntl(signal_pipe[0], F_SETFL, O_NONBLOCK) != 0 ||
        fcntl(signal_pipe[1], F_SETFL, O_NONBLOCK) != 0) {
        fprintf(stderr, "byedpid: cannot create the signal pipe\n");
        return 1;
    }
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_signal;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);

    char error[256];
    bye_ctl_t *ctl = bye_ctl_open(ctl_path, d.token_path, handle, &d, error, sizeof error);
    if (!ctl) {
        fprintf(stderr, "byedpid: %s\n", error);
        return 1;
    }
    fprintf(stderr, "byedpid: control socket %s\n", ctl_path);
    int ios_major = senko_ios_major();
    d.tls_switch = geteuid() == 0 && ios_major >= 5 && ios_major < 12;
    if (tls_owner(&d, 0) != 0) {
        bye_ctl_close(ctl);
        return 1;
    }

    /* a killed daemon leaves "1" behind, and the hook would keep the badge */
    bye_badge_off();
    if (bye_backend_init(&d.backend) != 0) {
        fprintf(stderr, "byedpid: cannot start the tunnel runtime\n");
        bye_ctl_close(ctl);
        return 1;
    }
    pthread_mutex_init(&d.direct_lock, NULL);
    load_config(&d);
    proxy_apply(&d);

    if (d.config.autostart && !d.config_error[0]) {
        d.wanted = 1;
        d.next_try_ms = 0;
    }

    int stop = 0;
    while (!stop) {
        fd_set readable, writable;
        FD_ZERO(&readable);
        FD_ZERO(&writable);
        int highest = -1;
        bye_ctl_prepare(ctl, &readable, &writable, &highest);
        FD_SET(signal_pipe[0], &readable);
        if (signal_pipe[0] > highest) highest = signal_pipe[0];
        int ended_fd = bye_backend_ended_fd(&d.backend);
        if (ended_fd >= 0) {
            FD_SET(ended_fd, &readable);
            if (ended_fd > highest) highest = ended_fd;
        }
        struct timeval wait = { 1, 0 };
        int ready = select(highest + 1, &readable, &writable, NULL, &wait);
        if (ready < 0 && errno != EINTR) {
            fprintf(stderr, "byedpid: select failed (errno %d)\n", errno);
            break;
        }
        if (ready > 0) {
            if (FD_ISSET(signal_pipe[0], &readable)) stop = 1;
            if (ended_fd >= 0 && FD_ISSET(ended_fd, &readable)) bye_backend_drain_ended(&d.backend);
            bye_ctl_service(ctl, &readable, &writable);
        }
        supervise(&d, senko_now_ms());
        char revive_error[256];
        int revived = bye_ctl_revive(ctl, revive_error, sizeof revive_error);
        if (revived > 0) fprintf(stderr, "byedpid: control socket %s was removed, made again\n", ctl_path);
        else if (revived < 0) fprintf(stderr, "byedpid: %s\n", revive_error);
    }

    fprintf(stderr, "byedpid: shutting down\n");
    d.wanted = 0;
    tunnel_stop(&d);
    proxy_stop(&d);
    if (d.probe) {
        bye_probe_destroy(d.probe);
        free(d.probe);
    }
    bye_backend_destroy(&d.backend);
    bye_ctl_close(ctl);
    return 0;
}

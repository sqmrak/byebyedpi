/* the tcp and udp relays end to end. the app speaks tcp by hand through a
   socketpair standing in for the utun descriptor, to destinations on
   127.0.0.1 that this process serves: an echo server, and a stand-in for
   telegram's gateway (tls, a websocket, and a datacenter that checks the
   mtproto init). nothing leaves the machine */

#define _DEFAULT_SOURCE

#include "bye_altaddr.h"
#include "bye_tcp.h"
#include "bye_udp.h"
#include "bye_mtp.h"
#include "bye_sniff.h"
#include "packet_fixture.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "check.h"
#include "hello_openssl.inc"
#include "hello_fixture.h"

static const uint8_t APP4[4]   = { 198, 18, 0, 1 };
static const uint8_t LOCAL4[4] = { 198, 18, 0, 2 };
static const uint8_t SYNTH4[4] = { 198, 18, 0, 3 };
static const uint8_t LOOP4[4]  = { 127, 0, 0, 1 };
static const uint8_t LOCAL6[16] = { 0xfd, 0, 0x5e, 0x4b, 0,0,0,0, 0,0,0,0, 0,0,0,2 };
static const uint8_t SYNTH6[16] = { 0xfd, 0, 0x5e, 0x4b, 0,0,0,0, 0,0,0,0, 0,0,0,3 };

#define GENERATION 9

static void pause_ms(int ms) {
    struct timespec t = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&t, NULL);
}

static uint32_t fnv(uint32_t h, const uint8_t *d, size_t n) {
    for (size_t i = 0; i < n; ++i) { h ^= d[i]; h *= 16777619u; }
    return h;
}

static uint8_t pattern_byte(size_t i) { return (uint8_t)(i * 31u + (i >> 9)); }

static int write_full(int fd, const uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w > 0) { off += (size_t)w; continue; }
        if (w < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

/* ---- an echo server that records what it was sent ------------------------ */

#define RECORD_MAX (512u * 1024u)
#define SERVER_CONNS 16

typedef struct {
    int      used;
    int      finished;
    uint8_t *data;
    size_t   len;
} record_t;

typedef struct {
    int             listen_fd;
    uint16_t        port;
    pthread_mutex_t lock;
    record_t        conns[SERVER_CONNS];
} echo_t;

typedef struct { echo_t *echo; int fd; record_t *record; } echo_job_t;

static void *echo_one(void *arg) {
    echo_job_t *job = arg;
    uint8_t buf[8192];
    for (;;) {
        ssize_t n = read(job->fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        pthread_mutex_lock(&job->echo->lock);
        if (job->record->len + (size_t)n <= RECORD_MAX) {
            memcpy(job->record->data + job->record->len, buf, (size_t)n);
            job->record->len += (size_t)n;
        }
        pthread_mutex_unlock(&job->echo->lock);
        if (write_full(job->fd, buf, (size_t)n) != 0) break;
    }
    shutdown(job->fd, SHUT_WR);
    close(job->fd);
    pthread_mutex_lock(&job->echo->lock);
    job->record->finished = 1;
    pthread_mutex_unlock(&job->echo->lock);
    free(job);
    return NULL;
}

static void *echo_main(void *arg) {
    echo_t *echo = arg;
    for (;;) {
        int fd = accept(echo->listen_fd, NULL, NULL);
        if (fd < 0) return NULL;
        echo_job_t *job = calloc(1, sizeof *job);
        pthread_mutex_lock(&echo->lock);
        for (size_t i = 0; i < SERVER_CONNS; ++i) {
            if (echo->conns[i].used) continue;
            echo->conns[i].used = 1;
            echo->conns[i].finished = 0;
            echo->conns[i].len = 0;
            job->record = &echo->conns[i];
            break;
        }
        pthread_mutex_unlock(&echo->lock);
        if (!job->record) { close(fd); free(job); continue; }
        job->echo = echo;
        job->fd = fd;
        pthread_t t;
        pthread_create(&t, NULL, echo_one, job);
        pthread_detach(t);
    }
}

static void echo_start(echo_t *echo) {
    memset(echo, 0, sizeof *echo);
    pthread_mutex_init(&echo->lock, NULL);
    for (size_t i = 0; i < SERVER_CONNS; ++i) echo->conns[i].data = malloc(RECORD_MAX);
    echo->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(echo->listen_fd, (struct sockaddr *)&a, sizeof a) == 0);
    socklen_t len = sizeof a;
    getsockname(echo->listen_fd, (struct sockaddr *)&a, &len);
    echo->port = ntohs(a.sin_port);
    CHECK(listen(echo->listen_fd, 16) == 0);
    pthread_t t;
    pthread_create(&t, NULL, echo_main, echo);
    pthread_detach(t);
}

/* the connection that has sent at least want bytes, waiting up to wait_ms */
static record_t *echo_wait(echo_t *echo, size_t want, int wait_ms) {
    for (int waited = 0; waited <= wait_ms; waited += 5) {
        pthread_mutex_lock(&echo->lock);
        for (size_t i = 0; i < SERVER_CONNS; ++i) {
            if (echo->conns[i].used && echo->conns[i].len >= want) {
                pthread_mutex_unlock(&echo->lock);
                return &echo->conns[i];
            }
        }
        pthread_mutex_unlock(&echo->lock);
        pause_ms(5);
    }
    return NULL;
}

static void echo_forget(echo_t *echo) {
    pthread_mutex_lock(&echo->lock);
    for (size_t i = 0; i < SERVER_CONNS; ++i) {
        echo->conns[i].used = 0;
        echo->conns[i].len = 0;
    }
    pthread_mutex_unlock(&echo->lock);
}

/* ---- a stand-in for telegram's gateway and datacenter -------------------- */

typedef struct {
    int      used;
    int      finished;
    int      fd;
    char     host[64];
    int      subprotocol_ok;
    int      init_ok;
    uint32_t tag;
    int      dc;
    size_t   messages;
    size_t   misaligned;    /* messages that are not exactly one abridged packet */
    size_t   bytes;
    uint32_t hash;          /* of the decrypted messages after the init */
} gate_conn_t;

static struct {
    int             listen_fd;
    uint16_t        port;
    SSL_CTX        *ctx;
    pthread_mutex_t lock;
    gate_conn_t     conns[SERVER_CONNS];
    int             reject_all;   /* answer every upgrade with a 404 */
    int             reject_relay; /* a 404 for the relay's host only */
} gate;

static int ssl_read_full(SSL *ssl, uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        int r = SSL_read(ssl, buf + off, (int)(n - off));
        if (r <= 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

static int ssl_write_full(SSL *ssl, const uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        int w = SSL_write(ssl, buf + off, (int)(n - off));
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static void b64(const uint8_t *in, size_t len, char *out) {
    static const char d[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t j = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (i + 1 < len ? (uint32_t)in[i + 1] << 8 : 0) |
                     (i + 2 < len ? in[i + 2] : 0);
        out[j++] = d[(v >> 18) & 63];
        out[j++] = d[(v >> 12) & 63];
        out[j++] = i + 1 < len ? d[(v >> 6) & 63] : '=';
        out[j++] = i + 2 < len ? d[v & 63] : '=';
    }
    out[j] = '\0';
}

static EVP_CIPHER_CTX *ctr_new(const uint8_t *key, const uint8_t *iv) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    CHECK(EVP_EncryptInit_ex(c, EVP_aes_256_ctr(), NULL, key, iv) == 1);
    return c;
}

static void ctr_xor(EVP_CIPHER_CTX *c, uint8_t *data, size_t len) {
    int n = 0;
    CHECK(EVP_EncryptUpdate(c, data, &n, data, (int)len) == 1 && (size_t)n == len);
}

static int send_server_frame(SSL *ssl, const uint8_t *payload, size_t n) {
    uint8_t head[10];
    size_t h = 0;
    head[h++] = 0x82;
    if (n < 126) {
        head[h++] = (uint8_t)n;
    } else if (n < 65536) {
        head[h++] = 126;
        head[h++] = (uint8_t)(n >> 8);
        head[h++] = (uint8_t)n;
    } else {
        head[h++] = 127;
        for (int k = 7; k >= 0; --k) head[h++] = (uint8_t)((uint64_t)n >> (8 * k));
    }
    return ssl_write_full(ssl, head, h) == 0 && ssl_write_full(ssl, payload, n) == 0 ? 0 : -1;
}

/* the datacenter: reads the init, then each message is one abridged packet,
   which it answers by echoing the plain packet back, in two frames */
static void gate_serve(SSL *ssl, gate_conn_t *rec) {
    char req[2048];
    size_t len = 0;
    while (len < sizeof req - 1) {
        int r = SSL_read(ssl, req + len, 1);
        if (r <= 0) return;
        ++len;
        if (len >= 4 && memcmp(req + len - 4, "\r\n\r\n", 4) == 0) break;
    }
    req[len] = '\0';
    const char *host = strstr(req, "\r\nHost: ");
    const char *key = strstr(req, "\r\nSec-WebSocket-Key: ");
    if (host) sscanf(host + 8, "%63[^\r]", rec->host);
    rec->subprotocol_ok = strstr(req, "Sec-WebSocket-Protocol: binary\r\n") != NULL;
    if (gate.reject_all || !key || !rec->subprotocol_ok ||
        (gate.reject_relay && strstr(rec->host, "kws2.relay.test"))) {
        static const char no[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        ssl_write_full(ssl, (const uint8_t *)no, sizeof no - 1);
        return;
    }
    char keyval[64], joined[128], accept[40];
    sscanf(key + 21, "%63[^\r]", keyval);
    snprintf(joined, sizeof joined, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", keyval);
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    EVP_Digest(joined, strlen(joined), digest, &dlen, EVP_sha1(), NULL);
    b64(digest, dlen, accept);
    char resp[256];
    int rn = snprintf(resp, sizeof resp,
                      "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
                      "Sec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: binary\r\n\r\n", accept);
    if (ssl_write_full(ssl, (const uint8_t *)resp, (size_t)rn) != 0) return;

    EVP_CIPHER_CTX *dec = NULL, *enc = NULL;
    uint8_t *msg = malloc(RECORD_MAX + 4096);
    uint32_t hash = 2166136261u;
    for (;;) {
        uint8_t h2[2];
        if (ssl_read_full(ssl, h2, 2) != 0) break;
        size_t n = h2[1] & 0x7F;
        if (n == 126) {
            uint8_t e[2];
            if (ssl_read_full(ssl, e, 2) != 0) break;
            n = (size_t)(e[0] << 8 | e[1]);
        } else if (n == 127) {
            uint8_t e[8];
            if (ssl_read_full(ssl, e, 8) != 0) break;
            n = 0;
            for (int k = 0; k < 8; ++k) n = (n << 8) | e[k];
        }
        uint8_t mask[4] = { 0 };
        if (!(h2[1] & 0x80)) break;
        if (ssl_read_full(ssl, mask, 4) != 0 || n > RECORD_MAX + 4096) break;
        if (ssl_read_full(ssl, msg, n) != 0) break;
        for (size_t i = 0; i < n; ++i) msg[i] ^= mask[i & 3];
        int opcode = h2[0] & 0x0F;
        if (opcode == 0x8) break;
        if (opcode == 0x9 || opcode == 0xA) continue;
        if (!dec) {
            if (n != 64) break;
            uint8_t rev[48], plain[64];
            dec = ctr_new(msg + 8, msg + 40);
            memcpy(plain, msg, 64);
            ctr_xor(dec, plain, 64);
            for (size_t i = 0; i < 48; ++i) rev[i] = msg[8 + 47 - i];
            enc = ctr_new(rev, rev + 32);
            rec->tag = (uint32_t)plain[56] | (uint32_t)plain[57] << 8 | (uint32_t)plain[58] << 16 |
                       (uint32_t)plain[59] << 24;
            rec->dc = (int16_t)((uint16_t)plain[60] | (uint16_t)plain[61] << 8);
            rec->init_ok = 1;
            continue;
        }
        ctr_xor(dec, msg, n);
        /* one abridged packet exactly: a length byte or four, then the words */
        size_t head = 1, payload = (size_t)(msg[0] & 0x7F) * 4;
        if ((msg[0] & 0x7F) == 0x7F) {
            head = 4;
            payload = ((size_t)msg[1] | (size_t)msg[2] << 8 | (size_t)msg[3] << 16) * 4;
        }
        pthread_mutex_lock(&gate.lock);
        ++rec->messages;
        rec->bytes += n;
        if (head + payload != n) ++rec->misaligned;
        rec->hash = hash = fnv(hash, msg, n);
        pthread_mutex_unlock(&gate.lock);
        ctr_xor(enc, msg, n);
        size_t half = n / 2;
        if (send_server_frame(ssl, msg, half) != 0 || send_server_frame(ssl, msg + half, n - half) != 0)
            break;
    }
    free(msg);
    EVP_CIPHER_CTX_free(dec);
    EVP_CIPHER_CTX_free(enc);
}

typedef struct { int fd; gate_conn_t *rec; } gate_job_t;

static void *gate_one(void *arg) {
    gate_job_t *job = arg;
    SSL *ssl = SSL_new(gate.ctx);
    SSL_set_fd(ssl, job->fd);
    if (SSL_accept(ssl) == 1) gate_serve(ssl, job->rec);
    SSL_free(ssl);
    close(job->fd);
    pthread_mutex_lock(&gate.lock);
    job->rec->finished = 1;
    pthread_mutex_unlock(&gate.lock);
    free(job);
    return NULL;
}

static void *gate_main(void *arg) {
    (void)arg;
    for (;;) {
        int fd = accept(gate.listen_fd, NULL, NULL);
        if (fd < 0) return NULL;
        gate_job_t *job = calloc(1, sizeof *job);
        job->fd = fd;
        pthread_mutex_lock(&gate.lock);
        for (size_t i = 0; i < SERVER_CONNS; ++i) {
            if (gate.conns[i].used) continue;
            memset(&gate.conns[i], 0, sizeof gate.conns[i]);
            gate.conns[i].used = 1;
            gate.conns[i].fd = fd;
            job->rec = &gate.conns[i];
            break;
        }
        pthread_mutex_unlock(&gate.lock);
        if (!job->rec) { close(fd); free(job); continue; }
        pthread_t t;
        pthread_create(&t, NULL, gate_one, job);
        pthread_detach(t);
    }
}

static char dir[] = "/tmp/bye-flows-XXXXXX";
static char cert_path[256];

static void gate_start(void) {
    CHECK(mkdtemp(dir) != NULL);
    char key_path[256], cmd[1024];
    snprintf(cert_path, sizeof cert_path, "%s/cert.pem", dir);
    snprintf(key_path, sizeof key_path, "%s/key.pem", dir);
    snprintf(cmd, sizeof cmd,
             "openssl req -x509 -newkey rsa:2048 -nodes -keyout %s -out %s -days 2 -subj /CN=gateway "
             "-addext subjectAltName=DNS:kws2.web.telegram.org,DNS:kws2-1.web.telegram.org,"
             "DNS:kws4.web.telegram.org,DNS:kws4-1.web.telegram.org,DNS:kws2.relay.test,DNS:kws2.relay2.test >/dev/null 2>&1",
             key_path, cert_path);
    CHECK(system(cmd) == 0);
    pthread_mutex_init(&gate.lock, NULL);
    gate.ctx = SSL_CTX_new(TLS_server_method());
    CHECK(SSL_CTX_use_certificate_file(gate.ctx, cert_path, SSL_FILETYPE_PEM) == 1);
    CHECK(SSL_CTX_use_PrivateKey_file(gate.ctx, key_path, SSL_FILETYPE_PEM) == 1);
    gate.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(gate.listen_fd, (struct sockaddr *)&a, sizeof a) == 0);
    socklen_t len = sizeof a;
    getsockname(gate.listen_fd, (struct sockaddr *)&a, &len);
    gate.port = ntohs(a.sin_port);
    CHECK(listen(gate.listen_fd, 16) == 0);
    pthread_t t;
    pthread_create(&t, NULL, gate_main, NULL);
    pthread_detach(t);
}

static gate_conn_t *gate_wait(size_t messages, int wait_ms) {
    for (int waited = 0; waited <= wait_ms; waited += 5) {
        pthread_mutex_lock(&gate.lock);
        for (size_t i = 0; i < SERVER_CONNS; ++i) {
            if (gate.conns[i].used && gate.conns[i].init_ok && gate.conns[i].messages >= messages) {
                pthread_mutex_unlock(&gate.lock);
                return &gate.conns[i];
            }
        }
        pthread_mutex_unlock(&gate.lock);
        pause_ms(5);
    }
    return NULL;
}

static gate_conn_t *gate_any(int wait_ms) {
    for (int waited = 0; waited <= wait_ms; waited += 5) {
        pthread_mutex_lock(&gate.lock);
        for (size_t i = 0; i < SERVER_CONNS; ++i) {
            if (gate.conns[i].used) {
                pthread_mutex_unlock(&gate.lock);
                return &gate.conns[i];
            }
        }
        pthread_mutex_unlock(&gate.lock);
        pause_ms(5);
    }
    return NULL;
}

static void gate_forget(void) {
    pthread_mutex_lock(&gate.lock);
    for (size_t i = 0; i < SERVER_CONNS; ++i) gate.conns[i].used = 0;
    pthread_mutex_unlock(&gate.lock);
}

/* ---- the tunnel under test ------------------------------------------------ */

enum { WAY_DIRECT, WAY_DESYNC, WAY_TELEGRAM };

static echo_t direct_echo, desync_echo, fallback_echo;
static bye_wsconn_ctx_t *tls_ctx;

/* what the next tunnel is configured with */
static const char *knob_strategies = BYE_DESYNC_DEFAULT_SPEC;
static bye_hosts_t *knob_hosts;
static int knob_hosts_only;
static int knob_gateway_addresses;
static uint32_t knob_auto_wait_ms;
static uint16_t filter_port;
static size_t knob_pool;

static struct {
    tun_loop_t   *loop;
    bye_tcp_t    *tcp;
    bye_udp_t    *udp;
    utun_device_t device;
    int           peer;
    pthread_t     thread;
    tun_loop_result_t result;
} tunnel;

static bye_path_t classify(void *ctx, const uint8_t *addr, size_t len, uint16_t port) {
    (void)ctx; (void)addr; (void)len;
    if (port == desync_echo.port || (filter_port && port == filter_port)) return BYE_PATH_DESYNC;
    if (port == fallback_echo.port) return BYE_PATH_TELEGRAM;
    return BYE_PATH_DIRECT;
}

static int plain_socket(void *ctx, int family, int type, char *error, size_t cap) {
    (void)ctx; (void)error; (void)cap;
    int fd = socket(family, type, 0);
    if (fd >= 0) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    return fd;
}

static void *run_tunnel(void *arg) {
    (void)arg;
    tun_loop_run(tunnel.loop, &tunnel.result);
    return NULL;
}

static void tunnel_start(uint16_t gateway_port, int block_quic, int with_relay) {
    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) == 0);
    int big = 1 << 20;
    setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    tunnel.peer = fds[1];
    utun_device_init(&tunnel.device);
    CHECK(utun_device_adopt(&tunnel.device, fds[0], "utun7") == UTUN_DEVICE_OK);

    tun_loop_config_t config;
    memset(&config, 0, sizeof config);
    config.generation = GENERATION;
    tun_stack_config_t *s = &config.stack;
    s->mtu = 1500;
    s->have_ipv4 = 1;
    memcpy(s->address4, LOCAL4, 4);
    memcpy(s->synthetic4, SYNTH4, 4);
    memset(s->netmask4, 255, 4);
    s->have_ipv6 = 1;
    memcpy(s->address6, LOCAL6, 16);
    memcpy(s->synthetic6, SYNTH6, 16);
    s->queue_max_packets = 16;
    s->pending_max_ms = 3000;

    bye_tcp_config_t tcp;
    memset(&tcp, 0, sizeof tcp);
    tcp.policy.telegram = 1;
    CHECK(bye_strategies_parse(knob_strategies, &tcp.strategies, NULL, 0) == BYE_DESYNC_OK);
    tcp.hosts = knob_hosts;
    tcp.hosts_only = knob_hosts_only;
    tcp.auto_wait_ms = knob_auto_wait_ms;
    tcp.pool = knob_pool;
    tcp.classify = classify;
    tcp.direct_socket = plain_socket;
    tcp.tls = tls_ctx;
    tcp.gateway_set = 1;
    memcpy(tcp.gateway, LOOP4, 4);
    tcp.gateway_port = gateway_port;
    if (knob_gateway_addresses) {
        tcp.gateway_set = 0;
        tcp.ws_addresses.dc[1][0].valid = tcp.ws_addresses.dc[1][1].valid = 1;
        memcpy(tcp.ws_addresses.dc[1][0].address, (const uint8_t[]){127, 0, 0, 2}, 4);
        memcpy(tcp.ws_addresses.dc[1][1].address, LOOP4, 4);
    }
    tcp.trace = getenv("BYE_TEST_TRACE") != NULL;
    if (with_relay) {
        snprintf(tcp.relay[0], sizeof tcp.relay[0], "relay.test");
        memcpy(tcp.relay_addr[0], LOOP4, 4);
        tcp.relay_count = 1;
        if (with_relay == 2) {
            snprintf(tcp.relay[1], sizeof tcp.relay[1], "relay2.test");
            memcpy(tcp.relay_addr[1], LOOP4, 4);
            tcp.relay_count = 2;
        }
    }
    bye_udp_config_t udp;
    memset(&udp, 0, sizeof udp);
    udp.direct_socket = plain_socket;
    udp.block_quic = block_quic;

    tunnel.tcp = calloc(1, bye_tcp_size());
    tunnel.udp = calloc(1, bye_udp_size());
    CHECK(bye_tcp_init(tunnel.tcp, &tcp, &config) == 0);
    CHECK(bye_udp_init(tunnel.udp, &udp, &config) == 0);
    tunnel.loop = malloc(tun_loop_size());
    CHECK(tun_loop_init(tunnel.loop, &config, &tunnel.device) == TUN_LOOP_OK);
    pthread_create(&tunnel.thread, NULL, run_tunnel, NULL);
}

static void tunnel_stop(void) {
    tun_loop_command_t stop = { TUN_LOOP_CMD_STOP, GENERATION, 0 };
    tun_loop_post(tunnel.loop, &stop);
    pthread_join(tunnel.thread, NULL);
    tun_loop_destroy(tunnel.loop);
    close(tunnel.peer);
    free(tunnel.loop);
    free(tunnel.tcp);
    free(tunnel.udp);
}

/* ---- an app speaking tcp by hand ------------------------------------------ */

#define APP_RX_MAX (1024u * 1024u)
#define MSS 1300

typedef struct {
    uint8_t  src[4];
    uint8_t  dst[4];
    uint16_t sport;
    uint16_t dport;
    uint32_t snd_nxt;
    uint32_t snd_una;
    uint32_t rcv_nxt;
    uint32_t peer_window;
    uint16_t window;
    int      established;
    int      got_fin;
    int      got_rst;
    int      syn_acked;
    int      ack_delay_ms;
    int64_t  ack_due_ms;
    size_t   rx_len;
    uint8_t *rx;
} app_t;

static app_t *apps[8];

static size_t build(const app_t *a, uint8_t *p, uint8_t flags, const uint8_t *data, size_t len) {
    size_t total = pkt_ip4(p, a->src, a->dst, 6, 20 + len);
    uint8_t *t = p + pkt_l4(p, total);
    pkt_tcp_fields(t, a->sport, a->dport, flags, a->snd_nxt, a->rcv_nxt, 0);
    pkt_wr16(t + 14, a->window);
    if (len) memcpy(t + 20, data, len);
    pkt_fill_l4(p, total, 16);
    return total;
}

static void app_send_raw(app_t *a, uint8_t flags, const uint8_t *data, size_t len) {
    uint8_t p[1600], frame[1604];
    size_t n = build(a, p, flags, data, len);
    size_t f = pkt_frame(frame, p, n);
    send(tunnel.peer, frame, f, 0);
}

static void app_ack(app_t *a) {
    app_send_raw(a, PKT_ACK, NULL, 0);
    a->ack_due_ms = 0;
}

static int64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void due_acks(void) {
    int64_t now = now_ms();
    for (size_t i = 0; i < 8; ++i)
        if (apps[i] && apps[i]->ack_due_ms && now >= apps[i]->ack_due_ms) app_ack(apps[i]);
}

static app_t *match(const uint8_t *p, size_t len) {
    size_t l4 = pkt_l4(p, len);
    uint16_t sport = pkt_rd16(p + l4), dport = pkt_rd16(p + l4 + 2);
    for (size_t i = 0; i < 8; ++i) {
        app_t *a = apps[i];
        if (!a || a->sport != dport || a->dport != sport) continue;
        if (memcmp(pkt_src(p), a->dst, 4) != 0) continue;
        return a;
    }
    return NULL;
}

typedef struct {
    int      udp_seen;
    uint16_t udp_sport;
    size_t   udp_len;
    uint8_t  udp_payload[1500];
    int      icmp_seen;
    uint8_t  icmp_type, icmp_code;
    uint16_t icmp_quoted_sport, icmp_quoted_dport;
} udp_inbox_t;

static udp_inbox_t inbox;

static int pump(int wait_ms) {
    int seen = 0;
    for (;;) {
        due_acks();
        int timeout = seen ? 0 : wait_ms;
        int64_t now = now_ms();
        for (size_t i = 0; i < 8; ++i) {
            if (!apps[i] || !apps[i]->ack_due_ms) continue;
            int64_t left = apps[i]->ack_due_ms - now;
            if (left < 0) left = 0;
            if (left < timeout) timeout = (int)left;
        }
        struct pollfd pfd = { tunnel.peer, POLLIN, 0 };
        if (poll(&pfd, 1, timeout) <= 0) { due_acks(); return seen; }
        uint8_t frame[2048];
        ssize_t got = recv(tunnel.peer, frame, sizeof frame, 0);
        if (got <= 4) return seen;
        ++seen;
        const uint8_t *p = frame + 4;
        size_t len = (size_t)got - 4;
        if (pkt_proto(p, len) == 17 && pkt_is_v4(p)) {
            size_t l4 = pkt_l4(p, len);
            inbox.udp_seen = 1;
            inbox.udp_sport = pkt_rd16(p + l4);
            inbox.udp_len = len - l4 - 8;
            memcpy(inbox.udp_payload, p + l4 + 8, inbox.udp_len);
            continue;
        }
        if (pkt_proto(p, len) == 1 && pkt_is_v4(p) && pkt_l4_valid(p, len) && len >= 56) {
            size_t l4 = pkt_l4(p, len);
            ++inbox.icmp_seen;
            inbox.icmp_type = p[l4];
            inbox.icmp_code = p[l4 + 1];
            inbox.icmp_quoted_sport = pkt_rd16(p + l4 + 8 + 20);
            inbox.icmp_quoted_dport = pkt_rd16(p + l4 + 8 + 22);
            continue;
        }
        if (pkt_proto(p, len) != 6 || !pkt_l4_valid(p, len)) continue;
        app_t *a = match(p, len);
        if (!a) continue;
        const uint8_t *t = p + pkt_l4(p, len);
        uint8_t flags = t[13];
        uint32_t seq = pkt_rd32(t + 4), ack = pkt_rd32(t + 8);
        size_t hl = (size_t)(t[12] >> 4) * 4;
        size_t data = len - pkt_l4(p, len) - hl;
        if (flags & PKT_RST) { a->got_rst = 1; continue; }
        if ((flags & PKT_SYN) && (flags & PKT_ACK)) {
            a->rcv_nxt = seq + 1;
            a->snd_una = ack;
            a->peer_window = pkt_rd16(t + 14);
            a->syn_acked = 1;
            continue;
        }
        if (flags & PKT_ACK) {
            if ((int32_t)(ack - a->snd_una) > 0) a->snd_una = ack;
            a->peer_window = pkt_rd16(t + 14);
        }
        int advanced = 0;
        if (data && seq == a->rcv_nxt) {
            size_t take = data;
            if (a->rx_len + take > APP_RX_MAX) take = APP_RX_MAX - a->rx_len;
            memcpy(a->rx + a->rx_len, t + hl, take);
            a->rx_len += take;
            a->rcv_nxt += (uint32_t)take;
            advanced = 1;
        }
        if ((flags & PKT_FIN) && seq + (uint32_t)data == a->rcv_nxt) {
            a->rcv_nxt += 1;
            a->got_fin = 1;
            advanced = 1;
        }
        if (advanced || data) {
            if (!a->ack_delay_ms) app_ack(a);
            else if (!a->ack_due_ms) a->ack_due_ms = now_ms() + a->ack_delay_ms;
        }
    }
}

/* serves the tunnel for ms of wall time. pump() returns at the first packet, so a late
   packet of an earlier flow would end a plain pump(ms) long before the time is up */
static void pump_for(int ms) {
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (long)(now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000;
        if (elapsed >= ms) return;
        pump(elapsed + 10 < ms ? 10 : (int)(ms - elapsed));
    }
}

static int wait_until(int *flag, int wait_ms) {
    for (int waited = 0; !*flag && waited < wait_ms; waited += 10) pump(10);
    return *flag;
}

static void app_init(app_t *a, size_t slot, uint16_t dport, uint16_t sport) {
    memset(a, 0, sizeof *a);
    memcpy(a->src, APP4, 4);
    memcpy(a->dst, LOOP4, 4);
    a->dport = dport;
    a->sport = sport;
    a->snd_nxt = 1000u * sport;
    a->window = 65535;
    a->rx = malloc(APP_RX_MAX);
    apps[slot] = a;
}

static void app_forget(app_t *a) {
    for (size_t i = 0; i < 8; ++i) if (apps[i] == a) apps[i] = NULL;
    free(a->rx);
    a->rx = NULL;
}

static int app_connect(app_t *a) {
    app_send_raw(a, PKT_SYN, NULL, 0);
    a->snd_nxt += 1;
    if (!wait_until(&a->syn_acked, 3000)) return 0;
    app_ack(a);
    a->established = 1;
    return 1;
}

static int app_send(app_t *a, const uint8_t *data, size_t len, int wait_ms) {
    size_t sent = 0;
    int idle = 0;
    while (sent < len) {
        uint32_t in_flight = a->snd_nxt - a->snd_una;
        if (in_flight >= a->peer_window) {
            if (!pump(20)) idle += 20;
            if (idle > wait_ms) return 0;
            continue;
        }
        idle = 0;
        size_t room = a->peer_window - in_flight;
        size_t n = len - sent;
        if (n > MSS) n = MSS;
        if (n > room) n = room;
        app_send_raw(a, PKT_ACK | 0x08, data + sent, n);
        a->snd_nxt += (uint32_t)n;
        sent += n;
        pump(0);
    }
    for (int waited = 0; a->snd_una != a->snd_nxt && waited < wait_ms; waited += 10) pump(10);
    return a->snd_una == a->snd_nxt;
}

static void app_fin(app_t *a) {
    app_send_raw(a, PKT_FIN | PKT_ACK, NULL, 0);
    a->snd_nxt += 1;
}

static int app_read(app_t *a, size_t want, int wait_ms) {
    for (int waited = 0; a->rx_len < want && waited < wait_ms; waited += 10) pump(10);
    return a->rx_len >= want;
}

/* ---- the mtproto client ---------------------------------------------------- */

typedef struct {
    EVP_CIPHER_CTX *enc;
    EVP_CIPHER_CTX *dec;
    uint8_t wire_init[64];
} client_t;

static void client_open(client_t *cl, uint32_t proto, int dc) {
    uint8_t init[64], rev[48];
    for (;;) {
        CHECK(RAND_bytes(init, 64) == 1);
        if (init[0] == 0xEF) continue;
        if (!memcmp(init, "HEAD", 4) || !memcmp(init, "POST", 4) || !memcmp(init, "GET ", 4) ||
            !memcmp(init, "OPTI", 4)) continue;
        if (!memcmp(init, "\xee\xee\xee\xee", 4) || !memcmp(init, "\xdd\xdd\xdd\xdd", 4)) continue;
        if (!init[4] && !init[5] && !init[6] && !init[7]) continue;
        break;
    }
    init[56] = (uint8_t)proto; init[57] = (uint8_t)(proto >> 8);
    init[58] = (uint8_t)(proto >> 16); init[59] = (uint8_t)(proto >> 24);
    init[60] = (uint8_t)(uint16_t)dc; init[61] = (uint8_t)((uint16_t)dc >> 8);
    cl->enc = ctr_new(init + 8, init + 40);
    uint8_t sealed[64];
    memcpy(sealed, init, 64);
    ctr_xor(cl->enc, sealed, 64);
    memcpy(cl->wire_init, init, 56);
    memcpy(cl->wire_init + 56, sealed + 56, 8);
    for (size_t i = 0; i < 48; ++i) rev[i] = init[8 + 47 - i];
    cl->dec = ctr_new(rev, rev + 32);
}

static void client_close(client_t *cl) {
    EVP_CIPHER_CTX_free(cl->enc);
    EVP_CIPHER_CTX_free(cl->dec);
}

static size_t abridged_packet(uint8_t *out, size_t words, uint8_t fill) {
    size_t at = 0;
    if (words < 0x7F) {
        out[at++] = (uint8_t)words;
    } else {
        out[at++] = 0x7F;
        out[at++] = (uint8_t)words;
        out[at++] = (uint8_t)(words >> 8);
        out[at++] = (uint8_t)(words >> 16);
    }
    for (size_t i = 0; i < words * 4; ++i) out[at + i] = (uint8_t)(fill + i);
    return at + words * 4;
}

/* ---- the tests -------------------------------------------------------------- */

static void test_direct(void) {
    static app_t a;
    app_init(&a, 0, direct_echo.port, 40001);
    CHECK(app_connect(&a));
    static uint8_t data[200000];
    for (size_t i = 0; i < sizeof data; ++i) data[i] = pattern_byte(i);
    CHECK(app_send(&a, data, sizeof data, 5000));
    CHECK(app_read(&a, sizeof data, 8000));
    CHECK(a.rx_len == sizeof data && memcmp(a.rx, data, sizeof data) == 0);
    app_fin(&a);
    CHECK(wait_until(&a.got_fin, 3000));
    record_t *rec = echo_wait(&direct_echo, sizeof data, 2000);
    CHECK(rec && rec->len == sizeof data && memcmp(rec->data, data, sizeof data) == 0);
    app_forget(&a);
    echo_forget(&direct_echo);

    /* nothing listens: the app gets a reset instead of a connection */
    int closed = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(closed, (struct sockaddr *)&addr, sizeof addr);
    socklen_t alen = sizeof addr;
    getsockname(closed, (struct sockaddr *)&addr, &alen);
    close(closed);
    app_init(&a, 0, ntohs(addr.sin_port), 40002);
    app_send_raw(&a, PKT_SYN, NULL, 0);
    a.snd_nxt += 1;
    CHECK(wait_until(&a.got_rst, 3000));
    CHECK(!a.syn_acked);
    app_forget(&a);
}

/* the records of a stream, joined */
static size_t join_records(const uint8_t *buf, size_t len, uint8_t *body) {
    size_t at = 0, n = 0;
    while (at + 5 <= len) {
        size_t rec = ((size_t)buf[at + 3] << 8) | buf[at + 4];
        if (buf[at] != 0x16 || at + 5 + rec > len) return (size_t)-1;
        memcpy(body + n, buf + at + 5, rec);
        n += rec;
        at += 5 + rec;
    }
    return at == len ? n : (size_t)-1;
}

static void test_fragmented_hello(void) {
    static app_t a;
    static uint8_t hello[17000], original[17000], body[17000];
    const size_t padding[] = { 0, 6000, 16384 - (sizeof hello_openssl - 5) - 4 };
    for (size_t i = 0; i < sizeof padding / sizeof padding[0]; ++i) {
        size_t len = padded_hello(hello, sizeof hello, padding[i]);
        size_t original_len = join_records(hello, len, original);
        app_init(&a, 0, desync_echo.port, (uint16_t)(40110 + i));
        CHECK(app_connect(&a));
        CHECK(app_send(&a, hello, 2, 3000));
        CHECK(app_send(&a, hello + 2, len - 2, 3000));
        size_t want = len + 5;
        CHECK(app_read(&a, want, 3000));
        record_t *rec = echo_wait(&desync_echo, want, 100);
        CHECK(rec && rec->len == want);
        if (rec && rec->len == want) {
            CHECK(join_records(rec->data, rec->len, body) == original_len);
            CHECK(memcmp(body, original, original_len) == 0);
        }
        app_fin(&a);
        CHECK(wait_until(&a.got_fin, 3000));
        app_forget(&a);
        echo_forget(&desync_echo);
    }
}

static void test_desync(void) {
    static app_t a;
    static uint8_t body[2048], original[2048];
    size_t original_len = join_records(hello_openssl, hello_openssl_len, original);

    /* a hello in one write: the server sees the same handshake in two records */
    app_init(&a, 0, desync_echo.port, 40010);
    CHECK(app_connect(&a));
    CHECK(app_send(&a, hello_openssl, hello_openssl_len, 3000));
    size_t want = hello_openssl_len + 5;
    record_t *rec = echo_wait(&desync_echo, want, 3000);
    CHECK(rec && rec->len == want);
    if (rec && rec->len == want) {
        CHECK(join_records(rec->data, rec->len, body) == original_len);
        CHECK(memcmp(body, original, original_len) == 0);
        bye_sniff_t first;
        CHECK(bye_sniff_tls(rec->data, 1 + 4, &first) == BYE_SNIFF_NEED_MORE);
    }
    CHECK(app_read(&a, want, 3000));
    CHECK(a.rx_len == want && rec && memcmp(a.rx, rec->data, want) == 0);
    app_fin(&a);
    CHECK(wait_until(&a.got_fin, 3000));
    app_forget(&a);
    echo_forget(&desync_echo);

    /* the hello arrives in two pieces, a pause between them */
    app_init(&a, 0, desync_echo.port, 40011);
    CHECK(app_connect(&a));
    CHECK(app_send(&a, hello_openssl, 700, 3000));
    pump(120);
    CHECK(app_send(&a, hello_openssl + 700, hello_openssl_len - 700, 3000));
    rec = echo_wait(&desync_echo, want, 3000);
    CHECK(rec && rec->len == want);
    if (rec && rec->len == want) {
        CHECK(join_records(rec->data, rec->len, body) == original_len);
        CHECK(memcmp(body, original, original_len) == 0);
    }
    app_forget(&a);
    echo_forget(&desync_echo);

    /* a request with a host header is cut and arrives whole */
    static const char req[] = "GET /page HTTP/1.1\r\nHost: blocked.example.org\r\nAccept: */*\r\n\r\n";
    app_init(&a, 0, desync_echo.port, 40012);
    CHECK(app_connect(&a));
    CHECK(app_send(&a, (const uint8_t *)req, sizeof req - 1, 3000));
    rec = echo_wait(&desync_echo, sizeof req - 1, 3000);
    CHECK(rec && rec->len == sizeof req - 1 && memcmp(rec->data, req, sizeof req - 1) == 0);
    app_forget(&a);
    echo_forget(&desync_echo);

    /* a stream that is neither passes at once, and more can follow */
    static uint8_t other[3000];
    for (size_t i = 0; i < sizeof other; ++i) other[i] = pattern_byte(i + 77);
    other[0] = 0x00;
    app_init(&a, 0, desync_echo.port, 40013);
    CHECK(app_connect(&a));
    CHECK(app_send(&a, other, 1000, 3000));
    CHECK(app_send(&a, other + 1000, 2000, 3000));
    rec = echo_wait(&desync_echo, sizeof other, 3000);
    CHECK(rec && rec->len == sizeof other && memcmp(rec->data, other, sizeof other) == 0);
    app_forget(&a);
    echo_forget(&desync_echo);

    /* a start that never completes is sent as it is after a wait */
    static const char half[] = "GET /slow HTTP/1.1\r\nHost: wait.exam";
    app_init(&a, 0, desync_echo.port, 40014);
    CHECK(app_connect(&a));
    CHECK(app_send(&a, (const uint8_t *)half, sizeof half - 1, 3000));
    pump_for(2000);
    rec = echo_wait(&desync_echo, sizeof half - 1, 1000);
    CHECK(rec && rec->len == sizeof half - 1 && memcmp(rec->data, half, sizeof half - 1) == 0);
    app_forget(&a);
    echo_forget(&desync_echo);
}

/* ---- a server that behaves like a filter ----------------------------------- */

typedef enum {
    F_REJECT_CUT,   /* resets a hello whose first record is not the whole hello */
    F_REJECT_ALL,   /* resets every hello */
    F_SILENT_FIRST, /* says nothing to the first connection */
    F_ALERT_FIRST,  /* answers the first connection with a tls alert */
    F_BLOCK_ADDR    /* says nothing on 127.0.0.1 and answers on 127.0.0.2, the way a filter
                       answers one address of a site with silence */
} filter_mode_t;

typedef struct {
    int             listen_fd;
    uint16_t        port;
    filter_mode_t   mode;
    pthread_mutex_t lock;
    int             accepts;
    int             intact[16]; /* the hello arrived as one record, by connection */
    int             silenced;   /* connections on 127.0.0.1 left without an answer */
    int             served;     /* connections on 127.0.0.2 that got the server's hello */
} filter_t;

static filter_t filter;
static const uint8_t SERVER_HELLO[] = { 0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00 };
static const uint8_t TLS_ALERT[] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28 };

static int read_exact(int fd, uint8_t *buf, size_t n) {
    size_t at = 0;
    while (at < n) {
        ssize_t got = read(fd, buf + at, n - at);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return -1;
        at += (size_t)got;
    }
    return 0;
}

static void drain_and_close(int fd) {
    uint8_t sink[2048];
    while (read(fd, sink, sizeof sink) > 0) {}
    close(fd);
}

static void *filter_one(void *arg) {
    int fd = (int)(intptr_t)arg;
    pthread_mutex_lock(&filter.lock);
    int ordinal = filter.accepts++;
    pthread_mutex_unlock(&filter.lock);
    uint8_t head[5];
    uint8_t body[16384];
    if (read_exact(fd, head, 5) != 0) { close(fd); return NULL; }
    size_t len = (size_t)head[3] << 8 | head[4];
    if (len > sizeof body || read_exact(fd, body, len) != 0) { close(fd); return NULL; }
    int intact = 5 + len == hello_openssl_len;
    if (getenv("BYE_TEST_TRACE")) fprintf(stderr, "filter conn %d first record %zu intact %d\n", ordinal, len, intact);
    if (ordinal < 16) filter.intact[ordinal] = intact;
    if (filter.mode == F_BLOCK_ADDR) {
        struct sockaddr_in local;
        socklen_t local_len = sizeof local;
        int first_address = getsockname(fd, (struct sockaddr *)&local, &local_len) == 0 &&
                            local.sin_addr.s_addr == htonl(INADDR_LOOPBACK);
        pthread_mutex_lock(&filter.lock);
        if (first_address) ++filter.silenced;
        else ++filter.served;
        pthread_mutex_unlock(&filter.lock);
        if (first_address) {
            drain_and_close(fd);
            return NULL;
        }
    }
    int reset = filter.mode == F_REJECT_ALL || (filter.mode == F_REJECT_CUT && !intact);
    if (reset) {
        struct linger hard = { 1, 0 };
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &hard, sizeof hard);
        close(fd);
        return NULL;
    }
    if (filter.mode == F_SILENT_FIRST && ordinal == 0) {
        drain_and_close(fd);
        return NULL;
    }
    if (filter.mode == F_ALERT_FIRST && ordinal == 0) {
        CHECK(write_full(fd, TLS_ALERT, sizeof TLS_ALERT) == 0);
        drain_and_close(fd);
        return NULL;
    }
    CHECK(write_full(fd, SERVER_HELLO, sizeof SERVER_HELLO) == 0);
    drain_and_close(fd);
    return NULL;
}

static void *filter_main(void *arg) {
    (void)arg;
    for (;;) {
        int fd = accept(filter.listen_fd, NULL, NULL);
        if (fd < 0) return NULL;
        pthread_t t;
        pthread_create(&t, NULL, filter_one, (void *)(intptr_t)fd);
        pthread_detach(t);
    }
}

static void filter_start(filter_mode_t mode) {
    memset(&filter, 0, sizeof filter);
    filter.mode = mode;
    pthread_mutex_init(&filter.lock, NULL);
    filter.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(mode == F_BLOCK_ADDR ? INADDR_ANY : INADDR_LOOPBACK);
    CHECK(bind(filter.listen_fd, (struct sockaddr *)&a, sizeof a) == 0);
    socklen_t alen = sizeof a;
    getsockname(filter.listen_fd, (struct sockaddr *)&a, &alen);
    filter.port = ntohs(a.sin_port);
    CHECK(listen(filter.listen_fd, 16) == 0);
    pthread_t t;
    pthread_create(&t, NULL, filter_main, NULL);
    pthread_detach(t);
    filter_port = filter.port;
}

static void filter_stop(void) {
    filter_port = 0;
    shutdown(filter.listen_fd, SHUT_RDWR);
    close(filter.listen_fd);
}

static int filter_accepts(void) {
    pthread_mutex_lock(&filter.lock);
    int n = filter.accepts;
    pthread_mutex_unlock(&filter.lock);
    return n;
}

/* one app sends a hello to the port and waits for want bytes or a reset */
static int hello_flow(uint16_t port, uint16_t sport, size_t want, int *got_rst) {
    static app_t a;
    app_init(&a, 0, port, sport);
    CHECK(app_connect(&a));
    /* a filter that resets every hello ends the flow under the app's feet */
    (void)app_send(&a, hello_openssl, hello_openssl_len, 3000);
    for (int waited = 0; a.rx_len < want && !a.got_rst && waited < 5000; waited += 10) pump(10);
    int answered = a.rx_len >= want;
    int first_byte = a.rx_len ? a.rx[0] : -1;
    if (got_rst) *got_rst = a.got_rst;
    app_forget(&a);
    return answered ? first_byte : -1;
}

static const bye_tcp_stats_t *tcp_stats(void) {
    return bye_tcp_stats(tunnel.tcp);
}

static void test_auto(void) {
    int rst = 0;

    /* the first strategy cuts the record and the filter resets it: the second
       gets through, and the next flow to that address starts with it */
    filter_start(F_REJECT_CUT);
    CHECK(hello_flow(filter.port, 41001, sizeof SERVER_HELLO, &rst) == 0x16 && !rst);
    CHECK(filter_accepts() == 2 && !filter.intact[0] && filter.intact[1]);
    CHECK(tcp_stats()->auto_retried == 1 && tcp_stats()->auto_learned == 1 &&
          tcp_stats()->auto_exhausted == 0);
    /* the retry is named in the report, with the server name from the hello */
    CHECK(tcp_stats()->recent_count >= 1);
    const char *last = tcp_stats()->recent[(tcp_stats()->recent_count - 1) % BYE_TCP_RECENT_MAX];
    CHECK(strstr(last, "desync no answer, next strategy") != NULL && strstr(last, "127.0.0.1") != NULL);
    CHECK(hello_flow(filter.port, 41002, sizeof SERVER_HELLO, &rst) == 0x16 && !rst);
    CHECK(filter_accepts() == 3 && filter.intact[2]);
    CHECK(tcp_stats()->auto_retried == 1 && tcp_stats()->auto_learned == 1);
    /* a new destination has no address cache entry, but shares the site's strategy */
    static app_t other;
    app_init(&other, 0, desync_echo.port, 41007);
    CHECK(app_connect(&other));
    CHECK(app_send(&other, hello_openssl, hello_openssl_len, 3000));
    CHECK(app_read(&other, hello_openssl_len, 3000));
    record_t *rec = echo_wait(&desync_echo, hello_openssl_len, 100);
    CHECK(rec && rec->len == hello_openssl_len &&
          memcmp(rec->data, hello_openssl, hello_openssl_len) == 0);
    app_fin(&other);
    CHECK(wait_until(&other.got_fin, 3000));
    app_forget(&other);
    echo_forget(&desync_echo);
    filter_stop();

    /* every strategy is reset: the app gets a reset too, and the address is
       left alone for a while */
    uint64_t retried = tcp_stats()->auto_retried;
    filter_start(F_REJECT_ALL);
    hello_flow(filter.port, 41003, sizeof SERVER_HELLO, &rst);
    CHECK(rst);
    CHECK(filter_accepts() == 4);
    CHECK(tcp_stats()->auto_retried == retried + 3 && tcp_stats()->auto_exhausted == 1);
    /* the whole hello is kept, once the last retry has seen it all for the strategy check, with the name and address it went to */
    CHECK(tcp_stats()->capture.hello_len == hello_openssl_len && tcp_stats()->capture.name[0] != '\0');
    CHECK(memcmp(tcp_stats()->capture.hello, hello_openssl, hello_openssl_len) == 0);
    CHECK(tcp_stats()->capture.addr[0] == 127 && tcp_stats()->capture.port == filter.port);
    hello_flow(filter.port, 41004, sizeof SERVER_HELLO, &rst);
    CHECK(rst && filter_accepts() == 5);
    CHECK(tcp_stats()->auto_retried == retried + 3 && tcp_stats()->auto_exhausted == 1);
    filter_stop();

    /* no answer at all: the wait ends and the next strategy is tried */
    retried = tcp_stats()->auto_retried;
    filter_start(F_SILENT_FIRST);
    CHECK(hello_flow(filter.port, 41005, sizeof SERVER_HELLO, &rst) == 0x16 && !rst);
    CHECK(filter_accepts() == 2 && tcp_stats()->auto_retried == retried + 1);
    filter_stop();

    /* a tls alert is the filter's answer, not the server's */
    retried = tcp_stats()->auto_retried;
    filter_start(F_ALERT_FIRST);
    CHECK(hello_flow(filter.port, 41006, sizeof SERVER_HELLO, &rst) == 0x16 && !rst);
    CHECK(filter_accepts() == 2 && tcp_stats()->auto_retried == retried + 1);
    filter_stop();
}

/* the other address of the site, as a lookup would find it */
static size_t fake_site_lookup(const char *name, uint8_t out[][4], size_t max) {
    if (strcmp(name, "www.example-blocked.org") != 0 || max < 1) return 0;
    out[0][0] = 127; out[0][1] = 0; out[0][2] = 0; out[0][3] = 2;
    return 1;
}

static size_t no_lookup(const char *name, uint8_t out[][4], size_t max) {
    (void)name; (void)out; (void)max;
    return 0;
}

/* every cut is met with silence at the app's address, and another address of the site
   answers: the flow moves there, and later flows go there at once */
static void test_alt_address(void) {
    int rst = 0;
    bye_altaddr_set_resolver(fake_site_lookup);
    filter_start(F_BLOCK_ADDR);
    uint64_t retried = tcp_stats()->auto_retried;
    CHECK(hello_flow(filter.port, 41101, sizeof SERVER_HELLO, &rst) == 0x16 && !rst);
    CHECK(tcp_stats()->addr_retried == 1);
    CHECK(tcp_stats()->auto_retried == retried + 3);
    pthread_mutex_lock(&filter.lock);
    int silenced = filter.silenced, served = filter.served;
    pthread_mutex_unlock(&filter.lock);
    CHECK(silenced == 4 && served == 1);

    /* the next flow goes to the address that answered, with no wait at the first one */
    CHECK(hello_flow(filter.port, 41102, sizeof SERVER_HELLO, &rst) == 0x16 && !rst);
    pthread_mutex_lock(&filter.lock);
    CHECK(filter.silenced == 4 && filter.served == 2);
    pthread_mutex_unlock(&filter.lock);
    CHECK(tcp_stats()->addr_retried == 1);
    filter_stop();

    bye_altaddr_set_resolver(NULL);
}

/* the same hello through a host list */
static void test_hosts_flow(const char *list, int only, int want_cut, uint64_t want_skipped) {
    bye_sniff_t name;
    char text[256], error[BYE_HOSTS_ERROR_MAX];
    CHECK(bye_sniff_tls(hello_openssl, hello_openssl_len, &name) == BYE_SNIFF_OK);
    snprintf(text, sizeof text, list, (int)name.name_len, (const char *)hello_openssl + name.name_off);
    knob_hosts = bye_hosts_parse(text, strlen(text), error, sizeof error);
    CHECK(knob_hosts != NULL);
    knob_hosts_only = only;
    tunnel_start(gate.port, 1, 0);
    static app_t a;
    app_init(&a, 0, desync_echo.port, 41100);
    CHECK(app_connect(&a));
    CHECK(app_send(&a, hello_openssl, hello_openssl_len, 3000));
    size_t want = want_cut ? hello_openssl_len + 5 : hello_openssl_len;
    record_t *rec = echo_wait(&desync_echo, want, 3000);
    CHECK(rec && rec->len == want);
    if (rec && !want_cut) CHECK(memcmp(rec->data, hello_openssl, hello_openssl_len) == 0);
    CHECK(tcp_stats()->hosts_skipped == want_skipped);
    app_forget(&a);
    echo_forget(&desync_echo);
    tunnel_stop();
    bye_hosts_free(knob_hosts);
    knob_hosts = NULL;
}

/* an app running the obfuscated transport: sends the wire init and packets
   and reads back what the datacenter echoes */
static void test_telegram(void) {
    static app_t a;
    client_t cl;
    uint8_t stream[2000], wire[2000], packets[2000];
    size_t used = 0, sizes[3];

    /* init and three packets in one write, to datacenter 2 */
    client_open(&cl, BYE_MTP_TAG_ABRIDGED, 2);
    sizes[0] = abridged_packet(packets + used, 5, 0x10); used += sizes[0];
    sizes[1] = abridged_packet(packets + used, 20, 0x30); used += sizes[1];
    sizes[2] = abridged_packet(packets + used, 130, 0x50); used += sizes[2];
    memcpy(wire, packets, used);
    ctr_xor(cl.enc, wire, used);
    memcpy(stream, cl.wire_init, 64);
    memcpy(stream + 64, wire, used);

    app_init(&a, 0, fallback_echo.port, 40020);
    CHECK(app_connect(&a));
    CHECK(app_send(&a, stream, 64 + used, 3000));
    gate_conn_t *g = gate_wait(3, 5000);
    CHECK(g != NULL);
    if (g) {
        CHECK(g->init_ok && g->tag == BYE_MTP_TAG_ABRIDGED && g->dc == 2);
        CHECK(strcmp(g->host, "kws2.web.telegram.org") == 0 && g->subprotocol_ok);
        CHECK(g->messages == 3 && g->misaligned == 0 && g->bytes == used);
        uint32_t h = 2166136261u;
        h = fnv(h, packets, used);
        CHECK(g->hash == h);
    }
    CHECK(app_read(&a, used, 5000));
    CHECK(a.rx_len == used);
    ctr_xor(cl.dec, a.rx, a.rx_len);
    CHECK(memcmp(a.rx, packets, used) == 0);
    /* it never touched the direct echo */
    CHECK(echo_wait(&fallback_echo, 1, 100) == NULL);
    app_fin(&a);
    app_forget(&a);
    client_close(&cl);
    gate_forget();

    /* the media connection of datacenter 4 asks the "-1" host first */
    client_open(&cl, BYE_MTP_TAG_INTERMEDIATE, -4);
    app_init(&a, 0, fallback_echo.port, 40021);
    CHECK(app_connect(&a));
    uint8_t pkt[4 + 64], wirepkt[4 + 64];
    pkt[0] = 64; pkt[1] = pkt[2] = pkt[3] = 0;
    memset(pkt + 4, 0x6b, 64);
    memcpy(wirepkt, pkt, sizeof pkt);
    ctr_xor(cl.enc, wirepkt, sizeof pkt);
    memcpy(stream, cl.wire_init, 64);
    memcpy(stream + 64, wirepkt, sizeof pkt);
    CHECK(app_send(&a, stream, 64 + sizeof pkt, 3000));
    g = gate_any(5000);
    CHECK(g != NULL);
    for (int i = 0; g && i < 200 && !g->init_ok; ++i) pause_ms(10);
    if (g) {
        CHECK(g->init_ok && g->tag == BYE_MTP_TAG_INTERMEDIATE && g->dc == -4);
        CHECK(strcmp(g->host, "kws4-1.web.telegram.org") == 0);
    }
    app_fin(&a);
    app_forget(&a);
    client_close(&cl);
    gate_forget();
    pump(100);

    /* a large upload in many tcp writes is one message at the datacenter, and
       its echo comes back through a small window */
    client_open(&cl, BYE_MTP_TAG_ABRIDGED, 2);
    app_init(&a, 0, fallback_echo.port, 40022);
    a.window = 4096;
    CHECK(app_connect(&a));
    static uint8_t big[300000], bigwire[400000];
    size_t big_len = abridged_packet(big, 70000, 0x21);
    memcpy(bigwire, big, big_len);
    ctr_xor(cl.enc, bigwire, big_len);
    CHECK(app_send(&a, cl.wire_init, 64, 3000));
    CHECK(app_send(&a, bigwire, big_len, 20000));
    g = gate_wait(1, 10000);
    CHECK(g != NULL);
    if (g) CHECK(g->messages == 1 && g->misaligned == 0 && g->bytes == big_len);
    for (int w = 0; a.rx_len < big_len && w < 20000; w += 10) {
        pump(10);
        if (w % 50 == 0) app_ack(&a);
    }
    CHECK(a.rx_len == big_len);
    ctr_xor(cl.dec, a.rx, a.rx_len);
    CHECK(memcmp(a.rx, big, big_len) == 0);
    app_fin(&a);
    app_forget(&a);
    client_close(&cl);
    gate_forget();
    pump(100);
}

static void test_telegram_fallback(const char *what, const uint8_t *first, size_t first_len) {
    static app_t a;
    app_init(&a, 0, fallback_echo.port, 40030);
    CHECK(app_connect(&a));
    CHECK(app_send(&a, first, first_len, 3000));
    record_t *rec = echo_wait(&fallback_echo, first_len, 8000);
    if (!rec || rec->len != first_len || memcmp(rec->data, first, first_len) != 0)
        fprintf(stderr, "fallback case failed: %s\n", what);
    CHECK(rec && rec->len == first_len && memcmp(rec->data, first, first_len) == 0);
    CHECK(app_read(&a, first_len, 3000));
    CHECK(a.rx_len == first_len && memcmp(a.rx, first, first_len) == 0);
    /* the flow goes on as a plain one in both directions */
    uint8_t more[500];
    for (size_t i = 0; i < sizeof more; ++i) more[i] = pattern_byte(i + 9);
    CHECK(app_send(&a, more, sizeof more, 3000));
    CHECK(app_read(&a, first_len + sizeof more, 3000));
    CHECK(a.rx_len == first_len + sizeof more && memcmp(a.rx + first_len, more, sizeof more) == 0);
    app_fin(&a);
    CHECK(wait_until(&a.got_fin, 3000));
    app_forget(&a);
    echo_forget(&fallback_echo);
}

static void test_udp(int expect_quic_dropped) {
    static const uint8_t payload[] = "hello over udp";
    uint8_t p[1600], frame[1604];
    inbox.udp_seen = 0;
    echo_t *unused = NULL;
    (void)unused;

    int server = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(server, (struct sockaddr *)&a, sizeof a) == 0);
    socklen_t alen = sizeof a;
    getsockname(server, (struct sockaddr *)&a, &alen);
    uint16_t port = ntohs(a.sin_port);
    fcntl(server, F_SETFL, fcntl(server, F_GETFL, 0) | O_NONBLOCK);

    size_t n = pkt_udp4(p, APP4, 41000, LOOP4, port, payload, sizeof payload);
    size_t f = pkt_frame(frame, p, n);
    send(tunnel.peer, frame, f, 0);
    uint8_t got[64];
    struct sockaddr_in from;
    socklen_t flen = sizeof from;
    ssize_t r = -1;
    for (int i = 0; i < 300 && r < 0; ++i) {
        pump(10);
        r = recvfrom(server, got, sizeof got, 0, (struct sockaddr *)&from, &flen);
    }
    CHECK(r == (ssize_t)sizeof payload && memcmp(got, payload, sizeof payload) == 0);
    if (r > 0) sendto(server, "pong", 4, 0, (struct sockaddr *)&from, flen);
    CHECK(wait_until(&inbox.udp_seen, 3000));
    CHECK(inbox.udp_len == 4 && memcmp(inbox.udp_payload, "pong", 4) == 0 && inbox.udp_sport == port);
    close(server);

    /* udp 443 is quic: refused with icmp port unreachable when asked to,
       relayed otherwise */
    inbox.udp_seen = 0;
    int quic = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(443);
    int bound = bind(quic, (struct sockaddr *)&a, sizeof a);
    if (bound != 0) {
        /* an unprivileged run cannot take port 443: the refusal is still
           checked on the tunnel */
        close(quic);
        quic = -1;
    } else {
        fcntl(quic, F_SETFL, fcntl(quic, F_GETFL, 0) | O_NONBLOCK);
    }
    n = pkt_udp4(p, APP4, 41001, LOOP4, 443, payload, sizeof payload);
    f = pkt_frame(frame, p, n);
    inbox.icmp_seen = 0;
    send(tunnel.peer, frame, f, 0);
    pump(300);
    if (expect_quic_dropped) {
        CHECK(inbox.icmp_seen == 1);
        CHECK(inbox.icmp_type == 3 && inbox.icmp_code == 3);
        CHECK(inbox.icmp_quoted_sport == 41001 && inbox.icmp_quoted_dport == 443);
    } else {
        CHECK(inbox.icmp_seen == 0);
    }
    if (quic >= 0) {
        r = recv(quic, got, sizeof got, 0);
        CHECK(expect_quic_dropped ? r < 0 : r == (ssize_t)sizeof payload);
        close(quic);
    }
}

/* one telegram flow, and the host the gateway was asked for */
static void test_relay(const char *what, const char *want_host) {
    static app_t a;
    client_t cl;
    uint8_t stream[200], pkt[1 + 16], wirepkt[1 + 16];
    client_open(&cl, BYE_MTP_TAG_ABRIDGED, 2);
    pkt[0] = 4;
    memset(pkt + 1, 0x33, 16);
    memcpy(wirepkt, pkt, sizeof pkt);
    ctr_xor(cl.enc, wirepkt, sizeof pkt);
    memcpy(stream, cl.wire_init, 64);
    memcpy(stream + 64, wirepkt, sizeof pkt);
    app_init(&a, 0, fallback_echo.port, 40040);
    CHECK(app_connect(&a));
    CHECK(app_send(&a, stream, 64 + sizeof pkt, 3000));
    gate_conn_t *g = gate_wait(1, 5000);
    if (!g || strcmp(g->host, want_host) != 0)
        fprintf(stderr, "relay case failed: %s (host '%s')\n", what, g ? g->host : "none");
    CHECK(g != NULL);
    if (g) CHECK(strcmp(g->host, want_host) == 0 && g->init_ok && g->messages == 1);
    CHECK(app_read(&a, sizeof pkt, 5000));
    app_fin(&a);
    app_forget(&a);
    client_close(&cl);
    gate_forget();
    pump(100);
}

/* upgraded gateway connections no flow has taken yet */
static int gate_idle(void) {
    int idle = 0;
    pthread_mutex_lock(&gate.lock);
    for (size_t i = 0; i < SERVER_CONNS; ++i)
        if (gate.conns[i].used && !gate.conns[i].finished && gate.conns[i].subprotocol_ok &&
            !gate.conns[i].init_ok) ++idle;
    pthread_mutex_unlock(&gate.lock);
    return idle;
}

/* the gateway hangs up on every connection nobody has used */
static void gate_drop_idle(void) {
    pthread_mutex_lock(&gate.lock);
    for (size_t i = 0; i < SERVER_CONNS; ++i)
        if (gate.conns[i].used && !gate.conns[i].finished && gate.conns[i].subprotocol_ok &&
            !gate.conns[i].init_ok)
            shutdown(gate.conns[i].fd, SHUT_RDWR);
    pthread_mutex_unlock(&gate.lock);
}

static int gate_taken(void) {
    int taken = 0;
    pthread_mutex_lock(&gate.lock);
    for (size_t i = 0; i < SERVER_CONNS; ++i)
        if (gate.conns[i].used && gate.conns[i].init_ok) ++taken;
    pthread_mutex_unlock(&gate.lock);
    return taken;
}

/* the gateway has the connections and the tunnel holds them ready */
static int wait_idle(int want, int wait_ms) {
    for (int waited = 0; waited <= wait_ms; waited += 10) {
        if (gate_idle() == want && tcp_stats()->pool_ready == (uint64_t)want) return 1;
        pump(10);
    }
    return 0;
}

/* a telegram flow that echoes one packet. the gateway's records stay, so
   the connections can be counted */
static void pool_flow(uint16_t sport, int dc) {
    static app_t a;
    client_t cl;
    uint8_t stream[200], pkt[1 + 16], wirepkt[1 + 16];
    client_open(&cl, BYE_MTP_TAG_ABRIDGED, dc);
    pkt[0] = 4;
    memset(pkt + 1, 0x33, 16);
    memcpy(wirepkt, pkt, sizeof pkt);
    ctr_xor(cl.enc, wirepkt, sizeof pkt);
    memcpy(stream, cl.wire_init, 64);
    memcpy(stream + 64, wirepkt, sizeof pkt);
    app_init(&a, 0, fallback_echo.port, sport);
    CHECK(app_connect(&a));
    CHECK(app_send(&a, stream, 64 + sizeof pkt, 3000));
    CHECK(app_read(&a, sizeof pkt, 5000));
    app_fin(&a);
    app_forget(&a);
    client_close(&cl);
    pump(100);
}

/* the gateway connection of a datacenter is made before a flow asks for it */
static void test_pool(void) {
    knob_pool = 1;
    gate_forget();
    tunnel_start(gate.port, 1, 0);
    CHECK(gate_idle() == 0);

    /* the first flow finds nothing ready and connects itself; the datacenter
       is then kept ready */
    pool_flow(41200, 2);
    CHECK(tcp_stats()->pool_hits == 0 && tcp_stats()->pool_misses == 1);
    CHECK(wait_idle(1, 5000));

    /* the next flow takes it, with no new connection of its own, and the
       pool is filled again behind it */
    int before = gate_taken();
    pool_flow(41201, 2);
    CHECK(tcp_stats()->pool_hits == 1 && tcp_stats()->pool_misses == 1);
    CHECK(gate_taken() == before + 1);
    CHECK(wait_idle(1, 5000));

    /* the media connection of the datacenter has none ready: a miss, then it is kept too, and the
       pool never holds more than it was given */
    pool_flow(41202, -2);
    CHECK(tcp_stats()->pool_misses == 2);
    CHECK(wait_idle(2, 5000));
    pump(1500);
    CHECK(gate_idle() == 2 && tcp_stats()->pool_ready == 2);

    /* the gateway hangs up on its idle connections: the tunnel lets them go
       and makes new ones */
    gate_drop_idle();
    for (int waited = 0; gate_idle() != 0 && waited < 3000; waited += 10) pump(10);
    CHECK(gate_idle() == 0);
    CHECK(wait_idle(2, 8000));
    pool_flow(41203, 2);
    CHECK(tcp_stats()->pool_hits == 2);
    tunnel_stop();
    gate_forget();
    knob_pool = 0;
}

/* ack batches model an app that does not drain utun on every packet */
static int benchmark(void) {
    static app_t a;
    static uint8_t data[500000];
    echo_start(&direct_echo);
    if (failed) return failed;
    tunnel_start(0, 1, 0);
    app_init(&a, 0, direct_echo.port, 40200);
    CHECK(app_connect(&a));
    a.ack_delay_ms = 10;
    for (size_t i = 0; i < sizeof data; ++i) data[i] = pattern_byte(i);
    struct timespec start, end, cpu_start, cpu_end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_start);
    CHECK(app_send(&a, data, sizeof data, 10000));
    CHECK(app_read(&a, sizeof data, 20000));
    clock_gettime(CLOCK_MONOTONIC, &end);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_end);
    double seconds = end.tv_sec - start.tv_sec + (end.tv_nsec - start.tv_nsec) / 1e9;
    double cpu = cpu_end.tv_sec - cpu_start.tv_sec + (cpu_end.tv_nsec - cpu_start.tv_nsec) / 1e9;
    CHECK(a.rx_len == sizeof data && memcmp(a.rx, data, sizeof data) == 0);
    if (!failed)
        printf("local relay: %zu bytes, %.3f s, %.2f Mbit/s, %.3f CPU s\n",
               a.rx_len, seconds, a.rx_len * 8 / seconds / 1e6, cpu);
    a.ack_delay_ms = 0;
    app_ack(&a);
    app_fin(&a);
    CHECK(wait_until(&a.got_fin, 3000));
    app_forget(&a);
    tunnel_stop();
    return failed;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc == 2 && strcmp(argv[1], "--benchmark") == 0) return benchmark();
    gate_start();
    char error[BYE_WSCONN_ERROR_MAX];
    tls_ctx = bye_wsconn_ctx_new(cert_path, error, sizeof error);
    CHECK(tls_ctx != NULL);
    echo_start(&direct_echo);
    echo_start(&desync_echo);
    echo_start(&fallback_echo);

    tunnel_start(gate.port, 1, 0);
    test_direct();
    test_desync();
    test_fragmented_hello();
    test_telegram();
    test_udp(1);

    /* the gateway is up but refuses the upgrade: both hosts fail, the flow
       goes direct and the app's bytes are not changed */
    gate.reject_all = 1;
    {
        client_t cl;
        client_open(&cl, BYE_MTP_TAG_ABRIDGED, 2);
        uint8_t first[64 + 12];
        memcpy(first, cl.wire_init, 64);
        uint8_t pkt[12] = { 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
        ctr_xor(cl.enc, pkt, sizeof pkt);
        memcpy(first + 64, pkt, sizeof pkt);
        test_telegram_fallback("gateway refuses the upgrade", first, sizeof first);
        client_close(&cl);
    }
    gate.reject_all = 0;
    gate_forget();

    /* the gateway fails once, so the next flow does not wait for it again */
    {
        client_t cl;
        client_open(&cl, BYE_MTP_TAG_ABRIDGED, 2);
        uint8_t first[64 + 12];
        memcpy(first, cl.wire_init, 64);
        memset(first + 64, 0x44, 12);
        test_telegram_fallback("a datacenter in cooldown", first, sizeof first);
        client_close(&cl);
        gate_forget();
    }
    tunnel_stop();

    /* another websocket address follows a tcp refusal without going direct */
    knob_gateway_addresses = 1;
    tunnel_start(gate.port, 1, 0);
    test_relay("the next websocket address follows a tcp refusal", "kws2-1.web.telegram.org");
    tunnel_stop();
    knob_gateway_addresses = 0;

    /* a relay is tried first, and its host is the one the gateway sees */
    tunnel_start(gate.port, 1, 1);
    test_relay("relay.test host", "kws2.relay.test");
    gate.reject_relay = 1;
    test_relay("relay refused, the datacenter's host follows", "kws2.web.telegram.org");
    gate.reject_relay = 0;
    tunnel_stop();

    /* the first relay is refused, the second answers, and the next flow
       starts with the second */
    tunnel_start(gate.port, 1, 2);
    gate.reject_relay = 1;
    test_relay("the second relay follows the first", "kws2.relay2.test");
    test_relay("the relay that worked goes first", "kws2.relay2.test");
    gate.reject_relay = 0;
    tunnel_stop();

    /* nothing listens at the gateway address */
    tunnel_start(1, 0, 0);
    {
        client_t cl;
        client_open(&cl, BYE_MTP_TAG_PADDED, 3);
        uint8_t first[64 + 8];
        memcpy(first, cl.wire_init, 64);
        memset(first + 64, 0x17, 8);
        test_telegram_fallback("gateway port closed", first, sizeof first);
        client_close(&cl);
    }
    /* not an obfuscated stream: a hundred bytes of text */
    {
        uint8_t plain[100];
        memset(plain, 'q', sizeof plain);
        test_telegram_fallback("not obfuscated", plain, sizeof plain);
        static const char http[] =
            "POST /api HTTP/1.1\r\nHost: 149.154.167.51:80\r\nContent-Length: 40\r\n\r\n"
            "0123456789012345678901234567890123456789";
        test_telegram_fallback("http transport", (const uint8_t *)http, sizeof http - 1);
    }
    test_udp(0);
    tunnel_stop();

    test_pool();

    /* a strategy list: the same cuts reach the server, and a flow that gets no
       answer moves on */
    /* the second strategy keeps the record whole, which is what the filter
       here lets through */
    knob_strategies = "tlsrec=name+1;split=1,name+1|split=1,name+1|split=1,name+1;oob=1|none";
    knob_auto_wait_ms = 300;
    tunnel_start(gate.port, 1, 0);
    test_desync();
    bye_altaddr_set_resolver(no_lookup);
    test_auto();
    test_alt_address();
    tunnel_stop();
    knob_strategies = BYE_DESYNC_DEFAULT_SPEC;
    knob_auto_wait_ms = 0;

    /* the options of ciadpi: a disorder part, a cut and an urgent byte still deliver one
       stream, and the record is cut inside the name. one urgent byte only: a second one
       sent before the server reads the first turns the first into plain data */
    knob_strategies = "-d1 -s5 -q9 -r1+s";
    tunnel_start(gate.port, 1, 0);
    test_desync();
    tunnel_stop();
    knob_strategies = BYE_DESYNC_DEFAULT_SPEC;

    /* the host list: only the listed name is cut, or all but it */
    test_hosts_flow("%.*s\n", 1, 1, 0);
    test_hosts_flow("other.example\n", 1, 0, 1);
    test_hosts_flow("%.*s\n", 0, 0, 1);
    test_hosts_flow("other.example\n", 0, 1, 0);

    char cmd[300];
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
    if (system(cmd) != 0) fprintf(stderr, "cleanup of %s failed\n", dir);
    if (!failed) puts("test_flows ok");
    return failed;
}

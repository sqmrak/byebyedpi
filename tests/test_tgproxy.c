/* the local telegram proxy end to end: a client speaks the mtproxy obfuscation
   with a secret to 127.0.0.1, a stand-in for the gateway (tls, a websocket and
   a datacenter) answers. the client and the datacenter are written from the
   published obfuscation description, not from the bridge */

#define _DEFAULT_SOURCE

#include "bye_tgproxy.h"
#include "bye_wsconn.h"

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
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "check.h"

static const uint8_t SECRET[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
static const uint8_t LOOP4[4] = { 127, 0, 0, 1 };

static EVP_CIPHER_CTX *ctr(const uint8_t *key, const uint8_t *iv) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    CHECK(EVP_EncryptInit_ex(c, EVP_aes_256_ctr(), NULL, key, iv) == 1);
    return c;
}

static void xor_stream(EVP_CIPHER_CTX *c, uint8_t *data, size_t len) {
    int n = 0;
    CHECK(EVP_EncryptUpdate(c, data, &n, data, (int)len) == 1 && (size_t)n == len);
}



typedef struct {
    int  used;
    int  init_ok;
    int  dc;
    char host[64];
    size_t messages;
} gate_conn_t;

static struct {
    int             listen_fd;
    uint16_t        port;
    SSL_CTX        *ctx;
    pthread_mutex_t lock;
    gate_conn_t     conns[64];
    size_t          mark;       /* the first record of the running test */
    int             reject_all;
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

static int send_frame(SSL *ssl, const uint8_t *payload, size_t n) {
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

/* reads the init, then echoes every message back in the datacenter's key stream */
static void gate_serve(SSL *ssl, gate_conn_t *rec) {
    char req[2048];
    size_t len = 0;
    while (len < sizeof req - 1) {
        if (SSL_read(ssl, req + len, 1) <= 0) return;
        ++len;
        if (len >= 4 && memcmp(req + len - 4, "\r\n\r\n", 4) == 0) break;
    }
    req[len] = '\0';
    const char *host = strstr(req, "\r\nHost: ");
    const char *key = strstr(req, "\r\nSec-WebSocket-Key: ");
    if (host) sscanf(host + 8, "%63[^\r]", rec->host);
    if (gate.reject_all || !key || !strstr(req, "Sec-WebSocket-Protocol: binary\r\n")) {
        static const char no[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        ssl_write_full(ssl, (const uint8_t *)no, sizeof no - 1);
        return;
    }
    char keyval[64], joined[128], accept[40], resp[256];
    sscanf(key + 21, "%63[^\r]", keyval);
    snprintf(joined, sizeof joined, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", keyval);
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    EVP_Digest(joined, strlen(joined), digest, &dlen, EVP_sha1(), NULL);
    b64(digest, dlen, accept);
    int rn = snprintf(resp, sizeof resp,
                      "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
                      "Sec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: binary\r\n\r\n", accept);
    if (ssl_write_full(ssl, (const uint8_t *)resp, (size_t)rn) != 0) return;

    EVP_CIPHER_CTX *dec = NULL, *enc = NULL;
    uint8_t *msg = malloc(1u << 20);
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
        if (!(h2[1] & 0x80) || ssl_read_full(ssl, mask, 4) != 0 || n > (1u << 20)) break;
        if (ssl_read_full(ssl, msg, n) != 0) break;
        for (size_t i = 0; i < n; ++i) msg[i] ^= mask[i & 3];
        int opcode = h2[0] & 0x0F;
        if (opcode == 0x8) break;
        if (opcode == 0x9 || opcode == 0xA) continue;
        if (!dec) {
            if (n != 64) break;
            uint8_t rev[48], plain[64];
            dec = ctr(msg + 8, msg + 40);
            memcpy(plain, msg, 64);
            xor_stream(dec, plain, 64);
            for (size_t i = 0; i < 48; ++i) rev[i] = msg[8 + 47 - i];
            enc = ctr(rev, rev + 32);
            pthread_mutex_lock(&gate.lock);
            rec->dc = (int16_t)((uint16_t)plain[60] | (uint16_t)plain[61] << 8);
            rec->init_ok = 1;
            pthread_mutex_unlock(&gate.lock);
            continue;
        }
        xor_stream(dec, msg, n);
        pthread_mutex_lock(&gate.lock);
        ++rec->messages;
        pthread_mutex_unlock(&gate.lock);
        xor_stream(enc, msg, n);
        size_t half = n / 2;
        if (send_frame(ssl, msg, half) != 0 || send_frame(ssl, msg + half, n - half) != 0) break;
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
        for (size_t i = 0; i < sizeof gate.conns / sizeof gate.conns[0]; ++i) {
            if (gate.conns[i].used) continue;
            memset(&gate.conns[i], 0, sizeof gate.conns[i]);
            gate.conns[i].used = 1;
            job->rec = &gate.conns[i];
            break;
        }
        pthread_mutex_unlock(&gate.lock);
        if (!job->rec) {
            close(fd);
            free(job);
            continue;
        }
        pthread_t t;
        pthread_create(&t, NULL, gate_one, job);
        pthread_detach(t);
    }
}

static char dir[] = "/tmp/bye-tgproxy-XXXXXX";
static char cert_path[256];

static void gate_start(void) {
    CHECK(mkdtemp(dir) != NULL);
    char key_path[256], cmd[1024];
    snprintf(cert_path, sizeof cert_path, "%s/cert.pem", dir);
    snprintf(key_path, sizeof key_path, "%s/key.pem", dir);
    snprintf(cmd, sizeof cmd,
             "openssl req -x509 -newkey rsa:2048 -nodes -keyout %s -out %s -days 2 -subj /CN=gateway "
             "-addext subjectAltName=DNS:kws2.web.telegram.org,DNS:kws2-1.web.telegram.org,"
             "DNS:kws4.web.telegram.org,DNS:kws4-1.web.telegram.org,DNS:kws2.relay.test >/dev/null 2>&1",
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

/* connections the gateway took since the last gate_reset */
static int gate_conn_count(void) {
    int n = 0;
    pthread_mutex_lock(&gate.lock);
    for (size_t i = gate.mark; i < sizeof gate.conns / sizeof gate.conns[0]; ++i) n += gate.conns[i].used;
    pthread_mutex_unlock(&gate.lock);
    return n;
}

/* records stay where they are, a connection of the last test may still write to its own */
static void gate_reset(void) {
    pthread_mutex_lock(&gate.lock);
    gate.mark = 0;
    while (gate.mark < sizeof gate.conns / sizeof gate.conns[0] && gate.conns[gate.mark].used) ++gate.mark;
    gate.reject_all = 0;
    pthread_mutex_unlock(&gate.lock);
}



typedef struct {
    int             fd;
    EVP_CIPHER_CTX *enc;
    EVP_CIPHER_CTX *dec;
} client_t;

static void sha256_cat(const uint8_t *prekey, const uint8_t *secret, uint8_t *out) {
    uint8_t buf[48];
    unsigned int n = 0;
    memcpy(buf, prekey, 32);
    memcpy(buf + 32, secret, 16);
    CHECK(EVP_Digest(buf, 48, out, &n, EVP_sha256(), NULL) == 1);
}

/* connects and sends the obfuscated init for datacenter dc under secret */
static int client_open(client_t *cl, uint16_t port, const uint8_t *secret, int dc) {
    memset(cl, 0, sizeof *cl);
    cl->fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(cl->fd, (struct sockaddr *)&a, sizeof a) != 0) return -1;

    uint8_t init[64], key[32], rev[48], sealed[64];
    for (;;) {
        CHECK(RAND_bytes(init, 64) == 1);
        if (init[0] == 0xEF) continue;
        if (!memcmp(init, "HEAD", 4) || !memcmp(init, "POST", 4) || !memcmp(init, "GET ", 4) ||
            !memcmp(init, "OPTI", 4)) continue;
        if (!memcmp(init, "\xee\xee\xee\xee", 4) || !memcmp(init, "\xdd\xdd\xdd\xdd", 4)) continue;
        if (!init[4] && !init[5] && !init[6] && !init[7]) continue;
        break;
    }
    init[56] = init[57] = init[58] = init[59] = 0xEF; /* abridged */
    init[60] = (uint8_t)(uint16_t)dc;
    init[61] = (uint8_t)((uint16_t)dc >> 8);
    sha256_cat(init + 8, secret, key);
    cl->enc = ctr(key, init + 40);
    memcpy(sealed, init, 64);
    xor_stream(cl->enc, sealed, 64);
    memcpy(init + 56, sealed + 56, 8);
    for (size_t i = 0; i < 48; ++i) rev[i] = init[8 + 47 - i];
    sha256_cat(rev, secret, key);
    cl->dec = ctr(key, rev + 32);
    return write(cl->fd, init, 64) == 64 ? 0 : -1;
}

static void client_close(client_t *cl) {
    if (cl->fd >= 0) close(cl->fd);
    EVP_CIPHER_CTX_free(cl->enc);
    EVP_CIPHER_CTX_free(cl->dec);
}

static int read_timeout(int fd, uint8_t *buf, size_t n, int ms) {
    size_t off = 0;
    while (off < n) {
        struct pollfd p = { fd, POLLIN, 0 };
        if (poll(&p, 1, ms) <= 0) return -1;
        ssize_t r = read(fd, buf + off, n - off);
        if (r <= 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

/* one abridged packet of words*4 bytes, sent and read back through the echo */
static int client_echo(client_t *cl, size_t words) {
    size_t head = words < 0x7F ? 1 : 4, payload = words * 4, total = head + payload;
    uint8_t *packet = malloc(total), *back = malloc(total);
    if (head == 1) {
        packet[0] = (uint8_t)words;
    } else {
        packet[0] = 0x7F;
        packet[1] = (uint8_t)words;
        packet[2] = (uint8_t)(words >> 8);
        packet[3] = (uint8_t)(words >> 16);
    }
    for (size_t i = 0; i < payload; ++i) packet[head + i] = (uint8_t)(i * 13 + 5);
    uint8_t *wire = malloc(total);
    memcpy(wire, packet, total);
    xor_stream(cl->enc, wire, total);
    size_t off = 0;
    while (off < total) {
        ssize_t w = write(cl->fd, wire + off, total - off);
        if (w <= 0) {
            free(packet); free(back); free(wire);
            return -1;
        }
        off += (size_t)w;
    }
    int rc = read_timeout(cl->fd, back, total, 5000);
    if (rc == 0) {
        xor_stream(cl->dec, back, total);
        rc = memcmp(back, packet, total) == 0 ? 0 : -1;
    }
    free(packet);
    free(back);
    free(wire);
    return rc;
}



static int plain_socket(void *ctx, int family, int type, char *error, size_t cap) {
    (void)ctx;
    int fd = socket(family, type, 0);
    if (fd < 0 || fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) != 0) {
        snprintf(error, cap, "socket failed");
        return -1;
    }
    return fd;
}

static uint16_t free_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(fd, (struct sockaddr *)&a, sizeof a) == 0);
    socklen_t len = sizeof a;
    getsockname(fd, (struct sockaddr *)&a, &len);
    close(fd);
    return ntohs(a.sin_port);
}

static bye_wsconn_ctx_t *tls;

static bye_tgproxy_t *proxy_start(uint16_t port) {
    bye_tgproxy_config_t c;
    memset(&c, 0, sizeof c);
    c.port = port;
    memcpy(c.secret, SECRET, sizeof SECRET);
    c.tls = tls;
    c.socket = plain_socket;
    c.gateway_set = 1;
    memcpy(c.gateway, LOOP4, 4);
    c.gateway_port = gate.port;
    char error[BYE_TGPROXY_ERROR_MAX];
    bye_tgproxy_t *p = bye_tgproxy_start(&c, error, sizeof error);
    if (!p) fprintf(stderr, "start failed: %s\n", error);
    CHECK(p != NULL);
    return p;
}

static void pause_ms(int ms) {
    struct timespec t = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&t, NULL);
}

static void test_secret_parse(void) {
    uint8_t out[16];
    CHECK(bye_tgproxy_secret_parse("0102030405060708090a0b0c0d0e0f10", out) == 0);
    CHECK(memcmp(out, SECRET, 16) == 0);
    CHECK(bye_tgproxy_secret_parse("0102030405060708090A0B0C0D0E0F10", out) == 0);
    CHECK(bye_tgproxy_secret_parse("0102030405060708090a0b0c0d0e0f1", out) != 0);
    CHECK(bye_tgproxy_secret_parse("0102030405060708090a0b0c0d0e0f1g", out) != 0);
    CHECK(bye_tgproxy_secret_parse("", out) != 0);
    CHECK(bye_tgproxy_secret_parse(NULL, out) != 0);
}

static void test_echo(void) {
    gate_reset();
    uint16_t port = free_port();
    bye_tgproxy_t *proxy = proxy_start(port);
    client_t cl;
    CHECK(client_open(&cl, port, SECRET, 2) == 0);
    CHECK(client_echo(&cl, 10) == 0);
    /* a packet with the long length header, and a second one on the same stream */
    CHECK(client_echo(&cl, 1000) == 0);
    CHECK(client_echo(&cl, 3) == 0);
    pthread_mutex_lock(&gate.lock);
    CHECK(gate.conns[gate.mark].init_ok && gate.conns[gate.mark].dc == 2 &&
          gate.conns[gate.mark].messages >= 3);
    CHECK(strcmp(gate.conns[gate.mark].host, "kws2.web.telegram.org") == 0);
    pthread_mutex_unlock(&gate.lock);
    bye_tgproxy_stats_t stats;
    bye_tgproxy_stats(proxy, &stats);
    CHECK(stats.clients == 1 && stats.gateway_ok == 1 && stats.bad_init == 0 && stats.bytes_up > 0 &&
          stats.bytes_down > 0);
    client_close(&cl);
    bye_tgproxy_stop(proxy);
}

/* a 512 KiB packet goes up and comes back whole */
static void test_large_packet(void) {
    gate_reset();
    uint16_t port = free_port();
    bye_tgproxy_t *proxy = proxy_start(port);
    client_t cl;
    CHECK(client_open(&cl, port, SECRET, 4) == 0);
    CHECK(client_echo(&cl, 128 * 1024) == 0);
    client_close(&cl);
    bye_tgproxy_stop(proxy);
}

static void test_gateway_address_fallback(void) {
    gate_reset();
    uint16_t port = free_port();
    bye_tgproxy_config_t c;
    memset(&c, 0, sizeof c);
    c.port = port;
    memcpy(c.secret, SECRET, sizeof SECRET);
    c.tls = tls;
    c.socket = plain_socket;
    c.gateway_port = gate.port;
    /* the first address refuses tcp, the media host has a reachable address */
    c.ws_addresses.dc[1][0].valid = c.ws_addresses.dc[1][1].valid = 1;
    memcpy(c.ws_addresses.dc[1][0].address, (const uint8_t[]){127, 0, 0, 2}, 4);
    memcpy(c.ws_addresses.dc[1][1].address, LOOP4, 4);
    char error[BYE_TGPROXY_ERROR_MAX];
    bye_tgproxy_t *proxy = bye_tgproxy_start(&c, error, sizeof error);
    CHECK(proxy != NULL);
    if (!proxy) return;
    client_t cl;
    CHECK(client_open(&cl, port, SECRET, 2) == 0);
    CHECK(client_echo(&cl, 10) == 0);
    pthread_mutex_lock(&gate.lock);
    CHECK(!strcmp(gate.conns[gate.mark].host, "kws2-1.web.telegram.org"));
    pthread_mutex_unlock(&gate.lock);
    bye_tgproxy_stats_t stats;
    bye_tgproxy_stats(proxy, &stats);
    CHECK(stats.gateway_ok == 1 && stats.gateway_fail == 0);
    client_close(&cl);
    bye_tgproxy_stop(proxy);
}

/* several clients at once, each on its own datacenter */
static void test_many_clients(void) {
    gate_reset();
    uint16_t port = free_port();
    bye_tgproxy_t *proxy = proxy_start(port);
    client_t cl[4];
    int dcs[4] = { 2, 4, -2, 4 };
    for (int i = 0; i < 4; ++i) CHECK(client_open(&cl[i], port, SECRET, dcs[i]) == 0);
    for (int round = 0; round < 3; ++round)
        for (int i = 0; i < 4; ++i) CHECK(client_echo(&cl[i], 20 + (size_t)i) == 0);
    for (int i = 0; i < 4; ++i) client_close(&cl[i]);
    bye_tgproxy_stop(proxy);
}

/* a client with another secret never reaches the gateway */
static void test_wrong_secret(void) {
    gate_reset();
    static const uint8_t other[16] = { 9 };
    uint16_t port = free_port();
    bye_tgproxy_t *proxy = proxy_start(port);
    client_t cl;
    CHECK(client_open(&cl, port, other, 2) == 0);
    uint8_t byte;
    CHECK(read_timeout(cl.fd, &byte, 1, 3000) != 0);
    CHECK(gate_conn_count() == 0);
    bye_tgproxy_stats_t stats;
    bye_tgproxy_stats(proxy, &stats);
    CHECK(stats.bad_init == 1 && stats.gateway_ok == 0);
    client_close(&cl);
    bye_tgproxy_stop(proxy);
}

/* a client that sends plain http is closed without a word */
static void test_http_client(void) {
    gate_reset();
    uint16_t port = free_port();
    bye_tgproxy_t *proxy = proxy_start(port);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(connect(fd, (struct sockaddr *)&a, sizeof a) == 0);
    uint8_t request[64] = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    CHECK(write(fd, request, sizeof request) == (ssize_t)sizeof request);
    uint8_t byte;
    CHECK(read_timeout(fd, &byte, 1, 3000) != 0);
    CHECK(gate_conn_count() == 0);
    close(fd);
    bye_tgproxy_stop(proxy);
}

/* the gateway refuses every upgrade: the client is closed, and the proxy says so */
static void test_gateway_refuses(void) {
    gate_reset();
    pthread_mutex_lock(&gate.lock);
    gate.reject_all = 1;
    pthread_mutex_unlock(&gate.lock);
    uint16_t port = free_port();
    bye_tgproxy_t *proxy = proxy_start(port);
    client_t cl;
    CHECK(client_open(&cl, port, SECRET, 2) == 0);
    uint8_t byte;
    CHECK(read_timeout(cl.fd, &byte, 1, 8000) != 0);
    bye_tgproxy_stats_t stats;
    bye_tgproxy_stats(proxy, &stats);
    CHECK(stats.gateway_fail == 1 && stats.gateway_ok == 0 && stats.last_error[0] != '\0');
    client_close(&cl);
    /* the datacenter is remembered as failed: the next client is closed at once and the
       gateway is not asked again */
    int asked = gate_conn_count();
    CHECK(client_open(&cl, port, SECRET, 2) == 0);
    CHECK(read_timeout(cl.fd, &byte, 1, 1000) != 0);
    CHECK(gate_conn_count() == asked);
    bye_tgproxy_stats(proxy, &stats);
    CHECK(stats.gateway_fail == 2);
    client_close(&cl);
    bye_tgproxy_stop(proxy);
}

/* a client that sends only part of its init and stalls does not block a stop */
static void test_stop_with_stalled_client(void) {
    gate_reset();
    uint16_t port = free_port();
    bye_tgproxy_t *proxy = proxy_start(port);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(connect(fd, (struct sockaddr *)&a, sizeof a) == 0);
    uint8_t part[20] = { 0 };
    CHECK(write(fd, part, sizeof part) == (ssize_t)sizeof part);
    pause_ms(100);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    bye_tgproxy_stop(proxy);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    CHECK(t1.tv_sec - t0.tv_sec < 2);
    close(fd);
}

/* the port is taken: the start says which */
static void test_port_taken(void) {
    uint16_t port = free_port();
    bye_tgproxy_t *first = proxy_start(port);
    bye_tgproxy_config_t c;
    memset(&c, 0, sizeof c);
    c.port = port;
    c.tls = tls;
    c.socket = plain_socket;
    char error[BYE_TGPROXY_ERROR_MAX];
    CHECK(bye_tgproxy_start(&c, error, sizeof error) == NULL);
    CHECK(strstr(error, "bind") != NULL);
    bye_tgproxy_stop(first);
    /* the port is free again once the proxy stopped */
    bye_tgproxy_t *again = proxy_start(port);
    bye_tgproxy_stop(again);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    gate_start();
    char error[BYE_WSCONN_ERROR_MAX];
    tls = bye_wsconn_ctx_new(cert_path, error, sizeof error);
    CHECK(tls != NULL);
    if (!tls) return 1;
    test_secret_parse();
    test_echo();
    test_large_packet();
    test_gateway_address_fallback();
    test_many_clients();
    test_wrong_secret();
    test_http_client();
    test_gateway_refuses();
    test_stop_with_stalled_client();
    test_port_taken();
    bye_wsconn_ctx_free(tls);
    if (failed) return 1;
    printf("all tgproxy checks passed\n");
    return 0;
}

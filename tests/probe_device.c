/* a probe to run on the device with the tunnel up, not part of `make test`.
   it speaks like an app would and prints what came back:

     probe_device tg [IP] [PORT]    the obfuscated mtproto transport to a
                                    telegram datacenter, then req_pq_multi;
                                    a resPQ means the stream reached a datacenter
     probe_device tls IP SNI        a tls handshake with that server name;
                                    the certificate is not checked, the probe
                                    only asks whether the handshake completes */

#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

static int dial(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &to.sin_addr) != 1) { fprintf(stderr, "bad address\n"); exit(2); }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    struct timeval start, now;
    gettimeofday(&start, NULL);
    if (connect(fd, (struct sockaddr *)&to, sizeof to) != 0 && errno != EINPROGRESS) {
        perror("connect");
        exit(1);
    }
    struct pollfd p = { fd, POLLOUT, 0 };
    if (poll(&p, 1, 10000) != 1) { fprintf(stderr, "connect timed out\n"); exit(1); }
    int err = 0;
    socklen_t len = sizeof err;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
    if (err) { fprintf(stderr, "connect: %s\n", strerror(err)); exit(1); }
    gettimeofday(&now, NULL);
    printf("connected in %ld ms\n", (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000);
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
    struct timeval timeout = { 10, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    return fd;
}

static int telegram(const char *ip, int port) {
    int fd = dial(ip, port);
    uint8_t init[64], rev[48], sealed[64];
    for (;;) {
        RAND_bytes(init, 64);
        if (init[0] == 0xEF || !memcmp(init, "HEAD", 4) || !memcmp(init, "POST", 4) ||
            !memcmp(init, "GET ", 4) || !memcmp(init, "\xee\xee\xee\xee", 4) ||
            !memcmp(init, "\xdd\xdd\xdd\xdd", 4) || (!init[4] && !init[5] && !init[6] && !init[7]))
            continue;
        break;
    }
    init[56] = init[57] = init[58] = init[59] = 0xEF;
    init[60] = 2; /* datacenter 2 */
    init[61] = 0;
    EVP_CIPHER_CTX *enc = EVP_CIPHER_CTX_new(), *dec = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(enc, EVP_aes_256_ctr(), NULL, init + 8, init + 40);
    int n = 0;
    EVP_EncryptUpdate(enc, sealed, &n, init, 64);
    memcpy(init + 56, sealed + 56, 8);
    for (size_t i = 0; i < 48; ++i) rev[i] = init[8 + 47 - i];
    EVP_EncryptInit_ex(dec, EVP_aes_256_ctr(), NULL, rev, rev + 32);

    uint8_t packet[1 + 40];
    memset(packet, 0, sizeof packet);
    packet[0] = 10;
    uint8_t *m = packet + 1;
    uint64_t msg_id = ((uint64_t)time(NULL) << 32) & ~(uint64_t)3;
    for (int i = 0; i < 8; ++i) m[8 + i] = (uint8_t)(msg_id >> (8 * i));
    m[16] = 20;
    m[20] = 0xf1; m[21] = 0x8e; m[22] = 0x7e; m[23] = 0xbe;
    RAND_bytes(m + 24, 16);
    uint8_t out[sizeof packet];
    EVP_EncryptUpdate(enc, out, &n, packet, (int)sizeof packet);

    uint8_t wire[64 + sizeof packet];
    memcpy(wire, init, 64);
    memcpy(wire + 64, out, sizeof out);
    if (write(fd, wire, sizeof wire) != (ssize_t)sizeof wire) { perror("write"); return 1; }

    uint8_t reply[512];
    size_t have = 0;
    while (have < 1 + 8 + 8 + 4 + 4) {
        ssize_t got = read(fd, reply + have, sizeof reply - have);
        if (got <= 0) { fprintf(stderr, "no answer (%s)\n", got < 0 ? strerror(errno) : "closed"); return 1; }
        EVP_EncryptUpdate(dec, reply + have, &n, reply + have, (int)got);
        have += (size_t)got;
    }
    size_t head = reply[0] == 0x7f ? 4 : 1;
    const uint8_t *body = reply + head;
    uint32_t constructor = (uint32_t)body[20] | (uint32_t)body[21] << 8 | (uint32_t)body[22] << 16 |
                           (uint32_t)body[23] << 24;
    printf("%zu bytes back, constructor %08x\n", have, constructor);
    if (constructor != 0x05162463u) { puts("probe failed: not a resPQ"); return 1; }
    puts("probe ok: resPQ");
    return 0;
}

static int tls(const char *ip, const char *sni) {
    int fd = dial(ip, 443);
    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, sni);
    if (SSL_connect(ssl) != 1) { puts("probe failed: tls handshake"); return 1; }
    printf("probe ok: %s %s\n", SSL_get_version(ssl), SSL_get_cipher_name(ssl));
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "tg") == 0)
        return telegram(argc > 2 ? argv[2] : "149.154.167.51", argc > 3 ? atoi(argv[3]) : 443);
    if (argc == 4 && strcmp(argv[1], "tls") == 0) return tls(argv[2], argv[3]);
    fprintf(stderr, "usage: probe_device tg [IP] [PORT] | tls IP SNI\n");
    return 2;
}

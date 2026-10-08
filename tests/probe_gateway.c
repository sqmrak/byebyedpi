/* an integration probe, not part of `make test`: it needs the public network.
   it opens the real websocket gateway of datacenter 2, sends the first
   message of telegram's key exchange (req_pq_multi) through the same bridge
   code the daemon uses, and expects the datacenter's resPQ back. a pass means
   the certificate check, the upgrade, the mtproto init and the cipher chains
   all work against the live service */

#define _DEFAULT_SOURCE

#include "bye_mtp.h"
#include "bye_tg.h"
#include "bye_wsconn.h"
#include "bye_backend.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

static void wait_for(int fd, bye_wsconn_status_t want, int ms) {
    struct pollfd p = { fd, want == BYE_WSCONN_WANT_WRITE ? POLLOUT : POLLIN, 0 };
    if (poll(&p, 1, ms) <= 0) {
        fprintf(stderr, "probe: timed out\n");
        exit(1);
    }
}

static int emit(void *ctx, const uint8_t *msg, size_t len) {
    return bye_wsconn_send(ctx, msg, len);
}

int main(int argc, char **argv) {
    const char *roots = argc > 1 ? argv[1] : NULL;
    int dc = argc > 2 ? atoi(argv[2]) : 2;
    int media = argc > 3 ? atoi(argv[3]) : 0;
    char error[BYE_WSCONN_ERROR_MAX];
    bye_wsconn_ctx_t *ctx = bye_wsconn_ctx_new(roots, error, sizeof error);
    if (!ctx) { fprintf(stderr, "probe: %s\n", error); return 1; }

    /* the client side of the obfuscated transport, as telegram's apps do it */
    uint8_t init[64];
    for (;;) {
        RAND_bytes(init, 64);
        if (init[0] == 0xEF || !memcmp(init, "HEAD", 4) || !memcmp(init, "POST", 4) ||
            !memcmp(init, "GET ", 4) || !memcmp(init, "\xee\xee\xee\xee", 4) ||
            !memcmp(init, "\xdd\xdd\xdd\xdd", 4) || (!init[4] && !init[5] && !init[6] && !init[7]))
            continue;
        break;
    }
    int16_t dc_value = (int16_t)(media ? -dc : dc);
    init[56] = init[57] = init[58] = init[59] = 0xEF;
    init[60] = (uint8_t)(uint16_t)dc_value;
    init[61] = (uint8_t)((uint16_t)dc_value >> 8);
    EVP_CIPHER_CTX *enc = EVP_CIPHER_CTX_new(), *dec = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(enc, EVP_aes_256_ctr(), NULL, init + 8, init + 40);
    uint8_t sealed[64], rev[48];
    int n = 0;
    EVP_EncryptUpdate(enc, sealed, &n, init, 64);
    memcpy(init + 56, sealed + 56, 8);
    for (size_t i = 0; i < 48; ++i) rev[i] = init[8 + 47 - i];
    EVP_EncryptInit_ex(dec, EVP_aes_256_ctr(), NULL, rev, rev + 32);

    bye_mtp_t *mtp = NULL;
    bye_mtp_route_t route;
    uint8_t relay[64];
    if (bye_mtp_open(&mtp, NULL, 0, init, &route, relay) != BYE_MTP_OK) {
        fprintf(stderr, "probe: the bridge refused the client init\n");
        return 1;
    }
    printf("probe: dc %d%s, tag %08x\n", route.dc, route.is_media ? " media" : "", route.proto);

    uint8_t address[4];
    bye_tg_ws_addresses_t resolved;
    bye_resolve_gateways(&resolved);
    bye_tg_gateway_t gateways[BYE_TG_GATEWAYS_MAX];
    if (!bye_tg_gateways(route.dc, route.is_media, &resolved, gateways, BYE_TG_GATEWAYS_MAX)) {
        fprintf(stderr, "probe: no gateway for this datacenter\n");
        return 1;
    }
    memcpy(address, gateways[0].address, 4);
    char host[BYE_TG_WS_HOST_MAX];
    snprintf(host, sizeof host, "%s", gateways[0].host);
    char address_text[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, address, address_text, sizeof address_text))
        printf("probe: %s at %s\n", host, address_text);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(443);
    memcpy(&to.sin_addr, address, 4);
    if (connect(fd, (struct sockaddr *)&to, sizeof to) != 0) { perror("probe: connect"); return 1; }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    bye_wsconn_t *ws = bye_wsconn_new(ctx, fd, host, BYE_TG_WS_PATH);
    bye_wsconn_status_t s;
    while ((s = bye_wsconn_handshake(ws)) != BYE_WSCONN_OK) {
        if (s == BYE_WSCONN_ERR || s == BYE_WSCONN_CLOSED) {
            fprintf(stderr, "probe: handshake with %s failed: %s\n", host, bye_wsconn_error(ws));
            return 1;
        }
        wait_for(fd, s, 8000);
    }
    printf("probe: %s upgraded\n", host);

    /* req_pq_multi in one abridged packet */
    uint8_t packet[1 + 40];
    memset(packet, 0, sizeof packet);
    packet[0] = 10; /* words of payload */
    uint8_t *m = packet + 1;
    uint64_t msg_id = ((uint64_t)time(NULL) << 32) & ~(uint64_t)3;
    for (int i = 0; i < 8; ++i) m[8 + i] = (uint8_t)(msg_id >> (8 * i));
    m[16] = 20; /* message_data_length */
    m[20] = 0xf1; m[21] = 0x8e; m[22] = 0x7e; m[23] = 0xbe; /* 0xbe7e8ef1 */
    RAND_bytes(m + 24, 16);                                  /* nonce */

    EVP_CIPHER_CTX *wire = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(wire, EVP_aes_256_ctr(), NULL, init + 8, init + 40);
    uint8_t skip[64];
    EVP_EncryptUpdate(wire, skip, &n, skip, 64); /* the init used the first 64 bytes */
    uint8_t out[sizeof packet];
    EVP_EncryptUpdate(wire, out, &n, packet, (int)sizeof packet);

    if (bye_wsconn_send(ws, relay, 64) != 0 ||
        bye_mtp_up(mtp, out, sizeof out, emit, ws) != BYE_MTP_OK) {
        fprintf(stderr, "probe: cannot queue the request\n");
        return 1;
    }
    while ((s = bye_wsconn_flush(ws)) != BYE_WSCONN_OK) {
        if (s == BYE_WSCONN_ERR) { fprintf(stderr, "probe: %s\n", bye_wsconn_error(ws)); return 1; }
        wait_for(fd, s, 8000);
    }

    uint8_t reply[512];
    size_t have = 0;
    while (have < 1 + 8 + 8 + 4 + 4) {
        size_t got = 0;
        s = bye_wsconn_read(ws, reply + have, sizeof reply - have, &got);
        if (got) {
            bye_mtp_down(mtp, reply + have, got);
            EVP_EncryptUpdate(dec, reply + have, &n, reply + have, (int)got);
            have += got;
            continue;
        }
        if (s == BYE_WSCONN_ERR || s == BYE_WSCONN_CLOSED) {
            fprintf(stderr, "probe: the gateway ended early: %s\n", bye_wsconn_error(ws));
            return 1;
        }
        bye_wsconn_flush(ws);
        wait_for(fd, s, 8000);
    }
    /* the client's own decryption is the second cipher over the bridged bytes */
    size_t head = reply[0] == 0x7f ? 4 : 1;
    const uint8_t *body = reply + head;
    uint32_t constructor = (uint32_t)body[20] | (uint32_t)body[21] << 8 | (uint32_t)body[22] << 16 |
                           (uint32_t)body[23] << 24;
    printf("probe: %zu bytes back, constructor %08x\n", have, constructor);
    if (constructor != 0x05162463u) {
        fprintf(stderr, "probe: not a resPQ\n");
        return 1;
    }
    puts("probe ok: the datacenter answered req_pq_multi with resPQ");
    bye_wsconn_free(ws);
    close(fd);
    return 0;
}

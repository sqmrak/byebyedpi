#include "bye_mtp.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "check.h"

/* a telegram client and a datacenter written from the published obfuscation
   description, not from the bridge, so a mistake in one is not repeated in
   the other */

typedef struct {
    EVP_CIPHER_CTX *enc; /* client to the proxy */
    EVP_CIPHER_CTX *dec; /* proxy to the client */
    uint8_t wire_init[64];
} client_t;

static EVP_CIPHER_CTX *ctr(const uint8_t *key, const uint8_t *iv) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    CHECK(EVP_EncryptInit_ex(c, EVP_aes_256_ctr(), NULL, key, iv) == 1);
    return c;
}

static void xor_stream(EVP_CIPHER_CTX *c, uint8_t *data, size_t len) {
    int n = 0;
    CHECK(EVP_EncryptUpdate(c, data, &n, data, (int)len) == 1 && (size_t)n == len);
}

static void sha256_cat(const uint8_t *a, const uint8_t *secret, size_t secret_len, uint8_t *out) {
    uint8_t buf[32 + 16];
    unsigned int n = 0;
    memcpy(buf, a, 32);
    memcpy(buf + 32, secret, secret_len);
    CHECK(EVP_Digest(buf, 32 + secret_len, out, &n, EVP_sha256(), NULL) == 1);
}

static void client_key(const uint8_t *prekey, const uint8_t *secret, size_t secret_len,
                       uint8_t *key) {
    if (secret_len) sha256_cat(prekey, secret, secret_len, key);
    else memcpy(key, prekey, 32);
}

static void client_open(client_t *cl, uint32_t proto, int dc, const uint8_t *secret,
                        size_t secret_len) {
    uint8_t init[64], key[32], rev[48];
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

    client_key(init + 8, secret, secret_len, key);
    cl->enc = ctr(key, init + 40);
    uint8_t sealed[64];
    memcpy(sealed, init, 64);
    xor_stream(cl->enc, sealed, 64);
    memcpy(cl->wire_init, init, 56);
    memcpy(cl->wire_init + 56, sealed + 56, 8);

    for (size_t i = 0; i < 48; ++i) rev[i] = init[8 + 47 - i];
    client_key(rev, secret, secret_len, key);
    cl->dec = ctr(key, rev + 32);
}

static void client_close(client_t *cl) {
    EVP_CIPHER_CTX_free(cl->enc);
    EVP_CIPHER_CTX_free(cl->dec);
}

typedef struct {
    EVP_CIPHER_CTX *dec; /* the proxy's bytes to plain */
    EVP_CIPHER_CTX *enc; /* plain to the proxy */
    uint8_t plain_init[64];
} dc_t;

static void dc_open(dc_t *dc, const uint8_t *relay_init) {
    uint8_t rev[48];
    dc->dec = ctr(relay_init + 8, relay_init + 40);
    memcpy(dc->plain_init, relay_init, 64);
    xor_stream(dc->dec, dc->plain_init, 64);
    for (size_t i = 0; i < 48; ++i) rev[i] = relay_init[8 + 47 - i];
    dc->enc = ctr(rev, rev + 32);
}

static void dc_close(dc_t *dc) {
    EVP_CIPHER_CTX_free(dc->dec);
    EVP_CIPHER_CTX_free(dc->enc);
}

typedef struct {
    uint8_t msgs[16][2048];
    size_t  lens[16];
    size_t  count;
    int     refuse_at; /* the emit that fails, counted from 1, 0 for never */
} sink_t;

static int collect(void *ctx, const uint8_t *msg, size_t len) {
    sink_t *s = ctx;
    if (s->refuse_at && (int)s->count + 1 == s->refuse_at) return 1;
    CHECK(s->count < 16 && len <= sizeof s->msgs[0]);
    memcpy(s->msgs[s->count], msg, len);
    s->lens[s->count++] = len;
    return 0;
}

static void test_handshake(const uint8_t *secret, size_t secret_len, uint32_t proto, int dc_in,
                           int want_dc, int want_media) {
    client_t cl;
    client_open(&cl, proto, dc_in, secret, secret_len);

    bye_mtp_t *m = NULL;
    bye_mtp_route_t route;
    uint8_t relay[64];
    CHECK(bye_mtp_open(&m, secret, secret_len, cl.wire_init, &route, relay) == BYE_MTP_OK);
    CHECK(m != NULL);
    CHECK(route.dc == want_dc && route.is_media == want_media && route.proto == proto);

    dc_t dc;
    dc_open(&dc, relay);
    /* the datacenter reads the tag and its own id from the tail */
    uint32_t tag = (uint32_t)dc.plain_init[56] | ((uint32_t)dc.plain_init[57] << 8) |
                   ((uint32_t)dc.plain_init[58] << 16) | ((uint32_t)dc.plain_init[59] << 24);
    int16_t id = (int16_t)((uint16_t)dc.plain_init[60] | ((uint16_t)dc.plain_init[61] << 8));
    CHECK(tag == proto);
    CHECK(id == dc_in);

    /* up: the client's bytes come out as the datacenter's key stream over the
       same plain bytes */
    uint8_t plain[300], wire[300];
    for (size_t i = 0; i < sizeof plain; ++i) plain[i] = (uint8_t)(i * 7 + 1);
    memcpy(wire, plain, sizeof wire);
    xor_stream(cl.enc, wire, sizeof wire);
    CHECK(bye_mtp_up(m, wire, sizeof wire, NULL, NULL) == BYE_MTP_OK);
    xor_stream(dc.dec, wire, sizeof wire);
    CHECK(memcmp(wire, plain, sizeof plain) == 0);

    /* down, in two reads */
    uint8_t answer[500], got[500];
    for (size_t i = 0; i < sizeof answer; ++i) answer[i] = (uint8_t)(255 - i);
    memcpy(got, answer, sizeof got);
    xor_stream(dc.enc, got, sizeof got);
    CHECK(bye_mtp_down(m, got, 123) == BYE_MTP_OK);
    CHECK(bye_mtp_down(m, got + 123, sizeof got - 123) == BYE_MTP_OK);
    xor_stream(cl.dec, got, sizeof got);
    CHECK(memcmp(got, answer, sizeof answer) == 0);

    dc_close(&dc);
    client_close(&cl);
    bye_mtp_close(m);
}

static void test_handshakes(void) {
    static const uint8_t secret[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    static const uint8_t zero[16] = { 0 };
    test_handshake(NULL, 0, BYE_MTP_TAG_ABRIDGED, 2, 2, 0);
    test_handshake(NULL, 0, BYE_MTP_TAG_INTERMEDIATE, -4, 4, 1);
    test_handshake(NULL, 0, BYE_MTP_TAG_PADDED, 203, 203, 0);
    test_handshake(secret, 16, BYE_MTP_TAG_ABRIDGED, 5, 5, 0);
    test_handshake(secret, 16, BYE_MTP_TAG_PADDED, -1, 1, 1);
    test_handshake(zero, 16, BYE_MTP_TAG_INTERMEDIATE, 3, 3, 0);
    test_handshake(secret, 5, BYE_MTP_TAG_ABRIDGED, 1, 1, 0);
}

static void test_rejects(void) {
    static const uint8_t secret[16] = { 9 };
    client_t cl;
    bye_mtp_t *m = (bye_mtp_t *)1;
    bye_mtp_route_t route;
    uint8_t relay[64];

    /* the client holds another secret: the tag does not decrypt */
    client_open(&cl, BYE_MTP_TAG_ABRIDGED, 2, secret, 16);
    CHECK(bye_mtp_open(&m, NULL, 0, cl.wire_init, &route, relay) == BYE_MTP_ERR_INIT);
    CHECK(m == NULL);
    uint8_t other[16] = { 8 };
    CHECK(bye_mtp_open(&m, other, 16, cl.wire_init, &route, relay) == BYE_MTP_ERR_INIT);
    CHECK(bye_mtp_open(&m, secret, 16, cl.wire_init, &route, relay) == BYE_MTP_OK);
    bye_mtp_close(m);
    client_close(&cl);

    uint8_t noise[64];
    memset(noise, 0x5a, sizeof noise);
    CHECK(bye_mtp_open(&m, NULL, 0, noise, &route, relay) == BYE_MTP_ERR_INIT);

    uint8_t http[64] = "POST /api HTTP/1.1\r\nHost: 149.154.167.51\r\n";
    CHECK(bye_mtp_open(&m, NULL, 0, http, &route, relay) == BYE_MTP_ERR_HTTP);
    memcpy(http, "GET / HTTP/1.1\r\n", 16);
    CHECK(bye_mtp_open(&m, NULL, 0, http, &route, relay) == BYE_MTP_ERR_HTTP);

    CHECK(bye_mtp_open(&m, secret, 17, noise, &route, relay) == BYE_MTP_ERR_ARG);
    CHECK(bye_mtp_open(&m, NULL, 1, noise, &route, relay) == BYE_MTP_ERR_ARG);
    CHECK(bye_mtp_open(NULL, NULL, 0, noise, &route, relay) == BYE_MTP_ERR_ARG);
    CHECK(bye_mtp_open(&m, NULL, 0, NULL, &route, relay) == BYE_MTP_ERR_ARG);
}

/* a client and a datacenter around one bridge, to drive the splitter */
typedef struct {
    client_t cl;
    dc_t dc;
    bye_mtp_t *m;
} rig_t;

static void rig_open(rig_t *r, uint32_t proto) {
    bye_mtp_route_t route;
    uint8_t relay[64];
    client_open(&r->cl, proto, 2, NULL, 0);
    CHECK(bye_mtp_open(&r->m, NULL, 0, r->cl.wire_init, &route, relay) == BYE_MTP_OK);
    dc_open(&r->dc, relay);
}

static void rig_close(rig_t *r) {
    dc_close(&r->dc);
    client_close(&r->cl);
    bye_mtp_close(r->m);
}

/* an abridged packet of payload_words*4 bytes, a quick-ack flag optional */
static size_t abridged_packet(uint8_t *out, size_t payload_words, uint8_t fill, int quick) {
    size_t at = 0;
    if (payload_words < 0x7F) {
        out[at++] = (uint8_t)(payload_words | (quick ? 0x80 : 0));
    } else {
        out[at++] = (uint8_t)(0x7F | (quick ? 0x80 : 0));
        out[at++] = (uint8_t)payload_words;
        out[at++] = (uint8_t)(payload_words >> 8);
        out[at++] = (uint8_t)(payload_words >> 16);
    }
    memset(out + at, fill, payload_words * 4);
    return at + payload_words * 4;
}

static size_t intermediate_packet(uint8_t *out, size_t payload, uint8_t fill, int quick) {
    uint32_t v = (uint32_t)payload | (quick ? 0x80000000u : 0);
    out[0] = (uint8_t)v; out[1] = (uint8_t)(v >> 8); out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
    memset(out + 4, fill, payload);
    return 4 + payload;
}

/* what the datacenter reads from a message */
static void dc_read(rig_t *r, uint8_t *msg, size_t len) {
    xor_stream(r->dc.dec, msg, len);
}

static void test_split_abridged(void) {
    rig_t r;
    rig_open(&r, BYE_MTP_TAG_ABRIDGED);
    sink_t sink;
    memset(&sink, 0, sizeof sink);

    /* three packets in one read: three messages, each whole */
    uint8_t stream[600], wire[600];
    size_t n = 0, sizes[3];
    sizes[0] = abridged_packet(stream + n, 3, 0x11, 0); n += sizes[0];
    sizes[1] = abridged_packet(stream + n, 10, 0x22, 1); n += sizes[1];
    sizes[2] = abridged_packet(stream + n, 130, 0x33, 0); n += sizes[2];
    memcpy(wire, stream, n);
    xor_stream(r.cl.enc, wire, n);
    CHECK(bye_mtp_up(r.m, wire, n, collect, &sink) == BYE_MTP_OK);
    CHECK(sink.count == 3);
    size_t at = 0;
    for (size_t i = 0; i < 3 && i < sink.count; ++i) {
        CHECK(sink.lens[i] == sizes[i]);
        dc_read(&r, sink.msgs[i], sink.lens[i]);
        CHECK(memcmp(sink.msgs[i], stream + at, sizes[i]) == 0);
        at += sizes[i];
    }

    /* one packet over four reads, the header split too: one message at the end */
    memset(&sink, 0, sizeof sink);
    n = abridged_packet(stream, 130, 0x44, 0); /* a four byte header */
    memcpy(wire, stream, n);
    xor_stream(r.cl.enc, wire, n);
    size_t cuts[] = { 1, 3, 200, n };
    size_t from = 0;
    for (size_t i = 0; i < 4; ++i) {
        CHECK(sink.count == 0);
        CHECK(bye_mtp_up(r.m, wire + from, cuts[i] - from, collect, &sink) == BYE_MTP_OK);
        from = cuts[i];
    }
    CHECK(sink.count == 1 && sink.lens[0] == n);
    dc_read(&r, sink.msgs[0], n);
    CHECK(memcmp(sink.msgs[0], stream, n) == 0);

    /* a packet ends one read and the next starts the following one */
    memset(&sink, 0, sizeof sink);
    uint8_t two[200], two_wire[200];
    size_t a = abridged_packet(two, 4, 0x55, 0);
    size_t b = abridged_packet(two + a, 6, 0x66, 0);
    memcpy(two_wire, two, a + b);
    xor_stream(r.cl.enc, two_wire, a + b);
    CHECK(bye_mtp_up(r.m, two_wire, a, collect, &sink) == BYE_MTP_OK);
    CHECK(sink.count == 1 && sink.lens[0] == a);
    CHECK(bye_mtp_up(r.m, two_wire + a, b, collect, &sink) == BYE_MTP_OK);
    CHECK(sink.count == 2 && sink.lens[1] == b);
    dc_read(&r, sink.msgs[0], a);
    dc_read(&r, sink.msgs[1], b);
    CHECK(memcmp(sink.msgs[0], two, a) == 0 && memcmp(sink.msgs[1], two + a, b) == 0);

    /* the client closes in the middle of a packet: the held part is flushed */
    memset(&sink, 0, sizeof sink);
    a = abridged_packet(two, 20, 0x77, 0);
    memcpy(two_wire, two, a);
    xor_stream(r.cl.enc, two_wire, a);
    CHECK(bye_mtp_up(r.m, two_wire, 30, collect, &sink) == BYE_MTP_OK);
    CHECK(sink.count == 0);
    CHECK(bye_mtp_up_flush(r.m, collect, &sink) == BYE_MTP_OK);
    CHECK(sink.count == 1 && sink.lens[0] == 30);
    CHECK(bye_mtp_up_flush(r.m, collect, &sink) == BYE_MTP_OK && sink.count == 1);
    rig_close(&r);
}

static void test_split_intermediate(void) {
    rig_t r;
    rig_open(&r, BYE_MTP_TAG_INTERMEDIATE);
    sink_t sink;
    memset(&sink, 0, sizeof sink);
    uint8_t stream[400], wire[400];
    size_t n = 0, a, b;
    a = intermediate_packet(stream + n, 40, 0x11, 0); n += a;
    b = intermediate_packet(stream + n, 7, 0x22, 1); n += b;
    memcpy(wire, stream, n);
    xor_stream(r.cl.enc, wire, n);
    /* the cut lands inside the second header */
    CHECK(bye_mtp_up(r.m, wire, a + 2, collect, &sink) == BYE_MTP_OK);
    CHECK(sink.count == 1 && sink.lens[0] == a);
    CHECK(bye_mtp_up(r.m, wire + a + 2, n - a - 2, collect, &sink) == BYE_MTP_OK);
    CHECK(sink.count == 2 && sink.lens[1] == b);
    dc_read(&r, sink.msgs[0], a);
    dc_read(&r, sink.msgs[1], b);
    CHECK(memcmp(sink.msgs[0], stream, a) == 0 && memcmp(sink.msgs[1], stream + a, b) == 0);
    rig_close(&r);
}

static void test_split_limits(void) {
    rig_t r;
    sink_t sink;

    /* a packet with no payload is not what a client sends: the splitter stops
       cutting and every read after is one message, nothing lost */
    rig_open(&r, BYE_MTP_TAG_ABRIDGED);
    memset(&sink, 0, sizeof sink);
    uint8_t stream[200], wire[200];
    size_t a = abridged_packet(stream, 2, 0x11, 0);
    stream[a] = 0x00;
    memset(stream + a + 1, 0x99, 30);
    size_t n = a + 31;
    memcpy(wire, stream, n);
    xor_stream(r.cl.enc, wire, n);
    CHECK(bye_mtp_up(r.m, wire, n, collect, &sink) == BYE_MTP_OK);
    CHECK(sink.count == 2 && sink.lens[0] == a && sink.lens[1] == 31);
    uint8_t more[50], more_wire[50];
    memset(more, 0x42, sizeof more);
    memcpy(more_wire, more, sizeof more);
    xor_stream(r.cl.enc, more_wire, sizeof more);
    CHECK(bye_mtp_up(r.m, more_wire, sizeof more, collect, &sink) == BYE_MTP_OK);
    CHECK(sink.count == 3 && sink.lens[2] == sizeof more);
    dc_read(&r, sink.msgs[0], sink.lens[0]);
    dc_read(&r, sink.msgs[1], sink.lens[1]);
    dc_read(&r, sink.msgs[2], sink.lens[2]);
    CHECK(memcmp(sink.msgs[1], stream + a, 31) == 0);
    CHECK(memcmp(sink.msgs[2], more, sizeof more) == 0);
    rig_close(&r);

    /* a packet longer than the cap closes the stream before any buffer grows */
    rig_open(&r, BYE_MTP_TAG_INTERMEDIATE);
    memset(&sink, 0, sizeof sink);
    uint8_t huge[4] = { 0x01, 0x00, 0x10, 0x00 }; /* 1 MiB + 1 */
    xor_stream(r.cl.enc, huge, 4);
    CHECK(bye_mtp_up(r.m, huge, 4, collect, &sink) == BYE_MTP_ERR_PACKET);
    rig_close(&r);

    /* a packet of exactly the cap is held and sent whole */
    rig_open(&r, BYE_MTP_TAG_INTERMEDIATE);
    memset(&sink, 0, sizeof sink);
    uint8_t *big = malloc(4 + BYE_MTP_PACKET_MAX);
    CHECK(big != NULL);
    intermediate_packet(big, BYE_MTP_PACKET_MAX, 0x5c, 0);
    xor_stream(r.cl.enc, big, 4 + BYE_MTP_PACKET_MAX);
    size_t sent = 0;
    int ok = 1;
    while (sent < 4 + BYE_MTP_PACKET_MAX && ok) {
        size_t step = 60000;
        if (step > 4 + BYE_MTP_PACKET_MAX - sent) step = 4 + BYE_MTP_PACKET_MAX - sent;
        ok = bye_mtp_up(r.m, big + sent, step, NULL, NULL) == BYE_MTP_OK;
        sent += step;
    }
    CHECK(ok);
    free(big);
    rig_close(&r);

    /* an emit that refuses ends the call with an error */
    rig_open(&r, BYE_MTP_TAG_ABRIDGED);
    memset(&sink, 0, sizeof sink);
    sink.refuse_at = 1;
    a = abridged_packet(stream, 2, 0x11, 0);
    memcpy(wire, stream, a);
    xor_stream(r.cl.enc, wire, a);
    CHECK(bye_mtp_up(r.m, wire, a, collect, &sink) == BYE_MTP_ERR_EMIT);
    rig_close(&r);

    CHECK(bye_mtp_up(NULL, wire, 1, NULL, NULL) == BYE_MTP_ERR_ARG);
    CHECK(bye_mtp_down(NULL, wire, 1) == BYE_MTP_ERR_ARG);
}

static void test_cap_exact(void) {
    /* a packet of the cap is held, one byte more is refused: the cap is on the payload */
    rig_t r;
    sink_t sink;
    memset(&sink, 0, sizeof sink);
    rig_open(&r, BYE_MTP_TAG_INTERMEDIATE);
    uint8_t head[4] = { 0x00, 0x00, 0x10, 0x00 }; /* exactly 1 MiB */
    xor_stream(r.cl.enc, head, 4);
    CHECK(bye_mtp_up(r.m, head, 4, collect, &sink) == BYE_MTP_OK);
    CHECK(sink.count == 0);
    rig_close(&r);
}

int main(void) {
    test_handshakes();
    test_rejects();
    test_split_abridged();
    test_split_intermediate();
    test_split_limits();
    test_cap_exact();
    if (!failed) puts("test_mtp ok");
    return failed;
}

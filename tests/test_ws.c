#include "bye_ws.h"

#include <stdlib.h>
#include <string.h>

#include "check.h"

/* the example of rfc 6455 section 1.3 */
static const char RFC_KEY[] = "dGhlIHNhbXBsZSBub25jZQ==";

static void test_request(void) {
    char req[BYE_WS_REQUEST_MAX], key[BYE_WS_KEY_LEN];
    size_t len;
    uint8_t random[16];
    memcpy(random, "the sample nonce", sizeof random);
    CHECK(bye_ws_request(req, sizeof req, &len, "kws2.web.telegram.org", "/apiws", random, key)
          == BYE_WS_OK);
    CHECK(strcmp(key, RFC_KEY) == 0);
    CHECK(len == strlen(req));
    CHECK(strncmp(req, "GET /apiws HTTP/1.1\r\nHost: kws2.web.telegram.org\r\n", 50) == 0);
    CHECK(strstr(req, "Sec-WebSocket-Protocol: binary\r\n") != NULL);
    CHECK(strstr(req, "Sec-WebSocket-Version: 13\r\n") != NULL);
    CHECK(strstr(req, "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n") != NULL);
    CHECK(len >= 4 && memcmp(req + len - 4, "\r\n\r\n", 4) == 0);

    CHECK(bye_ws_request(req, len, &len, "h", "/p", random, key) == BYE_WS_OK);
    CHECK(bye_ws_request(req, 20, &len, "h", "/p", random, key) == BYE_WS_ERR_SPACE);
    CHECK(bye_ws_request(req, sizeof req, &len, "bad host", "/p", random, key) == BYE_WS_ERR_HOST);
    CHECK(bye_ws_request(req, sizeof req, &len, "h\r\nX: 1", "/p", random, key) == BYE_WS_ERR_HOST);
    CHECK(bye_ws_request(req, sizeof req, &len, "h", "apiws", random, key) == BYE_WS_ERR_HOST);
    CHECK(bye_ws_request(req, sizeof req, &len, "", "/p", random, key) == BYE_WS_ERR_HOST);
}

static int check_response(const char *text, size_t *consumed, int *status) {
    return bye_ws_response((const uint8_t *)text, strlen(text), RFC_KEY, consumed, status);
}

static void test_response(void) {
    size_t used;
    int status;
    const char *ok =
        "HTTP/1.1 101 Switching Protocols\r\nServer: nginx\r\nConnection: upgrade\r\n"
        "Upgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Sec-WebSocket-Protocol: binary\r\n\r\n";
    CHECK(check_response(ok, &used, &status) == BYE_WS_OK);
    CHECK(used == strlen(ok) && status == 101);

    /* bytes after the blank line are frames, not part of the answer */
    char with_frame[512];
    snprintf(with_frame, sizeof with_frame, "%s\x82\x01X", ok);
    CHECK(check_response(with_frame, &used, &status) == BYE_WS_OK && used == strlen(ok));

    /* header names and tokens ignore case and list form */
    const char *loose =
        "HTTP/1.0 101 Switching\r\nCONNECTION: keep-alive, Upgrade\r\nupgrade: WebSocket\r\n"
        "sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Sec-WebSocket-Protocol: chat, binary\r\n\r\n";
    CHECK(check_response(loose, &used, &status) == BYE_WS_OK);

    /* every prefix is incomplete */
    for (size_t n = 0; n < strlen(ok); ++n) {
        CHECK(bye_ws_response((const uint8_t *)ok, n, RFC_KEY, &used, &status) == BYE_WS_NEED_MORE);
    }

    CHECK(check_response("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", &used, &status)
          == BYE_WS_ERR_STATUS);
    CHECK(status == 404);
    CHECK(check_response("HTTP/1.1 302 Found\r\nLocation: https://x/\r\n\r\n", &used, &status)
          == BYE_WS_ERR_STATUS && status == 302);

    /* a 101 that is not the answer to this request */
    const char *wrong_accept =
        "HTTP/1.1 101 x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\nSec-WebSocket-Protocol: binary\r\n\r\n";
    CHECK(check_response(wrong_accept, &used, &status) == BYE_WS_ERR_HEADERS);
    const char *no_protocol =
        "HTTP/1.1 101 x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    CHECK(check_response(no_protocol, &used, &status) == BYE_WS_ERR_HEADERS);
    const char *no_upgrade =
        "HTTP/1.1 101 x\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: binary\r\n\r\n";
    CHECK(check_response(no_upgrade, &used, &status) == BYE_WS_ERR_HEADERS);
    CHECK(check_response("SSH-2.0-x\r\n\r\n", &used, &status) == BYE_WS_ERR_HEADERS);
    CHECK(check_response("HTTP/1.1 10x y\r\n\r\n", &used, &status) == BYE_WS_ERR_HEADERS);

    /* an answer that never ends inside the limit */
    uint8_t *flood = malloc(BYE_WS_RESPONSE_MAX + 10);
    CHECK(flood != NULL);
    memset(flood, 'a', BYE_WS_RESPONSE_MAX + 10);
    memcpy(flood, "HTTP/1.1 101 ", 13);
    CHECK(bye_ws_response(flood, BYE_WS_RESPONSE_MAX + 10, RFC_KEY, &used, &status)
          == BYE_WS_ERR_HEADERS);
    free(flood);
}

static void test_frames(void) {
    static const uint8_t mask[4] = { 0x37, 0xfa, 0x21, 0x3d };
    size_t sizes[] = { 0, 1, 125, 126, 127, 65535, 65536, 70000 };
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; ++i) {
        size_t n = sizes[i];
        uint8_t *payload = malloc(n + 1), *frame = malloc(bye_ws_frame_size(n));
        CHECK(payload && frame);
        for (size_t k = 0; k < n; ++k) payload[k] = (uint8_t)(k * 31);
        size_t len = 0;
        CHECK(bye_ws_frame(frame, bye_ws_frame_size(n), &len, BYE_WS_OP_BINARY, payload, n, mask)
              == BYE_WS_OK);
        CHECK(len == bye_ws_frame_size(n));
        CHECK(frame[0] == 0x82);
        CHECK((frame[1] & 0x80) != 0);
        size_t head = 2;
        uint64_t declared = frame[1] & 0x7F;
        if (declared == 126) {
            declared = ((uint64_t)frame[2] << 8) | frame[3];
            head = 4;
        } else if (declared == 127) {
            declared = 0;
            for (int k = 0; k < 8; ++k) declared = (declared << 8) | frame[2 + k];
            head = 10;
        }
        CHECK(declared == n);
        CHECK(memcmp(frame + head, mask, 4) == 0);
        int same = 1;
        for (size_t k = 0; k < n; ++k)
            if ((uint8_t)(frame[head + 4 + k] ^ mask[k & 3]) != payload[k]) same = 0;
        CHECK(same);
        CHECK(bye_ws_frame(frame, len - 1, &len, BYE_WS_OP_BINARY, payload, n, mask)
              == BYE_WS_ERR_SPACE);
        free(payload);
        free(frame);
    }
    uint8_t out[300], big[200] = { 0 };
    size_t len;
    CHECK(bye_ws_frame(out, sizeof out, &len, BYE_WS_OP_PING, big, 126, mask) == BYE_WS_ERR_ARG);
    CHECK(bye_ws_frame(out, sizeof out, &len, BYE_WS_OP_PING, big, 125, mask) == BYE_WS_OK);
    CHECK(bye_ws_frame(out, sizeof out, &len, BYE_WS_OP_CLOSE, NULL, 0, mask) == BYE_WS_OK);
    CHECK(out[0] == 0x88 && len == 6);
}

typedef struct {
    uint8_t data[200000];
    size_t  data_len;
    uint8_t ping[200];
    size_t  ping_len;
    int     pings;
    int     data_calls;
} rx_log_t;

static int on_data(void *ctx, const uint8_t *p, size_t n) {
    rx_log_t *log = ctx;
    CHECK(log->data_len + n <= sizeof log->data);
    memcpy(log->data + log->data_len, p, n);
    log->data_len += n;
    ++log->data_calls;
    return 0;
}

static int on_ping(void *ctx, const uint8_t *p, size_t n) {
    rx_log_t *log = ctx;
    memcpy(log->ping, p, n);
    log->ping_len = n;
    ++log->pings;
    return 0;
}

/* an unmasked server frame */
static size_t server_frame(uint8_t *out, uint8_t first, const uint8_t *payload, size_t n) {
    size_t at = 0;
    out[at++] = first;
    if (n <= 125) {
        out[at++] = (uint8_t)n;
    } else if (n <= 65535) {
        out[at++] = 126;
        out[at++] = (uint8_t)(n >> 8);
        out[at++] = (uint8_t)n;
    } else {
        out[at++] = 127;
        for (int k = 7; k >= 0; --k) out[at++] = (uint8_t)((uint64_t)n >> (8 * k));
    }
    if (n) memcpy(out + at, payload, n);
    return at + n;
}

static void test_rx(void) {
    static uint8_t stream[100000], payload[70000];
    for (size_t i = 0; i < sizeof payload; ++i) payload[i] = (uint8_t)(i * 13 + 5);
    size_t n = 0;
    n += server_frame(stream + n, 0x82, payload, 5);
    n += server_frame(stream + n, 0x89, (const uint8_t *)"hello", 5); /* ping */
    n += server_frame(stream + n, 0x82, payload + 5, 300);
    n += server_frame(stream + n, 0x8A, NULL, 0); /* pong */
    n += server_frame(stream + n, 0x82, payload + 305, 0);
    n += server_frame(stream + n, 0x82, payload + 305, 69000);
    size_t data_total = 5 + 300 + 69000;

    static rx_log_t log;
    bye_ws_sink_t sink = { on_data, on_ping, &log };

    /* all at once, then one byte at a time, then in odd chunks */
    size_t steps[] = { n, 1, 7, 4096 };
    for (size_t s = 0; s < 4; ++s) {
        memset(&log, 0, sizeof log);
        bye_ws_rx_t rx;
        bye_ws_rx_init(&rx);
        for (size_t at = 0; at < n; at += steps[s]) {
            size_t take = n - at < steps[s] ? n - at : steps[s];
            CHECK(bye_ws_rx_feed(&rx, stream + at, take, &sink) == BYE_WS_OK);
        }
        CHECK(log.data_len == data_total);
        CHECK(memcmp(log.data, payload, 305) == 0);
        CHECK(memcmp(log.data + 305, payload + 305, 69000) == 0);
        CHECK(log.pings == 1 && log.ping_len == 5 && memcmp(log.ping, "hello", 5) == 0);
    }

    /* a message in fragments is the same bytes */
    memset(&log, 0, sizeof log);
    bye_ws_rx_t rx;
    bye_ws_rx_init(&rx);
    n = 0;
    n += server_frame(stream + n, 0x02, payload, 10);        /* binary, not final */
    n += server_frame(stream + n, 0x89, (const uint8_t *)"p", 1); /* a ping between */
    n += server_frame(stream + n, 0x00, payload + 10, 10);   /* continuation */
    n += server_frame(stream + n, 0x80, payload + 20, 10);   /* final continuation */
    CHECK(bye_ws_rx_feed(&rx, stream, n, &sink) == BYE_WS_OK);
    CHECK(log.data_len == 30 && memcmp(log.data, payload, 30) == 0 && log.pings == 1);

    /* close, with and without a reason */
    bye_ws_rx_init(&rx);
    n = server_frame(stream, 0x88, (const uint8_t *)"\x03\xe8", 2);
    CHECK(bye_ws_rx_feed(&rx, stream, n, &sink) == BYE_WS_CLOSED);
    bye_ws_rx_init(&rx);
    n = server_frame(stream, 0x88, NULL, 0);
    CHECK(bye_ws_rx_feed(&rx, stream, n, &sink) == BYE_WS_CLOSED);
}

static void test_rx_errors(void) {
    uint8_t frame[400];
    bye_ws_rx_t rx;
    bye_ws_sink_t sink = { NULL, NULL, NULL };
    uint8_t body[300] = { 0 };
    size_t n;

    /* a server must not mask */
    bye_ws_rx_init(&rx);
    n = server_frame(frame, 0x82, body, 4);
    frame[1] |= 0x80;
    CHECK(bye_ws_rx_feed(&rx, frame, n + 4, &sink) == BYE_WS_ERR_FRAME);

    /* reserved bits */
    uint8_t rsv[] = { 0xC2, 0x00, 0xA2, 0x00, 0x92, 0x00 };
    for (size_t i = 0; i < 6; i += 2) {
        bye_ws_rx_init(&rx);
        CHECK(bye_ws_rx_feed(&rx, rsv + i, 2, &sink) == BYE_WS_ERR_FRAME);
    }
    /* unknown opcodes */
    for (uint8_t op = 3; op <= 7; ++op) {
        uint8_t f[2] = { (uint8_t)(0x80 | op), 0 };
        bye_ws_rx_init(&rx);
        CHECK(bye_ws_rx_feed(&rx, f, 2, &sink) == BYE_WS_ERR_FRAME);
    }
    for (uint8_t op = 0xB; op <= 0xF; ++op) {
        uint8_t f[2] = { (uint8_t)(0x80 | op), 0 };
        bye_ws_rx_init(&rx);
        CHECK(bye_ws_rx_feed(&rx, f, 2, &sink) == BYE_WS_ERR_FRAME);
    }
    /* a continuation with nothing to continue, a new message inside one */
    bye_ws_rx_init(&rx);
    n = server_frame(frame, 0x80, body, 1);
    CHECK(bye_ws_rx_feed(&rx, frame, n, &sink) == BYE_WS_ERR_FRAME);
    bye_ws_rx_init(&rx);
    n = server_frame(frame, 0x02, body, 1);
    n += server_frame(frame + n, 0x82, body, 1);
    CHECK(bye_ws_rx_feed(&rx, frame, n, &sink) == BYE_WS_ERR_FRAME);
    /* control frames: fragmented, or longer than 125 */
    bye_ws_rx_init(&rx);
    n = server_frame(frame, 0x09, body, 1);
    CHECK(bye_ws_rx_feed(&rx, frame, n, &sink) == BYE_WS_ERR_FRAME);
    bye_ws_rx_init(&rx);
    n = server_frame(frame, 0x89, body, 126);
    CHECK(bye_ws_rx_feed(&rx, frame, n, &sink) == BYE_WS_ERR_FRAME);
    /* a 64 bit length with the top bit set */
    uint8_t huge[10] = { 0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 1 };
    bye_ws_rx_init(&rx);
    CHECK(bye_ws_rx_feed(&rx, huge, sizeof huge, &sink) == BYE_WS_ERR_FRAME);

    bye_ws_rx_init(&rx);
    CHECK(bye_ws_rx_feed(&rx, NULL, 1, &sink) == BYE_WS_ERR_ARG);
}

static int refuse_data(void *ctx, const uint8_t *p, size_t n) {
    (void)ctx; (void)p; (void)n;
    return 1;
}

static void test_sink_stop(void) {
    uint8_t frame[16];
    bye_ws_rx_t rx;
    bye_ws_sink_t sink = { refuse_data, NULL, NULL };
    size_t n = server_frame(frame, 0x82, (const uint8_t *)"abc", 3);
    bye_ws_rx_init(&rx);
    CHECK(bye_ws_rx_feed(&rx, frame, n, &sink) == BYE_WS_ERR_SINK);
}

int main(void) {
    test_request();
    test_response();
    test_frames();
    test_rx();
    test_rx_errors();
    test_sink_stop();
    if (!failed) puts("test_ws ok");
    return failed;
}

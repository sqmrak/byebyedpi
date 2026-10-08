#include "bye_wsconn.h"

#include "bye_ws.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#define RX_CHUNK 4096
#define HOST_MAX 128
#define PATH_MAX_LEN 64
#define BYE_WSCONN_CONTROL_ROOM 1024u
#define TX_SHRINK 65536

typedef enum {
    STATE_TLS = 0,
    STATE_UPGRADE_SEND,
    STATE_UPGRADE_RECV,
    STATE_OPEN,
    STATE_DEAD
} state_t;

struct bye_wsconn_ctx {
    SSL_CTX *ssl;
};

struct bye_wsconn {
    SSL        *ssl;
    state_t     state;
    char        host[HOST_MAX];
    char        path[PATH_MAX_LEN];
    char        key[BYE_WS_KEY_LEN];
    char        request[BYE_WS_REQUEST_MAX];
    size_t      request_len;
    size_t      request_off;
    uint8_t     head[BYE_WS_RESPONSE_MAX];
    size_t      head_len;
    uint8_t    *tx;
    size_t      tx_len;
    size_t      tx_off;
    size_t      tx_cap;
    bye_ws_rx_t rx;
    uint8_t     rx_raw[RX_CHUNK];
    size_t      rx_raw_len;  /* bytes after the upgrade answer, not parsed yet */
    size_t      rx_raw_off;
    int         closed;
    char        error[BYE_WSCONN_ERROR_MAX];
};

static void set_error(char *out, size_t cap, const char *what) {
    unsigned long code = ERR_peek_last_error();
    if (code) {
        char detail[96];
        ERR_error_string_n(code, detail, sizeof detail);
        snprintf(out, cap, "%s: %s", what, detail);
    } else {
        snprintf(out, cap, "%s", what);
    }
    ERR_clear_error();
}

bye_wsconn_ctx_t *bye_wsconn_ctx_new(const char *ca_file, char *error, size_t error_cap) {
    bye_wsconn_ctx_t *ctx = calloc(1, sizeof *ctx);
    if (!ctx) {
        if (error && error_cap) snprintf(error, error_cap, "out of memory");
        return NULL;
    }
    ctx->ssl = SSL_CTX_new(TLS_client_method());
    if (!ctx->ssl) {
        if (error && error_cap) set_error(error, error_cap, "cannot create the tls context");
        free(ctx);
        return NULL;
    }
    SSL_CTX_set_min_proto_version(ctx->ssl, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx->ssl, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_mode(ctx->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    /* an h2 answer would send binary frames to an http/1 upgrade */
    static const unsigned char alpn[] = "\x08http/1.1";
    if (SSL_CTX_set_alpn_protos(ctx->ssl, alpn, sizeof alpn - 1) != 0) {
        if (error && error_cap) set_error(error, error_cap, "cannot set alpn");
        SSL_CTX_free(ctx->ssl);
        free(ctx);
        return NULL;
    }
    int loaded = ca_file ? SSL_CTX_load_verify_locations(ctx->ssl, ca_file, NULL)
                         : SSL_CTX_set_default_verify_paths(ctx->ssl);
    if (loaded != 1) {
        if (error && error_cap) {
            char what[96];
            snprintf(what, sizeof what, "cannot load the trust roots%s%s",
                     ca_file ? " from " : "", ca_file ? ca_file : "");
            set_error(error, error_cap, what);
        }
        SSL_CTX_free(ctx->ssl);
        free(ctx);
        return NULL;
    }
    return ctx;
}

void bye_wsconn_ctx_free(bye_wsconn_ctx_t *ctx) {
    if (!ctx) return;
    SSL_CTX_free(ctx->ssl);
    free(ctx);
}

bye_wsconn_t *bye_wsconn_new(bye_wsconn_ctx_t *ctx, int fd, const char *host, const char *path) {
    if (!ctx || fd < 0 || !host || !path) return NULL;
    if (strlen(host) >= HOST_MAX || strlen(path) >= PATH_MAX_LEN) return NULL;
    bye_wsconn_t *conn = calloc(1, sizeof *conn);
    if (!conn) return NULL;
    snprintf(conn->host, sizeof conn->host, "%s", host);
    snprintf(conn->path, sizeof conn->path, "%s", path);
    bye_ws_rx_init(&conn->rx);

    uint8_t random[16];
    size_t request_len = 0;
    if (RAND_bytes(random, sizeof random) != 1 ||
        bye_ws_request(conn->request, sizeof conn->request, &request_len, conn->host,
                       conn->path, random, conn->key) != BYE_WS_OK)
        goto fail;
    conn->request_len = request_len;

    conn->ssl = SSL_new(ctx->ssl);
    if (!conn->ssl) goto fail;
    /* the name in the certificate and the name sent as sni are both the host */
    if (SSL_set_tlsext_host_name(conn->ssl, conn->host) != 1 ||
        SSL_set1_host(conn->ssl, conn->host) != 1 ||
        SSL_set_fd(conn->ssl, fd) != 1)
        goto fail;
    SSL_set_connect_state(conn->ssl);
    ERR_clear_error();
    return conn;
fail:
    ERR_clear_error();
    if (conn->ssl) SSL_free(conn->ssl);
    free(conn);
    return NULL;
}

void bye_wsconn_free(bye_wsconn_t *conn) {
    if (!conn) return;
    /* no close_notify: the socket may be dead and the write would block */
    if (conn->ssl) SSL_free(conn->ssl);
    free(conn->tx);
    free(conn);
}

const char *bye_wsconn_error(const bye_wsconn_t *conn) {
    return conn ? conn->error : "";
}

int bye_wsconn_buffered(const bye_wsconn_t *conn) {
    return conn && conn->ssl && (SSL_pending(conn->ssl) > 0 || conn->rx_raw_off < conn->rx_raw_len);
}

static bye_wsconn_status_t fail(bye_wsconn_t *conn, const char *what) {
    set_error(conn->error, sizeof conn->error, what);
    conn->state = STATE_DEAD;
    return BYE_WSCONN_ERR;
}

/* maps an ssl result to a wait or a failure. ret is the call's return */
static bye_wsconn_status_t ssl_status(bye_wsconn_t *conn, int ret, const char *what) {
    int err = SSL_get_error(conn->ssl, ret);
    switch (err) {
    case SSL_ERROR_WANT_READ:
        ERR_clear_error();
        return BYE_WSCONN_WANT_READ;
    case SSL_ERROR_WANT_WRITE:
        ERR_clear_error();
        return BYE_WSCONN_WANT_WRITE;
    case SSL_ERROR_ZERO_RETURN:
        ERR_clear_error();
        return BYE_WSCONN_CLOSED;
    case SSL_ERROR_SYSCALL:
        if (errno == EINTR) {
            ERR_clear_error();
            return BYE_WSCONN_WANT_READ;
        }
        if (errno == 0 && ERR_peek_error() == 0) {
            conn->closed = 1;
            return BYE_WSCONN_CLOSED;
        }
        /* fall through */
    default: {
        char text[96];
        snprintf(text, sizeof text, "%s (errno %d %s)", what, errno,
                 errno ? strerror(errno) : "none");
        return fail(conn, text);
    }
    }
}

static int verify_result_error(bye_wsconn_t *conn) {
    long verify = SSL_get_verify_result(conn->ssl);
    if (verify == X509_V_OK) return 0;
    char text[BYE_WSCONN_ERROR_MAX];
    snprintf(text, sizeof text, "the certificate was refused: %s",
             X509_verify_cert_error_string(verify));
    fail(conn, text);
    return -1;
}

bye_wsconn_status_t bye_wsconn_handshake(bye_wsconn_t *conn) {
    if (!conn) return BYE_WSCONN_ERR;
    for (;;) {
        switch (conn->state) {
        case STATE_TLS: {
            ERR_clear_error();
            int ret = SSL_connect(conn->ssl);
            if (ret != 1) {
                bye_wsconn_status_t status = ssl_status(conn, ret, "the tls handshake failed");
                if (status == BYE_WSCONN_ERR && verify_result_error(conn) != 0)
                    return BYE_WSCONN_ERR;
                if (status == BYE_WSCONN_CLOSED)
                    return fail(conn, "the server closed during the tls handshake");
                return status;
            }
            conn->state = STATE_UPGRADE_SEND;
            break;
        }
        case STATE_UPGRADE_SEND: {
            ERR_clear_error();
            int ret = SSL_write(conn->ssl, conn->request + conn->request_off,
                                (int)(conn->request_len - conn->request_off));
            if (ret <= 0) return ssl_status(conn, ret, "the upgrade request failed");
            conn->request_off += (size_t)ret;
            if (conn->request_off == conn->request_len) conn->state = STATE_UPGRADE_RECV;
            break;
        }
        case STATE_UPGRADE_RECV: {
            ERR_clear_error();
            /* read at most what is left of the answer buffer, so the answer
               and the first frames may arrive together */
            int ret = SSL_read(conn->ssl, conn->head + conn->head_len,
                               (int)(sizeof conn->head - conn->head_len));
            if (ret <= 0) {
                bye_wsconn_status_t status = ssl_status(conn, ret, "the upgrade answer failed");
                if (status == BYE_WSCONN_CLOSED)
                    return fail(conn, "the server closed instead of answering the upgrade");
                return status;
            }
            conn->head_len += (size_t)ret;
            size_t used = 0;
            int http = 0;
            bye_ws_status_t answer = bye_ws_response(conn->head, conn->head_len, conn->key,
                                                     &used, &http);
            if (answer == BYE_WS_NEED_MORE) break;
            if (answer == BYE_WS_ERR_STATUS) {
                char text[64];
                snprintf(text, sizeof text, "the gateway answered http %d", http);
                return fail(conn, text);
            }
            if (answer != BYE_WS_OK) return fail(conn, "the upgrade answer is not a websocket accept");
            size_t extra = conn->head_len - used;
            if (extra > sizeof conn->rx_raw) return fail(conn, "too many bytes after the upgrade");
            memcpy(conn->rx_raw, conn->head + used, extra);
            conn->rx_raw_len = extra;
            conn->state = STATE_OPEN;
            break;
        }
        case STATE_OPEN:
            return BYE_WSCONN_OK;
        case STATE_DEAD:
            return BYE_WSCONN_ERR;
        }
    }
}

static int tx_reserve(bye_wsconn_t *conn, size_t extra, int control) {
    /* a pong must go out even when the queue is full of data */
    size_t limit = BYE_WSCONN_TX_MAX + (control ? BYE_WSCONN_CONTROL_ROOM : 0);
    if (conn->tx_off == conn->tx_len) conn->tx_off = conn->tx_len = 0;
    size_t used = conn->tx_len - conn->tx_off;
    if (extra > limit || used > limit - extra) return -1;
    if (conn->tx_off && conn->tx_len + extra > conn->tx_cap) {
        memmove(conn->tx, conn->tx + conn->tx_off, used);
        conn->tx_len = used;
        conn->tx_off = 0;
    }
    if (conn->tx_len + extra > conn->tx_cap) {
        size_t cap = conn->tx_cap ? conn->tx_cap : 4096;
        while (cap < conn->tx_len + extra) cap *= 2;
        if (cap > limit) cap = limit;
        if (cap < conn->tx_len + extra) return -1;
        uint8_t *grown = realloc(conn->tx, cap);
        if (!grown) return -1;
        conn->tx = grown;
        conn->tx_cap = cap;
    }
    return 0;
}

static int queue_frame(bye_wsconn_t *conn, uint8_t opcode, const uint8_t *payload, size_t len) {
    uint8_t mask[4];
    if (RAND_bytes(mask, sizeof mask) != 1) return -1;
    size_t size = bye_ws_frame_size(len);
    if (tx_reserve(conn, size, (opcode & 0x8) != 0) != 0) return -1;
    size_t written = 0;
    if (bye_ws_frame(conn->tx + conn->tx_len, conn->tx_cap - conn->tx_len, &written, opcode,
                     payload, len, mask) != BYE_WS_OK)
        return -1;
    conn->tx_len += written;
    return 0;
}

int bye_wsconn_send(bye_wsconn_t *conn, const uint8_t *msg, size_t len) {
    if (!conn || conn->state != STATE_OPEN || (!msg && len)) return -1;
    return queue_frame(conn, BYE_WS_OP_BINARY, msg, len);
}

int bye_wsconn_ping(bye_wsconn_t *conn) {
    if (!conn || conn->state != STATE_OPEN) return -1;
    return queue_frame(conn, BYE_WS_OP_PING, NULL, 0);
}

size_t bye_wsconn_pending(const bye_wsconn_t *conn) {
    return conn ? conn->tx_len - conn->tx_off : 0;
}

bye_wsconn_status_t bye_wsconn_flush(bye_wsconn_t *conn) {
    if (!conn || conn->state == STATE_DEAD) return BYE_WSCONN_ERR;
    while (conn->tx_off < conn->tx_len) {
        ERR_clear_error();
        size_t left = conn->tx_len - conn->tx_off;
        int step = left > 16384 ? 16384 : (int)left;
        int ret = SSL_write(conn->ssl, conn->tx + conn->tx_off, step);
        if (ret <= 0) {
            bye_wsconn_status_t status = ssl_status(conn, ret, "writing to the gateway failed");
            if (status == BYE_WSCONN_CLOSED) return fail(conn, "the gateway closed the connection");
            return status;
        }
        conn->tx_off += (size_t)ret;
    }
    conn->tx_off = conn->tx_len = 0;
    if (conn->tx_cap > TX_SHRINK) {
        free(conn->tx);
        conn->tx = NULL;
        conn->tx_cap = 0;
    }
    return BYE_WSCONN_OK;
}

typedef struct {
    bye_wsconn_t *conn;
    uint8_t      *out;
    size_t        cap;
    size_t        got;
    int           pong_failed;
} read_sink_t;

static int sink_data(void *ctx, const uint8_t *data, size_t len) {
    read_sink_t *sink = ctx;
    if (len > sink->cap - sink->got) return 1;
    memcpy(sink->out + sink->got, data, len);
    sink->got += len;
    return 0;
}

static int sink_ping(void *ctx, const uint8_t *data, size_t len) {
    read_sink_t *sink = ctx;
    if (queue_frame(sink->conn, BYE_WS_OP_PONG, data, len) != 0) {
        sink->pong_failed = 1;
        return 1;
    }
    return 0;
}

bye_wsconn_status_t bye_wsconn_read(bye_wsconn_t *conn, uint8_t *out, size_t cap, size_t *got) {
    if (got) *got = 0;
    if (!conn || !out || cap == 0 || !got) return BYE_WSCONN_ERR;
    if (conn->state != STATE_OPEN) return conn->state == STATE_DEAD ? BYE_WSCONN_ERR : BYE_WSCONN_WANT_READ;
    if (conn->closed) return BYE_WSCONN_CLOSED;

    read_sink_t sink = { conn, out, cap, 0, 0 };
    bye_ws_sink_t handlers = { sink_data, sink_ping, &sink };

    /* the bytes that arrived with the upgrade answer come first */
    size_t chunk = 0;
    uint8_t *raw = conn->rx_raw;
    if (conn->rx_raw_off < conn->rx_raw_len) {
        raw += conn->rx_raw_off;
        chunk = conn->rx_raw_len - conn->rx_raw_off;
        if (chunk > cap) chunk = cap;
        conn->rx_raw_off += chunk;
    } else {
        ERR_clear_error();
        size_t want = cap < RX_CHUNK ? cap : RX_CHUNK;
        int ret = SSL_read(conn->ssl, conn->rx_raw, (int)want);
        if (ret <= 0) {
            bye_wsconn_status_t status = ssl_status(conn, ret, "reading from the gateway failed");
            if (status == BYE_WSCONN_CLOSED) conn->closed = 1;
            return status;
        }
        raw = conn->rx_raw;
        chunk = (size_t)ret;
        conn->rx_raw_off = conn->rx_raw_len = 0;
    }
    bye_ws_status_t fed = bye_ws_rx_feed(&conn->rx, raw, chunk, &handlers);
    *got = sink.got;
    if (fed == BYE_WS_CLOSED) {
        conn->closed = 1;
        return sink.got ? BYE_WSCONN_OK : BYE_WSCONN_CLOSED;
    }
    if (fed == BYE_WS_ERR_SINK && sink.pong_failed) return fail(conn, "the send queue is full");
    if (fed != BYE_WS_OK) return fail(conn, "the gateway broke the websocket framing");
    return sink.got ? BYE_WSCONN_OK : BYE_WSCONN_WANT_READ;
}

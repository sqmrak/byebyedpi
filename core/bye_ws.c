#include "bye_ws.h"

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

static const char GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static size_t base64(const uint8_t *in, size_t len, char *out) {
    static const char digits[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t j = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < len) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < len) v |= in[i + 2];
        out[j++] = digits[(v >> 18) & 63];
        out[j++] = digits[(v >> 12) & 63];
        out[j++] = i + 1 < len ? digits[(v >> 6) & 63] : '=';
        out[j++] = i + 2 < len ? digits[v & 63] : '=';
    }
    out[j] = '\0';
    return j;
}

static int token_ok(const char *s) {
    if (!s || !s[0]) return 0;
    for (const char *p = s; *p; ++p)
        if ((unsigned char)*p <= 0x20 || (unsigned char)*p >= 0x7f) return 0;
    return 1;
}

static int accept_for(const char key[BYE_WS_KEY_LEN], char accept[BYE_WS_ACCEPT_LEN]) {
    char joined[BYE_WS_KEY_LEN + sizeof GUID];
    int n = snprintf(joined, sizeof joined, "%s%s", key, GUID);
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (n < 0 || (size_t)n >= sizeof joined) return -1;
    if (EVP_Digest(joined, (size_t)n, digest, &digest_len, EVP_sha1(), NULL) != 1 ||
        digest_len != 20)
        return -1;
    base64(digest, digest_len, accept);
    return 0;
}

bye_ws_status_t bye_ws_request(char *out, size_t cap, size_t *out_len, const char *host,
                               const char *path, const uint8_t random[16],
                               char key[BYE_WS_KEY_LEN]) {
    if (out_len) *out_len = 0;
    if (!out || !out_len || !host || !path || !random || !key) return BYE_WS_ERR_ARG;
    if (!token_ok(host) || !token_ok(path) || path[0] != '/') return BYE_WS_ERR_HOST;
    base64(random, 16, key);
    int n = snprintf(out, cap,
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: %s\r\n"
                     "Sec-WebSocket-Version: 13\r\n"
                     "Sec-WebSocket-Protocol: binary\r\n"
                     "\r\n",
                     path, host, key);
    if (n < 0 || (size_t)n >= cap) return BYE_WS_ERR_SPACE;
    *out_len = (size_t)n;
    return BYE_WS_OK;
}

static int lower(int ch) {
    return (ch >= 'A' && ch <= 'Z') ? ch + ('a' - 'A') : ch;
}

static int equal_nocase(const char *a, size_t a_len, const char *b) {
    if (a_len != strlen(b)) return 0;
    for (size_t i = 0; i < a_len; ++i)
        if (lower((unsigned char)a[i]) != lower((unsigned char)b[i])) return 0;
    return 1;
}

/* a comma list holds a token, as in "Connection: keep-alive, Upgrade" */
static int list_has(const char *value, size_t len, const char *token) {
    size_t i = 0;
    while (i < len) {
        while (i < len && (value[i] == ' ' || value[i] == ',')) ++i;
        size_t start = i;
        while (i < len && value[i] != ',' && value[i] != ' ') ++i;
        if (i > start && equal_nocase(value + start, i - start, token)) return 1;
    }
    return 0;
}

bye_ws_status_t bye_ws_response(const uint8_t *buf, size_t len, const char key[BYE_WS_KEY_LEN],
                                size_t *consumed, int *http_status) {
    if (consumed) *consumed = 0;
    if (http_status) *http_status = 0;
    if (!buf || !key || !consumed || !http_status) return BYE_WS_ERR_ARG;

    const char *text = (const char *)buf;
    const char *end = NULL;
    size_t scan = len < BYE_WS_RESPONSE_MAX ? len : BYE_WS_RESPONSE_MAX;
    for (size_t i = 0; i + 4 <= scan; ++i) {
        if (memcmp(text + i, "\r\n\r\n", 4) == 0) {
            end = text + i;
            break;
        }
    }
    if (!end) return len >= BYE_WS_RESPONSE_MAX ? BYE_WS_ERR_HEADERS : BYE_WS_NEED_MORE;
    size_t head_len = (size_t)(end - text) + 4;

    /* the status line: HTTP/1.x, a space and three digits */
    if (head_len < 12 || memcmp(text, "HTTP/1.", 7) != 0 || text[8] != ' ' ||
        text[9] < '0' || text[9] > '9' || text[10] < '0' || text[10] > '9' ||
        text[11] < '0' || text[11] > '9')
        return BYE_WS_ERR_HEADERS;
    *http_status = (text[9] - '0') * 100 + (text[10] - '0') * 10 + (text[11] - '0');
    if (*http_status != 101) return BYE_WS_ERR_STATUS;

    char expected[BYE_WS_ACCEPT_LEN];
    if (accept_for(key, expected) != 0) return BYE_WS_ERR_HEADERS;

    int upgrade = 0, connection = 0, accepted = 0, binary = 0;
    const char *line = memchr(text, '\n', head_len);
    while (line && line + 1 < text + head_len) {
        ++line;
        const char *eol = memchr(line, '\r', (size_t)(text + head_len - line));
        if (!eol || eol == line) break;
        const char *colon = memchr(line, ':', (size_t)(eol - line));
        if (colon) {
            const char *value = colon + 1;
            while (value < eol && (*value == ' ' || *value == '\t')) ++value;
            const char *value_end = eol;
            while (value_end > value && (value_end[-1] == ' ' || value_end[-1] == '\t')) --value_end;
            size_t name_len = (size_t)(colon - line);
            size_t value_len = (size_t)(value_end - value);
            if (equal_nocase(line, name_len, "upgrade"))
                upgrade = list_has(value, value_len, "websocket");
            else if (equal_nocase(line, name_len, "connection"))
                connection = list_has(value, value_len, "upgrade");
            else if (equal_nocase(line, name_len, "sec-websocket-accept"))
                accepted = value_len == strlen(expected) && memcmp(value, expected, value_len) == 0;
            else if (equal_nocase(line, name_len, "sec-websocket-protocol"))
                binary = list_has(value, value_len, "binary");
        }
        line = memchr(eol, '\n', (size_t)(text + head_len - eol));
    }
    if (!upgrade || !connection || !accepted || !binary) return BYE_WS_ERR_HEADERS;
    *consumed = head_len;
    return BYE_WS_OK;
}

size_t bye_ws_frame_size(size_t payload_len) {
    size_t head = 2 + 4;
    if (payload_len > 65535) head += 8;
    else if (payload_len > 125) head += 2;
    return head + payload_len;
}

bye_ws_status_t bye_ws_frame(uint8_t *out, size_t cap, size_t *out_len, uint8_t opcode,
                             const uint8_t *payload, size_t len, const uint8_t mask[4]) {
    if (out_len) *out_len = 0;
    if (!out || !out_len || !mask || (!payload && len)) return BYE_WS_ERR_ARG;
    if ((opcode & 0x8) && len > BYE_WS_CONTROL_MAX) return BYE_WS_ERR_ARG;
    size_t total = bye_ws_frame_size(len);
    if (cap < total) return BYE_WS_ERR_SPACE;

    size_t at = 0;
    out[at++] = (uint8_t)(0x80 | (opcode & 0x0F));
    if (len <= 125) {
        out[at++] = (uint8_t)(0x80 | len);
    } else if (len <= 65535) {
        out[at++] = 0x80 | 126;
        out[at++] = (uint8_t)(len >> 8);
        out[at++] = (uint8_t)len;
    } else {
        out[at++] = 0x80 | 127;
        for (int shift = 56; shift >= 0; shift -= 8) out[at++] = (uint8_t)((uint64_t)len >> shift);
    }
    memcpy(out + at, mask, 4);
    at += 4;
    for (size_t i = 0; i < len; ++i) out[at + i] = payload[i] ^ mask[i & 3];
    *out_len = at + len;
    return BYE_WS_OK;
}

void bye_ws_rx_init(bye_ws_rx_t *rx) {
    if (rx) memset(rx, 0, sizeof *rx);
}

/* how many header bytes the frame needs, known once its second byte is in */
static size_t head_need(const uint8_t *head, size_t have) {
    if (have < 2) return 2;
    size_t n = head[1] & 0x7F;
    if (n == 126) return 4;
    if (n == 127) return 10;
    return 2;
}

static bye_ws_status_t start_frame(bye_ws_rx_t *rx) {
    const uint8_t *h = rx->head;
    int fin = h[0] & 0x80;
    int opcode = h[0] & 0x0F;
    if (h[0] & 0x70) return BYE_WS_ERR_FRAME;
    if (h[1] & 0x80) return BYE_WS_ERR_FRAME; /* a server never masks */

    uint64_t n = h[1] & 0x7F;
    if (n == 126) {
        n = ((uint64_t)h[2] << 8) | h[3];
    } else if (n == 127) {
        n = 0;
        if (h[2] & 0x80) return BYE_WS_ERR_FRAME;
        for (int i = 0; i < 8; ++i) n = (n << 8) | h[2 + i];
    }
    if (opcode & 0x8) {
        if (!fin || n > BYE_WS_CONTROL_MAX) return BYE_WS_ERR_FRAME;
        if (opcode != BYE_WS_OP_CLOSE && opcode != BYE_WS_OP_PING && opcode != BYE_WS_OP_PONG)
            return BYE_WS_ERR_FRAME;
    } else if (opcode == BYE_WS_OP_CONT) {
        if (!rx->in_message) return BYE_WS_ERR_FRAME;
    } else if (opcode == BYE_WS_OP_TEXT || opcode == BYE_WS_OP_BINARY) {
        if (rx->in_message) return BYE_WS_ERR_FRAME;
    } else {
        return BYE_WS_ERR_FRAME;
    }
    if (!(opcode & 0x8)) rx->in_message = !fin;
    rx->opcode = (uint8_t)opcode;
    rx->left = n;
    rx->control_len = 0;
    rx->in_frame = 1;
    return BYE_WS_OK;
}

static bye_ws_status_t finish_control(bye_ws_rx_t *rx, const bye_ws_sink_t *sink) {
    if (rx->opcode == BYE_WS_OP_CLOSE) return BYE_WS_CLOSED;
    if (rx->opcode == BYE_WS_OP_PING && sink && sink->on_ping &&
        sink->on_ping(sink->ctx, rx->control, rx->control_len) != 0)
        return BYE_WS_ERR_SINK;
    return BYE_WS_OK;
}

bye_ws_status_t bye_ws_rx_feed(bye_ws_rx_t *rx, const uint8_t *data, size_t len,
                               const bye_ws_sink_t *sink) {
    if (!rx || (!data && len)) return BYE_WS_ERR_ARG;
    size_t pos = 0;
    while (pos < len) {
        if (!rx->in_frame) {
            while (pos < len) {
                rx->head[rx->head_len++] = data[pos++];
                if (rx->head_len >= head_need(rx->head, rx->head_len)) break;
            }
            if (rx->head_len < head_need(rx->head, rx->head_len)) break;
            bye_ws_status_t status = start_frame(rx);
            rx->head_len = 0;
            if (status != BYE_WS_OK) return status;
            if (rx->left == 0) {
                rx->in_frame = 0;
                status = finish_control(rx, sink);
                if (status != BYE_WS_OK) return status;
            }
            continue;
        }
        size_t take = len - pos;
        if ((uint64_t)take > rx->left) take = (size_t)rx->left;
        if (rx->opcode & 0x8) {
            memcpy(rx->control + rx->control_len, data + pos, take);
            rx->control_len += take;
        } else if (take && sink && sink->on_data &&
                   sink->on_data(sink->ctx, data + pos, take) != 0) {
            return BYE_WS_ERR_SINK;
        }
        pos += take;
        rx->left -= take;
        if (rx->left == 0) {
            rx->in_frame = 0;
            if (rx->opcode & 0x8) {
                bye_ws_status_t status = finish_control(rx, sink);
                if (status != BYE_WS_OK) return status;
            }
        }
    }
    return BYE_WS_OK;
}

#include "bye_sniff.h"

#include <string.h>

#define TLS_RECORD_HEADER 5
#define TLS_RECORD_MAX 16384
#define TLS_HANDSHAKE_HEADER 4
#define TLS_EXT_SERVER_NAME 0
#define SNI_NAME_MAX 255
#define HTTP_SCAN_MAX 8192

static uint16_t be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

/* a cursor over the hello body. end is where the message ends, len is what
   has arrived: a field past end is malformed, a field past len is not here yet */
typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t end;
    size_t pos;
} cursor_t;

static bye_sniff_status_t take(cursor_t *c, size_t n) {
    if (n > c->end - c->pos) return BYE_SNIFF_MALFORMED;
    if (c->pos + n > c->len) return BYE_SNIFF_NEED_MORE;
    return BYE_SNIFF_OK;
}

#define NEED(c, n) do { \
        bye_sniff_status_t need_status_ = take((c), (n)); \
        if (need_status_ != BYE_SNIFF_OK) return need_status_; \
    } while (0)

static int name_bytes_ok(const uint8_t *name, size_t n) {
    for (size_t i = 0; i < n; ++i)
        if (name[i] <= 0x20 || name[i] >= 0x7f) return 0;
    return 1;
}

static bye_sniff_status_t sni_list(cursor_t *c, size_t list_end, bye_sniff_t *out) {
    while (c->pos < list_end) {
        c->end = list_end;
        NEED(c, 3);
        uint8_t type = c->buf[c->pos];
        size_t n = be16(c->buf + c->pos + 1);
        c->pos += 3;
        NEED(c, n);
        if (type == 0) {
            if (n == 0 || n > SNI_NAME_MAX) return BYE_SNIFF_MALFORMED;
            if (!name_bytes_ok(c->buf + c->pos, n)) return BYE_SNIFF_MALFORMED;
            out->name_off = c->pos;
            out->name_len = n;
            return BYE_SNIFF_OK;
        }
        c->pos += n;
    }
    return BYE_SNIFF_NO_NAME;
}

bye_sniff_status_t bye_sniff_tls(const uint8_t *buf, size_t len, bye_sniff_t *out) {
    if (!out) return BYE_SNIFF_MALFORMED;
    memset(out, 0, sizeof *out);
    if (!buf || len == 0) return BYE_SNIFF_NEED_MORE;
    if (buf[0] != 0x16) return BYE_SNIFF_NO_MATCH;
    if (len > 1 && buf[1] != 0x03) return BYE_SNIFF_NO_MATCH;
    if (len > 2 && buf[2] > 0x04) return BYE_SNIFF_NO_MATCH;
    if (len < TLS_RECORD_HEADER) return BYE_SNIFF_NEED_MORE;

    size_t body = be16(buf + 3);
    if (body < TLS_HANDSHAKE_HEADER || body > TLS_RECORD_MAX) return BYE_SNIFF_MALFORMED;
    size_t record_end = TLS_RECORD_HEADER + body;

    cursor_t c = { buf, len, record_end, TLS_RECORD_HEADER };
    NEED(&c, TLS_HANDSHAKE_HEADER);
    if (buf[c.pos] != 0x01) return BYE_SNIFF_NO_MATCH;
    size_t hello = ((size_t)buf[c.pos + 1] << 16) | ((size_t)buf[c.pos + 2] << 8) |
                   buf[c.pos + 3];
    c.pos += TLS_HANDSHAKE_HEADER;
    /* a hello split over several records is not handled */
    if (hello != body - TLS_HANDSHAKE_HEADER) return BYE_SNIFF_MALFORMED;

    /* version and random */
    NEED(&c, 2 + 32);
    c.pos += 2 + 32;

    NEED(&c, 1);
    size_t session = buf[c.pos++];
    if (session > 32) return BYE_SNIFF_MALFORMED;
    NEED(&c, session);
    c.pos += session;

    NEED(&c, 2);
    size_t suites = be16(buf + c.pos);
    c.pos += 2;
    if (suites < 2 || (suites & 1)) return BYE_SNIFF_MALFORMED;
    NEED(&c, suites);
    c.pos += suites;

    NEED(&c, 1);
    size_t compression = buf[c.pos++];
    if (compression == 0) return BYE_SNIFF_MALFORMED;
    NEED(&c, compression);
    c.pos += compression;

    out->record_len = record_end;
    if (c.pos == record_end) return BYE_SNIFF_NO_NAME;

    NEED(&c, 2);
    size_t exts = be16(buf + c.pos);
    c.pos += 2;
    if (exts != record_end - c.pos) return BYE_SNIFF_MALFORMED;
    while (c.pos < record_end) {
        NEED(&c, 4);
        uint16_t type = be16(buf + c.pos);
        size_t n = be16(buf + c.pos + 2);
        c.pos += 4;
        NEED(&c, n);
        if (type != TLS_EXT_SERVER_NAME) {
            c.pos += n;
            continue;
        }
        size_t ext_end = c.pos + n;
        c.end = ext_end;
        NEED(&c, 2);
        size_t list = be16(buf + c.pos);
        c.pos += 2;
        if (list != ext_end - c.pos) return BYE_SNIFF_MALFORMED;
        return sni_list(&c, ext_end, out);
    }
    return BYE_SNIFF_NO_NAME;
}

static int ascii_lower(int ch) {
    return (ch >= 'A' && ch <= 'Z') ? ch + ('a' - 'A') : ch;
}

static int line_is_host(const uint8_t *line, size_t n) {
    static const char host[] = "host:";
    if (n < sizeof host - 1) return 0;
    for (size_t i = 0; i < sizeof host - 1; ++i)
        if (ascii_lower(line[i]) != host[i]) return 0;
    return 1;
}

bye_sniff_status_t bye_sniff_http(const uint8_t *buf, size_t len, bye_sniff_t *out) {
    if (!out) return BYE_SNIFF_MALFORMED;
    memset(out, 0, sizeof *out);
    if (!buf || len == 0) return BYE_SNIFF_NEED_MORE;

    /* the method: upper case letters and a space */
    size_t method = 0;
    while (method < len && method < 8 && buf[method] >= 'A' && buf[method] <= 'Z') ++method;
    if (method < 3) return method == len ? BYE_SNIFF_NEED_MORE : BYE_SNIFF_NO_MATCH;
    if (method == len) return BYE_SNIFF_NEED_MORE;
    if (buf[method] != ' ') return BYE_SNIFF_NO_MATCH;

    size_t scan = len < HTTP_SCAN_MAX ? len : HTTP_SCAN_MAX;
    size_t pos = method;
    while (pos < scan) {
        const uint8_t *eol = memchr(buf + pos, '\n', scan - pos);
        if (!eol) break;
        size_t next = (size_t)(eol - buf) + 1;
        /* the line after the request line; an empty line ends the headers */
        if (pos > method) {
            size_t line_len = next - pos;
            while (line_len && (buf[pos + line_len - 1] == '\n' ||
                                buf[pos + line_len - 1] == '\r')) --line_len;
            if (line_len == 0) return BYE_SNIFF_NO_NAME;
            if (line_is_host(buf + pos, line_len)) {
                size_t off = pos + 5;
                size_t end = pos + line_len;
                while (off < end && (buf[off] == ' ' || buf[off] == '\t')) ++off;
                while (end > off && (buf[end - 1] == ' ' || buf[end - 1] == '\t')) --end;
                if (off == end) return BYE_SNIFF_MALFORMED;
                out->name_off = off;
                out->name_len = end - off;
                return BYE_SNIFF_OK;
            }
        }
        pos = next;
    }
    return scan == HTTP_SCAN_MAX ? BYE_SNIFF_MALFORMED : BYE_SNIFF_NEED_MORE;
}

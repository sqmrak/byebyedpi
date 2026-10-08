#include "bye_reply.h"

#include "bye_config.h"

#include <stdint.h>
#include <string.h>

static int blank(char c) {
    return c == ' ' || c == '\t' || c == '\r';
}

int bye_reply_parse(const char *text, size_t len, bye_reply_t *out) {
    if (out) memset(out, 0, sizeof *out);
    if (!text || !out) return -1;
    size_t line = 0;
    while (line < len && text[line] != '\n') ++line;
    int ok = len >= 2 && text[0] == 'O' && text[1] == 'K';
    int err = len >= 3 && text[0] == 'E' && text[1] == 'R' && text[2] == 'R';
    size_t head = ok ? 2 : 3;
    /* "OKAY" is not a status */
    if ((!ok && !err) || (line > head && text[head] != ' ' && text[head] != '\r')) return -1;
    out->ok = ok;
    size_t at = head;
    while (at < line && blank(text[at])) ++at;
    size_t end = line;
    while (end > at && blank(text[end - 1])) --end;
    size_t n = end - at;
    if (n >= sizeof out->detail) n = sizeof out->detail - 1;
    memcpy(out->detail, text + at, n);
    out->detail[n] = '\0';
    size_t body = line < len ? line + 1 : len;
    out->body = text + body;
    out->body_len = len - body;
    return 0;
}

/* splits one line at its first '=' and trims both sides. 0 for a line with none */
static int split(const char *line, size_t len, const char **key, size_t *key_len,
                 const char **value, size_t *value_len) {
    const char *eq = memchr(line, '=', len);
    if (!eq) return 0;
    size_t ks = 0, ke = (size_t)(eq - line);
    while (ks < ke && blank(line[ks])) ++ks;
    while (ke > ks && blank(line[ke - 1])) --ke;
    size_t vs = (size_t)(eq - line) + 1, ve = len;
    while (vs < ve && blank(line[vs])) ++vs;
    while (ve > vs && blank(line[ve - 1])) --ve;
    *key = line + ks;
    *key_len = ke - ks;
    *value = line + vs;
    *value_len = ve - vs;
    return *key_len > 0;
}

static void put(char *out, size_t cap, const char *text, size_t len) {
    if (!out || !cap) return;
    if (len >= cap) len = cap - 1;
    memcpy(out, text, len);
    out[len] = '\0';
}

int bye_reply_next(const bye_reply_t *reply, size_t *cursor, char *key, size_t key_cap,
                   char *value, size_t value_cap) {
    if (!reply || !cursor) return 0;
    while (*cursor < reply->body_len) {
        const char *line = reply->body + *cursor;
        size_t room = reply->body_len - *cursor;
        const char *nl = memchr(line, '\n', room);
        size_t len = nl ? (size_t)(nl - line) : room;
        *cursor += nl ? len + 1 : len;
        const char *k, *v;
        size_t kl, vl;
        if (!split(line, len, &k, &kl, &v, &vl)) continue;
        put(key, key_cap, k, kl);
        put(value, value_cap, v, vl);
        return 1;
    }
    return 0;
}

int bye_reply_value(const bye_reply_t *reply, const char *key, char *out, size_t cap) {
    if (out && cap) out[0] = '\0';
    if (!reply || !key) return 0;
    size_t cursor = 0;
    char k[96], v[BYE_CONFIG_SPEC_MAX + 16];
    while (bye_reply_next(reply, &cursor, k, sizeof k, v, sizeof v)) {
        if (strcmp(k, key) != 0) continue;
        put(out, cap, v, strlen(v));
        return 1;
    }
    return 0;
}

static int number(const char **p, unsigned *out) {
    const char *s = *p;
    uint32_t value = 0;
    if (*s < '0' || *s > '9') return 0;
    while (*s >= '0' && *s <= '9') {
        if (value > (UINT32_MAX - 9) / 10) return 0;
        value = value * 10 + (unsigned)(*s - '0');
        ++s;
    }
    *out = value;
    *p = s;
    return 1;
}

int bye_reply_candidate(const char *value, bye_reply_candidate_t *out) {
    if (out) memset(out, 0, sizeof *out);
    if (!value || !out) return 0;
    bye_reply_candidate_t found;
    memset(&found, 0, sizeof found);
    const char *p = value;
    if (!number(&p, &found.ok) || *p++ != '/' || !number(&p, &found.tried)) return 0;
    if (*p++ != ' ' || !number(&p, &found.ms) || p[0] != 'm' || p[1] != 's' || p[2] != ' ') return 0;
    p += 3;
    size_t n = strlen(p);
    if (n == 0 || n >= sizeof found.spec || found.ok > found.tried) return 0;
    memcpy(found.spec, p, n + 1);
    *out = found;
    return 1;
}

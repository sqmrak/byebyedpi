#include "bye_ciadpi.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARGS_MAX 160
#define TEXT_MAX 1024
#define REPEATS_MAX 65535

typedef struct {
    const char *name;
    char        key;
    int         has_arg;
} long_option_t;

static const long_option_t LONG_OPTIONS[] = {
    { "daemon", 'D', 0 }, { "pidfile", 'w', 1 }, { "no-domain", 'N', 0 }, { "no-ipv6", 'X', 0 },
    { "no-udp", 'U', 0 }, { "help", 'h', 0 }, { "version", 'v', 0 }, { "ip", 'i', 1 },
    { "port", 'p', 1 }, { "transparent", 'E', 0 }, { "conn-ip", 'I', 1 }, { "buf-size", 'b', 1 },
    { "max-conn", 'c', 1 }, { "debug", 'x', 1 }, { "tfo", 'F', 0 }, { "auto", 'A', 1 },
    { "auto-mode", 'L', 1 }, { "cache-ttl", 'u', 1 }, { "timeout", 'T', 1 }, { "copy", 'B', 1 },
    { "cache-file", 'y', 1 }, { "proto", 'K', 1 }, { "hosts", 'H', 1 }, { "pf", 'V', 1 },
    { "round", 'R', 1 }, { "split", 's', 1 }, { "disorder", 'd', 1 }, { "oob", 'o', 1 },
    { "disoob", 'q', 1 }, { "fake", 'f', 1 }, { "md5sig", 'S', 0 }, { "fake-sni", 'n', 1 },
    { "ttl", 't', 1 }, { "fake-data", 'l', 1 }, { "fake-offset", 'O', 1 },
    { "fake-tls-mod", 'Q', 1 }, { "oob-data", 'e', 1 }, { "mod-http", 'M', 1 },
    { "tlsrec", 'r', 1 }, { "tlsminor", 'm', 1 }, { "udp-fake", 'a', 1 }, { "def-ttl", 'g', 1 },
    { "wait-send", 'Z', 0 }, { "await-int", 'W', 1 }, { "drop-sack", 'Y', 0 },
    { "protect-path", 'P', 1 }, { "ipset", 'j', 1 }, { "connect-to", 'C', 1 },
    { "comment", '#', 1 }, { "cache-merge", '/', 1 }
};

static int short_has_arg(char key, int *known) {
    static const char WITH_ARG[] = "wpiIbcxAL" "uTByKHVRsdoqfntlOQeMrmagWPjC#/";
    static const char NO_ARG[] = "DNXUhvEFSZY";
    *known = 1;
    if (strchr(WITH_ARG, key)) return 1;
    if (strchr(NO_ARG, key)) return 0;
    *known = 0;
    return 0;
}

typedef struct {
    bye_strategies_t *out;
    char             *error;
    size_t            error_cap;
    size_t            notes_len;
    uint32_t          notes_seen; /* one line per reason */
} state_t;

static bye_desync_status_t fail(state_t *st, const char *fmt, const char *a, const char *b) {
    if (st->error && st->error_cap) snprintf(st->error, st->error_cap, fmt, a, b);
    return BYE_DESYNC_ERR_SPEC;
}

/* adds a line to the notes once, so a repeated option does not fill them */
static void note(state_t *st, uint32_t reason, const char *text) {
    if (st->notes_seen & (1u << reason)) return;
    st->notes_seen |= 1u << reason;
    size_t len = strlen(text);
    if (st->notes_len + len + 2 > BYE_NOTES_MAX) return;
    memcpy(st->out->notes + st->notes_len, text, len);
    st->notes_len += len;
    st->out->notes[st->notes_len++] = '\n';
    st->out->notes[st->notes_len] = '\0';
}

enum {
    NOTE_PROXY, NOTE_FAKE, NOTE_UDP, NOTE_LINUX, NOTE_FILTER, NOTE_ROUND, NOTE_TIMEOUT,
    NOTE_CONNECT, NOTE_CACHE, NOTE_FAKE_CUT
};

static int parse_long(const char *text, long *value, const char **end) {
    char *stop = NULL;
    errno = 0;
    long v = strtol(text, &stop, 0);
    if (stop == text || errno == ERANGE) return -1;
    *value = v;
    *end = stop;
    return 0;
}

/* offset[:repeats[:skip]][+flags], parse_offset of ciadpi */
static int parse_offset(const char *text, bye_offset_t *out) {
    memset(out, 0, sizeof *out);
    long value;
    const char *end;
    if (parse_long(text, &value, &end) != 0 || value > INT32_MAX || value < INT32_MIN) return -1;
    int seen_repeats = 0;
    while (*end == ':') {
        long item;
        if (parse_long(end + 1, &item, &end) != 0 || item < 0 || item > INT32_MAX) return -1;
        if (!seen_repeats) {
            if (item == 0 || item > REPEATS_MAX) return -1;
            out->repeats = (uint32_t)item;
            seen_repeats = 1;
        } else {
            out->skip = (int32_t)item;
            break;
        }
    }
    if (*end == '+') {
        switch (end[1]) {
        case 's': out->flags = BYE_OFFSET_SNI; break;
        case 'h': out->flags = BYE_OFFSET_HOST; break;
        case 'n': break;
        default: return -1;
        }
        switch (end[2]) {
        case 'e': out->flags |= BYE_OFFSET_END; end += 3; break;
        case 'm': out->flags |= BYE_OFFSET_MID; end += 3; break;
        case 'r': out->flags |= BYE_OFFSET_RAND; end += 3; break;
        case 's': out->flags |= BYE_OFFSET_START; end += 3; break;
        default: end += 2; break;
        }
    }
    if (*end) return -1;
    out->offset = (int32_t)value;
    return 0;
}

/* a list of letters split by commas, each one of `allowed`, as the -K -M -A values are */
static int each_letter(const char *text, const char *allowed, int (*take)(void *, char),
                       void *ctx) {
    for (const char *p = text;;) {
        if (!*p || !strchr(allowed, *p)) return -1;
        if (take(ctx, *p) != 0) return -1;
        ++p;
        if (*p == '\0') return 0;
        if (*p != ',') return -1;
        ++p;
    }
}

static int take_proto(void *ctx, char c) {
    uint32_t *proto = ctx;
    if (c == 't') *proto |= BYE_PROTO_TLS;
    else if (c == 'h') *proto |= BYE_PROTO_HTTP;
    return 0;
}

static int take_http(void *ctx, char c) {
    uint32_t *mods = ctx;
    *mods |= c == 'r' ? BYE_HTTP_SPACE : c == 'h' ? BYE_HTTP_HMIX : BYE_HTTP_DMIX;
    return 0;
}

static int take_trigger(void *ctx, char c) {
    uint32_t *trigger = ctx;
    if (c == 't') *trigger |= BYE_TRIGGER_TORST;
    else if (c == 'r') *trigger |= BYE_TRIGGER_REDIRECT;
    else if (c == 's') *trigger |= BYE_TRIGGER_TLSERR;
    return 0;
}

/* -A takes t r s c n and p=N (a priority) in one list */
static int parse_trigger(const char *text, uint32_t *trigger, int *connect_only) {
    *trigger = 0;
    *connect_only = 0;
    for (const char *p = text;;) {
        if (*p == 'p') {
            if (p[1] != '=') return -1;
            char *stop;
            (void)strtod(p + 2, &stop);
            if (stop == p + 2) return -1;
            p = stop;
        } else {
            if (!*p || !strchr("trscn", *p)) return -1;
            if (*p == 'c') *connect_only = 1;
            (void)take_trigger(trigger, *p);
            ++p;
        }
        if (*p == '\0') return 0;
        if (*p != ',') return -1;
        ++p;
    }
}

static int parse_char(const char *text, uint8_t *out) {
    size_t len = strlen(text);
    if (len == 1) {
        *out = (uint8_t)text[0];
        return 0;
    }
    if (len == 2 && text[0] == '\\') {
        switch (text[1]) {
        case 'n': *out = '\n'; return 0;
        case 'r': *out = '\r'; return 0;
        case 't': *out = '\t'; return 0;
        case '0': *out = 0; return 0;
        case '\\': *out = '\\'; return 0;
        default: return -1;
        }
    }
    if (len == 4 && text[0] == '\\' && text[1] == 'x') {
        char *stop;
        long v = strtol(text + 2, &stop, 16);
        if (*stop || v < 0 || v > 255) return -1;
        *out = (uint8_t)v;
        return 0;
    }
    return -1;
}

static int parse_number(const char *text, long min, long max, long *out) {
    const char *end;
    long v;
    if (parse_long(text, &v, &end) != 0 || *end || v < min || v > max) return -1;
    *out = v;
    return 0;
}

static bye_desync_status_t apply(state_t *st, bye_desync_t *group, char key, const char *arg,
                                 const char *shown) {
    char flag[3] = { '-', key, '\0' };
    long v;
    switch (key) {
    case 's': case 'd': case 'o': case 'q': case 'f': {
        if (group->part_count == BYE_PARTS_MAX)
            return fail(st, "too many split options in one group, at most %s", "32", NULL);
        bye_part_t *part = &group->parts[group->part_count];
        memset(part, 0, sizeof *part);
        if (parse_offset(arg, &part->pos)) break;
        part->mode = key == 'd' ? BYE_PART_DISORDER : key == 'o' ? BYE_PART_OOB
                   : key == 'q' ? BYE_PART_DISOOB : BYE_PART_SPLIT;
        if (key == 'f')
            note(st, NOTE_FAKE_CUT, "-f: the fake packet is not sent, the cut is made without it");
        ++group->part_count;
        return BYE_DESYNC_OK;
    }
    case 'r': {
        if (group->tlsrec_count == BYE_TLSREC_MAX)
            return fail(st, "too many -r options in one group, at most %s", "8", NULL);
        bye_offset_t *o = &group->tlsrec_parts[group->tlsrec_count];
        if (parse_offset(arg, o) || o->offset > 0xffff) break;
        ++group->tlsrec_count;
        return BYE_DESYNC_OK;
    }
    case 'e':
        if (parse_char(arg, &group->oob_char)) break;
        group->oob_char_set = 1;
        return BYE_DESYNC_OK;
    case 'M':
        if (each_letter(arg, "rhd", take_http, &group->mod_http)) break;
        return BYE_DESYNC_OK;
    case 'm':
        if (parse_number(arg, 1, 255, &v)) break;
        group->tlsminor = (uint8_t)v;
        return BYE_DESYNC_OK;
    case 'K': {
        uint32_t proto = 0;
        if (each_letter(arg, "thui", take_proto, &proto)) break;
        if (strpbrk(arg, "ui")) note(st, NOTE_FILTER, "-K u and i: udp and ipv4 filters are not used");
        group->proto |= proto;
        return BYE_DESYNC_OK;
    }
    case 'g':
        if (parse_number(arg, 1, 255, &v)) break;
        st->out->def_ttl = (uint8_t)v;
        return BYE_DESYNC_OK;
    case 'T': {
        char *stop;
        double seconds = strtod(arg, &stop);
        if (stop == arg || seconds < 0 || seconds > 3600) break;
        st->out->timeout_ms = (uint32_t)(seconds * 1000);
        if (*stop == ':') {
            note(st, NOTE_TIMEOUT, "-T: only the first number is used, the other three are for proxy mode");
            for (const char *p = stop; *p; ++p)
                if (*p != ':' && *p != '.' && (*p < '0' || *p > '9')) return fail(st, "option %s: bad value \"%s\"", flag, shown);
            return BYE_DESYNC_OK;
        }
        if (*stop) break;
        return BYE_DESYNC_OK;
    }
    case 'a':
        if (parse_number(arg, 0, INT_MAX, &v)) break;
        note(st, NOTE_UDP, "-a: fake udp packets are not sent, quic is refused instead");
        return BYE_DESYNC_OK;
    case 't':
        if (parse_number(arg, 1, 255, &v)) break;
        note(st, NOTE_FAKE, "-t -n -l -O -Q: they set fake packets, which are not sent");
        return BYE_DESYNC_OK;
    case 'n': case 'l': case 'O': case 'Q':
        note(st, NOTE_FAKE, "-t -n -l -O -Q: they set fake packets, which are not sent");
        return BYE_DESYNC_OK;
    case 'R':
        note(st, NOTE_ROUND, "-R: only the first send of a connection is cut");
        return BYE_DESYNC_OK;
    case 'H': case 'j': case 'V':
        note(st, NOTE_FILTER, "-H -j -V: lists of hosts, addresses and ports are set in the app");
        return BYE_DESYNC_OK;
    case 'L': case 'u': case 'B': case 'y': case '/':
        note(st, NOTE_CACHE, "-L -u -B -y: the cache is kept by the daemon, one hour per address");
        return BYE_DESYNC_OK;
    case '#':
        return BYE_DESYNC_OK;
    default:
        break;
    }
    return fail(st, "option %s: bad value \"%s\"", flag, shown);
}

static bye_desync_status_t apply_flag(state_t *st, char key) {
    switch (key) {
    case 'S': case 'Y':
        note(st, NOTE_LINUX, "-S -Y: they need linux sockets, which this system has not");
        return BYE_DESYNC_OK;
    case 'Z':
        return BYE_DESYNC_OK;
    case 'D': case 'N': case 'X': case 'U': case 'E': case 'F':
        note(st, NOTE_PROXY, "-D -N -X -U -E -F and the proxy address options are not used");
        return BYE_DESYNC_OK;
    case 'h': case 'v': {
        char flag[3] = { '-', key, '\0' };
        return fail(st, "option %s only prints text, remove it%s", flag, "");
    }
    default:
        return BYE_DESYNC_OK;
    }
}

static int is_proxy_option(char key) {
    return strchr("wpiIbcxWPC", key) != NULL;
}

/* splits the text into words, with '..' and ".." quoting and a backslash in the
   double quotes. the words live in buf */
static int split_words(const char *text, char *buf, size_t cap, char **words, size_t *count) {
    size_t used = 0;
    *count = 0;
    const char *p = text;
    for (;;) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') ++p;
        if (!*p) return 0;
        if (*count == ARGS_MAX) return -1;
        words[(*count)++] = buf + used;
        char quote = 0;
        while (*p && (quote || !(*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))) {
            if (quote) {
                if (*p == quote) { quote = 0; ++p; continue; }
                if (quote == '"' && *p == '\\' && p[1]) ++p;
            } else if (*p == '\'' || *p == '"') {
                quote = *p++;
                continue;
            }
            if (used + 1 >= cap) return -1;
            buf[used++] = *p++;
        }
        if (quote) return -2;
        if (used + 1 >= cap) return -1;
        buf[used++] = '\0';
    }
}

bye_desync_status_t bye_ciadpi_parse(const char *text, bye_strategies_t *out, char *error,
                                     size_t error_cap) {
    if (error && error_cap) error[0] = '\0';
    if (!text || !out) return BYE_DESYNC_ERR_ARG;
    memset(out, 0, sizeof *out);
    state_t st = { out, error, error_cap, 0, 0 };

    if (strlen(text) >= TEXT_MAX) return fail(&st, "the options are too long, at most %s bytes", "1023", NULL);
    char buf[TEXT_MAX + ARGS_MAX];
    char *words[ARGS_MAX];
    size_t count;
    int split = split_words(text, buf, sizeof buf, words, &count);
    if (split == -2) return fail(&st, "a quote is not closed%s%s", "", "");
    if (split != 0) return fail(&st, "too many words, at most %s", "160", NULL);

    bye_desync_t *group = &out->item[0];
    out->count = 1;
    group->cli = 1;

    for (size_t i = 0; i < count; ++i) {
        const char *word = words[i];
        char key = 0;
        const char *arg = NULL;
        char shown_key[3] = { '-', 0, 0 };
        if (word[0] != '-' || word[1] == '\0')
            return fail(&st, "unexpected word \"%s\", options start with -%s", word, "");
        int has_arg = 0;
        if (word[1] == '-') {
            const char *name = word + 2;
            const char *eq = strchr(name, '=');
            size_t name_len = eq ? (size_t)(eq - name) : strlen(name);
            const long_option_t *found = NULL;
            for (size_t k = 0; k < sizeof LONG_OPTIONS / sizeof LONG_OPTIONS[0]; ++k)
                if (strlen(LONG_OPTIONS[k].name) == name_len &&
                    strncmp(LONG_OPTIONS[k].name, name, name_len) == 0)
                    found = &LONG_OPTIONS[k];
            if (!found) return fail(&st, "unknown option %s%s", word, "");
            key = found->key;
            has_arg = found->has_arg;
            if (has_arg) {
                if (eq) arg = eq + 1;
                else if (i + 1 < count) arg = words[++i];
                else return fail(&st, "option %s needs a value%s", word, "");
            } else if (eq) {
                return fail(&st, "option %s takes no value%s", word, "");
            }
        } else {
            /* a cluster of short flags ends at the first option with a value */
            const char *c = word + 1;
            for (; *c; ++c) {
                int known;
                int takes = short_has_arg(*c, &known);
                if (!known) {
                    shown_key[1] = *c;
                    return fail(&st, "unknown option %s%s", shown_key, "");
                }
                if (!takes) {
                    bye_desync_status_t flag_status = apply_flag(&st, *c);
                    if (flag_status != BYE_DESYNC_OK) return flag_status;
                    continue;
                }
                key = *c;
                has_arg = 1;
                if (c[1]) arg = c + 1;
                else if (i + 1 < count) arg = words[++i];
                else {
                    shown_key[1] = key;
                    return fail(&st, "option %s needs a value%s", shown_key, "");
                }
                break;
            }
            if (!has_arg) continue;
        }
        if (!has_arg) {
            bye_desync_status_t flag_status = apply_flag(&st, key);
            if (flag_status != BYE_DESYNC_OK) return flag_status;
            continue;
        }

        if (key == 'A') {
            uint32_t trigger;
            int connect_only;
            if (parse_trigger(arg, &trigger, &connect_only))
                return fail(&st, "option -A: bad value \"%s\"%s", arg, "");
            if (connect_only)
                note(&st, NOTE_CONNECT, "-A c: a connection that cannot be made is not retried");
            if (out->count == BYE_STRATEGIES_MAX)
                return fail(&st, "too many groups (-A), at most %s", "8", NULL);
            group = &out->item[out->count++];
            memset(group, 0, sizeof *group);
            group->cli = 1;
            group->trigger = trigger;
            continue;
        }
        if (is_proxy_option(key)) {
            note(&st, NOTE_PROXY, "-D -N -X -U -E -F and the proxy address options are not used");
            continue;
        }
        bye_desync_status_t status = apply(&st, group, key, arg, arg);
        if (status != BYE_DESYNC_OK) return status;
    }
    return BYE_DESYNC_OK;
}

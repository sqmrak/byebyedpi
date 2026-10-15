#include "bye_desync.h"

#include "bye_ciadpi.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char BYE_DESYNC_DEFAULT_SPEC[] = "tlsrec=name+1;split=1,name+1";
const char BYE_STRATEGIES_DEFAULT[] = "auto";
/* the fake entry is for filters that drop a hello to some youtube addresses whatever the
   cut: ios 6.1.3 on a real network passed them only with a low ttl fake before a split */
const char BYE_STRATEGIES_AUTO_LIST[] =
    "tlsrec=mid;split=1,mid|tlsrec=name+1;split=1,name+1|-f-1 -t 8 -d1|split=1,name+1;oob=1|none";

static void set_error(char *error, size_t cap, const char *text) {
    if (error && cap) snprintf(error, cap, "%s", text);
}

static int parse_pos(const char *text, size_t len, bye_pos_t *out) {
    char buf[24];
    if (len == 0 || len >= sizeof buf) return -1;
    memcpy(buf, text, len);
    buf[len] = '\0';

    const char *rest = buf;
    out->delta = 0;
    if (strncmp(buf, "name", 4) == 0) {
        out->kind = BYE_POS_NAME;
        rest = buf + 4;
    } else if (strncmp(buf, "mid", 3) == 0) {
        out->kind = BYE_POS_MID;
        rest = buf + 3;
    } else if (strncmp(buf, "end", 3) == 0) {
        out->kind = BYE_POS_END;
        rest = buf + 3;
    } else {
        out->kind = BYE_POS_ABS;
    }
    if (*rest == '\0') return out->kind == BYE_POS_ABS ? -1 : 0;
    if (out->kind != BYE_POS_ABS && *rest != '+' && *rest != '-') return -1;
    const char *digits = (*rest == '+' || *rest == '-') ? rest + 1 : rest;
    if (*digits == '\0') return -1;
    for (const char *p = digits; *p; ++p)
        if (!isdigit((unsigned char)*p)) return -1;
    if (strlen(digits) > 5) return -1;
    long value = strtol(rest, NULL, 10);
    if (out->kind == BYE_POS_ABS && value < 1) return -1;
    out->delta = (int32_t)value;
    return 0;
}

static const char *skip_blank(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t')) ++p;
    return p;
}

static const char *trim_blank(const char *start, const char *end) {
    while (end > start && (end[-1] == ' ' || end[-1] == '\t')) --end;
    return end;
}

static bye_desync_status_t parse_split(const char *value, const char *stop,
                                       bye_desync_t *out, char *error, size_t error_cap) {
    if (out->split_count) {
        set_error(error, error_cap, "split is given twice");
        return BYE_DESYNC_ERR_SPEC;
    }
    while (value <= stop) {
        const char *comma = memchr(value, ',', (size_t)(stop - value));
        const char *item_end = comma ? comma : stop;
        const char *item = skip_blank(value, item_end);
        const char *item_stop = trim_blank(item, item_end);
        if (out->split_count == BYE_DESYNC_SPLIT_MAX ||
            parse_pos(item, (size_t)(item_stop - item), &out->split[out->split_count]) != 0) {
            set_error(error, error_cap, "bad split position");
            return BYE_DESYNC_ERR_SPEC;
        }
        ++out->split_count;
        if (!comma) break;
        value = comma + 1;
    }
    return BYE_DESYNC_OK;
}

bye_desync_status_t bye_desync_parse(const char *spec, bye_desync_t *out,
                                     char *error, size_t error_cap) {
    set_error(error, error_cap, "");
    if (!spec || !out) return BYE_DESYNC_ERR_ARG;
    memset(out, 0, sizeof *out);

    const char *p = spec;
    while (*p) {
        const char *clause_end = strchr(p, ';');
        if (!clause_end) clause_end = p + strlen(p);
        const char *start = skip_blank(p, clause_end);
        const char *stop = trim_blank(start, clause_end);
        p = *clause_end ? clause_end + 1 : clause_end;
        if (start == stop) continue;

        const char *eq = memchr(start, '=', (size_t)(stop - start));
        if (!eq) {
            set_error(error, error_cap, "a clause needs name=value");
            return BYE_DESYNC_ERR_SPEC;
        }
        size_t key_len = (size_t)(trim_blank(start, eq) - start);
        const char *value = skip_blank(eq + 1, stop);

        if (key_len == 5 && strncmp(start, "split", 5) == 0) {
            bye_desync_status_t status = parse_split(value, stop, out, error, error_cap);
            if (status != BYE_DESYNC_OK) return status;
        } else if (key_len == 6 && strncmp(start, "tlsrec", 6) == 0) {
            if (out->has_tlsrec || parse_pos(value, (size_t)(stop - value), &out->tlsrec) != 0) {
                set_error(error, error_cap, "bad tlsrec position");
                return BYE_DESYNC_ERR_SPEC;
            }
            out->has_tlsrec = 1;
        } else if (key_len == 3 && strncmp(start, "oob", 3) == 0) {
            if (out->has_oob || parse_pos(value, (size_t)(stop - value), &out->oob) != 0) {
                set_error(error, error_cap, "bad oob position");
                return BYE_DESYNC_ERR_SPEC;
            }
            out->has_oob = 1;
        } else {
            set_error(error, error_cap, "unknown clause");
            return BYE_DESYNC_ERR_SPEC;
        }
    }
    return BYE_DESYNC_OK;
}

bye_desync_status_t bye_strategies_parse(const char *list, bye_strategies_t *out,
                                         char *error, size_t error_cap) {
    set_error(error, error_cap, "");
    if (!list || !out) return BYE_DESYNC_ERR_ARG;
    memset(out, 0, sizeof *out);
    const char *p = list;
    const char *word = skip_blank(list, list + strlen(list));
    if (strncmp(word, "auto", 4) == 0 &&
        trim_blank(word, word + strlen(word)) == word + 4)
        p = BYE_STRATEGIES_AUTO_LIST;
    for (;;) {
        const char *end = strchr(p, '|');
        if (!end) end = p + strlen(p);
        const char *start = skip_blank(p, end);
        const char *stop = trim_blank(start, end);
        if (start == stop) {
            set_error(error, error_cap, "a strategy is empty");
            return BYE_DESYNC_ERR_SPEC;
        }
        size_t n = (size_t)(stop - start);
        if (*start == '-') {
            /* the command line of the original ByeDPI, which has no "|" of its own, so it can sit
               among native strategies and brings its own groups and options */
            char line[BYE_STRATEGY_LINE_MAX];
            bye_strategies_t part;
            if ((size_t)(end - p) >= sizeof line) {
                set_error(error, error_cap, "a strategy is too long");
                return BYE_DESYNC_ERR_SPEC;
            }
            memcpy(line, start, n);
            line[n] = '\0';
            bye_desync_status_t status = bye_ciadpi_parse(line, &part, error, error_cap);
            if (status != BYE_DESYNC_OK) return status;
            if (part.count > BYE_STRATEGIES_MAX - out->count) {
                set_error(error, error_cap, "too many strategies");
                return BYE_DESYNC_ERR_SPEC;
            }
            /* a line after another item is a step of the list: without a trigger of its own its
               first group could only be reached as the first one, and a failure would skip it */
            if (out->count > 0 && part.item[0].trigger == 0)
                part.item[0].trigger = BYE_TRIGGER_TORST | BYE_TRIGGER_TLSERR;
            memcpy(&out->item[out->count], part.item, part.count * sizeof part.item[0]);
            out->count += part.count;
            if (part.timeout_ms) out->timeout_ms = part.timeout_ms;
            if (part.def_ttl) out->def_ttl = part.def_ttl;
            size_t used = strlen(out->notes);
            if (part.notes[0] && used + strlen(part.notes) + 1 < sizeof out->notes)
                memcpy(out->notes + used, part.notes, strlen(part.notes) + 1);
            if (!*end) break;
            p = end + 1;
            continue;
        }
        if (out->count == BYE_STRATEGIES_MAX) {
            set_error(error, error_cap, "too many strategies");
            return BYE_DESYNC_ERR_SPEC;
        }
        char spec[BYE_STRATEGY_SPEC_MAX];
        if (n >= sizeof spec) {
            set_error(error, error_cap, "a strategy is too long");
            return BYE_DESYNC_ERR_SPEC;
        }
        memcpy(spec, start, n);
        spec[n] = '\0';
        if (strcmp(spec, "none") == 0) spec[0] = '\0';
        bye_desync_status_t status = bye_desync_parse(spec, &out->item[out->count], error, error_cap);
        if (status != BYE_DESYNC_OK) return status;
        ++out->count;
        if (!*end) break;
        p = end + 1;
    }
    return BYE_DESYNC_OK;
}

size_t bye_strategies_after(const bye_strategies_t *list, size_t start, size_t attempt,
                            uint32_t kind) {
    if (!list || list->count == 0) return 0;
    for (size_t step = attempt + 1; step < list->count; ++step) {
        const bye_desync_t *item = &list->item[(start + step) % list->count];
        if (!item->cli || (item->trigger & kind)) return step;
    }
    return 0;
}

static int64_t resolve(const bye_pos_t *pos, const bye_sniff_t *name) {
    switch (pos->kind) {
    case BYE_POS_ABS:
        return pos->delta;
    case BYE_POS_NAME:
        return (int64_t)name->name_off + pos->delta;
    case BYE_POS_MID:
        return (int64_t)name->name_off + (int64_t)(name->name_len / 2) + pos->delta;
    case BYE_POS_END:
        return (int64_t)name->name_off + (int64_t)name->name_len + pos->delta;
    }
    return -1;
}

static void single_segment(const uint8_t *in, size_t in_len, uint8_t *out, bye_plan_t *plan) {
    memcpy(out, in, in_len);
    plan->ops[0].off = 0;
    plan->ops[0].len = in_len;
    plan->ops[0].oob_after = 0;
    plan->count = 1;
    plan->total = in_len;
}

typedef struct {
    size_t at;  /* a cut before this offset of the app's bytes */
    int    oob; /* an urgent byte follows the bytes before it */
} cut_t;

#define CUTS_MAX (BYE_DESYNC_SPLIT_MAX + 1)

/* keeps the cuts sorted; two cuts at one offset become one */
static void add_cut(cut_t *cuts, size_t *count, size_t at, int oob) {
    for (size_t i = 0; i < *count; ++i) {
        if (cuts[i].at == at) {
            cuts[i].oob |= oob;
            return;
        }
    }
    size_t i = *count;
    while (i > 0 && cuts[i - 1].at > at) {
        cuts[i] = cuts[i - 1];
        --i;
    }
    cuts[i].at = at;
    cuts[i].oob = oob;
    ++*count;
}


typedef struct {
    int    found; /* the app's bytes hold a name */
    int    tls;
    size_t off;
    size_t len;
} name_t;

static uint32_t seed_from(const uint8_t *in, size_t in_len) {
    /* a hello carries 32 random bytes from offset 11, so every flow draws its own cuts */
    uint32_t h = 2166136261u;
    size_t from = in_len > 11 ? 11 : 0;
    size_t to = from + 64 < in_len ? from + 64 : in_len;
    for (size_t i = from; i < to; ++i) h = (h ^ in[i]) * 16777619u;
    return h ? h : 1u;
}

static uint32_t draw(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

/* the offset the way ciadpi resolves it, gen_offset in desync.c. n is the length
   the offset counts from, lp the end of the last part. -1 when a name was asked
   for and there is none */
static int64_t gen_offset(const bye_offset_t *o, const name_t *name, size_t n, int64_t lp,
                          uint32_t *rng) {
    int64_t pos = o->offset;
    if (o->flags & (BYE_OFFSET_SNI | BYE_OFFSET_HOST)) {
        if (!name->found || name->off == 0) return -1;
        if ((o->flags & BYE_OFFSET_SNI) && !name->tls) return -1;
        pos += (int64_t)name->off;
        if (o->flags & BYE_OFFSET_END) pos += (int64_t)name->len;
        else if (o->flags & BYE_OFFSET_MID) pos += (int64_t)(name->len / 2);
        else if ((o->flags & BYE_OFFSET_RAND) && name->len) pos += (int64_t)(draw(rng) % name->len);
    } else if (o->flags & BYE_OFFSET_RAND) {
        pos += lp;
        if ((int64_t)n > lp) pos += (int64_t)(draw(rng) % (uint32_t)((int64_t)n - lp));
    } else if (o->flags & BYE_OFFSET_MID) {
        pos += (int64_t)(n / 2);
    } else if (pos < 0 || (o->flags & BYE_OFFSET_END)) {
        pos += (int64_t)n;
    }
    return pos;
}

static int is_chello(const uint8_t *in, size_t len) {
    return len > 5 && in[0] == 0x16 && in[1] == 3 && in[5] == 1;
}

/* mod_http of ciadpi: the host is at `host` and ends before host + host_len */
static void mod_http(uint8_t *buf, size_t len, size_t host, size_t host_len, uint32_t mods) {
    size_t colon = host;
    while (colon > 0 && buf[colon - 1] != ':') --colon;
    if (colon < 5 || colon > host) return;
    uint8_t *par = buf + colon - 5; /* the 'H' of "Host:" */
    if (mods & BYE_HTTP_HMIX) {
        par[0] = (uint8_t)tolower(par[0]);
        par[1] = (uint8_t)toupper(par[1]);
        par[3] = (uint8_t)toupper(par[3]);
    }
    if (mods & BYE_HTTP_DMIX) {
        for (size_t i = 0; i < host_len; i += 2) buf[host + i] = (uint8_t)toupper(buf[host + i]);
    }
    if (mods & BYE_HTTP_SPACE) {
        size_t value_len = host_len;
        while (host + value_len < len && !isspace(buf[host + value_len])) ++value_len;
        size_t spaces = host - colon;
        memmove(buf + colon, buf + host, value_len);
        memset(buf + colon + value_len, '\t', spaces);
    }
}

/* tlsrec of ciadpi: cuts the record in the out buffer at body offset `at` of the
   record that starts at `rec`. returns the growth, 0 when it cannot be cut */
static int cut_record(uint8_t *buf, size_t cap, size_t len, size_t rec, size_t at) {
    if (len - rec < 3 || cap - len < BYE_DESYNC_TLSREC_GROWTH || at + 5 > len - rec) return 0;
    size_t body = ((size_t)buf[rec + 3] << 8) | buf[rec + 4];
    if (body < at) return 0;
    memmove(buf + rec + 5 + at + 5, buf + rec + 5 + at, len - (rec + 5 + at));
    memcpy(buf + rec + 5 + at, buf + rec, 3);
    buf[rec + 3] = (uint8_t)(at >> 8);
    buf[rec + 4] = (uint8_t)at;
    buf[rec + 5 + at + 3] = (uint8_t)((body - at) >> 8);
    buf[rec + 5 + at + 4] = (uint8_t)(body - at);
    return BYE_DESYNC_TLSREC_GROWTH;
}

static bye_desync_status_t build_cli(const bye_desync_t *desync, const uint8_t *in,
                                     size_t in_len, uint8_t *out, size_t out_cap,
                                     bye_plan_t *plan) {
    bye_sniff_t sniff = { 0, 0, 0 };
    int is_tls = 1;
    bye_sniff_status_t sniffed = bye_sniff_tls(in, in_len, &sniff);
    if (sniffed == BYE_SNIFF_NO_MATCH) {
        is_tls = 0;
        sniffed = bye_sniff_http(in, in_len, &sniff);
    }
    if (sniffed == BYE_SNIFF_NEED_MORE) return BYE_DESYNC_NEED_MORE;
    uint32_t proto = sniffed == BYE_SNIFF_NO_MATCH ? 0u : is_tls ? BYE_PROTO_TLS : BYE_PROTO_HTTP;

    name_t name = { 0, is_tls, 0, 0 };
    if (sniffed == BYE_SNIFF_OK) {
        name.found = 1;
        name.off = sniff.name_off;
        name.len = sniff.name_len;
        plan->has_name = 1;
        plan->tls = is_tls;
        plan->name_off = sniff.name_off;
        plan->name_len = sniff.name_len;
    }

    memcpy(out, in, in_len);
    size_t n = in_len;
    /* a group for another protocol leaves the bytes alone */
    if (desync->proto && !(desync->proto & proto)) {
        plan->ops[0].off = 0;
        plan->ops[0].len = n;
        plan->count = 1;
        plan->total = n;
        return BYE_DESYNC_OK;
    }

    uint32_t rng = seed_from(in, in_len);
    int changed = 0;

    if (desync->mod_http && proto == BYE_PROTO_HTTP && name.found) {
        mod_http(out, n, name.off, name.len, desync->mod_http);
        changed = 1;
        /* the name moved with the spaces, and the offsets count from where it is now */
        bye_sniff_t again;
        if (bye_sniff_http(out, n, &again) == BYE_SNIFF_OK) {
            name.off = again.name_off;
            name.len = again.name_len;
        } else {
            name.found = 0;
        }
    }
    if (desync->tlsminor && is_chello(out, n)) {
        out[2] = desync->tlsminor;
        changed = 1;
    }
    if (desync->tlsrec_count && is_chello(out, n)) {
        /* the offsets count from the app's bytes, as in ciadpi: a part adds the
           headers of the cuts before it */
        int64_t lp = 0;
        size_t cuts = 0;
        for (size_t i = 0; i < desync->tlsrec_count && cuts < BYE_TLSREC_MAX; ++i) {
            const bye_offset_t *o = &desync->tlsrec_parts[i];
            uint32_t reps = o->repeats ? o->repeats : 1;
            int stop = 0;
            for (uint32_t k = 0; k < reps && !stop; ++k) {
                int64_t pos = gen_offset(o, &name, in_len, lp, &rng);
                if (pos < 0 && (o->flags & (BYE_OFFSET_SNI | BYE_OFFSET_HOST))) { stop = 1; break; }
                pos += (int64_t)(cuts * BYE_DESYNC_TLSREC_GROWTH);
                if (o->offset < 0 || o->flags) pos -= BYE_DESYNC_TLSREC_GROWTH;
                pos += (int64_t)o->skip * (int64_t)k;
                if (pos < lp || cuts >= BYE_TLSREC_MAX ||
                    !cut_record(out, out_cap, n, (size_t)lp, (size_t)(pos - lp))) {
                    stop = 1;
                    break;
                }
                n += BYE_DESYNC_TLSREC_GROWTH;
                lp = pos + BYE_DESYNC_TLSREC_GROWTH;
                ++cuts;
            }
            if (stop) break;
        }
        if (cuts) changed = 1;
    }

    plan->oob_char = desync->oob_char_set ? desync->oob_char : BYE_DESYNC_OOB_BYTE;
    int64_t lp = 0;
    for (size_t i = 0; i < desync->part_count && plan->count + 1 < BYE_DESYNC_OPS_MAX; ++i) {
        const bye_part_t *part = &desync->parts[i];
        uint32_t reps = part->pos.repeats ? part->pos.repeats : 1;
        int stop = 0;
        for (uint32_t k = 0; k < reps && plan->count + 1 < BYE_DESYNC_OPS_MAX; ++k) {
            int64_t pos = gen_offset(&part->pos, &name, n, lp, &rng);
            if (pos < 0 && (part->pos.flags & (BYE_OFFSET_SNI | BYE_OFFSET_HOST))) { stop = 1; break; }
            pos += (int64_t)part->pos.skip * (int64_t)k;
            if (pos < 0 || pos < lp) { stop = 1; break; }
            if (pos > (int64_t)n) pos = (int64_t)n;
            uint32_t flags = 0;
            if ((part->mode == BYE_PART_DISORDER || part->mode == BYE_PART_DISOOB) && k % 2 == 0)
                flags |= BYE_OP_TTL1;
            if (part->mode == BYE_PART_OOB || part->mode == BYE_PART_DISOOB) flags |= BYE_OP_OOB;
            if (part->mode == BYE_PART_FAKE) flags |= BYE_OP_FAKE;
            /* a cut that is empty sends nothing, except an urgent byte on its own */
            if (pos > lp || (flags & BYE_OP_OOB)) {
                bye_op_t *op = &plan->ops[plan->count++];
                op->off = (size_t)lp;
                op->len = (size_t)(pos - lp);
                op->oob_after = 0;
                op->flags = flags;
            }
            lp = pos;
        }
        if (stop) break;
    }
    if ((size_t)lp < n || plan->count == 0) {
        bye_op_t *op = &plan->ops[plan->count++];
        op->off = (size_t)lp;
        op->len = n - (size_t)lp;
        op->oob_after = 0;
        op->flags = 0;
    }
    plan->total = n;
    plan->applied = plan->count > 1 || changed;
    return BYE_DESYNC_OK;
}

int bye_strategies_use_fake(const bye_strategies_t *list) {
    if (!list) return 0;
    for (size_t i = 0; i < list->count && i < BYE_STRATEGIES_MAX; ++i) {
        const bye_desync_t *group = &list->item[i];
        if (!group->cli) continue;
        for (size_t k = 0; k < group->part_count; ++k)
            if (group->parts[k].mode == BYE_PART_FAKE) return 1;
    }
    return 0;
}

size_t bye_desync_fake(const bye_desync_t *group, int tls, const uint8_t *real, size_t real_len,
                       size_t len, uint8_t *out, size_t out_cap) {
    uint8_t blob[BYE_FAKE_BLOB_MAX];
    size_t blob_len;
    if (!group || !out || len == 0) return 0;
    if (group->fake_data_len) {
        blob_len = group->fake_data_len;
        memcpy(blob, group->fake_data, blob_len);
    } else if (tls) {
        blob_len = bye_fake_tls(blob, sizeof blob, group->fake_sni, group->fake_mods, real,
                                real_len, seed_from(real, real_len));
    } else {
        blob_len = bye_fake_http(blob, sizeof blob, group->fake_sni);
    }
    if (blob_len == 0) return 0;
    int64_t start = group->fake_offset;
    if (start < 0) start += (int64_t)blob_len;
    if (start < 0 || start >= (int64_t)blob_len) return 0;
    size_t n = blob_len - (size_t)start;
    if (n > len) n = len;
    if (n > BYE_FAKE_PAYLOAD_MAX) n = BYE_FAKE_PAYLOAD_MAX;
    if (n > out_cap) return 0;
    memcpy(out, blob + start, n);
    return n;
}

bye_desync_status_t bye_desync_build(const bye_desync_t *desync, const uint8_t *in,
                                     size_t in_len, uint8_t *out, size_t out_cap,
                                     bye_plan_t *plan) {
    if (!desync || !in || !out || !plan || in_len == 0) return BYE_DESYNC_ERR_ARG;
    if (out_cap < in_len + BYE_DESYNC_GROWTH_MAX) return BYE_DESYNC_ERR_SPACE;
    memset(plan, 0, sizeof *plan);
    if (desync->cli) return build_cli(desync, in, in_len, out, out_cap, plan);

    bye_sniff_t name;
    int is_tls = 1;
    bye_sniff_status_t sniffed = bye_sniff_tls(in, in_len, &name);
    if (sniffed == BYE_SNIFF_NO_MATCH) {
        is_tls = 0;
        sniffed = bye_sniff_http(in, in_len, &name);
    }
    if (sniffed == BYE_SNIFF_NEED_MORE) return BYE_DESYNC_NEED_MORE;
    if (sniffed != BYE_SNIFF_OK) {
        single_segment(in, in_len, out, plan);
        return BYE_DESYNC_OK;
    }
    plan->has_name = 1;
    plan->tls = is_tls;
    plan->name_off = name.name_off;
    plan->name_len = name.name_len;

    cut_t cuts[CUTS_MAX];
    size_t cut_count = 0;
    for (size_t i = 0; i < desync->split_count; ++i) {
        int64_t at = resolve(&desync->split[i], &name);
        if (at > 0 && at < (int64_t)in_len) add_cut(cuts, &cut_count, (size_t)at, 0);
    }
    if (desync->has_oob) {
        int64_t at = resolve(&desync->oob, &name);
        if (at > 0 && at < (int64_t)in_len) add_cut(cuts, &cut_count, (size_t)at, 1);
    }

    /* the cut must leave a byte of the hello on both sides of the new header,
       and the bytes in hand must reach past it: the rest of a hello that has
       not all arrived follows the plan as it is */
    size_t tlsrec_at = 0;
    if (is_tls && desync->has_tlsrec) {
        int64_t at = resolve(&desync->tlsrec, &name);
        if (at > 5 && at < (int64_t)name.record_len && at < (int64_t)in_len)
            tlsrec_at = (size_t)at;
    }

    memcpy(out, in, in_len);
    size_t out_len = in_len;
    if (tlsrec_at) {
        size_t first = tlsrec_at - 5;
        size_t second = name.record_len - tlsrec_at;
        memmove(out + tlsrec_at + BYE_DESYNC_TLSREC_GROWTH, in + tlsrec_at, in_len - tlsrec_at);
        out[3] = (uint8_t)(first >> 8);
        out[4] = (uint8_t)first;
        out[tlsrec_at + 0] = in[0];
        out[tlsrec_at + 1] = in[1];
        out[tlsrec_at + 2] = in[2];
        out[tlsrec_at + 3] = (uint8_t)(second >> 8);
        out[tlsrec_at + 4] = (uint8_t)second;
        out_len += BYE_DESYNC_TLSREC_GROWTH;
    }

    /* a cut at the record cut lands before the new header, one past it lands
       after it */
    size_t start = 0;
    for (size_t i = 0; i <= cut_count; ++i) {
        size_t stop = out_len;
        int oob_after = 0;
        if (i < cut_count) {
            stop = cuts[i].at;
            if (tlsrec_at && stop > tlsrec_at) stop += BYE_DESYNC_TLSREC_GROWTH;
            oob_after = cuts[i].oob;
        }
        plan->ops[plan->count].off = start;
        plan->ops[plan->count].len = stop - start;
        plan->ops[plan->count].oob_after = oob_after;
        ++plan->count;
        start = stop;
    }
    plan->total = out_len;
    plan->applied = plan->count > 1 || tlsrec_at != 0;
    return BYE_DESYNC_OK;
}

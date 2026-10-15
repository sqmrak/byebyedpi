#include "bye_fake.h"

#include "bye_sniff.h"

#include <stdio.h>
#include <string.h>

static void put16(uint8_t *p, unsigned v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static unsigned get16(const uint8_t *p) {
    return ((unsigned)p[0] << 8) | p[1];
}

static uint32_t get32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint32_t sum_words(const uint8_t *data, size_t len, uint32_t sum) {
    while (len > 1) {
        sum += get16(data);
        data += 2;
        len -= 2;
    }
    if (len) sum += (uint32_t)data[0] << 8;
    return sum;
}

static uint16_t fold(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

#define MD5_OPT_LEN 20 /* kind 19, length 18, 16 bytes, and two nops to a word boundary */

size_t bye_fake_packet_build(const bye_fake_packet_t *packet, int host_order, uint8_t *out,
                             size_t out_cap) {
    if (!packet || !out || (!packet->payload && packet->len) || packet->len > BYE_FAKE_PAYLOAD_MAX)
        return 0;
    size_t opt = packet->md5sig ? MD5_OPT_LEN : 0;
    size_t tcp_len = 20 + opt + packet->len;
    size_t total = 20 + tcp_len;
    if (out_cap < total) return 0;
    memset(out, 0, 20 + 20 + opt);
    out[0] = 0x45;
    if (host_order) {
        memcpy(out + 2, &(uint16_t){ (uint16_t)total }, 2);
        memcpy(out + 6, &(uint16_t){ 0x4000 }, 2);
    } else {
        put16(out + 2, (unsigned)total);
        put16(out + 6, 0x4000);
    }
    put16(out + 4, packet->id);
    out[8] = packet->ttl;
    out[9] = 6;
    memcpy(out + 12, packet->src, 4);
    memcpy(out + 16, packet->dst, 4);
    uint8_t *tcp = out + 20;
    put16(tcp, packet->sport);
    put16(tcp + 2, packet->dport);
    put32(tcp + 4, packet->seq);
    put32(tcp + 8, packet->ack);
    tcp[12] = (uint8_t)(((20 + opt) / 4) << 4);
    tcp[13] = 0x18; /* psh, ack */
    put16(tcp + 14, 65535);
    if (opt) {
        tcp[20] = 19;
        tcp[21] = 18;
        /* a signature no key makes; the bytes are not zero so a log reads them as data */
        for (size_t i = 0; i < 16; ++i) tcp[22 + i] = (uint8_t)(0xa5 ^ (packet->seq >> (i % 24)));
        tcp[38] = tcp[39] = 1;
    }
    if (packet->len) memcpy(tcp + 20 + opt, packet->payload, packet->len);

    uint8_t pseudo[12];
    memcpy(pseudo, packet->src, 4);
    memcpy(pseudo + 4, packet->dst, 4);
    pseudo[8] = 0;
    pseudo[9] = 6;
    put16(pseudo + 10, (unsigned)tcp_len);
    uint32_t sum = sum_words(pseudo, sizeof pseudo, 0);
    put16(tcp + 16, fold(sum_words(tcp, tcp_len, sum)));
    put16(out + 10, fold(sum_words(out, 20, 0)));
    return total;
}

int bye_fake_syn_parse(unsigned link, const uint8_t *frame, size_t len, bye_fake_syn_t *out) {
    size_t at;
    if (!frame || !out) return 0;
    if (link == BYE_LINK_ETHERNET) {
        if (len < 14 || get16(frame + 12) != 0x0800) return 0;
        at = 14;
    } else if (link == BYE_LINK_NULL) {
        uint32_t family;
        if (len < 4) return 0;
        /* the family is written in the byte order of the machine that captured it */
        memcpy(&family, frame, 4);
        if (family != 2) return 0;
        at = 4;
    } else if (link == BYE_LINK_RAW) {
        at = 0;
    } else {
        return 0;
    }
    if (len < at + 20 || (frame[at] >> 4) != 4) return 0;
    size_t ihl = (size_t)(frame[at] & 0x0f) * 4;
    if (ihl < 20 || frame[at + 9] != 6 || (get16(frame + at + 6) & 0x1fff) != 0) return 0;
    if (len < at + ihl + 20) return 0;
    const uint8_t *tcp = frame + at + ihl;
    if (!(tcp[13] & 0x02)) return 0;
    memcpy(out->src, frame + at + 12, 4);
    memcpy(out->dst, frame + at + 16, 4);
    out->sport = (uint16_t)get16(tcp);
    out->dport = (uint16_t)get16(tcp + 2);
    out->seq = get32(tcp + 4);
    out->flags = tcp[13];
    return 1;
}

size_t bye_fake_bpf_filter(unsigned link, bye_bpf_insn_t *out, size_t cap) {
    enum { LD_H = 0x28, LD_B = 0x30, LD_W = 0x20, LDX_MSH = 0xb1, LD_XB = 0x50, ALU_AND = 0x54,
           JEQ = 0x15, JSET = 0x45, RET = 0x06 };
    /* a jump marked reject lands on the last instruction, which keeps nothing */
    struct { bye_bpf_insn_t insn; int reject_true, reject_false; } list[BYE_BPF_FILTER_MAX];
    size_t n = 0;
    uint32_t base;
#define STEP(c, t, f, kk, rt, rf) do { \
        if (n == BYE_BPF_FILTER_MAX) return 0; \
        list[n].insn.code = (c); list[n].insn.jt = (t); list[n].insn.jf = (f); list[n].insn.k = (kk); \
        list[n].reject_true = (rt); list[n].reject_false = (rf); ++n; } while (0)
    if (link == BYE_LINK_ETHERNET) {
        STEP(LD_H, 0, 0, 12, 0, 0);
        STEP(JEQ, 0, 0, 0x0800, 0, 1);
        base = 14;
    } else if (link == BYE_LINK_NULL) {
        /* the four bytes are the family in host order, which bpf reads as big endian */
        STEP(LD_W, 0, 0, 0, 0, 0);
        STEP(JEQ, 0, 0, 0x02000000u, 0, 1);
        base = 4;
    } else if (link == BYE_LINK_RAW) {
        STEP(LD_B, 0, 0, 0, 0, 0);
        STEP(ALU_AND, 0, 0, 0xf0, 0, 0);
        STEP(JEQ, 0, 0, 0x40, 0, 1);
        base = 0;
    } else {
        return 0;
    }
    STEP(LD_B, 0, 0, base + 9, 0, 0);
    STEP(JEQ, 0, 0, 6, 0, 1);
    STEP(LD_H, 0, 0, base + 6, 0, 0);
    STEP(JSET, 0, 0, 0x1fff, 1, 0);
    STEP(LDX_MSH, 0, 0, base, 0, 0);
    STEP(LD_XB, 0, 0, base + 13, 0, 0);
    STEP(JSET, 0, 0, 0x02, 0, 1);
    STEP(RET, 0, 0, 128, 0, 0);
    STEP(RET, 0, 0, 0, 0, 0);
#undef STEP
    if (cap < n) return 0;
    for (size_t i = 0; i < n; ++i) {
        if (list[i].reject_true) list[i].insn.jt = (uint8_t)(n - 1 - i - 1);
        if (list[i].reject_false) list[i].insn.jf = (uint8_t)(n - 1 - i - 1);
        out[i] = list[i].insn;
    }
    return n;
}

void bye_fake_track_init(bye_fake_track_t *track) {
    if (track) memset(track, 0, sizeof *track);
}

static int same_peer(const bye_fake_entry_t *e, const uint8_t local[4], uint16_t lport,
                     const uint8_t remote[4], uint16_t rport) {
    return e->used && e->lport == lport && e->rport == rport &&
           memcmp(e->local, local, 4) == 0 && memcmp(e->remote, remote, 4) == 0;
}

void bye_fake_track_note(bye_fake_track_t *track, const bye_fake_syn_t *syn) {
    if (!track || !syn) return;
    if (!(syn->flags & 0x10)) {
        /* a new syn on a known pair is a retransmit or a reused port: the newest wins */
        for (size_t i = 0; i < BYE_FAKE_TRACK_MAX; ++i)
            if (same_peer(&track->entry[i], syn->src, syn->sport, syn->dst, syn->dport))
                track->entry[i].used = 0;
        bye_fake_entry_t *e = &track->entry[track->next];
        track->next = (track->next + 1) % BYE_FAKE_TRACK_MAX;
        memset(e, 0, sizeof *e);
        memcpy(e->local, syn->src, 4);
        memcpy(e->remote, syn->dst, 4);
        e->lport = syn->sport;
        e->rport = syn->dport;
        e->isn = syn->seq;
        e->used = 1;
        return;
    }
    for (size_t i = 0; i < BYE_FAKE_TRACK_MAX; ++i) {
        bye_fake_entry_t *e = &track->entry[i];
        if (same_peer(e, syn->dst, syn->dport, syn->src, syn->sport)) {
            e->sisn = syn->seq;
            e->have_sisn = 1;
        }
    }
}

int bye_fake_track_find(const bye_fake_track_t *track, const uint8_t local[4], uint16_t lport,
                        const uint8_t remote[4], uint16_t rport, uint32_t *isn, uint32_t *sisn) {
    if (!track || !local || !remote) return 0;
    for (size_t i = 0; i < BYE_FAKE_TRACK_MAX; ++i) {
        const bye_fake_entry_t *e = &track->entry[i];
        if (!same_peer(e, local, lport, remote, rport) || !e->have_sisn) continue;
        if (isn) *isn = e->isn;
        if (sisn) *sisn = e->sisn;
        return 1;
    }
    return 0;
}

/* xorshift32, enough for bytes a filter reads and no server ever sees */
static uint32_t next_random(uint32_t *state) {
    uint32_t x = *state ? *state : 0x9e3779b9u;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static void fill_random(uint8_t *out, size_t len, uint32_t *state) {
    for (size_t i = 0; i < len; ++i) out[i] = (uint8_t)(next_random(state) >> 11);
}

#define HELLO_TARGET 517

/* the suites, groups and extensions a recent browser offers */
static const uint8_t SUITES[] = {
    0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
    0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35
};
static const uint8_t EXT_FIXED_BEFORE_SNI[] = { 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00 };
static const uint8_t EXT_AFTER_SNI[] = {
    0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, /* groups */
    0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,                                     /* point formats */
    0x00, 0x23, 0x00, 0x00,                                                 /* session ticket */
    0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1',
    0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05,
    0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01,                         /* signature algorithms */
    0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03,                   /* versions */
    0x00, 0x2d, 0x00, 0x02, 0x01, 0x01                                      /* psk modes */
};

static size_t sni_length(const char *sni) {
    size_t len = sni ? strlen(sni) : 0;
    if (len == 0 || len > BYE_FAKE_SNI_MAX - 1) return 0;
    return len;
}

static size_t tls_template(uint8_t *out, size_t cap, const char *sni, uint32_t mods,
                           const uint8_t *real, size_t real_len, size_t want_total, uint32_t *rng) {
    size_t name = sni_length(sni);
    if (!name) {
        sni = BYE_FAKE_SNI_DEFAULT;
        name = strlen(sni);
    }
    size_t sni_ext = 4 + 2 + 1 + 2 + name;
    size_t key_ext = 4 + 2 + 2 + 2 + 32;
    size_t ext_len = sni_ext + sizeof EXT_FIXED_BEFORE_SNI + sizeof EXT_AFTER_SNI + key_ext;
    size_t body = 2 + 32 + 1 + 32 + 2 + sizeof SUITES + 2 + 2 + ext_len;
    size_t total = 5 + 4 + body;
    size_t pad = want_total > total + 4 ? want_total - total - 4 : 0;
    if (pad) {
        ext_len += 4 + pad;
        body += 4 + pad;
        total += 4 + pad;
    }
    if (cap < total || total > BYE_FAKE_BLOB_MAX) return 0;
    uint8_t *p = out;
    *p++ = 0x16; *p++ = 0x03; *p++ = 0x01;
    put16(p, (unsigned)(total - 5)); p += 2;
    *p++ = 0x01;
    *p++ = 0; put16(p, (unsigned)body); p += 2;
    *p++ = 0x03; *p++ = 0x03;
    uint8_t *random = p;
    /* without -Q r the bytes are the same in every fake, as in ciadpi's built-in one */
    uint32_t fixed = 0x42595445u;
    fill_random(random, 32, (mods & BYE_FAKE_MOD_RAND) ? rng : &fixed);
    p += 32;
    *p++ = 32;
    fill_random(p, 32, (mods & BYE_FAKE_MOD_RAND) ? rng : &fixed);
    /* a session id of 32 bytes in the app's hello, which is what a tls 1.3 client sends */
    if ((mods & BYE_FAKE_MOD_DUPSID) && real && real_len >= 44 + 32 && real[43] == 32)
        memcpy(p, real + 44, 32);
    p += 32;
    put16(p, (unsigned)sizeof SUITES); p += 2;
    memcpy(p, SUITES, sizeof SUITES); p += sizeof SUITES;
    *p++ = 0x01; *p++ = 0x00;
    put16(p, (unsigned)ext_len); p += 2;
    put16(p, 0x0000); p += 2;
    put16(p, (unsigned)(2 + 1 + 2 + name)); p += 2;
    put16(p, (unsigned)(1 + 2 + name)); p += 2;
    *p++ = 0;
    put16(p, (unsigned)name); p += 2;
    memcpy(p, sni, name); p += name;
    memcpy(p, EXT_FIXED_BEFORE_SNI, sizeof EXT_FIXED_BEFORE_SNI); p += sizeof EXT_FIXED_BEFORE_SNI;
    memcpy(p, EXT_AFTER_SNI, sizeof EXT_AFTER_SNI); p += sizeof EXT_AFTER_SNI;
    put16(p, 0x0033); p += 2;
    put16(p, 2 + 2 + 2 + 32); p += 2;
    put16(p, 2 + 2 + 32); p += 2;
    put16(p, 0x001d); p += 2;
    put16(p, 32); p += 2;
    fill_random(p, 32, (mods & BYE_FAKE_MOD_RAND) ? rng : &fixed);
    p += 32;
    if (pad) {
        put16(p, 0x0015); p += 2;
        put16(p, (unsigned)pad); p += 2;
        memset(p, 0, pad);
        p += pad;
    }
    return (size_t)(p - out);
}

/* the app's hello with its server name replaced. every length that covers the
   name moves by the same amount. 0 when the bytes are not a hello this can walk */
static size_t tls_with_name(uint8_t *out, size_t cap, const uint8_t *real, size_t real_len,
                            const char *sni, uint32_t mods, uint32_t *rng) {
    bye_sniff_t found;
    size_t name = sni_length(sni);
    if (!name) {
        sni = BYE_FAKE_SNI_DEFAULT;
        name = strlen(sni);
    }
    if (bye_sniff_tls(real, real_len, &found) != BYE_SNIFF_OK || found.name_off < 9 ||
        found.name_off + found.name_len > real_len || real_len < 44)
        return 0;
    /* the walk to the extension block: version, random, session id, suites, compression */
    size_t at = 9 + 2 + 32;
    if (at >= real_len) return 0;
    at += 1 + real[at];
    if (at + 2 > real_len) return 0;
    at += 2 + get16(real + at);
    if (at + 1 > real_len) return 0;
    at += 1 + real[at];
    if (at + 2 > real_len) return 0;
    size_t ext_at = at;
    if (found.name_off < ext_at + 2 + 9) return 0;
    long delta = (long)name - (long)found.name_len;
    size_t new_len = (size_t)((long)real_len + delta);
    if (new_len > cap || new_len > BYE_FAKE_BLOB_MAX) return 0;
    memcpy(out, real, found.name_off);
    memcpy(out + found.name_off, sni, name);
    memcpy(out + found.name_off + name, real + found.name_off + found.name_len,
           real_len - found.name_off - found.name_len);
    put16(out + 3, (unsigned)((long)get16(real + 3) + delta));
    size_t hs = ((size_t)real[6] << 16) | ((size_t)real[7] << 8) | real[8];
    hs = (size_t)((long)hs + delta);
    out[6] = (uint8_t)(hs >> 16); out[7] = (uint8_t)(hs >> 8); out[8] = (uint8_t)hs;
    put16(out + ext_at, (unsigned)((long)get16(real + ext_at) + delta));
    put16(out + found.name_off - 2, (unsigned)name);
    put16(out + found.name_off - 5, (unsigned)((long)get16(real + found.name_off - 5) + delta));
    put16(out + found.name_off - 7, (unsigned)((long)get16(real + found.name_off - 7) + delta));
    if (mods & BYE_FAKE_MOD_RAND) {
        fill_random(out + 11, 32, rng);
        size_t sid = 43;
        if (out[sid] <= 32 && sid + 1 + out[sid] <= new_len) fill_random(out + sid + 1, out[sid], rng);
    }
    return new_len;
}

size_t bye_fake_tls(uint8_t *out, size_t cap, const char *sni, uint32_t mods,
                    const uint8_t *real, size_t real_len, uint32_t seed) {
    if (!out) return 0;
    uint32_t rng = seed;
    if ((mods & BYE_FAKE_MOD_ORIG) && real && real_len) {
        size_t made = tls_with_name(out, cap, real, real_len, sni, mods, &rng);
        if (made) return made;
    }
    size_t want = HELLO_TARGET;
    if ((mods & BYE_FAKE_MOD_MIMIC) && real && real_len > 5) want = real_len;
    return tls_template(out, cap, sni, mods, real, real_len, want, &rng);
}

size_t bye_fake_http(uint8_t *out, size_t cap, const char *host) {
    if (!out) return 0;
    size_t name = sni_length(host);
    if (!name) host = BYE_FAKE_HOST_DEFAULT;
    int n = snprintf((char *)out, cap,
                     "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/7.65.3\r\nAccept: */*\r\n"
                     "Connection: close\r\n\r\n", host);
    return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

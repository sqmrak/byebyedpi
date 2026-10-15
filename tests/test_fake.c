#include "bye_ciadpi.h"
#include "bye_desync.h"
#include "bye_fake.h"
#include "bye_sniff.h"

#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "hello_openssl.inc"

static uint32_t checksum_ok(const uint8_t *data, size_t len, uint32_t sum) {
    while (len > 1) {
        sum += ((uint32_t)data[0] << 8) | data[1];
        data += 2;
        len -= 2;
    }
    if (len) sum += (uint32_t)data[0] << 8;
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return sum;
}

static bye_fake_packet_t sample(const uint8_t *payload, size_t len) {
    bye_fake_packet_t p;
    memset(&p, 0, sizeof p);
    p.src[0] = 192; p.src[1] = 168; p.src[3] = 7;
    p.dst[0] = 93; p.dst[1] = 184; p.dst[2] = 216; p.dst[3] = 34;
    p.sport = 51251;
    p.dport = 443;
    p.seq = 0xfffffff0u;
    p.ack = 0x01020304u;
    p.ttl = 8;
    p.id = 0x1234;
    p.payload = payload;
    p.len = len;
    return p;
}

static void test_packet(void) {
    static const uint8_t body[] = "FAKE-PAYLOAD-OF-ODD-LENGTH";
    uint8_t out[BYE_FAKE_PACKET_MAX];
    for (int host = 0; host < 2; ++host) {
        for (int md5 = 0; md5 < 2; ++md5) {
            bye_fake_packet_t p = sample(body, sizeof body - 1);
            p.md5sig = md5;
            size_t size = bye_fake_packet_build(&p, host, out, sizeof out);
            size_t opt = md5 ? 20 : 0;
            CHECK(size == 40 + opt + sizeof body - 1);
            CHECK(out[0] == 0x45 && out[8] == 8 && out[9] == 6);
            if (host) {
                uint16_t len;
                memcpy(&len, out + 2, 2);
                CHECK(len == size);
            } else {
                CHECK(((out[2] << 8) | out[3]) == (int)size);
                CHECK(((out[6] << 8) | out[7]) == 0x4000);
            }
            /* the checksums verify when summed with themselves */
            CHECK(checksum_ok(out, 20, 0) == 0xffff);
            uint8_t pseudo[12];
            memcpy(pseudo, out + 12, 8);
            pseudo[8] = 0; pseudo[9] = 6;
            pseudo[10] = (uint8_t)((size - 20) >> 8); pseudo[11] = (uint8_t)(size - 20);
            CHECK(checksum_ok(out + 20, size - 20, checksum_ok(pseudo, 12, 0)) == 0xffff);
            const uint8_t *tcp = out + 20;
            CHECK(((tcp[0] << 8) | tcp[1]) == 51251 && ((tcp[2] << 8) | tcp[3]) == 443);
            CHECK(tcp[4] == 0xff && tcp[7] == 0xf0 && tcp[8] == 1 && tcp[11] == 4);
            CHECK(tcp[12] == (uint8_t)(((20 + opt) / 4) << 4) && tcp[13] == 0x18);
            if (md5) CHECK(tcp[20] == 19 && tcp[21] == 18 && tcp[38] == 1 && tcp[39] == 1);
            CHECK(memcmp(tcp + 20 + opt, body, sizeof body - 1) == 0);
        }
    }
    bye_fake_packet_t p = sample(body, sizeof body - 1);
    CHECK(bye_fake_packet_build(&p, 0, out, 40) == 0);
    p.len = BYE_FAKE_PAYLOAD_MAX + 1;
    CHECK(bye_fake_packet_build(&p, 0, out, sizeof out) == 0);
    p = sample(NULL, 0);
    CHECK(bye_fake_packet_build(&p, 0, out, sizeof out) == 40);
    CHECK(bye_fake_packet_build(NULL, 0, out, sizeof out) == 0);
}

/* the classic bpf machine, enough for the opcodes the filter uses */
static uint32_t bpf_run(const bye_bpf_insn_t *prog, size_t n, const uint8_t *pkt, size_t len) {
    uint32_t a = 0, x = 0;
    for (size_t pc = 0; pc < n; ++pc) {
        const bye_bpf_insn_t *i = &prog[pc];
        switch (i->code) {
        case 0x28: if (i->k + 2 > len) return 0; a = (pkt[i->k] << 8) | pkt[i->k + 1]; break;
        case 0x30: if (i->k + 1 > len) return 0; a = pkt[i->k]; break;
        case 0x20: if (i->k + 4 > len) return 0;
            a = ((uint32_t)pkt[i->k] << 24) | (pkt[i->k + 1] << 16) | (pkt[i->k + 2] << 8) | pkt[i->k + 3]; break;
        case 0x50: if (x + i->k + 1 > len) return 0; a = pkt[x + i->k]; break;
        case 0xb1: if (i->k + 1 > len) return 0; x = (uint32_t)(pkt[i->k] & 0x0f) * 4; break;
        case 0x54: a &= i->k; break;
        case 0x15: pc += a == i->k ? i->jt : i->jf; break;
        case 0x45: pc += (a & i->k) ? i->jt : i->jf; break;
        case 0x06: return i->k;
        default: return 0xdeadbeef;
        }
    }
    return 0;
}

static size_t frame(unsigned link, uint8_t flags, int fragment, uint8_t proto, uint8_t *out) {
    size_t at = 0;
    memset(out, 0, 128);
    if (link == BYE_LINK_ETHERNET) { out[12] = 0x08; out[13] = 0x00; at = 14; }
    else if (link == BYE_LINK_NULL) { uint32_t family = 2; memcpy(out, &family, 4); at = 4; }
    uint8_t *ip = out + at;
    ip[0] = 0x46; /* options present: the header is 24 bytes */
    ip[9] = proto;
    if (fragment) ip[7] = 0x08;
    ip[12] = 10; ip[15] = 1; ip[16] = 9; ip[19] = 9;
    uint8_t *tcp = ip + 24;
    tcp[0] = 0xc8; tcp[1] = 0x33; tcp[2] = 0x01; tcp[3] = 0xbb;
    tcp[4] = 0x10; tcp[5] = 0x20; tcp[6] = 0x30; tcp[7] = 0x40;
    tcp[13] = flags;
    return at + 24 + 20;
}

static void test_filter_and_parse(void) {
    static const unsigned links[] = { BYE_LINK_ETHERNET, BYE_LINK_NULL, BYE_LINK_RAW };
    for (size_t k = 0; k < 3; ++k) {
        bye_bpf_insn_t prog[BYE_BPF_FILTER_MAX];
        size_t n = bye_fake_bpf_filter(links[k], prog, BYE_BPF_FILTER_MAX);
        CHECK(n > 4 && n <= BYE_BPF_FILTER_MAX);
        CHECK(bye_fake_bpf_filter(links[k], prog, 4) == 0);
        uint8_t buf[128];
        size_t len = frame(links[k], 0x02, 0, 6, buf);
        CHECK(bpf_run(prog, n, buf, len) != 0);
        len = frame(links[k], 0x12, 0, 6, buf);
        CHECK(bpf_run(prog, n, buf, len) != 0);
        len = frame(links[k], 0x10, 0, 6, buf);
        CHECK(bpf_run(prog, n, buf, len) == 0);
        len = frame(links[k], 0x02, 1, 6, buf);
        CHECK(bpf_run(prog, n, buf, len) == 0);
        len = frame(links[k], 0x02, 0, 17, buf);
        CHECK(bpf_run(prog, n, buf, len) == 0);
        len = frame(links[k], 0x02, 0, 6, buf);
        CHECK(bpf_run(prog, n, buf, 20) == 0);

        bye_fake_syn_t syn;
        len = frame(links[k], 0x12, 0, 6, buf);
        CHECK(bye_fake_syn_parse(links[k], buf, len, &syn) == 1);
        CHECK(syn.sport == 0xc833 && syn.dport == 443 && syn.seq == 0x10203040u && syn.flags == 0x12);
        CHECK(syn.src[0] == 10 && syn.src[3] == 1 && syn.dst[0] == 9 && syn.dst[3] == 9);
        CHECK(bye_fake_syn_parse(links[k], buf, len - 1, &syn) == 0);
        len = frame(links[k], 0x10, 0, 6, buf);
        CHECK(bye_fake_syn_parse(links[k], buf, len, &syn) == 0);
        len = frame(links[k], 0x02, 1, 6, buf);
        CHECK(bye_fake_syn_parse(links[k], buf, len, &syn) == 0);
        len = frame(links[k], 0x02, 0, 17, buf);
        CHECK(bye_fake_syn_parse(links[k], buf, len, &syn) == 0);
    }
    uint8_t buf[128];
    size_t len = frame(BYE_LINK_ETHERNET, 0x02, 0, 6, buf);
    bye_fake_syn_t syn;
    CHECK(bye_fake_syn_parse(99, buf, len, &syn) == 0);
    CHECK(bye_fake_bpf_filter(99, (bye_bpf_insn_t[BYE_BPF_FILTER_MAX]){ {0} }, BYE_BPF_FILTER_MAX) == 0);
    buf[12] = 0x86; buf[13] = 0xdd;
    CHECK(bye_fake_syn_parse(BYE_LINK_ETHERNET, buf, len, &syn) == 0);
}

static void test_track(void) {
    static bye_fake_track_t track;
    bye_fake_track_init(&track);
    const uint8_t local[4] = { 10, 0, 0, 2 }, remote[4] = { 1, 1, 1, 1 }, other[4] = { 2, 2, 2, 2 };
    bye_fake_syn_t syn = { { 10, 0, 0, 2 }, { 1, 1, 1, 1 }, 40000, 443, 1000, 0x02 };
    uint32_t isn = 0, sisn = 0;
    bye_fake_track_note(&track, &syn);
    CHECK(!bye_fake_track_find(&track, local, 40000, remote, 443, &isn, &sisn));
    bye_fake_syn_t answer = { { 1, 1, 1, 1 }, { 10, 0, 0, 2 }, 443, 40000, 5000, 0x12 };
    bye_fake_track_note(&track, &answer);
    CHECK(bye_fake_track_find(&track, local, 40000, remote, 443, &isn, &sisn) && isn == 1000 && sisn == 5000);
    CHECK(!bye_fake_track_find(&track, local, 40001, remote, 443, &isn, &sisn));
    CHECK(!bye_fake_track_find(&track, local, 40000, other, 443, &isn, &sisn));
    /* a reused port starts again, and the old answer does not carry over */
    syn.seq = 2000;
    bye_fake_track_note(&track, &syn);
    CHECK(!bye_fake_track_find(&track, local, 40000, remote, 443, &isn, &sisn));
    answer.seq = 6000;
    bye_fake_track_note(&track, &answer);
    CHECK(bye_fake_track_find(&track, local, 40000, remote, 443, &isn, &sisn) && isn == 2000 && sisn == 6000);
    /* the ring forgets the oldest entry after BYE_FAKE_TRACK_MAX newer ones */
    for (unsigned i = 0; i < BYE_FAKE_TRACK_MAX; ++i) {
        bye_fake_syn_t s = { { 10, 0, 0, 2 }, { 3, 3, 3, 3 }, (uint16_t)(1000 + i), 80, i, 0x02 };
        bye_fake_track_note(&track, &s);
    }
    CHECK(!bye_fake_track_find(&track, local, 40000, remote, 443, &isn, &sisn));
    bye_fake_track_note(NULL, &syn);
    CHECK(!bye_fake_track_find(NULL, local, 1, remote, 1, &isn, &sisn));
}

static void test_tls(void) {
    uint8_t out[BYE_FAKE_BLOB_MAX];
    bye_sniff_t name;
    size_t n = bye_fake_tls(out, sizeof out, NULL, 0, NULL, 0, 1);
    CHECK(n == 517 && bye_sniff_tls(out, n, &name) == BYE_SNIFF_OK);
    CHECK(name.name_len == strlen(BYE_FAKE_SNI_DEFAULT) && memcmp(out + name.name_off, BYE_FAKE_SNI_DEFAULT, name.name_len) == 0);
    CHECK(name.record_len == n);
    uint8_t again[BYE_FAKE_BLOB_MAX];
    CHECK(bye_fake_tls(again, sizeof again, NULL, 0, NULL, 0, 99) == n && memcmp(again, out, n) == 0);

    n = bye_fake_tls(out, sizeof out, "example.org", 0, NULL, 0, 1);
    CHECK(n == 517 && bye_sniff_tls(out, n, &name) == BYE_SNIFF_OK && name.name_len == 11 &&
          memcmp(out + name.name_off, "example.org", 11) == 0);
    /* a name that is too long is not used */
    char long_name[128];
    memset(long_name, 'a', sizeof long_name - 1);
    long_name[sizeof long_name - 1] = '\0';
    n = bye_fake_tls(out, sizeof out, long_name, 0, NULL, 0, 1);
    CHECK(n == 517 && bye_sniff_tls(out, n, &name) == BYE_SNIFF_OK && name.name_len == strlen(BYE_FAKE_SNI_DEFAULT));

    n = bye_fake_tls(again, sizeof again, "example.org", BYE_FAKE_MOD_RAND, NULL, 0, 1);
    uint8_t other[BYE_FAKE_BLOB_MAX];
    size_t m = bye_fake_tls(other, sizeof other, "example.org", BYE_FAKE_MOD_RAND, NULL, 0, 2);
    CHECK(n == m && memcmp(again + 11, other + 11, 32) != 0);
    CHECK(memcmp(again + 11, out + 11, 32) != 0);
    CHECK(bye_fake_tls(out, 100, NULL, 0, NULL, 0, 1) == 0);

    /* the app's own hello with the name replaced, every length moving with it */
    n = bye_fake_tls(out, sizeof out, "a.io", BYE_FAKE_MOD_ORIG, hello_openssl, hello_openssl_len, 1);
    if (hello_openssl_len + 100 < sizeof out) {
        long delta = (long)strlen("a.io") - 23;
        CHECK(n == (size_t)((long)hello_openssl_len + delta));
        CHECK(bye_sniff_tls(out, n, &name) == BYE_SNIFF_OK && name.name_len == 4 &&
              memcmp(out + name.name_off, "a.io", 4) == 0 && name.record_len == n);
    } else {
        /* the openssl fixture is bigger than a fake may be: the built-in hello takes its place */
        CHECK(n == 517);
    }
    uint8_t real[BYE_FAKE_BLOB_MAX];
    size_t real_len = bye_fake_tls(real, sizeof real, "real-host.example.net", BYE_FAKE_MOD_RAND, NULL, 0, 7);
    CHECK(real_len == 517);
    n = bye_fake_tls(out, sizeof out, "a.io", BYE_FAKE_MOD_ORIG, real, real_len, 1);
    CHECK(n == real_len - (strlen("real-host.example.net") - 4));
    CHECK(bye_sniff_tls(out, n, &name) == BYE_SNIFF_OK && name.name_len == 4 && memcmp(out + name.name_off, "a.io", 4) == 0);
    n = bye_fake_tls(out, sizeof out, "longer-than-the-real-name.example", BYE_FAKE_MOD_ORIG, real, real_len, 1);
    CHECK(n == real_len + (strlen("longer-than-the-real-name.example") - strlen("real-host.example.net")));
    CHECK(bye_sniff_tls(out, n, &name) == BYE_SNIFF_OK && name.record_len == n);
    /* the session id of the app's hello */
    n = bye_fake_tls(out, sizeof out, NULL, BYE_FAKE_MOD_DUPSID, real, real_len, 1);
    CHECK(n == 517 && real[43] == 32 && memcmp(out + 44, real + 44, 32) == 0);
    /* mimic matches the app's length, up to what the template can pad to */
    uint8_t big[BYE_FAKE_BLOB_MAX];
    size_t big_len = bye_fake_tls(big, sizeof big, "x.example", 0, NULL, 0, 1);
    CHECK(big_len == 517);
    n = bye_fake_tls(out, sizeof out, NULL, BYE_FAKE_MOD_MIMIC, hello_openssl, 800, 1);
    CHECK(n == 800 && bye_sniff_tls(out, n, &name) == BYE_SNIFF_OK);
}

static void test_http(void) {
    uint8_t out[512];
    size_t n = bye_fake_http(out, sizeof out, NULL);
    CHECK(n > 0 && memcmp(out, "GET / HTTP/1.1\r\nHost: www.w3.org\r\n", 34) == 0);
    bye_sniff_t name;
    CHECK(bye_sniff_http(out, n, &name) == BYE_SNIFF_OK && memcmp(out + name.name_off, "www.w3.org", name.name_len) == 0);
    n = bye_fake_http(out, sizeof out, "example.org");
    CHECK(n > 0 && bye_sniff_http(out, n, &name) == BYE_SNIFF_OK && name.name_len == 11);
    CHECK(bye_fake_http(out, 10, NULL) == 0);
}

static bye_strategies_t cli(const char *text) {
    bye_strategies_t list;
    char error[160];
    bye_desync_status_t status = bye_ciadpi_parse(text, &list, error, sizeof error);
    if (status != BYE_DESYNC_OK) fprintf(stderr, "parse %s: %s\n", text, error);
    CHECK(status == BYE_DESYNC_OK);
    return list;
}

static void test_options(void) {
    bye_strategies_t list = cli("-f1 -t 6 -n example.org -Qr,o,m,d -O 2 -S -As -f-1");
    CHECK(list.count == 2);
    const bye_desync_t *g = &list.item[0];
    CHECK(g->parts[0].mode == BYE_PART_FAKE && g->fake_ttl == 6 && !strcmp(g->fake_sni, "example.org"));
    CHECK(g->fake_mods == (BYE_FAKE_MOD_RAND | BYE_FAKE_MOD_ORIG | BYE_FAKE_MOD_MIMIC | BYE_FAKE_MOD_DUPSID));
    CHECK(g->fake_offset == 2 && g->md5sig && !g->fake_file[0]);
    /* the options of one group stay out of the next */
    CHECK(list.item[1].fake_ttl == 0 && !list.item[1].md5sig && !list.item[1].fake_sni[0] && list.item[1].fake_mods == 0);
    CHECK(list.item[1].parts[0].mode == BYE_PART_FAKE);
    CHECK(!strstr(list.notes, "-f") && !strstr(list.notes, "-t") && !strstr(list.notes, "-S"));
    CHECK(bye_strategies_use_fake(&list));
    CHECK(!bye_strategies_use_fake(&(bye_strategies_t){ 0 }));
    bye_strategies_t plain = cli("-d1 -s3+s -r1+s");
    CHECK(!bye_strategies_use_fake(&plain));
    list = cli("-n {sni} -l fake.bin -O -3 -t255");
    CHECK(!list.item[0].fake_sni[0] && !strcmp(list.item[0].fake_file, "fake.bin") && list.item[0].fake_offset == -3);
    CHECK(list.item[0].fake_ttl == 255);
    list = cli("--fake 3 --ttl 4 --fake-sni a.b --fake-offset 5 --fake-tls-mod r --md5sig --fake-data x.bin");
    CHECK(list.item[0].parts[0].mode == BYE_PART_FAKE && list.item[0].fake_ttl == 4 && list.item[0].md5sig &&
          !strcmp(list.item[0].fake_file, "x.bin") && list.item[0].fake_mods == BYE_FAKE_MOD_RAND);

    static const char *const bad[] = {
        "-t 0", "-t 256", "-n ''", "-Q x", "-Q", "-l ../etc/passwd", "-l /etc/passwd", "-l .hidden",
        "-l a/b", "-O 99999", "-t x", "-f"
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        char error[160];
        bye_strategies_t out;
        CHECK(bye_ciadpi_parse(bad[i], &out, error, sizeof error) != BYE_DESYNC_OK);
    }
}

static void test_payload(void) {
    bye_strategies_t list = cli("-f1");
    bye_desync_t group = list.item[0];
    uint8_t out[BYE_FAKE_PAYLOAD_MAX];
    uint8_t real[BYE_FAKE_BLOB_MAX];
    size_t real_len = bye_fake_tls(real, sizeof real, "real.example", 0, NULL, 0, 3);
    bye_sniff_t name;
    uint8_t whole[BYE_FAKE_BLOB_MAX];
    size_t whole_len = bye_fake_tls(whole, sizeof whole, NULL, 0, NULL, 0, 0);
    size_t n = bye_desync_fake(&group, 1, real, real_len, 100, out, sizeof out);
    CHECK(n == 100 && memcmp(out, whole, 100) == 0);
    n = bye_desync_fake(&group, 1, real, real_len, 5000, out, sizeof out);
    CHECK(n == whole_len && memcmp(out, whole, whole_len) == 0);
    CHECK(bye_sniff_tls(out, n, &name) == BYE_SNIFF_OK);
    group.fake_offset = 10;
    n = bye_desync_fake(&group, 1, real, real_len, 20, out, sizeof out);
    CHECK(n == 20 && memcmp(out, whole + 10, 20) == 0);
    group.fake_offset = -5;
    n = bye_desync_fake(&group, 1, real, real_len, 20, out, sizeof out);
    CHECK(n == 5 && memcmp(out, whole + whole_len - 5, 5) == 0);
    group.fake_offset = (int32_t)whole_len;
    CHECK(bye_desync_fake(&group, 1, real, real_len, 20, out, sizeof out) == 0);
    group.fake_offset = 0;
    CHECK(bye_desync_fake(&group, 1, real, real_len, 0, out, sizeof out) == 0);
    n = bye_desync_fake(&group, 0, (const uint8_t *)"GET / HTTP/1.1\r\n\r\n", 18, 1000, out, sizeof out);
    CHECK(n > 20 && memcmp(out, "GET / HTTP/1.1\r\nHost: www.w3.org", 31) == 0);
    memcpy(group.fake_data, "ABCDEFGH", 8);
    group.fake_data_len = 8;
    n = bye_desync_fake(&group, 1, real, real_len, 100, out, sizeof out);
    CHECK(n == 8 && memcmp(out, "ABCDEFGH", 8) == 0);
    group.fake_offset = 2;
    n = bye_desync_fake(&group, 1, real, real_len, 3, out, sizeof out);
    CHECK(n == 3 && memcmp(out, "CDE", 3) == 0);
    CHECK(bye_desync_fake(&group, 1, real, real_len, 3, out, 2) == 0);
    CHECK(bye_desync_fake(NULL, 1, real, real_len, 3, out, sizeof out) == 0);
}

static void test_plan(void) {
    bye_strategies_t list = cli("-f1 -s5 -f-1");
    uint8_t out[sizeof hello_openssl + BYE_DESYNC_GROWTH_MAX + 8];
    bye_plan_t plan;
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) == BYE_DESYNC_OK);
    CHECK(plan.count == 4);
    CHECK(plan.ops[0].len == 1 && (plan.ops[0].flags & BYE_OP_FAKE));
    CHECK(plan.ops[1].len == 4 && plan.ops[1].flags == 0);
    CHECK(plan.ops[2].len == hello_openssl_len - 6 && (plan.ops[2].flags & BYE_OP_FAKE));
    CHECK(plan.ops[3].len == 1 && plan.ops[3].flags == 0);
    size_t total = 0;
    for (size_t i = 0; i < plan.count; ++i) total += plan.ops[i].len;
    CHECK(total == hello_openssl_len && memcmp(out, hello_openssl, hello_openssl_len) == 0);
}

int main(void) {
    test_packet();
    test_filter_and_parse();
    test_track();
    test_tls();
    test_http();
    test_options();
    test_payload();
    test_plan();
    if (!failed) puts("test_fake ok");
    return failed;
}

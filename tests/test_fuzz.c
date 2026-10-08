#include "bye_ciadpi.h"
#include "bye_config.h"
#include "bye_desync.h"
#include "bye_hosts.h"
#include "bye_mtp.h"
#include "bye_sniff.h"
#include "bye_ws.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "check.h"
#include "hello_openssl.inc"

/* hostile input: none of these may crash or read out of bounds. the sanitizer
   build is what gives the loops their teeth */

static uint64_t state = 0x9E3779B97F4A7C15ull;

static uint32_t next(void) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return (uint32_t)(state >> 16);
}

static void fuzz_sniff(void) {
    uint8_t buf[2048], out[2048];
    bye_plan_t plan;
    static const char *const specs[] = {
        "tlsrec=name+1;split=1,name+1", "tlsrec=end+400;split=1,end+3", "split=2,mid,end;oob=name",
        "tlsrec=6", "tlsrec=name-1;split=name,name-1;oob=end+50", "tlsrec=mid+1000"
    };
    bye_desync_t d;
    for (int round = 0; round < 20000; ++round) {
        CHECK(bye_desync_parse(specs[round % 6], &d, NULL, 0) == BYE_DESYNC_OK);
        size_t len = hello_openssl_len;
        memcpy(buf, hello_openssl, len);
        int flips = 1 + (int)(next() % 4);
        for (int i = 0; i < flips; ++i) buf[next() % 96] = (uint8_t)next();
        if (next() % 3 == 0) len = next() % (len + 1);
        bye_sniff_t s;
        bye_sniff_status_t status = bye_sniff_tls(buf, len, &s);
        if (status == BYE_SNIFF_OK) {
            CHECK(s.name_len > 0 && s.name_off + s.name_len <= len);
        }
        if (len > 0) {
            bye_desync_status_t built = bye_desync_build(&d, buf, len, out, sizeof out, &plan);
            if (built == BYE_DESYNC_OK) {
                size_t total = 0;
                for (size_t i = 0; i < plan.count; ++i) {
                    CHECK(plan.ops[i].off == total && plan.ops[i].len > 0);
                    total += plan.ops[i].len;
                }
                CHECK(total == plan.total && total >= len && total <= len + BYE_DESYNC_GROWTH_MAX);
            }
        }
        (void)bye_sniff_http(buf, len, &s);
    }
}

static void fuzz_ciadpi(void) {
    static const char *const words[] = {
        "-d1", "-s5", "-o3", "-q9", "-f2", "-r1+s", "-r10", "-s0+sm", "-d3+s", "-s6+se", "-s-1",
        "-s2:5:3", "-d1:1000:7", "-s5+hr", "-s0+nr", "-As", "-At", "-Ar", "-An", "-Mh", "-Md",
        "-Mr", "-m", "2", "-Kt", "-Kh", "-e", "\\x41", "-T", "1.5", "-g", "64", "-S", "-a1",
        "--split", "--tlsrec=7", "-s", "-d", "-1", "+s", "'", "\"", "x", "-", "--", "-A", "s,t"
    };
    char text[512];
    uint8_t buf[2048], out[2048 + BYE_DESYNC_GROWTH_MAX + 8];
    static const char req[] = "GET / HTTP/1.1\r\nHost: blocked.example.org\r\nAccept: */*\r\n\r\n";
    bye_strategies_t list;
    bye_plan_t plan;
    for (int round = 0; round < 20000; ++round) {
        size_t n = 0;
        int count = 1 + (int)(next() % 8);
        for (int i = 0; i < count; ++i)
            n += (size_t)snprintf(text + n, sizeof text - n, "%s%s", i ? " " : "",
                                  words[next() % (sizeof words / sizeof words[0])]);
        if (next() % 5 == 0) text[next() % (n + 1)] = (char)next();
        text[sizeof text - 1] = '\0';
        char error[160];
        bye_desync_status_t status = bye_ciadpi_parse(text, &list, error, sizeof error);
        if (status != BYE_DESYNC_OK) {
            CHECK(error[0] != '\0');
            continue;
        }
        CHECK(list.count >= 1 && list.count <= BYE_STRATEGIES_MAX);
        size_t len;
        if (next() % 4 == 0) {
            len = sizeof req - 1;
            memcpy(buf, req, len);
        } else {
            len = hello_openssl_len;
            memcpy(buf, hello_openssl, len);
        }
        int flips = (int)(next() % 4);
        for (int i = 0; i < flips; ++i) buf[next() % len] = (uint8_t)next();
        if (next() % 3 == 0) len = 1 + next() % len;
        for (size_t g = 0; g < list.count; ++g) {
            bye_desync_status_t built = bye_desync_build(&list.item[g], buf, len, out, sizeof out, &plan);
            if (built != BYE_DESYNC_OK) continue;
            size_t total = 0;
            for (size_t i = 0; i < plan.count; ++i) {
                CHECK(plan.ops[i].off == total);
                CHECK(plan.ops[i].len > 0 || (plan.ops[i].flags & BYE_OP_OOB));
                total += plan.ops[i].len;
            }
            CHECK(plan.count > 0 && plan.count <= BYE_DESYNC_OPS_MAX);
            CHECK(total == plan.total && total >= len && total < len + BYE_DESYNC_GROWTH_MAX);
            if (!list.item[g].tlsrec_count && !list.item[g].mod_http && !list.item[g].tlsminor)
                CHECK(total == len && memcmp(out, buf, len) == 0);
        }
    }
}

static void fuzz_hosts(void) {
    static const char alphabet[] = "abcXYZ019-_.*# \t\r\n/:|";
    static const char spec_alphabet[] = "split=,;|nonetlsrcmidoobam1+-";
    char text[256], name[64];
    for (int round = 0; round < 20000; ++round) {
        size_t len = next() % sizeof text;
        for (size_t i = 0; i < len; ++i) text[i] = alphabet[next() % (sizeof alphabet - 1)];
        bye_hosts_t *hosts = bye_hosts_parse(text, len, NULL, 0);
        if (hosts) {
            CHECK(bye_hosts_count(hosts) <= len);
            size_t n = next() % sizeof name;
            for (size_t i = 0; i < n; ++i) name[i] = alphabet[next() % (sizeof alphabet - 1)];
            (void)bye_hosts_match(hosts, name, n);
            bye_hosts_free(hosts);
        }
        bye_strategies_t list;
        char spec[64];
        size_t slen = next() % sizeof spec;
        for (size_t i = 0; i < slen; ++i) spec[i] = spec_alphabet[next() % (sizeof spec_alphabet - 1)];
        spec[slen] = '\0';
        if (bye_strategies_parse(spec, &list, NULL, 0) == BYE_DESYNC_OK) CHECK(list.count >= 1);
    }
}

static void fuzz_http(void) {
    static const char base[] = "GET /a HTTP/1.1\r\nUser-Agent: x\r\nHost: blocked.example.org\r\n\r\n";
    uint8_t buf[128];
    for (int round = 0; round < 20000; ++round) {
        size_t len = sizeof base - 1;
        memcpy(buf, base, len);
        for (int i = 0; i < 3; ++i) buf[next() % len] = (uint8_t)next();
        len = next() % (len + 1);
        bye_sniff_t s;
        if (bye_sniff_http(buf, len, &s) == BYE_SNIFF_OK)
            CHECK(s.name_len > 0 && s.name_off + s.name_len <= len);
    }
}

static int count_data(void *ctx, const uint8_t *p, size_t n) {
    (void)p;
    *(size_t *)ctx += n;
    return 0;
}

static void fuzz_ws(void) {
    uint8_t buf[600];
    for (int round = 0; round < 20000; ++round) {
        size_t total = 0;
        bye_ws_sink_t sink = { count_data, NULL, &total };
        bye_ws_rx_t rx;
        bye_ws_rx_init(&rx);
        size_t len = 1 + next() % sizeof buf;
        for (size_t i = 0; i < len; ++i) buf[i] = (uint8_t)next();
        if (round % 2) {
            buf[0] = 0x82;
            buf[1] = (uint8_t)(next() % 126);
        }
        size_t at = 0;
        while (at < len) {
            size_t step = 1 + next() % 40;
            if (step > len - at) step = len - at;
            if (bye_ws_rx_feed(&rx, buf + at, step, &sink) < 0) break;
            at += step;
        }
        CHECK(total <= len);
    }
    /* a response that is any prefix or mutation of a good one */
    char key[BYE_WS_KEY_LEN] = "dGhlIHNhbXBsZSBub25jZQ==";
    static const char good[] =
        "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: binary\r\n\r\n";
    for (int round = 0; round < 20000; ++round) {
        uint8_t resp[256];
        size_t len = sizeof good - 1;
        memcpy(resp, good, len);
        for (int i = 0; i < 2; ++i) resp[next() % len] = (uint8_t)next();
        len = next() % (len + 1);
        size_t used = 0;
        int status = 0;
        bye_ws_status_t r = bye_ws_response(resp, len, key, &used, &status);
        if (r == BYE_WS_OK) CHECK(used <= len);
    }
}

static int drop(void *ctx, const uint8_t *msg, size_t len) {
    (void)ctx; (void)msg; (void)len;
    return 0;
}

static void fuzz_mtp(void) {
    for (int round = 0; round < 300; ++round) {
        uint8_t init[64], relay[64];
        for (size_t i = 0; i < 64; ++i) init[i] = (uint8_t)next();
        bye_mtp_t *m = NULL;
        bye_mtp_route_t route;
        bye_mtp_status_t status = bye_mtp_open(&m, NULL, 0, init, &route, relay);
        if (status != BYE_MTP_OK) {
            CHECK(m == NULL);
            continue;
        }
        /* garbage after a valid open: the splitter reads lengths from noise */
        for (int i = 0; i < 40; ++i) {
            uint8_t chunk[900];
            size_t len = 1 + next() % sizeof chunk;
            for (size_t k = 0; k < len; ++k) chunk[k] = (uint8_t)next();
            if (bye_mtp_up(m, chunk, len, drop, NULL) != BYE_MTP_OK) break;
        }
        bye_mtp_close(m);
    }
    /* a client that does open, to reach the splitter with noise: the tag
       bytes are set against the key stream the proxy will read them with */
    int opened = 0;
    static const uint32_t protos[] = { BYE_MTP_TAG_ABRIDGED, BYE_MTP_TAG_INTERMEDIATE,
                                       BYE_MTP_TAG_PADDED };
    for (int round = 0; round < 300; ++round) {
        uint8_t init[64], relay[64], ks[64] = { 0 };
        for (size_t i = 0; i < 64; ++i) init[i] = (uint8_t)next();
        EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
        int n = 0;
        CHECK(c && EVP_EncryptInit_ex(c, EVP_aes_256_ctr(), NULL, init + 8, init + 40) == 1);
        CHECK(EVP_EncryptUpdate(c, ks, &n, ks, 64) == 1 && n == 64);
        EVP_CIPHER_CTX_free(c);
        uint32_t proto = protos[round % 3];
        for (size_t i = 0; i < 4; ++i) init[56 + i] = (uint8_t)(proto >> (8 * i)) ^ ks[56 + i];
        init[60] = (uint8_t)(2 + round % 4) ^ ks[60];
        init[61] = ks[61];
        bye_mtp_t *m = NULL;
        bye_mtp_route_t route;
        if (bye_mtp_open(&m, NULL, 0, init, &route, relay) != BYE_MTP_OK) continue;
        ++opened;
        for (int i = 0; i < 40; ++i) {
            uint8_t chunk[900];
            size_t len = 1 + next() % sizeof chunk;
            for (size_t k = 0; k < len; ++k) chunk[k] = (uint8_t)next();
            if (bye_mtp_up(m, chunk, len, drop, NULL) != BYE_MTP_OK) break;
        }
        (void)bye_mtp_up_flush(m, drop, NULL);
        bye_mtp_close(m);
    }
    CHECK(opened > 0);
}

static void fuzz_config(void) {
    static const char base[] =
        "desync = on\ndesync.spec = tlsrec=name+1;split=1,name+1;oob=mid\ntelegram = off\n"
        "quic = block\ndns = 9.9.9.9\n";
    char text[200];
    for (int round = 0; round < 20000; ++round) {
        size_t len = sizeof base - 1;
        memcpy(text, base, len);
        for (int i = 0; i < 3; ++i) text[next() % len] = (char)next();
        len = next() % (len + 1);
        bye_config_t c;
        char error[BYE_CONFIG_ERROR_MAX];
        bye_config_defaults(&c);
        (void)bye_config_parse(text, len, &c, error, sizeof error);
    }
}

int main(void) {
    fuzz_sniff();
    fuzz_hosts();
    fuzz_http();
    fuzz_ws();
    fuzz_mtp();
    fuzz_config();
    fuzz_ciadpi();
    if (!failed) puts("test_fuzz ok");
    return failed;
}

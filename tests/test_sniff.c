#include "bye_sniff.h"

#include <string.h>

#include "check.h"
#include "hello_openssl.inc"

/* a hello built by hand, so every length can be placed where a test needs it */
static size_t build_hello(uint8_t *out, const char *name, int pad_before, int pad_after) {
    uint8_t exts[512];
    size_t e = 0;
    if (pad_before) {
        exts[e++] = 0x00; exts[e++] = 0x0b; /* ec_point_formats */
        exts[e++] = 0x00; exts[e++] = 0x02;
        exts[e++] = 0x01; exts[e++] = 0x00;
    }
    if (name) {
        size_t n = strlen(name);
        exts[e++] = 0x00; exts[e++] = 0x00;
        exts[e++] = (uint8_t)((n + 5) >> 8); exts[e++] = (uint8_t)(n + 5);
        exts[e++] = (uint8_t)((n + 3) >> 8); exts[e++] = (uint8_t)(n + 3);
        exts[e++] = 0x00;
        exts[e++] = (uint8_t)(n >> 8); exts[e++] = (uint8_t)n;
        memcpy(exts + e, name, n);
        e += n;
    }
    if (pad_after) {
        exts[e++] = 0x00; exts[e++] = 0x15; /* padding */
        exts[e++] = 0x00; exts[e++] = 0x03;
        exts[e++] = 0x00; exts[e++] = 0x00; exts[e++] = 0x00;
    }
    uint8_t body[800];
    size_t b = 0;
    body[b++] = 0x03; body[b++] = 0x03;
    memset(body + b, 0xAA, 32); b += 32;
    body[b++] = 4; memset(body + b, 0xBB, 4); b += 4;
    body[b++] = 0x00; body[b++] = 0x04; body[b++] = 0x13; body[b++] = 0x01;
    body[b++] = 0xC0; body[b++] = 0x2F;
    body[b++] = 1; body[b++] = 0;
    if (e) {
        body[b++] = (uint8_t)(e >> 8); body[b++] = (uint8_t)e;
        memcpy(body + b, exts, e); b += e;
    }
    size_t hs = b;
    out[0] = 0x16; out[1] = 0x03; out[2] = 0x01;
    out[3] = (uint8_t)((hs + 4) >> 8); out[4] = (uint8_t)(hs + 4);
    out[5] = 0x01; out[6] = 0; out[7] = (uint8_t)(hs >> 8); out[8] = (uint8_t)hs;
    memcpy(out + 9, body, b);
    return 9 + b;
}

static int name_is(const uint8_t *buf, const bye_sniff_t *s, const char *name) {
    return s->name_len == strlen(name) && memcmp(buf + s->name_off, name, s->name_len) == 0;
}

static void test_hand_built(void) {
    uint8_t hello[1024];
    bye_sniff_t s;
    size_t n = build_hello(hello, "blocked.example.org", 1, 1);
    CHECK(bye_sniff_tls(hello, n, &s) == BYE_SNIFF_OK);
    CHECK(name_is(hello, &s, "blocked.example.org"));
    CHECK(s.record_len == n);

    n = build_hello(hello, "a.b", 0, 0);
    CHECK(bye_sniff_tls(hello, n, &s) == BYE_SNIFF_OK && name_is(hello, &s, "a.b"));

    n = build_hello(hello, NULL, 1, 1);
    CHECK(bye_sniff_tls(hello, n, &s) == BYE_SNIFF_NO_NAME);
    CHECK(s.record_len == n);

    n = build_hello(hello, NULL, 0, 0);
    CHECK(bye_sniff_tls(hello, n, &s) == BYE_SNIFF_NO_NAME);
}

/* every prefix of a hello is a valid prefix, and once the name is in the
   answer stays OK */
static void test_prefixes(void) {
    uint8_t hello[1024];
    bye_sniff_t s;
    size_t n = build_hello(hello, "blocked.example.org", 1, 1);
    int seen_ok = 0;
    for (size_t len = 0; len <= n; ++len) {
        bye_sniff_status_t status = bye_sniff_tls(hello, len, &s);
        if (status == BYE_SNIFF_OK) {
            seen_ok = 1;
            CHECK(name_is(hello, &s, "blocked.example.org"));
            CHECK(s.name_off + s.name_len <= len);
        } else {
            CHECK(!seen_ok);
            CHECK(status == BYE_SNIFF_NEED_MORE);
        }
    }
    CHECK(seen_ok);
}

static void test_real_hello(void) {
    bye_sniff_t s;
    CHECK(bye_sniff_tls(hello_openssl, hello_openssl_len, &s) == BYE_SNIFF_OK);
    CHECK(name_is(hello_openssl, &s, "www.example-blocked.org"));
    CHECK(s.record_len == hello_openssl_len);
    for (size_t len = 0; len < hello_openssl_len; ++len) {
        bye_sniff_status_t status = bye_sniff_tls(hello_openssl, len, &s);
        CHECK(status == BYE_SNIFF_OK || status == BYE_SNIFF_NEED_MORE);
    }
}

static void test_not_tls(void) {
    bye_sniff_t s;
    CHECK(bye_sniff_tls((const uint8_t *)"GET / HTTP/1.1\r\n", 16, &s) == BYE_SNIFF_NO_MATCH);
    CHECK(bye_sniff_tls((const uint8_t *)"\x16\x02\x01", 3, &s) == BYE_SNIFF_NO_MATCH);
    CHECK(bye_sniff_tls((const uint8_t *)"\x16\x03\x09", 3, &s) == BYE_SNIFF_NO_MATCH);
    CHECK(bye_sniff_tls((const uint8_t *)"\x17\x03\x03\x00\x10", 5, &s) == BYE_SNIFF_NO_MATCH);
    CHECK(bye_sniff_tls(NULL, 0, &s) == BYE_SNIFF_NEED_MORE);
    /* a server hello is a handshake record that is not a client hello */
    CHECK(bye_sniff_tls((const uint8_t *)"\x16\x03\x03\x00\x05\x02\x00\x00\x01\x00", 10, &s)
          == BYE_SNIFF_NO_MATCH);
}

static void test_malformed(void) {
    uint8_t hello[1024];
    bye_sniff_t s;
    size_t n = build_hello(hello, "blocked.example.org", 1, 0);

    uint8_t bad[1024];
    memcpy(bad, hello, n);
    bad[3] = 0xFF; bad[4] = 0xFF; /* a record longer than tls allows */
    CHECK(bye_sniff_tls(bad, n, &s) == BYE_SNIFF_MALFORMED);

    memcpy(bad, hello, n);
    bad[3] = 0; bad[4] = 2; /* a record too short to hold a handshake header */
    CHECK(bye_sniff_tls(bad, n, &s) == BYE_SNIFF_MALFORMED);

    memcpy(bad, hello, n);
    bad[8] += 1; /* the hello claims more than the record holds */
    CHECK(bye_sniff_tls(bad, n, &s) == BYE_SNIFF_MALFORMED);

    memcpy(bad, hello, n);
    bad[9 + 34] = 33; /* a session id longer than 32 */
    CHECK(bye_sniff_tls(bad, n, &s) == BYE_SNIFF_MALFORMED);

    memcpy(bad, hello, n);
    bad[9 + 35 + 4 + 1] = 5; /* an odd cipher suite length */
    CHECK(bye_sniff_tls(bad, n, &s) == BYE_SNIFF_MALFORMED);

    /* a name with a control byte or a space */
    n = build_hello(hello, "bad host", 0, 0);
    CHECK(bye_sniff_tls(hello, n, &s) == BYE_SNIFF_MALFORMED);

    /* the extension block runs past the record */
    n = build_hello(hello, "blocked.example.org", 0, 0);
    memcpy(bad, hello, n);
    bad[9 + 2 + 32 + 5 + 2 + 4 + 2 + 1] += 1;
    CHECK(bye_sniff_tls(bad, n, &s) == BYE_SNIFF_MALFORMED);
}

static void test_http(void) {
    bye_sniff_t s;
    const char *req = "GET /index.html HTTP/1.1\r\nUser-Agent: x\r\nHost: Blocked.Example.org:8080 \r\n\r\n";
    CHECK(bye_sniff_http((const uint8_t *)req, strlen(req), &s) == BYE_SNIFF_OK);
    CHECK(s.name_len == strlen("Blocked.Example.org:8080") &&
          memcmp(req + s.name_off, "Blocked.Example.org:8080", s.name_len) == 0);

    req = "POST /a HTTP/1.1\r\nhOsT:\tfoo.org\r\nContent-Length: 0\r\n\r\n";
    CHECK(bye_sniff_http((const uint8_t *)req, strlen(req), &s) == BYE_SNIFF_OK);
    CHECK(s.name_len == 7 && memcmp(req + s.name_off, "foo.org", 7) == 0);

    /* headers that end with no host */
    req = "GET / HTTP/1.0\r\nAccept: */*\r\n\r\n";
    CHECK(bye_sniff_http((const uint8_t *)req, strlen(req), &s) == BYE_SNIFF_NO_NAME);

    /* the same request cut short is a prefix */
    req = "GET / HTTP/1.1\r\nHost: examp";
    CHECK(bye_sniff_http((const uint8_t *)req, strlen(req), &s) == BYE_SNIFF_NEED_MORE);
    req = "GET / HTT";
    CHECK(bye_sniff_http((const uint8_t *)req, strlen(req), &s) == BYE_SNIFF_NEED_MORE);
    CHECK(bye_sniff_http((const uint8_t *)"GE", 2, &s) == BYE_SNIFF_NEED_MORE);

    CHECK(bye_sniff_http((const uint8_t *)"\x16\x03\x01\x00\x10", 5, &s) == BYE_SNIFF_NO_MATCH);
    CHECK(bye_sniff_http((const uint8_t *)"get / HTTP/1.1\r\n", 16, &s) == BYE_SNIFF_NO_MATCH);
    CHECK(bye_sniff_http((const uint8_t *)"Host: x\r\n", 9, &s) == BYE_SNIFF_NO_MATCH);

    req = "GET / HTTP/1.1\r\nHost: \r\n\r\n";
    CHECK(bye_sniff_http((const uint8_t *)req, strlen(req), &s) == BYE_SNIFF_MALFORMED);

    /* a header block with no end inside the scan limit */
    uint8_t big[9000];
    memcpy(big, "GET / HTTP/1.1\r\n", 16);
    memset(big + 16, 'a', sizeof big - 16);
    CHECK(bye_sniff_http(big, sizeof big, &s) == BYE_SNIFF_MALFORMED);
}

int main(void) {
    test_hand_built();
    test_prefixes();
    test_real_hello();
    test_not_tls();
    test_malformed();
    test_http();
    if (!failed) puts("test_sniff ok");
    return failed;
}

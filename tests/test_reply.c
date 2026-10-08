#include "bye_reply.h"

#include <string.h>

#include "check.h"

static bye_reply_t parse(const char *text) {
    bye_reply_t reply;
    CHECK(bye_reply_parse(text, strlen(text), &reply) == 0);
    return reply;
}

static void test_status_line(void) {
    bye_reply_t r = parse("OK\nrunning=1\n");
    CHECK(r.ok && r.detail[0] == '\0' && r.body_len == strlen("running=1\n"));
    r = parse("OK utun0\n");
    CHECK(r.ok && strcmp(r.detail, "utun0") == 0 && r.body_len == 0);
    r = parse("ERR hosts list test.txt, line 1: not a domain name\n");
    CHECK(!r.ok && strcmp(r.detail, "hosts list test.txt, line 1: not a domain name") == 0);
    r = parse("ERR\n");
    CHECK(!r.ok && r.detail[0] == '\0');
    r = parse("OK   restart to apply  \r\n");
    CHECK(r.ok && strcmp(r.detail, "restart to apply") == 0);
    r = parse("OK");
    CHECK(r.ok && r.body_len == 0);

    bye_reply_t bad;
    CHECK(bye_reply_parse("", 0, &bad) == -1 && !bad.ok);
    CHECK(bye_reply_parse("OKAY\n", 5, &bad) == -1);
    CHECK(bye_reply_parse("ERRATA\n", 7, &bad) == -1);
    CHECK(bye_reply_parse("running=1\n", 10, &bad) == -1);
    CHECK(bye_reply_parse("ok\n", 3, &bad) == -1);
    CHECK(bye_reply_parse(NULL, 4, &bad) == -1);
    CHECK(bye_reply_parse("OK\n", 3, NULL) == -1);

    /* a detail longer than its field is cut, and the field ends with a NUL */
    char longtext[400] = "ERR ";
    memset(longtext + 4, 'x', 300);
    longtext[304] = '\n';
    bye_reply_t cut;
    CHECK(bye_reply_parse(longtext, 305, &cut) == 0 && !cut.ok);
    CHECK(strlen(cut.detail) == BYE_REPLY_DETAIL_MAX - 1);
}

static void test_values(void) {
    static const char text[] =
        "OK\nrunning=1\ninterface=utun0\nerror=\ndns=system dns stays 192.168.0.1, kept by a configd entry\n"
        "key with spaces = spaced value \nno equals here\n=orphan\nrunning=2\ntcp.up=1048576\n";
    bye_reply_t r;
    CHECK(bye_reply_parse(text, sizeof text - 1, &r) == 0);
    char v[64];
    CHECK(bye_reply_value(&r, "running", v, sizeof v) && strcmp(v, "1") == 0);
    CHECK(bye_reply_value(&r, "interface", v, sizeof v) && strcmp(v, "utun0") == 0);
    CHECK(bye_reply_value(&r, "error", v, sizeof v) && v[0] == '\0');
    CHECK(bye_reply_value(&r, "key with spaces", v, sizeof v) && strcmp(v, "spaced value") == 0);
    CHECK(bye_reply_value(&r, "tcp.up", v, sizeof v) && strcmp(v, "1048576") == 0);
    CHECK(!bye_reply_value(&r, "missing", v, sizeof v) && v[0] == '\0');
    CHECK(!bye_reply_value(&r, "no equals here", v, sizeof v));
    CHECK(!bye_reply_value(&r, "", v, sizeof v));
    CHECK(!bye_reply_value(&r, "runnin", v, sizeof v) && !bye_reply_value(&r, "running1", v, sizeof v));
    /* a value longer than the buffer is cut, not overrun */
    char tiny[8];
    CHECK(bye_reply_value(&r, "dns", tiny, sizeof tiny) && strcmp(tiny, "system ") == 0);
    CHECK(!bye_reply_value(NULL, "x", v, sizeof v) && !bye_reply_value(&r, NULL, v, sizeof v));
    CHECK(bye_reply_value(&r, "running", NULL, 0) == 1);

    /* the config reply writes "key = value" */
    static const char config[] = "OK\ndesync = on\ndesync.spec = tlsrec=name+1;split=1,name+1|none\nhosts = none\n";
    CHECK(bye_reply_parse(config, sizeof config - 1, &r) == 0);
    CHECK(bye_reply_value(&r, "desync.spec", v, sizeof v) &&
          strcmp(v, "tlsrec=name+1;split=1,name+1|none") == 0);
    CHECK(bye_reply_value(&r, "hosts", v, sizeof v) && strcmp(v, "none") == 0);

    size_t cursor = 0, count = 0;
    char k[32];
    CHECK(bye_reply_parse(text, sizeof text - 1, &r) == 0);
    while (bye_reply_next(&r, &cursor, k, sizeof k, v, sizeof v)) ++count;
    CHECK(count == 7);
    CHECK(!bye_reply_next(&r, &cursor, k, sizeof k, v, sizeof v));
    size_t none = 0;
    CHECK(!bye_reply_next(NULL, &none, k, sizeof k, v, sizeof v));
    CHECK(!bye_reply_next(&r, NULL, k, sizeof k, v, sizeof v));
    /* a last line without a newline still counts */
    CHECK(bye_reply_parse("OK\na=1\nb=2", 10, &r) == 0);
    cursor = 0;
    count = 0;
    while (bye_reply_next(&r, &cursor, k, sizeof k, v, sizeof v)) ++count;
    CHECK(count == 2 && strcmp(v, "2") == 0);
}

static void test_candidate(void) {
    bye_reply_candidate_t c;
    CHECK(bye_reply_candidate("2/2 366ms tlsrec=name+1;split=1,name+1", &c));
    CHECK(c.ok == 2 && c.tried == 2 && c.ms == 366 && strcmp(c.spec, "tlsrec=name+1;split=1,name+1") == 0);
    CHECK(bye_reply_candidate("0/2 0ms none", &c) && c.ok == 0 && c.tried == 2 && strcmp(c.spec, "none") == 0);
    CHECK(bye_reply_candidate("1/2 944ms oob=1", &c) && c.ms == 944);
    CHECK(bye_reply_candidate("0/0 0ms split=1", &c) && c.tried == 0);

    static const char *const bad[] = {
        "", "2/2", "2/2 366ms", "2/2 366ms ", "2 366ms split=1", "a/2 1ms x", "2/b 1ms x", "2/2 xms x",
        "3/2 1ms x", "2/2 366 split=1", "2/2366ms split=1", "-1/2 1ms x", "2/2 1ms", "99999999999/2 1ms x",
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        CHECK(!bye_reply_candidate(bad[i], &c));
        CHECK(c.spec[0] == '\0' && c.ok == 0);
    }
    char long_value[1100] = "1/1 1ms ";
    memset(long_value + 8, 'a', 1024);
    long_value[1032] = '\0';
    CHECK(!bye_reply_candidate(long_value, &c));
    CHECK(!bye_reply_candidate(NULL, &c) && !bye_reply_candidate("1/1 1ms x", NULL));
}

/* the report as it came from the iphone 4s */
static void test_real_report(void) {
    static const char text[] =
        "OK\nstate=done\nprogress=18/18\nconfigured=4\n"
        "candidate.0=2/2 366ms tlsrec=name+1;split=1,name+1\n"
        "candidate.1=0/2 0ms split=1,name+1\n"
        "candidate.2=2/2 255ms split=1,name+1;oob=1\n"
        "candidate.3=0/2 0ms none\n"
        "address.0=youtube.com 142.251.156.4\n"
        "suggest=tlsrec=name+1;split=1,name+1|split=1,name+1;oob=1\n";
    bye_reply_t r;
    CHECK(bye_reply_parse(text, sizeof text - 1, &r) == 0);
    size_t cursor = 0, found = 0;
    char k[32], v[160];
    unsigned ok_total = 0;
    while (bye_reply_next(&r, &cursor, k, sizeof k, v, sizeof v)) {
        bye_reply_candidate_t c;
        if (strncmp(k, "candidate.", 10) != 0) continue;
        CHECK(bye_reply_candidate(v, &c));
        ok_total += c.ok;
        ++found;
    }
    CHECK(found == 4 && ok_total == 4);
    CHECK(bye_reply_value(&r, "suggest", v, sizeof v) &&
          strcmp(v, "tlsrec=name+1;split=1,name+1|split=1,name+1;oob=1") == 0);
}

int main(void) {
    test_status_line();
    test_values();
    test_candidate();
    test_real_report();
    if (!failed) puts("test_reply ok");
    return failed;
}

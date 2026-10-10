#include "bye_desync.h"

#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "hello_openssl.inc"

static bye_desync_t parse_ok(const char *spec) {
    bye_desync_t d;
    char error[64];
    CHECK(bye_desync_parse(spec, &d, error, sizeof error) == BYE_DESYNC_OK);
    return d;
}

static void test_parse(void) {
    char error[64];
    bye_desync_t d = parse_ok("split=1,name+1;tlsrec=name+1;oob=mid");
    CHECK(d.split_count == 2);
    CHECK(d.split[0].kind == BYE_POS_ABS && d.split[0].delta == 1);
    CHECK(d.split[1].kind == BYE_POS_NAME && d.split[1].delta == 1);
    CHECK(d.has_tlsrec && d.tlsrec.kind == BYE_POS_NAME && d.tlsrec.delta == 1);
    CHECK(d.has_oob && d.oob.kind == BYE_POS_MID && d.oob.delta == 0);

    d = parse_ok(" split = 3 , end-2 ; ");
    CHECK(d.split_count == 2 && d.split[1].kind == BYE_POS_END && d.split[1].delta == -2);

    d = parse_ok("");
    CHECK(d.split_count == 0 && !d.has_tlsrec && !d.has_oob);
    d = parse_ok(BYE_DESYNC_DEFAULT_SPEC);
    CHECK(d.split_count == 2 && d.has_tlsrec);

    static const char *bad[] = {
        "split", "split=", "split=0", "split=-1", "split=1,", "split=,1", "split=a",
        "split=name+", "split=name+x", "split=1,2,3,4,5", "split=1;split=2",
        "tlsrec=", "tlsrec=1;tlsrec=2", "oob=0", "oob=1;oob=2", "frob=1", "name=1",
        "split=999999", "split=mid*2"
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        CHECK(bye_desync_parse(bad[i], &d, error, sizeof error) == BYE_DESYNC_ERR_SPEC);
        CHECK(error[0] != '\0');
    }
    CHECK(bye_desync_parse(NULL, &d, NULL, 0) == BYE_DESYNC_ERR_ARG);
    CHECK(bye_desync_parse("", NULL, NULL, 0) == BYE_DESYNC_ERR_ARG);
}

/* the records of a stream, joined: what a server sees as the handshake */
static size_t join_records(const uint8_t *buf, size_t len, uint8_t *body) {
    size_t at = 0, n = 0;
    while (at + 5 <= len) {
        size_t rec = ((size_t)buf[at + 3] << 8) | buf[at + 4];
        if (buf[at] != 0x16 || at + 5 + rec > len) return (size_t)-1;
        memcpy(body + n, buf + at + 5, rec);
        n += rec;
        at += 5 + rec;
    }
    return at == len ? n : (size_t)-1;
}

static size_t plan_bytes(const bye_plan_t *plan, const uint8_t *out, uint8_t *joined) {
    size_t n = 0;
    for (size_t i = 0; i < plan->count; ++i) {
        memcpy(joined + n, out + plan->ops[i].off, plan->ops[i].len);
        n += plan->ops[i].len;
    }
    return n;
}

static void check_plan_covers(const bye_plan_t *plan) {
    size_t at = 0;
    for (size_t i = 0; i < plan->count; ++i) {
        CHECK(plan->ops[i].off == at);
        CHECK(plan->ops[i].len > 0);
        at += plan->ops[i].len;
    }
    CHECK(at == plan->total);
}

static void test_tls(void) {
    bye_sniff_t name;
    CHECK(bye_sniff_tls(hello_openssl, hello_openssl_len, &name) == BYE_SNIFF_OK);

    uint8_t out[2048], joined[2048], original_body[2048], new_body[2048];
    bye_plan_t plan;
    bye_desync_t d = parse_ok(BYE_DESYNC_DEFAULT_SPEC);

    CHECK(bye_desync_build(&d, hello_openssl, hello_openssl_len, out, sizeof out, &plan)
          == BYE_DESYNC_OK);
    check_plan_covers(&plan);
    CHECK(plan.applied);
    CHECK(plan.total == hello_openssl_len + 5);
    /* cuts: after the first byte, then where the second record starts, one
       byte into the name */
    CHECK(plan.count == 3);
    CHECK(plan.ops[0].len == 1);
    size_t cut = name.name_off + 1;
    CHECK(plan.ops[1].off + plan.ops[1].len == cut);
    CHECK(plan.ops[2].len == plan.total - cut);

    size_t n = plan_bytes(&plan, out, joined);
    CHECK(n == plan.total);
    size_t body_len = join_records(joined, n, new_body);
    size_t original_len = join_records(hello_openssl, hello_openssl_len, original_body);
    CHECK(body_len == original_len && body_len != (size_t)-1);
    CHECK(memcmp(new_body, original_body, original_len) == 0);
    /* two records now, the second starts at the name */
    CHECK(out[3] * 256 + out[4] == (int)(name.name_off + 1 - 5));
    CHECK(out[name.name_off + 1] == 0x16);

    /* a split alone changes no byte */
    d = parse_ok("split=1,mid");
    CHECK(bye_desync_build(&d, hello_openssl, hello_openssl_len, out, sizeof out, &plan)
          == BYE_DESYNC_OK);
    check_plan_covers(&plan);
    CHECK(plan.count == 3 && plan.total == hello_openssl_len);
    CHECK(plan.ops[1].off + plan.ops[1].len == name.name_off + name.name_len / 2);
    CHECK(memcmp(out, hello_openssl, hello_openssl_len) == 0);

    /* a record cut alone is one send with two records inside */
    d = parse_ok("tlsrec=end");
    CHECK(bye_desync_build(&d, hello_openssl, hello_openssl_len, out, sizeof out, &plan)
          == BYE_DESYNC_OK);
    CHECK(plan.count == 1 && plan.applied && plan.total == hello_openssl_len + 5);
    CHECK(join_records(out, plan.total, new_body) == original_len);
    CHECK(memcmp(new_body, original_body, original_len) == 0);

    /* a cut at the record cut stays before the new header, one before it too */
    d = parse_ok("tlsrec=name;split=name,name-1");
    CHECK(bye_desync_build(&d, hello_openssl, hello_openssl_len, out, sizeof out, &plan)
          == BYE_DESYNC_OK);
    check_plan_covers(&plan);
    CHECK(plan.count == 3);
    CHECK(plan.ops[0].len == name.name_off - 1);
    CHECK(plan.ops[1].len == 1);
    CHECK(out[name.name_off] == 0x16);
    CHECK(plan.ops[2].off == name.name_off);

    /* out of range positions are dropped, not clamped */
    d = parse_ok("split=5000,name-5000;tlsrec=3");
    CHECK(bye_desync_build(&d, hello_openssl, hello_openssl_len, out, sizeof out, &plan)
          == BYE_DESYNC_OK);
    CHECK(plan.count == 1 && !plan.applied && plan.total == hello_openssl_len);
    CHECK(memcmp(out, hello_openssl, hello_openssl_len) == 0);

    /* two cuts at one offset are one cut, and an oob flag survives the merge */
    d = parse_ok("split=7;oob=7");
    CHECK(bye_desync_build(&d, hello_openssl, hello_openssl_len, out, sizeof out, &plan)
          == BYE_DESYNC_OK);
    CHECK(plan.count == 2 && plan.ops[0].len == 7 && plan.ops[0].oob_after == 1);
    CHECK(plan.ops[1].oob_after == 0);
}

/* only the front of the hello is in hand when the name shows: the plan covers
   those bytes and a record cut past them is left out */
static void test_partial_hello(void) {
    bye_sniff_t name;
    CHECK(bye_sniff_tls(hello_openssl, hello_openssl_len, &name) == BYE_SNIFF_OK);
    size_t have = name.name_off + name.name_len;
    uint8_t out[2048], joined[2048];
    bye_plan_t plan;

    bye_desync_t d = parse_ok("tlsrec=end+400;split=1,end");
    CHECK(bye_desync_build(&d, hello_openssl, have, out, sizeof out, &plan) == BYE_DESYNC_OK);
    check_plan_covers(&plan);
    CHECK(plan.total == have);
    CHECK(plan_bytes(&plan, out, joined) == have && memcmp(joined, hello_openssl, have) == 0);

    /* a record cut inside the bytes in hand still works, and the rest of the
       hello can follow unchanged */
    d = parse_ok("tlsrec=name+1");
    CHECK(bye_desync_build(&d, hello_openssl, have, out, sizeof out, &plan) == BYE_DESYNC_OK);
    CHECK(plan.total == have + 5);
    uint8_t stream[2048], original_body[2048], new_body[2048];
    memcpy(stream, out, plan.total);
    memcpy(stream + plan.total, hello_openssl + have, hello_openssl_len - have);
    size_t n = plan.total + hello_openssl_len - have;
    CHECK(join_records(stream, n, new_body) == join_records(hello_openssl, hello_openssl_len, original_body));
    CHECK(memcmp(new_body, original_body, hello_openssl_len - 5) == 0);

    /* a cut at the very end of what is in hand is dropped too */
    d = parse_ok("tlsrec=end");
    CHECK(bye_desync_build(&d, hello_openssl, have, out, sizeof out, &plan) == BYE_DESYNC_OK);
    CHECK(plan.total == have && !plan.applied);
}

static void test_boundaries(void) {
    uint8_t out[2048];
    bye_plan_t plan;

    /* a prefix that does not hold the name yet asks for more */
    bye_desync_t d = parse_ok(BYE_DESYNC_DEFAULT_SPEC);
    CHECK(bye_desync_build(&d, hello_openssl, 40, out, sizeof out, &plan) == BYE_DESYNC_NEED_MORE);
    CHECK(bye_desync_build(&d, hello_openssl, 1, out, sizeof out, &plan) == BYE_DESYNC_NEED_MORE);

    /* the buffer must hold what the plan may add: record headers and an urgent byte */
    CHECK(bye_desync_build(&d, hello_openssl, hello_openssl_len, out,
                           hello_openssl_len + BYE_DESYNC_GROWTH_MAX - 1, &plan) == BYE_DESYNC_ERR_SPACE);
    CHECK(bye_desync_build(&d, hello_openssl, hello_openssl_len, out,
                           hello_openssl_len + BYE_DESYNC_GROWTH_MAX, &plan) == BYE_DESYNC_OK);

    CHECK(bye_desync_build(NULL, hello_openssl, 10, out, sizeof out, &plan) == BYE_DESYNC_ERR_ARG);
    CHECK(bye_desync_build(&d, hello_openssl, 0, out, sizeof out, &plan) == BYE_DESYNC_ERR_ARG);

    /* another protocol, or data with no name, goes out whole */
    const char *other = "SSH-2.0-OpenSSH_9.0\r\n";
    CHECK(bye_desync_build(&d, (const uint8_t *)other, strlen(other), out, sizeof out, &plan)
          == BYE_DESYNC_OK);
    CHECK(plan.count == 1 && !plan.applied && plan.total == strlen(other));
    CHECK(memcmp(out, other, strlen(other)) == 0);

    /* the hello stops where the application data begins */
    uint8_t tail[2048];
    memcpy(tail, hello_openssl, hello_openssl_len);
    memcpy(tail + hello_openssl_len, "\x14\x03\x03\x00\x01\x01", 6);
    CHECK(bye_desync_build(&d, tail, hello_openssl_len + 6, out, sizeof out, &plan) == BYE_DESYNC_OK);
    check_plan_covers(&plan);
    CHECK(plan.total == hello_openssl_len + 6 + 5);
    CHECK(memcmp(out + plan.total - 6, "\x14\x03\x03\x00\x01\x01", 6) == 0);
}

static void test_http(void) {
    const char *req = "GET / HTTP/1.1\r\nHost: blocked.example.org\r\nAccept: */*\r\n\r\n";
    size_t len = strlen(req);
    const char *host = strstr(req, "blocked");
    uint8_t out[256], joined[256];
    bye_plan_t plan;
    bye_desync_t d = parse_ok("split=1,name+3;tlsrec=name");
    CHECK(bye_desync_build(&d, (const uint8_t *)req, len, out, sizeof out, &plan) == BYE_DESYNC_OK);
    check_plan_covers(&plan);
    CHECK(plan.count == 3 && plan.total == len);
    CHECK(plan.ops[0].len == 1);
    CHECK(plan.ops[1].off + plan.ops[1].len == (size_t)(host - req) + 3);
    CHECK(plan_bytes(&plan, out, joined) == len && memcmp(joined, req, len) == 0);

    /* the request is not complete: the host header has not arrived */
    CHECK(bye_desync_build(&d, (const uint8_t *)req, 20, out, sizeof out, &plan)
          == BYE_DESYNC_NEED_MORE);
}

static void test_strategies(void) {
    bye_strategies_t list;
    char error[48];
    CHECK(bye_strategies_parse("split=1", &list, error, sizeof error) == BYE_DESYNC_OK);
    CHECK(list.count == 1 && list.item[0].split_count == 1);
    CHECK(bye_strategies_parse(BYE_STRATEGIES_DEFAULT, &list, error, sizeof error) == BYE_DESYNC_OK);
    /* auto is the built-in list, tried in order, the plain hello last */
    CHECK(list.count == 4);
    CHECK(list.item[0].has_tlsrec && list.item[0].tlsrec.kind == BYE_POS_MID && list.item[0].split_count == 2);
    CHECK(list.item[2].has_oob && list.item[3].split_count == 0 && !list.item[3].has_tlsrec);
    CHECK(bye_strategies_after(&list, 0, 0, BYE_TRIGGER_TORST) == 1);
    CHECK(bye_strategies_after(&list, 0, 3, BYE_TRIGGER_TORST) == 0);
    CHECK(bye_strategies_parse("  auto ", &list, error, sizeof error) == BYE_DESYNC_OK && list.count == 4);
    CHECK(bye_strategies_parse("auto|none", &list, error, sizeof error) == BYE_DESYNC_ERR_SPEC);
    CHECK(bye_strategies_parse("autos", &list, error, sizeof error) == BYE_DESYNC_ERR_SPEC);
    CHECK(bye_strategies_parse(" none | split=2 ", &list, error, sizeof error) == BYE_DESYNC_OK);
    CHECK(list.count == 2 && list.item[0].split_count == 0 && list.item[1].split_count == 1);

    static const char *const bad[] = { "", "|", "split=1|", "|split=1", "split=1||none", " ",
        "none|none|none|none|none|none|none|none|none", "split=1|frob=2", "none;split=1" };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i)
        CHECK(bye_strategies_parse(bad[i], &list, error, sizeof error) == BYE_DESYNC_ERR_SPEC);
    char long_item[BYE_STRATEGY_SPEC_MAX + 8];
    memset(long_item, 'a', sizeof long_item - 1);
    long_item[sizeof long_item - 1] = '\0';
    CHECK(bye_strategies_parse(long_item, &list, error, sizeof error) == BYE_DESYNC_ERR_SPEC);
    CHECK(bye_strategies_parse(NULL, &list, error, sizeof error) == BYE_DESYNC_ERR_ARG);

    /* a ciadpi line among native items, as the strategy editor saves it, brings its own groups */
    bye_strategies_t cli_only;
    CHECK(bye_strategies_parse("-d1 -s5+s -As -s3+s", &cli_only, error, sizeof error) == BYE_DESYNC_OK);
    CHECK(bye_strategies_parse("tlsrec=mid|-d1 -s5+s -As -s3+s|none", &list, error, sizeof error) == BYE_DESYNC_OK);
    CHECK(list.count == cli_only.count + 2 && !list.item[0].cli && list.item[1].cli &&
          !list.item[list.count - 1].cli);
    CHECK(bye_strategies_parse("none|-d1 -T 7|none", &list, error, sizeof error) == BYE_DESYNC_OK);
    CHECK(list.count == 3 && list.timeout_ms != 0);
    CHECK(bye_strategies_parse("none|-d1 -frob|none", &list, error, sizeof error) == BYE_DESYNC_ERR_SPEC);
    /* groups and native items together still stop at the list limit */
    CHECK(bye_strategies_parse("none|none|none|none|none|none|none|-d1 -As -d2", &list, error, sizeof error) ==
          BYE_DESYNC_ERR_SPEC);
    char long_cli[BYE_STRATEGY_LINE_MAX + 8];
    memset(long_cli, ' ', sizeof long_cli - 1);
    long_cli[sizeof long_cli - 1] = '\0';
    memcpy(long_cli, "none|-d1", 8);
    long_cli[8] = ' ';
    long_cli[sizeof long_cli - 2] = '1';
    CHECK(bye_strategies_parse(long_cli, &list, error, sizeof error) == BYE_DESYNC_ERR_SPEC);

    /* the none strategy sends the hello as it is, and the plan still names the server */
    uint8_t out[sizeof hello_openssl + BYE_DESYNC_GROWTH_MAX];
    bye_plan_t plan;
    CHECK(bye_strategies_parse("none", &list, error, sizeof error) == BYE_DESYNC_OK);
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.count == 1 && !plan.applied && plan.total == hello_openssl_len);
    CHECK(plan.has_name && plan.tls && plan.name_len > 0 &&
          plan.name_off + plan.name_len <= hello_openssl_len);
    CHECK(memcmp(out, hello_openssl, hello_openssl_len) == 0);
    bye_desync_t cut = parse_ok(BYE_DESYNC_DEFAULT_SPEC);
    CHECK(bye_desync_build(&cut, hello_openssl, hello_openssl_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.applied && plan.has_name && plan.tls);

    /* an http request has a name too, a stream of another protocol has none */
    static const char req[] = "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n";
    CHECK(bye_desync_build(&cut, (const uint8_t *)req, sizeof req - 1, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.has_name && !plan.tls && plan.name_len == 11 &&
          memcmp(req + plan.name_off, "example.org", 11) == 0);
    static const uint8_t other[] = { 0x13, 0x37, 0x00, 0x01, 0x02 };
    CHECK(bye_desync_build(&cut, other, sizeof other, out, sizeof out, &plan) == BYE_DESYNC_OK);
    CHECK(!plan.has_name && !plan.applied && plan.count == 1);
}



static bye_strategies_t cli_ok(const char *text) {
    bye_strategies_t list;
    char error[96];
    bye_desync_status_t status = bye_strategies_parse(text, &list, error, sizeof error);
    if (status != BYE_DESYNC_OK) fprintf(stderr, "cli_ok(%s): %s\n", text, error);
    CHECK(status == BYE_DESYNC_OK);
    return list;
}

static int cli_bad(const char *text) {
    bye_strategies_t list;
    char error[96];
    int bad = bye_strategies_parse(text, &list, error, sizeof error) == BYE_DESYNC_ERR_SPEC &&
              error[0] != '\0';
    if (!bad) fprintf(stderr, "cli_bad(%s) was accepted or had no message\n", text);
    return bad;
}

static void test_cli_parse(void) {
    /* the line a user pastes from the original: two groups, the second one for a bad answer */
    static const char line[] =
        "-d1 -d3+s -s6+s -d9+s -s12+s -d15+s -s20+s -d25+s -s30+s -d35+s -r1+s -S -a1 "
        "-As -d1 -d3+s -s6+s -d9+s -s12+s -d15+s -s20+s -d25+s -s30+s -d35+s -S -a1";
    bye_strategies_t list = cli_ok(line);
    CHECK(list.count == 2);
    CHECK(list.item[0].cli && list.item[0].trigger == 0);
    CHECK(list.item[0].part_count == 10 && list.item[0].tlsrec_count == 1);
    CHECK(list.item[0].tlsrec_parts[0].offset == 1 && list.item[0].tlsrec_parts[0].flags == BYE_OFFSET_SNI);
    CHECK(list.item[1].cli && list.item[1].trigger == BYE_TRIGGER_TLSERR);
    CHECK(list.item[1].part_count == 10 && list.item[1].tlsrec_count == 0);
    for (size_t i = 0; i < 10; ++i) {
        static const int32_t at[] = { 1, 3, 6, 9, 12, 15, 20, 25, 30, 35 };
        static const char mode[] = { 'd', 'd', 's', 'd', 's', 'd', 's', 'd', 's', 'd' };
        CHECK(list.item[0].parts[i].pos.offset == at[i]);
        CHECK(list.item[0].parts[i].mode == (mode[i] == 'd' ? BYE_PART_DISORDER : BYE_PART_SPLIT));
        CHECK(list.item[0].parts[i].pos.flags == (i ? BYE_OFFSET_SNI : 0u));
    }
    CHECK(strstr(list.notes, "-S") && strstr(list.notes, "-a"));
    CHECK(list.timeout_ms == 0 && list.def_ttl == 0);

    /* long options, quotes and clusters read the same */
    list = cli_ok("--disorder=1 --split 5+h --oob 7");
    CHECK(list.count == 1 && list.item[0].part_count == 3);
    CHECK(list.item[0].parts[0].mode == BYE_PART_DISORDER && list.item[0].parts[1].mode == BYE_PART_SPLIT &&
          list.item[0].parts[2].mode == BYE_PART_OOB);
    CHECK(list.item[0].parts[1].pos.flags == BYE_OFFSET_HOST);
    list = cli_ok("  -e '\\x41' -o 3 -q 5 -M h,d -m 2 -Kt,h -g 64 -T 2.5 -f 4 ");
    CHECK(list.item[0].oob_char_set && list.item[0].oob_char == 0x41);
    CHECK(list.item[0].parts[1].mode == BYE_PART_DISOOB && list.item[0].parts[2].mode == BYE_PART_SPLIT);
    CHECK(list.item[0].mod_http == (BYE_HTTP_HMIX | BYE_HTTP_DMIX) && list.item[0].tlsminor == 2);
    CHECK(list.item[0].proto == (BYE_PROTO_TLS | BYE_PROTO_HTTP));
    CHECK(list.def_ttl == 64 && list.timeout_ms == 2500);
    CHECK(strstr(list.notes, "-f"));
    list = cli_ok("-s1:3:2 -s-1 -s4+nm -s0+sr -s2+ss");
    CHECK(list.item[0].parts[0].pos.repeats == 3 && list.item[0].parts[0].pos.skip == 2);
    CHECK(list.item[0].parts[1].pos.offset == -1);
    CHECK(list.item[0].parts[2].pos.flags == BYE_OFFSET_MID);
    CHECK(list.item[0].parts[3].pos.flags == (BYE_OFFSET_SNI | BYE_OFFSET_RAND));
    CHECK(list.item[0].parts[4].pos.flags == (BYE_OFFSET_SNI | BYE_OFFSET_START));
    list = cli_ok("-At,r -s1 -An -d2 -Ac -s3");
    CHECK(list.count == 4 && list.item[1].trigger == (BYE_TRIGGER_TORST | BYE_TRIGGER_REDIRECT));
    CHECK(list.item[2].trigger == 0 && list.item[3].trigger == 0 && strstr(list.notes, "-A c"));
    list = cli_ok("-i 0.0.0.0 -p 1080 -c 512 -N -D -R 1 -H hosts.txt");
    CHECK(list.count == 1 && list.item[0].part_count == 0 && strstr(list.notes, "proxy"));

    static const char *const bad[] = {
        "-d", "-d x", "-d 1+x", "-d 1:0", "-d 1:-2", "-d +s", "-d 1+s? ", "-s 99999999999",
        "-r 70000", "-r -1x", "-Kx", "-Mx", "-m 0", "-m 256", "-g 0", "-g 300", "-e ab", "-T x",
        "-A x", "-Ap", "-Ap=", "-d1 foo", "--bogus", "--split", "--split=1 --nosuch", "-d1 -d2 -h",
        "-v", "-z", "-d1 --no-udp=1", "-e '\\x4", "-d1 \"quote", "-a x", "-t 0", "-s1:70000"
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) CHECK(cli_bad(bad[i]));

    /* limits */
    char big[1400];
    size_t n = 0;
    for (int i = 0; i < 33; ++i) n += (size_t)snprintf(big + n, sizeof big - n, "-s%d ", i + 1);
    CHECK(cli_bad(big));
    n = 0;
    for (int i = 0; i < 9; ++i) n += (size_t)snprintf(big + n, sizeof big - n, "-r%d ", i + 1);
    CHECK(cli_bad(big));
    n = 0;
    for (int i = 0; i < 9; ++i) n += (size_t)snprintf(big + n, sizeof big - n, "-As -s1 ");
    CHECK(cli_bad(big));
    memset(big, ' ', sizeof big - 1);
    big[sizeof big - 1] = '\0';
    memcpy(big, "-d1", 3);
    CHECK(cli_bad(big));
}

static void test_cli_plan(void) {
    bye_sniff_t name;
    CHECK(bye_sniff_tls(hello_openssl, hello_openssl_len, &name) == BYE_SNIFF_OK);
    uint8_t out[sizeof hello_openssl + BYE_DESYNC_GROWTH_MAX], joined[sizeof out];
    bye_plan_t plan;

    /* a plain cut and a disorder, the rest goes after them */
    bye_strategies_t list = cli_ok("-d1 -s5");
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    check_plan_covers(&plan);
    CHECK(plan.count == 3 && plan.total == hello_openssl_len && plan.applied);
    CHECK(plan.ops[0].len == 1 && plan.ops[0].flags == BYE_OP_TTL1);
    CHECK(plan.ops[1].len == 4 && plan.ops[1].flags == 0 && plan.ops[2].flags == 0);
    CHECK(plan.has_name && plan.tls && plan.name_off == name.name_off);
    CHECK(plan_bytes(&plan, out, joined) == hello_openssl_len &&
          memcmp(joined, hello_openssl, hello_openssl_len) == 0);

    /* names: sni, mid and end, and a name that is not there cancels the rest */
    list = cli_ok("-s0+sm -s0+se -s5+he");
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.count == 4);
    CHECK(plan.ops[0].len == name.name_off + name.name_len / 2);
    CHECK(plan.ops[1].off + plan.ops[1].len == name.name_off + name.name_len);
    CHECK(plan.ops[2].off + plan.ops[2].len == name.name_off + name.name_len + 5);
    static const char ssh[] = "SSH-2.0-OpenSSH_9.0\r\n";
    list = cli_ok("-s3+s -s8");
    CHECK(bye_desync_build(&list.item[0], (const uint8_t *)ssh, sizeof ssh - 1, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.count == 1 && !plan.applied && !plan.has_name);
    list = cli_ok("-s3 -s8 -s-2");
    CHECK(bye_desync_build(&list.item[0], (const uint8_t *)ssh, sizeof ssh - 1, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.count == 4 && plan.ops[0].len == 3 && plan.ops[1].len == 5 && plan.ops[2].len == sizeof ssh - 1 - 2 - 8);

    /* repeats walk by skip, and a repeat that lands on the last cut is empty */
    list = cli_ok("-s2:3:2");
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    check_plan_covers(&plan);
    CHECK(plan.count == 4 && plan.ops[0].len == 2 && plan.ops[1].len == 2 && plan.ops[2].len == 2);
    list = cli_ok("-s2:3");
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.count == 2);
    /* disorder takes every second repeat, as ciadpi does */
    list = cli_ok("-d1:4:1");
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.count == 5 && plan.ops[0].flags == BYE_OP_TTL1 && plan.ops[1].flags == 0 &&
          plan.ops[2].flags == BYE_OP_TTL1 && plan.ops[3].flags == 0 && plan.ops[4].flags == 0);
    /* a repeat count far past what a plan holds still sends every byte */
    list = cli_ok("-s1:60000:1");
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.count <= BYE_DESYNC_OPS_MAX);
    check_plan_covers(&plan);
    CHECK(plan_bytes(&plan, out, joined) == hello_openssl_len &&
          memcmp(joined, hello_openssl, hello_openssl_len) == 0);

    /* oob: a segment and the urgent byte that stands in for the next one */
    list = cli_ok("-o2 -q4");
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.count == 3 && plan.ops[0].len == 2 && plan.ops[0].flags == BYE_OP_OOB);
    CHECK(plan.ops[1].len == 2 && plan.ops[1].flags == (BYE_OP_TTL1 | BYE_OP_OOB));
    CHECK(plan.oob_char == BYE_DESYNC_OOB_BYTE);
    CHECK(plan_bytes(&plan, out, joined) == hello_openssl_len &&
          memcmp(joined, hello_openssl, hello_openssl_len) == 0);
    list = cli_ok("-e '\\x00' -o3");
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.oob_char == 0);
    /* an oob on the last byte uses the spare byte behind the plan */
    char last[24];
    snprintf(last, sizeof last, "-o%u", (unsigned)hello_openssl_len);
    list = cli_ok(last);
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.count == 1 && plan.ops[0].len == hello_openssl_len && plan.total == hello_openssl_len);

    /* tlsrec: the header sits one byte into the name, the cut counts from the app's bytes */
    list = cli_ok("-r1+s");
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.total == hello_openssl_len + 5 && plan.applied && plan.count == 1);
    CHECK(out[3] * 256 + out[4] == (int)(name.name_off + 1 - 5));
    CHECK(out[name.name_off + 1] == 0x16);
    CHECK((out[name.name_off + 4] << 8 | out[name.name_off + 5]) ==
          (int)(hello_openssl_len - 5 - (name.name_off + 1 - 5)));
    CHECK(join_records(out, plan.total, joined) == hello_openssl_len - 5 &&
          memcmp(joined, hello_openssl + 5, hello_openssl_len - 5) == 0);
    /* a plain offset counts the record body */
    list = cli_ok("-r10");
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(out[3] * 256 + out[4] == 10 && out[15] == 0x16 &&
          join_records(out, plan.total, joined) == hello_openssl_len - 5);
    /* two cuts make three records, and the second counts from the app's bytes too */
    list = cli_ok("-r10 -r30");
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.total == hello_openssl_len + 10 && out[3] * 256 + out[4] == 10 &&
          out[15 + 3] * 256 + out[15 + 4] == 20);
    CHECK(join_records(out, plan.total, joined) == hello_openssl_len - 5 &&
          memcmp(joined, hello_openssl + 5, hello_openssl_len - 5) == 0);
    /* a cut behind the record, behind the previous cut, or without a name is not made */
    list = cli_ok("-r60000");
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.total == hello_openssl_len && !plan.applied);
    list = cli_ok("-r30 -r10");
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.total == hello_openssl_len + 5);
    list = cli_ok("-r1+h");
    CHECK(bye_desync_build(&list.item[0], (const uint8_t *)ssh, sizeof ssh - 1, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.total == sizeof ssh - 1);
    /* the parts run on the bytes after the tlsrec, with the name where the app had it */
    list = cli_ok("-r1+s -d1 -s3+s");
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    check_plan_covers(&plan);
    CHECK(plan.count == 3 && plan.ops[0].len == 1 && plan.ops[1].off + plan.ops[1].len == name.name_off + 3);
    CHECK(plan.total == hello_openssl_len + 5);
    list = cli_ok("-m 2");
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(out[2] == 2 && plan.applied && plan.count == 1);

    /* the group for another protocol leaves the bytes alone */
    list = cli_ok("-Kh -s5");
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.count == 1 && !plan.applied && plan.has_name);
    static const char req[] = "GET / HTTP/1.1\r\nHost: blocked.example.org\r\nAccept: */*\r\n\r\n";
    size_t req_len = sizeof req - 1;
    const char *host = strstr(req, "blocked");
    list = cli_ok("-Kt -s5");
    CHECK(bye_desync_build(&list.item[0], (const uint8_t *)req, req_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.count == 1 && !plan.applied);

    /* http: +h counts from the host, and +s is a tls thing */
    list = cli_ok("-s0+h -s3+hm -s2+s");
    CHECK(bye_desync_build(&list.item[0], (const uint8_t *)req, req_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.count == 3 && plan.ops[0].len == (size_t)(host - req));
    CHECK(plan.has_name && !plan.tls && plan.name_off == (size_t)(host - req));
    /* mod-http */
    list = cli_ok("-Mh");
    CHECK(bye_desync_build(&list.item[0], (const uint8_t *)req, req_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(memcmp(out, "GET / HTTP/1.1\r\nhOsT: blocked.example.org\r\n", 41) == 0 && plan.applied);
    list = cli_ok("-Md");
    CHECK(bye_desync_build(&list.item[0], (const uint8_t *)req, req_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(memcmp(out + (host - req), "BlOcKeD.ExAmPlE.OrG", 19) == 0);
    list = cli_ok("-Mr -s0+h");
    CHECK(bye_desync_build(&list.item[0], (const uint8_t *)req, req_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(memcmp(out, "GET / HTTP/1.1\r\nHost:blocked.example.org\t\r\n", 41) == 0);
    CHECK(plan.count == 2 && plan.ops[0].len == (size_t)(host - req) - 1 && plan.total == req_len);
    CHECK(plan.name_off == (size_t)(host - req));
    list = cli_ok("-Mh -Md -Mr");
    CHECK(bye_desync_build(&list.item[0], (const uint8_t *)req, req_len, out, sizeof out, &plan) ==
          BYE_DESYNC_OK);
    CHECK(plan.total == req_len);

    /* a prefix that does not hold the name yet still asks for more */
    CHECK(bye_desync_build(&list.item[0], hello_openssl, 40, out, sizeof out, &plan) == BYE_DESYNC_NEED_MORE);

    /* same bytes, same plan: the cuts that draw by chance come from the hello */
    list = cli_ok("-s0+sr -s1+nr");
    bye_plan_t again;
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) == BYE_DESYNC_OK);
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &again) == BYE_DESYNC_OK);
    CHECK(plan.count == again.count && memcmp(plan.ops, again.ops, sizeof plan.ops[0] * plan.count) == 0);
    CHECK(plan.ops[0].off + plan.ops[0].len >= name.name_off &&
          plan.ops[0].off + plan.ops[0].len < name.name_off + name.name_len);

    /* no parts at all is the bytes as they are */
    list = cli_ok("-S -a1");
    CHECK(bye_desync_build(&list.item[0], hello_openssl, hello_openssl_len, out, sizeof out, &plan) == BYE_DESYNC_OK);
    CHECK(plan.count == 1 && !plan.applied && memcmp(out, hello_openssl, hello_openssl_len) == 0);
}

static void test_cli_groups(void) {
    bye_strategies_t list = cli_ok("-d1 -At -s2 -As -s3 -Ar -s4");
    CHECK(list.count == 4);
    /* the first group is the start and takes no failure, a later group takes the ones it names */
    CHECK(bye_strategies_after(&list, 0, 0, BYE_TRIGGER_TORST) == 1);
    CHECK(bye_strategies_after(&list, 0, 0, BYE_TRIGGER_TLSERR) == 2);
    CHECK(bye_strategies_after(&list, 0, 1, BYE_TRIGGER_TLSERR) == 2);
    CHECK(bye_strategies_after(&list, 0, 2, BYE_TRIGGER_TLSERR) == 0);
    CHECK(bye_strategies_after(&list, 0, 1, BYE_TRIGGER_TORST) == 0);
    CHECK(bye_strategies_after(&list, 0, 0, BYE_TRIGGER_REDIRECT) == 3);
    /* a flow that began at the second group goes round, the first group takes nothing */
    CHECK(bye_strategies_after(&list, 1, 0, BYE_TRIGGER_TORST) == 0);
    CHECK(bye_strategies_after(&list, 1, 0, BYE_TRIGGER_TLSERR) == 1);
    /* the spec syntax takes every failure, as it always did */
    list = cli_ok("split=1|split=2|none");
    CHECK(bye_strategies_after(&list, 0, 0, BYE_TRIGGER_TORST) == 1);
    CHECK(bye_strategies_after(&list, 0, 1, BYE_TRIGGER_TLSERR) == 2);
    CHECK(bye_strategies_after(&list, 1, 1, BYE_TRIGGER_TORST) == 2);
    CHECK(bye_strategies_after(&list, 1, 2, BYE_TRIGGER_TORST) == 0);
    CHECK(bye_strategies_after(NULL, 0, 0, BYE_TRIGGER_TORST) == 0);
}

int main(void) {
    test_cli_parse();
    test_cli_plan();
    test_cli_groups();
    test_strategies();
    test_parse();
    test_tls();
    test_partial_hello();
    test_boundaries();
    test_http();
    if (!failed) puts("test_desync ok");
    return failed;
}

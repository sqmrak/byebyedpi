#include "bye_config.h"

#include <string.h>

#include "check.h"

static bye_config_status_t parse(const char *text, bye_config_t *c, char *error, size_t cap) {
    return bye_config_parse(text, strlen(text), c, error, cap);
}

static void test_defaults(void) {
    bye_config_t c;
    bye_config_defaults(&c);
    CHECK(c.telegram && c.block_quic && !c.dns[0] && !c.autostart);
    CHECK(strcmp(c.desync_spec, BYE_STRATEGIES_DEFAULT) == 0);
    CHECK(strcmp(c.desync_spec, "auto") == 0 && c.desync_strategies.count == 5);
    CHECK(c.desync_strategies.item[0].split_count == 2 && c.desync_strategies.item[0].has_tlsrec);
    CHECK(c.hosts[0] == '\0' && c.hosts_only && c.pool == 1);
    CHECK(strcmp(c.relay, BYE_CONFIG_RELAY_DEFAULT) == 0 && c.version == BYE_CONFIG_VERSION);
    CHECK(!c.proxy && c.proxy_port == 1082 && c.proxy_secret[0] == '\0' && !c.spec_reduced);
}

static void test_parse(void) {
    bye_config_t c;
    char error[BYE_CONFIG_ERROR_MAX];
    bye_config_defaults(&c);
    const char *text =
        "# the first line is a comment\r\n"
        "desync = off\r\n"
        "  telegram=on  \n"
        "\n"
        "quic = pass\n"
        "autostart = on\n"
        "relay = relay.example.co.uk\n"
        "desync.spec = split = 2, mid ; oob=end\n"
        "dns = 1.1.1.1";
    CHECK(parse(text, &c, error, sizeof error) == BYE_CONFIG_OK);
    CHECK(c.telegram && !c.block_quic && c.autostart);
    CHECK(strcmp(c.relay, "relay.example.co.uk") == 0);
    CHECK(strcmp(c.dns, "1.1.1.1") == 0);
    CHECK(strcmp(c.desync_spec, "split = 2, mid ; oob=end") == 0);
    CHECK(c.desync_strategies.count == 1);
    CHECK(c.desync_strategies.item[0].split_count == 2 && c.desync_strategies.item[0].has_oob &&
          !c.desync_strategies.item[0].has_tlsrec);

    /* a list from an older file keeps its first strategy and says so */
    CHECK(parse("desync.spec = split=1 | none|tlsrec=mid\n", &c, error, sizeof error) == BYE_CONFIG_OK);
    CHECK(c.spec_reduced && strcmp(c.desync_spec, "split=1") == 0 && c.desync_strategies.count == 1);
    CHECK(parse("desync.spec = none\n", &c, error, sizeof error) == BYE_CONFIG_OK && !c.spec_reduced);
    CHECK(c.desync_strategies.count == 1 && c.desync_strategies.item[0].split_count == 0);
    /* the command line of the original, with its -S and -a left out and said so */
    CHECK(parse("desync.spec = -d1 -d3+s -s6+s -r1+s -S -a1 -As -d1 -s3+s -a1\n", &c, error, sizeof error) ==
          BYE_CONFIG_OK);
    CHECK(c.desync_strategies.count == 2 && c.desync_strategies.item[0].cli &&
          c.desync_strategies.item[0].part_count == 3 && c.desync_strategies.notes[0] != '\0');
    CHECK(strcmp(c.desync_spec, "-d1 -d3+s -s6+s -r1+s -S -a1 -As -d1 -s3+s -a1") == 0);
    char cli_long[BYE_CONFIG_SPEC_MAX + 32] = "desync.spec = -d1 -# ";
    memset(cli_long + 20, 'a', BYE_CONFIG_SPEC_MAX);
    cli_long[20 + BYE_CONFIG_SPEC_MAX] = '\0';
    CHECK(parse(cli_long, &c, error, sizeof error) == BYE_CONFIG_ERR_PARSE);
    /* the list that shipped before becomes the new default, not its failing first item */
    CHECK(parse("desync.spec = tlsrec=name+1;split=1,name+1|tlsrec=mid;split=1,mid|split=1,name+1;oob=1|none\n",
                &c, error, sizeof error) == BYE_CONFIG_OK);
    CHECK(c.spec_reduced && strcmp(c.desync_spec, BYE_STRATEGIES_DEFAULT) == 0);
    /* a command line with a bar anywhere is cut at it too */
    CHECK(parse("desync.spec = -d1 -s5+s | -s3\n", &c, error, sizeof error) == BYE_CONFIG_OK);
    CHECK(c.spec_reduced && strcmp(c.desync_spec, "-d1 -s5+s") == 0);
    CHECK(parse("hosts = blocked.txt\nhosts.mode = except\ntelegram.pool = 2\n", &c, error,
                sizeof error) == BYE_CONFIG_OK);
    CHECK(strcmp(c.hosts, "blocked.txt") == 0 && !c.hosts_only && c.pool == 2);
    CHECK(parse("hosts = none\nhosts.mode = only\ntelegram.pool = 0\n", &c, error, sizeof error) ==
          BYE_CONFIG_OK);
    CHECK(c.hosts[0] == '\0' && c.hosts_only && c.pool == 0);

    CHECK(parse("dns = system\n", &c, error, sizeof error) == BYE_CONFIG_OK && c.dns[0] == '\0');
    CHECK(parse("relay = a.org , b-c.co.uk,d.org\n", &c, error, sizeof error) == BYE_CONFIG_OK);
    CHECK(strcmp(c.relay, "a.org,b-c.co.uk,d.org") == 0);
    CHECK(parse("relay = none\n", &c, error, sizeof error) == BYE_CONFIG_OK && c.relay[0] == '\0');
    CHECK(parse("", &c, error, sizeof error) == BYE_CONFIG_OK);

    CHECK(parse("proxy = on\nproxy.port = 1443\nproxy.secret = 000102030405060708090a0b0c0d0e0f\n", &c, error,
                sizeof error) == BYE_CONFIG_OK);
    CHECK(c.proxy && c.proxy_port == 1443 && strcmp(c.proxy_secret, "000102030405060708090a0b0c0d0e0f") == 0);
    CHECK(parse("proxy.secret = auto\nproxy = off\n", &c, error, sizeof error) == BYE_CONFIG_OK);
    CHECK(!c.proxy && c.proxy_secret[0] == '\0');
}

static void test_errors(void) {
    static const struct { const char *text; const char *want; } bad[] = {
        { "desync = maybe\n", "line 1: desync is on or off" },
        { "telegram = 1\n", "line 1: telegram is on or off" },
        { "quic = on\n", "line 1: quic is block or pass" },
        { "autostart = yes\n", "line 1: autostart is on or off" },
        { "relay = a.org,b.org,c.org,d.org,e.org\n", "line 1: relay is up to 4 domain names or none" },
        { "relay = a.org,\n", "line 1: relay is up to 4 domain names or none" },
        { "relay = ,a.org\n", "line 1: relay is up to 4 domain names or none" },
        { "relay = a.org,,b.org\n", "line 1: relay is up to 4 domain names or none" },
        { "relay = nodots\n", "line 1: relay is up to 4 domain names or none" },
        { "relay = .bad.org\n", "line 1: relay is up to 4 domain names or none" },
        { "relay = bad..org\n", "line 1: relay is up to 4 domain names or none" },
        { "relay = Upper.org\n", "line 1: relay is up to 4 domain names or none" },
        { "relay = a b.org\n", "line 1: relay is up to 4 domain names or none" },
        { "relay = x.org/path\n", "line 1: relay is up to 4 domain names or none" },
        { "relay = -x.org\n", "line 1: relay is up to 4 domain names or none" },
        { "relay = x.org-\n", "line 1: relay is up to 4 domain names or none" },
        { "relay = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.org\n", "line 1: relay is up to 4 domain names or none" },
        { "\n\ndns = 1.1.1\n", "line 3: dns is an ipv4 address or system" },
        { "dns = ::1\n", "line 1: dns is an ipv4 address or system" },
        { "desync.spec = split=0\n", "line 1: desync.spec: bad split position" },
        { "desync.spec = frob=1\n", "line 1: desync.spec: unknown clause" },
        { "desync.spec = -d\n", "line 1: desync.spec: option -d needs a value" },
        { "desync.spec = -d1 -s x\n", "line 1: desync.spec: option -s: bad value \"x\"" },
        { "desync.spec = -d1 --nope\n", "line 1: desync.spec: unknown option --nope" },
        { "hosts = /etc/passwd\n", "line 1: hosts is a file name or none" },
        { "hosts = ../x\n", "line 1: hosts is a file name or none" },
        { "hosts = .hidden\n", "line 1: hosts is a file name or none" },
        { "hosts = a b\n", "line 1: hosts is a file name or none" },
        { "hosts.mode = all\n", "line 1: hosts.mode is only or except" },
        { "telegram.pool = 3\n", "line 1: telegram.pool is 0 to 2" },
        { "telegram.pool = 01\n", "line 1: telegram.pool is 0 to 2" },
        { "telegram.pool = -1\n", "line 1: telegram.pool is 0 to 2" },
        { "proxy = maybe\n", "line 1: proxy is on or off" },
        { "proxy.port = 0\n", "line 1: proxy.port is 1 to 65535" },
        { "proxy.port = 65536\n", "line 1: proxy.port is 1 to 65535" },
        { "proxy.port = 80x\n", "line 1: proxy.port is 1 to 65535" },
        { "proxy.port = -5\n", "line 1: proxy.port is 1 to 65535" },
        { "proxy.secret = 0001\n", "line 1: proxy.secret is 32 lowercase hex digits or auto" },
        { "proxy.secret = 000102030405060708090A0B0C0D0E0F\n", "line 1: proxy.secret is 32 lowercase hex digits or auto" },
        { "proxy.secret = 000102030405060708090a0b0c0d0e0g\n", "line 1: proxy.secret is 32 lowercase hex digits or auto" },
        { "colour = blue\n", "line 1: unknown key" },
        { "no equals here\n", "line 1: expected key = value" },
        { "= value\n", "line 1: key or value too long" },
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        bye_config_t c, before;
        char error[BYE_CONFIG_ERROR_MAX];
        bye_config_defaults(&c);
        before = c;
        CHECK(parse(bad[i].text, &c, error, sizeof error) == BYE_CONFIG_ERR_PARSE);
        if (strcmp(error, bad[i].want) != 0) fprintf(stderr, "got '%s' want '%s'\n", error, bad[i].want);
        CHECK(strcmp(error, bad[i].want) == 0);
        CHECK(memcmp(&c, &before, sizeof c) == 0);
    }

    /* a failure late in the file leaves the earlier lines unapplied */
    bye_config_t c, before;
    char error[BYE_CONFIG_ERROR_MAX];
    bye_config_defaults(&c);
    before = c;
    CHECK(parse("desync = off\nquic = pass\nbogus\n", &c, error, sizeof error) == BYE_CONFIG_ERR_PARSE);
    CHECK(memcmp(&c, &before, sizeof c) == 0);

    char big[BYE_CONFIG_FILE_MAX + 2];
    memset(big, '#', sizeof big);
    CHECK(bye_config_parse(big, sizeof big, &c, error, sizeof error) == BYE_CONFIG_ERR_PARSE);
    char longspec[300] = "desync.spec = ";
    memset(longspec + 14, 'a', 270);
    longspec[284] = '\0';
    CHECK(parse(longspec, &c, error, sizeof error) == BYE_CONFIG_ERR_PARSE);
    CHECK(bye_config_parse(NULL, 0, &c, NULL, 0) == BYE_CONFIG_ERR_ARG);
}

static void test_render(void) {
    bye_config_t c, back;
    char text[1024], error[BYE_CONFIG_ERROR_MAX];
    bye_config_defaults(&c);
    snprintf(c.hosts, sizeof c.hosts, "blocked.txt");
    c.hosts_only = 0;
    c.pool = 2;
    c.telegram = 0;
    c.block_quic = 0;
    c.autostart = 1;
    snprintf(c.relay, sizeof c.relay, "relay.example.org");
    snprintf(c.dns, sizeof c.dns, "8.8.4.4");
    c.proxy = 1;
    c.proxy_port = 2080;
    snprintf(c.proxy_secret, sizeof c.proxy_secret, "ffeeddccbbaa99887766554433221100");
    CHECK(bye_config_render(&c, text, sizeof text) == 0);
    bye_config_defaults(&back);
    CHECK(parse(text, &back, error, sizeof error) == BYE_CONFIG_OK);
    CHECK(back.telegram == 0 && back.block_quic == 0 && back.autostart);
    CHECK(strcmp(back.hosts, "blocked.txt") == 0 && !back.hosts_only && back.pool == 2);
    CHECK(back.desync_strategies.count == 5 && strcmp(back.desync_spec, "auto") == 0);
    CHECK(back.proxy && back.proxy_port == 2080 && strcmp(back.proxy_secret, c.proxy_secret) == 0);
    CHECK(strcmp(back.relay, "relay.example.org") == 0);
    CHECK(strcmp(back.dns, "8.8.4.4") == 0 && strcmp(back.desync_spec, c.desync_spec) == 0);
    CHECK(bye_config_render(&c, text, 10) == -1);
    CHECK(bye_config_render(&c, text, sizeof text) == 0);
    CHECK(strncmp(text, "version = 6\n", 12) == 0);

    /* the version is read back, so the daemon can tell an old file from a chosen none */
    bye_config_defaults(&back);
    back.version = 1;
    CHECK(parse("relay = none\n", &back, error, sizeof error) == BYE_CONFIG_OK);
    CHECK(back.version == 1 && back.relay[0] == '\0');
    CHECK(parse("version = 3\n", &back, error, sizeof error) == BYE_CONFIG_OK && back.version == 3);
    CHECK(parse("version = 4\n", &back, error, sizeof error) == BYE_CONFIG_OK && back.version == 4);
    CHECK(parse("version = 5\n", &back, error, sizeof error) == BYE_CONFIG_OK && back.version == 5);
    CHECK(parse("version = 7\n", &back, error, sizeof error) == BYE_CONFIG_ERR_PARSE);
    CHECK(strcmp(error, "line 1: version is 1 to 6") == 0);

    /* a command line goes through the file as it is */
    snprintf(c.desync_spec, sizeof c.desync_spec, "-d1 -d3+s -r1+s -As -s2");
    CHECK(bye_config_render(&c, text, sizeof text) == 0);
    bye_config_defaults(&back);
    CHECK(parse(text, &back, error, sizeof error) == BYE_CONFIG_OK);
    CHECK(strcmp(back.desync_spec, c.desync_spec) == 0 && back.desync_strategies.count == 2);
}

static void test_migration(void) {
    static const char *const old[] = {
        "",
        "version = 1\ndns = system\n",
        "version = 3\ndns = 1.1.1.1\n",
        "version = 4\ndns = 8.8.4.4\n",
        "version = 5\ndns = 8.8.4.4\n"
    };
    for (size_t i = 0; i < sizeof old / sizeof old[0]; ++i) {
        bye_config_t c, fresh, back;
        char text[BYE_CONFIG_FILE_MAX], error[BYE_CONFIG_ERROR_MAX];
        bye_config_defaults(&fresh);
        bye_config_defaults(&c);
        c.version = 1;
        CHECK(parse(old[i], &c, error, sizeof error) == BYE_CONFIG_OK);
        CHECK(parse("hosts = youtube.sites\nhosts.mode = only\nautostart = on\nproxy.port = 2080\n"
                    "relay = none\ntelegram = off\nquic = pass\ndesync.spec = split=1,mid\n",
                    &c, error, sizeof error) == BYE_CONFIG_OK);
        CHECK(bye_config_migrate(&c) == 1);
        CHECK(c.version == BYE_CONFIG_VERSION);
        CHECK(!c.hosts[0] && !c.autostart && c.proxy_port == fresh.proxy_port);
        CHECK(!strcmp(c.relay, BYE_CONFIG_RELAY_DEFAULT) && c.telegram == fresh.telegram);
        CHECK(c.block_quic == fresh.block_quic && !c.dns[0]);
        CHECK(!strcmp(c.desync_spec, fresh.desync_spec) && c.desync_strategies.count == fresh.desync_strategies.count);
        CHECK(bye_config_migrate(&c) == 0);
        CHECK(bye_config_render(&c, text, sizeof text) == 0);
        bye_config_defaults(&back);
        CHECK(parse(text, &back, error, sizeof error) == BYE_CONFIG_OK);
        CHECK(bye_config_migrate(&back) == 0 && !back.hosts[0]);
    }
    bye_config_t current;
    char error[BYE_CONFIG_ERROR_MAX];
    bye_config_defaults(&current);
    CHECK(parse("hosts = youtube.sites\nautostart = on\n", &current, error, sizeof error) == BYE_CONFIG_OK);
    CHECK(bye_config_migrate(&current) == 0 && !strcmp(current.hosts, "youtube.sites") && current.autostart);
    CHECK(bye_config_migrate(NULL) == 0);
}

int main(void) {
    test_defaults();
    test_parse();
    test_errors();
    test_render();
    test_migration();
    if (!failed) puts("test_config ok");
    return failed;
}

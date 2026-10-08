#include "bye_hosts.h"

#include <stdlib.h>
#include <string.h>

#include "check.h"

static bye_hosts_t *load(const char *text) {
    char error[BYE_HOSTS_ERROR_MAX];
    bye_hosts_t *hosts = bye_hosts_parse(text, strlen(text), error, sizeof error);
    if (!hosts) fprintf(stderr, "parse failed: %s\n", error);
    return hosts;
}

static int match(const bye_hosts_t *hosts, const char *name) {
    return bye_hosts_match(hosts, name, strlen(name));
}

static void test_match(void) {
    bye_hosts_t *hosts = load(
        "# blocked in the region\r\n"
        "youtube.com\n"
        "  *.googlevideo.com  # cdn\n"
        ".ytimg.com\n"
        "\n"
        "Example.ORG.\n"
        "t.me\n"
        "intranet\n");
    CHECK(hosts != NULL && bye_hosts_count(hosts) == 6);
    if (!hosts) return;
    CHECK(match(hosts, "youtube.com") && match(hosts, "www.youtube.com") &&
          match(hosts, "a.b.youtube.com"));
    CHECK(match(hosts, "r4---sn-x.googlevideo.com") && match(hosts, "googlevideo.com"));
    CHECK(match(hosts, "i.ytimg.com") && match(hosts, "ytimg.com"));
    CHECK(match(hosts, "example.org") && match(hosts, "CDN.EXAMPLE.ORG") && match(hosts, "example.org."));
    CHECK(match(hosts, "t.me") && match(hosts, "web.t.me") && match(hosts, "intranet"));

    /* a suffix of the text is not a parent name */
    CHECK(!match(hosts, "notyoutube.com") && !match(hosts, "youtube.com.evil.net"));
    CHECK(!match(hosts, "com") && !match(hosts, "me") && !match(hosts, "ytimg.co"));
    CHECK(!match(hosts, "xt.me") && !match(hosts, "") && !match(hosts, "."));
    CHECK(!match(hosts, "evilintranet") && !match(hosts, "x.intranet.evil"));
    CHECK(bye_hosts_match(hosts, NULL, 3) == 0 && bye_hosts_match(NULL, "t.me", 4) == 0);
    char big[BYE_HOSTS_NAME_MAX + 8];
    memset(big, 'a', sizeof big);
    CHECK(!bye_hosts_match(hosts, big, sizeof big));
    /* the length bounds the name, not a terminator */
    CHECK(bye_hosts_match(hosts, "t.mexyz", 4) == 1);
    bye_hosts_free(hosts);
}

static void test_edges(void) {
    char error[BYE_HOSTS_ERROR_MAX];
    bye_hosts_t *empty = load("# nothing\n\n   \n");
    CHECK(empty != NULL && bye_hosts_count(empty) == 0 && !match(empty, "t.me"));
    bye_hosts_free(empty);
    bye_hosts_t *none = bye_hosts_parse("", 0, error, sizeof error);
    CHECK(none != NULL && bye_hosts_count(none) == 0);
    bye_hosts_free(none);
    bye_hosts_t *no_newline = load("a.org\nb.org");
    CHECK(no_newline && match(no_newline, "b.org") && match(no_newline, "a.org"));
    bye_hosts_free(no_newline);
    bye_hosts_t *dup = load("a.org\na.org\nA.ORG\n");
    CHECK(dup && bye_hosts_count(dup) == 3 && match(dup, "x.a.org"));
    bye_hosts_free(dup);

    /* one bad line rejects the list and names the line */
    static const struct { const char *text; const char *want; } bad[] = {
        { "a.org\nbad name.org\n", "line 2: not a domain name" },
        { "a..org\n", "line 1: not a domain name" },
        { "a.org/path\n", "line 1: not a domain name" },
        { "-.org\n", "line 1: not a domain name" },
        { "http://a.org\n", "line 1: not a domain name" },
        { "1.2.3.4:80\n", "line 1: not a domain name" },
        { "\xd0\xbf.org\n", "line 1: not a domain name" },
        { "*.\n", "line 1: not a domain name" },
        { "a.org\n..\n", "line 2: not a domain name" },
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        bye_hosts_t *hosts = bye_hosts_parse(bad[i].text, strlen(bad[i].text), error, sizeof error);
        if (hosts || strcmp(error, bad[i].want) != 0)
            fprintf(stderr, "case %zu: got '%s' want '%s'\n", i, error, bad[i].want);
        CHECK(hosts == NULL && strcmp(error, bad[i].want) == 0);
        bye_hosts_free(hosts);
    }

    /* a label of 64 characters, and a name of 254 */
    char label[80];
    memset(label, 'a', 64);
    strcpy(label + 64, ".org\n");
    CHECK(bye_hosts_parse(label, strlen(label), error, sizeof error) == NULL);
    memset(label, 'a', 63);
    strcpy(label + 63, ".org\n");
    bye_hosts_t *ok63 = bye_hosts_parse(label, strlen(label), error, sizeof error);
    CHECK(ok63 != NULL);
    bye_hosts_free(ok63);
    static char longname[BYE_HOSTS_NAME_MAX + 128];
    size_t at = 0;
    while (at < BYE_HOSTS_NAME_MAX + 2) {
        memset(longname + at, 'a', 60);
        at += 60;
        longname[at++] = '.';
    }
    longname[at - 1] = '\n';
    CHECK(bye_hosts_parse(longname, at, error, sizeof error) == NULL);

    CHECK(bye_hosts_parse(NULL, 4, error, sizeof error) == NULL);
    CHECK(bye_hosts_parse("a.org", BYE_HOSTS_FILE_MAX + 1, error, sizeof error) == NULL &&
          strcmp(error, "line 0: the list is too large") == 0);
    bye_hosts_free(NULL);
    CHECK(bye_hosts_count(NULL) == 0);
}

static void test_limits(void) {
    char error[BYE_HOSTS_ERROR_MAX];
    size_t cap = (BYE_HOSTS_NAMES_MAX + 8u) * 12u;
    char *text = malloc(cap);
    CHECK(text != NULL);
    if (!text) return;
    size_t at = 0;
    for (unsigned i = 0; i < BYE_HOSTS_NAMES_MAX; ++i)
        at += (size_t)snprintf(text + at, cap - at, "h%u.org\n", i);
    bye_hosts_t *full = bye_hosts_parse(text, at, error, sizeof error);
    CHECK(full != NULL && bye_hosts_count(full) == BYE_HOSTS_NAMES_MAX);
    if (full) {
        CHECK(match(full, "h0.org") && match(full, "x.h16383.org") && match(full, "h777.org"));
        CHECK(!match(full, "h16384.org") && !match(full, "h.org"));
    }
    bye_hosts_free(full);
    at += (size_t)snprintf(text + at, cap - at, "one.more.org\n");
    CHECK(bye_hosts_parse(text, at, error, sizeof error) == NULL &&
          strcmp(error, "line 16385: too many names") == 0);
    free(text);
}

int main(void) {
    test_match();
    test_edges();
    test_limits();
    if (!failed) puts("test_hosts ok");
    return failed;
}

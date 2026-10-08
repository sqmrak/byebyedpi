#define _DEFAULT_SOURCE
#include "../daemon/bye_probe.c"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>

#include "check.h"

static int lookup_code;
static int lookup_errno;
static int have_answer;
static unsigned freed;
static struct addrinfo answer;
static struct sockaddr_in address;

/* deterministic libc answers keep dns errors independent of the host network */
int getaddrinfo(const char *name, const char *service, const struct addrinfo *hints,
                struct addrinfo **out) {
    CHECK(name && name[0] && !service);
    CHECK(hints->ai_family == AF_INET && hints->ai_socktype == SOCK_STREAM);
    *out = have_answer ? &answer : NULL;
    errno = lookup_errno;
    return lookup_code;
}

void freeaddrinfo(struct addrinfo *entry) {
    CHECK(entry == &answer);
    ++freed;
}

static void reset_answer(void) {
    lookup_code = lookup_errno = have_answer = 0;
    freed = 0;
    memset(&answer, 0, sizeof answer);
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    CHECK(inet_pton(AF_INET, "192.0.2.1", &address.sin_addr) == 1);
    answer.ai_family = AF_INET;
    answer.ai_addr = (struct sockaddr *)&address;
    answer.ai_addrlen = sizeof address;
}

static void test_lookup_errors(void) {
    const int codes[] = { EAI_NONAME, EAI_AGAIN, EAI_FAIL, EAI_SYSTEM };
    for (size_t i = 0; i < sizeof codes / sizeof codes[0]; ++i) {
        reset_answer();
        lookup_code = codes[i];
        lookup_errno = EACCES;
        uint8_t out[4] = { 1, 2, 3, 4 };
        char error[160], expected[48];
        CHECK(resolve_v4("youtube.com", out, error, sizeof error) == -1);
        CHECK(!memcmp(out, (uint8_t[]){0, 0, 0, 0}, 4));
        snprintf(expected, sizeof expected, "getaddrinfo(%d)", codes[i]);
        CHECK(strstr(error, expected) && freed == 0);
        if (codes[i] == EAI_SYSTEM) {
            snprintf(expected, sizeof expected, "errno=%d", EACCES);
            CHECK(strstr(error, expected));
        } else {
            CHECK(strstr(error, gai_strerror(codes[i])));
        }
        char small[4] = { 'x', 'x', 'x', 'x' };
        CHECK(resolve_v4("youtube.com", out, small, sizeof small) == -1);
        CHECK(small[3] == '\0');
        CHECK(resolve_v4("youtube.com", out, NULL, 0) == -1);
    }
}

static void test_answer_bounds(void) {
    uint8_t out[4];
    char error[160];
    reset_answer();
    CHECK(resolve_v4("youtube.com", out, error, sizeof error) == -1);
    CHECK(!strcmp(error, "no IPv4 address in DNS answer") && freed == 0);
    have_answer = 1;
    answer.ai_family = AF_INET6;
    CHECK(resolve_v4("youtube.com", out, error, sizeof error) == -1 && freed == 1);
    answer.ai_family = AF_INET;
    answer.ai_addrlen = sizeof address - 1;
    CHECK(resolve_v4("youtube.com", out, error, sizeof error) == -1 && freed == 2);
    answer.ai_addrlen = sizeof address;
    answer.ai_addr = NULL;
    CHECK(resolve_v4("youtube.com", out, error, sizeof error) == -1 && freed == 3);
    answer.ai_addr = (struct sockaddr *)&address;
    CHECK(resolve_v4("youtube.com", out, error, sizeof error) == 0 && freed == 4);
    CHECK(!memcmp(out, (uint8_t[]){192, 0, 2, 1}, 4) && !error[0]);
    lookup_code = EAI_FAIL;
    CHECK(resolve_v4("youtube.com", out, error, sizeof error) == -1 && freed == 5);
}

static void test_report(void) {
    reset_answer();
    lookup_code = EAI_NONAME;
    bye_probe_t probe;
    bye_probe_init(&probe);
    const char *names[] = { "youtube.com", "www.youtube.com", "googlevideo.com", "ytimg.com" };
    probe.request.name_count = BYE_PROBE_NAMES_MAX;
    for (size_t i = 0; i < BYE_PROBE_NAMES_MAX; ++i)
        snprintf(probe.request.names[i], BYE_PROBE_NAME_MAX, "%s", names[i]);
    build_candidates(&probe, "auto");
    probe.running = 1;
    run(&probe);
    CHECK(!probe.running && probe.unresolved_count == BYE_PROBE_NAMES_MAX);
    char report[BYE_PROBE_REPORT_MAX];
    bye_probe_report(&probe, report, sizeof report);
    CHECK(strstr(report, "state=done\n") && strstr(report, "progress=0/0\n"));
    for (size_t i = 0; i < BYE_PROBE_NAMES_MAX; ++i) {
        char expected[160];
        snprintf(expected, sizeof expected, "unresolved=%s\n", names[i]);
        CHECK(strstr(report, expected));
        snprintf(expected, sizeof expected, "unresolved.error=%s getaddrinfo(%d):", names[i], EAI_NONAME);
        CHECK(strstr(report, expected));
    }
    CHECK(strstr(report, "address.") == NULL && strstr(report, "suggest=\n"));
    probe.request.name_count = 2;
    snprintf(probe.request.names[0], BYE_PROBE_NAME_MAX, "discord.com");
    snprintf(probe.unresolved[0], BYE_PROBE_NAME_MAX, "youtube.com");
    probe.unresolved_count = 1;
    probe.resolved[0] = 1;
    memcpy(probe.addrs[0], (uint8_t[]){192, 0, 2, 1}, 4);
    probe.candidates[0].ok = probe.candidates[0].tried = 1;
    probe.candidates[0].ms = 133;
    bye_probe_report(&probe, report, sizeof report);
    CHECK(strstr(report, "candidate.0=1/1 133ms "));
    CHECK(strstr(report, "unresolved=youtube.com\n"));
    CHECK(strstr(report, "address.0=discord.com 192.0.2.1\n"));
    size_t len = bye_probe_report(&probe, report, 180);
    CHECK(len > 0 && len < 180 && report[len] == '\0' && report[len - 1] == '\n');
    CHECK(strstr(report, "unresolved.error=youtube.com getaddrinfo("));
    CHECK(bye_probe_report(&probe, report, 1) == 0 && report[0] == '\0');
    probe.unresolved_count = 0;
    bye_probe_report(&probe, report, sizeof report);
    CHECK(strstr(report, "unresolved") == NULL);
    bye_probe_destroy(&probe);
}

int main(void) {
    test_lookup_errors();
    test_answer_bounds();
    test_report();
    if (!failed) puts("test_probe_dns ok");
    return failed;
}

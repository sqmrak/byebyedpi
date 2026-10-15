#define _DEFAULT_SOURCE

#include "bye_probe.h"
#include "bye_sniff.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "check.h"

/* a server that behaves like a filter, on a port of its own */

typedef enum {
    S_REJECT_CUT, /* resets a hello that comes in more than one record */
    S_SILENT,     /* reads and says nothing */
    S_ALERT       /* answers with a tls alert */
} mode_t_;

static int listen_fd;
static uint16_t server_port;
static mode_t_ server_mode;

static int read_exact(int fd, uint8_t *buf, size_t n) {
    size_t at = 0;
    while (at < n) {
        ssize_t got = read(fd, buf + at, n - at);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return -1;
        at += (size_t)got;
    }
    return 0;
}

static void *serve_one(void *arg) {
    int fd = (int)(intptr_t)arg;
    uint8_t head[5], body[16384];
    if (read_exact(fd, head, 5) != 0) goto out;
    size_t len = (size_t)head[3] << 8 | head[4];
    if (len > sizeof body || read_exact(fd, body, len) != 0) goto out;
    if (server_mode == S_REJECT_CUT) {
        /* another record header right behind the first one is a cut hello */
        struct pollfd item = { fd, POLLIN, 0 };
        if (poll(&item, 1, 150) > 0) {
            struct linger hard = { 1, 0 };
            setsockopt(fd, SOL_SOCKET, SO_LINGER, &hard, sizeof hard);
            close(fd);
            return NULL;
        }
        static const uint8_t reply[] = { 0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0, 0, 0 };
        if (write(fd, reply, sizeof reply) < 0) goto out;
    } else if (server_mode == S_ALERT) {
        static const uint8_t alert[] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28 };
        if (write(fd, alert, sizeof alert) < 0) goto out;
    }
    {
        uint8_t sink[512];
        while (read(fd, sink, sizeof sink) > 0) {}
    }
out:
    close(fd);
    return NULL;
}

static void *accept_loop(void *arg) {
    (void)arg;
    for (;;) {
        int fd = accept(listen_fd, NULL, NULL);
        if (fd < 0) return NULL;
        pthread_t t;
        pthread_create(&t, NULL, serve_one, (void *)(intptr_t)fd);
        pthread_detach(t);
    }
}

static void server_start(void) {
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(listen_fd, (struct sockaddr *)&a, sizeof a) == 0);
    socklen_t len = sizeof a;
    getsockname(listen_fd, (struct sockaddr *)&a, &len);
    server_port = ntohs(a.sin_port);
    CHECK(listen(listen_fd, 16) == 0);
    pthread_t t;
    pthread_create(&t, NULL, accept_loop, NULL);
    pthread_detach(t);
}

static const uint8_t LOOP[4] = { 127, 0, 0, 1 };

static bye_desync_t spec(const char *text) {
    bye_desync_t d;
    CHECK(bye_desync_parse(text, &d, NULL, 0) == BYE_DESYNC_OK);
    return d;
}

static void test_hello(void) {
    uint8_t hello[4096];
    size_t len = 0;
    CHECK(bye_probe_hello("example.org", hello, sizeof hello, &len) == 0);
    CHECK(len > 100 && hello[0] == 0x16 && hello[5] == 0x01);
    bye_sniff_t found;
    CHECK(bye_sniff_tls(hello, len, &found) == BYE_SNIFF_OK);
    CHECK(found.name_len == 11 && memcmp(hello + found.name_off, "example.org", 11) == 0);
    CHECK(found.record_len == len);

    CHECK(bye_probe_hello("example.org", hello, 64, &len) == -1 && len == 0);
    CHECK(bye_probe_hello("", hello, sizeof hello, &len) == -1);
    CHECK(bye_probe_hello(NULL, hello, sizeof hello, &len) == -1);
    CHECK(bye_probe_hello("example.org", NULL, sizeof hello, &len) == -1);
    /* two hellos for one name differ: the random is fresh */
    uint8_t other[4096];
    size_t other_len = 0;
    CHECK(bye_probe_hello("example.org", other, sizeof other, &other_len) == 0);
    CHECK(other_len > 0 && memcmp(hello, other, 40) != 0);
}

static void test_attempt(void) {
    bye_probe_request_t request;
    memset(&request, 0, sizeof request);
    request.port = server_port;
    request.wait_ms = 400;
    uint32_t ms = 0;
    bye_desync_t tlsrec = spec("tlsrec=name+1;split=1,name+1");
    bye_desync_t split = spec("split=1,name+1");
    bye_desync_t none = spec("");
    bye_desync_t oob = spec("split=1;oob=1");

    server_mode = S_REJECT_CUT;
    CHECK(bye_probe_attempt(&request, LOOP, "blocked.example", &tlsrec, &ms) == BYE_PROBE_RESET);
    CHECK(bye_probe_attempt(&request, LOOP, "blocked.example", &split, &ms) == BYE_PROBE_ANSWERED);
    CHECK(ms < 400);
    CHECK(bye_probe_attempt(&request, LOOP, "blocked.example", &none, &ms) == BYE_PROBE_ANSWERED);
    CHECK(bye_probe_attempt(&request, LOOP, "blocked.example", &oob, &ms) == BYE_PROBE_ANSWERED);

    server_mode = S_SILENT;
    CHECK(bye_probe_attempt(&request, LOOP, "blocked.example", &none, &ms) == BYE_PROBE_SILENT);
    CHECK(ms >= 380 && ms < 2000);

    server_mode = S_ALERT;
    CHECK(bye_probe_attempt(&request, LOOP, "blocked.example", &none, &ms) == BYE_PROBE_OTHER);

    /* nothing listens there */
    int closed = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(closed, (struct sockaddr *)&a, sizeof a) == 0);
    socklen_t alen = sizeof a;
    getsockname(closed, (struct sockaddr *)&a, &alen);
    close(closed);
    request.port = ntohs(a.sin_port);
    CHECK(bye_probe_attempt(&request, LOOP, "blocked.example", &none, &ms) == BYE_PROBE_UNREACHABLE);

    CHECK(bye_probe_attempt(NULL, LOOP, "x.example", &none, &ms) == BYE_PROBE_FAILED);
    CHECK(bye_probe_attempt(&request, NULL, "x.example", &none, &ms) == BYE_PROBE_FAILED);
    CHECK(bye_probe_attempt(&request, LOOP, "x.example", NULL, &ms) == BYE_PROBE_FAILED);
}

static int wait_done(bye_probe_t *probe, int wait_ms) {
    for (int waited = 0; waited < wait_ms; waited += 20) {
        if (!bye_probe_running(probe)) return 1;
        usleep(20 * 1000);
    }
    return 0;
}

static const char *line_of(const char *report, const char *key, char *out, size_t cap) {
    size_t key_len = strlen(key);
    const char *at = report;
    while (at && *at) {
        if (strncmp(at, key, key_len) == 0 && at[key_len] == '=') {
            size_t n = strcspn(at + key_len + 1, "\n");
            snprintf(out, cap, "%.*s", (int)n, at + key_len + 1);
            return out;
        }
        at = strchr(at, '\n');
        if (at) ++at;
    }
    return NULL;
}

static void test_run(void) {
    bye_probe_t *probe = calloc(1, bye_probe_size());
    bye_probe_init(probe);
    char report[BYE_PROBE_REPORT_MAX], value[256], error[160];

    bye_probe_report(probe, report, sizeof report);
    CHECK(line_of(report, "state", value, sizeof value) && strcmp(value, "idle") == 0);

    bye_probe_request_t request;
    memset(&request, 0, sizeof request);
    CHECK(bye_probe_start(probe, &request, error, sizeof error) == -1);
    request.name_count = BYE_PROBE_NAMES_MAX + 1;
    CHECK(bye_probe_start(probe, &request, error, sizeof error) == -1);

    server_mode = S_REJECT_CUT;
    request.name_count = 2;
    snprintf(request.names[0], BYE_PROBE_NAME_MAX, "localhost");
    snprintf(request.names[1], BYE_PROBE_NAME_MAX, "name.invalid");
    snprintf(request.configured, sizeof request.configured, "split=1 | tlsrec=name+1;split=1,name+1");
    request.port = server_port;
    request.wait_ms = 400;
    CHECK(bye_probe_start(probe, &request, error, sizeof error) == 0);
    CHECK(bye_probe_start(probe, &request, error, sizeof error) == -1 ||
          !bye_probe_running(probe)); /* refused while it runs, unless it was already over */
    CHECK(wait_done(probe, 60000));

    bye_probe_report(probe, report, sizeof report);
    CHECK(line_of(report, "state", value, sizeof value) && strcmp(value, "done") == 0);
    CHECK(line_of(report, "configured", value, sizeof value) && strcmp(value, "2") == 0);
    /* the configured specs come first, then the built-in ones without repeats */
    CHECK(strstr(report, "candidate.0=1/1 ") && strstr(report, " split=1\n"));
    CHECK(strstr(report, "candidate.1=0/1 0ms tlsrec=name+1;split=1,name+1\n"));
    CHECK(strstr(report, "candidate.2=0/1 0ms tlsrec=name+1\n"));
    CHECK(strstr(report, " split=1,name+1\n") && strstr(report, " none\n"));
    CHECK(strstr(report, "candidate.10=0/1 0ms -d1 -d3+s -s6+s -r1+s\n"));
    CHECK(strstr(report, "candidate.12=") == NULL);
    CHECK(line_of(report, "progress", value, sizeof value) && strcmp(value, "12/12") == 0);
    CHECK(line_of(report, "unresolved", value, sizeof value) && strcmp(value, "name.invalid") == 0);
    CHECK(line_of(report, "address.0", value, sizeof value) && strcmp(value, "localhost 127.0.0.1") == 0);
    CHECK(line_of(report, "address.1", value, sizeof value) == NULL);
    CHECK(line_of(report, "suggest", value, sizeof value));
    /* none of the cut records is suggested, and split=1 leads: it is first in the list */
    CHECK(strncmp(value, "split=1|split=1,name+1|", 23) == 0 && strstr(value, "tlsrec") == NULL);
    size_t bars = 0;
    for (const char *p = value; *p; ++p) bars += *p == '|';
    CHECK(bars == 3);

    /* a second run replaces the first */
    request.name_count = 1;
    CHECK(bye_probe_start(probe, &request, error, sizeof error) == 0);
    CHECK(wait_done(probe, 60000));
    bye_probe_report(probe, report, sizeof report);
    CHECK(line_of(report, "progress", value, sizeof value) && strcmp(value, "12/12") == 0);
    CHECK(line_of(report, "unresolved", value, sizeof value) == NULL);

    /* a flow of an app that got no answer: its own hello is tried at its address, next to ours */
    snprintf(request.configured, sizeof request.configured, "split=1 | tlsrec=name+1;split=1,name+1");
    snprintf(request.app_name, sizeof request.app_name, "app.example.org");
    request.app_addr[0] = 127; request.app_addr[3] = 1;
    CHECK(bye_probe_hello(request.app_name, request.app_hello, sizeof request.app_hello, &request.app_hello_len) == 0);
    CHECK(bye_probe_start(probe, &request, error, sizeof error) == 0);
    CHECK(wait_done(probe, 60000));
    bye_probe_report(probe, report, sizeof report);
    CHECK(line_of(report, "app", value, sizeof value) && strncmp(value, "app.example.org 127.0.0.1 ", 26) == 0);
    CHECK(line_of(report, "app.0", value, sizeof value) && strncmp(value, "answered ", 9) == 0 && strstr(value, " | answered ") != NULL);
    CHECK(line_of(report, "app.1", value, sizeof value) && strncmp(value, "answered ", 9) != 0 && strstr(value, " | answered ") == NULL);
    CHECK(line_of(report, "progress", value, sizeof value) && strchr(value, '/') != NULL);
    CHECK(line_of(report, "alt", value, sizeof value) == NULL);

    /* the app's address does not answer, another address of the same site does */
    snprintf(request.app_name, sizeof request.app_name, "www.localhost");
    request.app_addr[3] = 2;
    CHECK(bye_probe_hello(request.app_name, request.app_hello, sizeof request.app_hello, &request.app_hello_len) == 0);
    CHECK(bye_probe_start(probe, &request, error, sizeof error) == 0);
    CHECK(wait_done(probe, 60000));
    bye_probe_report(probe, report, sizeof report);
    CHECK(line_of(report, "app.0", value, sizeof value) && strncmp(value, "unreachable ", 12) == 0);
    CHECK(line_of(report, "alt", value, sizeof value) && strcmp(value, "localhost 127.0.0.1") == 0);
    CHECK(line_of(report, "alt.0", value, sizeof value) && strncmp(value, "answered ", 9) == 0);
    CHECK(line_of(report, "alt.1", value, sizeof value) && strncmp(value, "answered ", 9) != 0);
    request.app_hello_len = 0;

    /* auto stands for the daemon's own list */
    snprintf(request.configured, sizeof request.configured, "auto");
    CHECK(bye_probe_start(probe, &request, error, sizeof error) == 0);
    CHECK(wait_done(probe, 60000));
    bye_probe_report(probe, report, sizeof report);
    CHECK(line_of(report, "configured", value, sizeof value) && strcmp(value, "5") == 0);
    CHECK(strstr(report, "candidate.0=") && strstr(report, " tlsrec=mid;split=1,mid\n"));

    /* a small buffer cuts the report at a line, never inside one */
    size_t part = bye_probe_report(probe, report, 60);
    CHECK(part < 60 && (part == 0 || report[part - 1] == '\n'));
    CHECK(bye_probe_report(probe, report, 0) == 0);

    /* cancelled while a silent server holds every attempt */
    server_mode = S_SILENT;
    request.wait_ms = 1000;
    CHECK(bye_probe_start(probe, &request, error, sizeof error) == 0);
    usleep(150 * 1000);
    bye_probe_cancel(probe);
    CHECK(wait_done(probe, 5000));
    bye_probe_report(probe, report, sizeof report);
    CHECK(line_of(report, "state", value, sizeof value) && strcmp(value, "stopped") == 0);

    bye_probe_destroy(probe);
    free(probe);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    server_start();
    test_hello();
    test_attempt();
    test_run();
    if (!failed) puts("test_probe ok");
    return failed;
}

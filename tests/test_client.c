#define _DEFAULT_SOURCE

#include "bye_client.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "check.h"

/* a stand-in for the daemon: it speaks the control protocol one line at a time */

static char dir[] = "/tmp/bye-client-XXXXXX";
static char sock_path[100], token_path[104];
static int listen_fd;
static const char TOKEN[] = "0123456789abcdef0123456789abcdef";

static void write_all(int fd, const char *text, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, text + off, len - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return;
        off += (size_t)n;
    }
}

static int read_line(int fd, char *line, size_t cap) {
    size_t len = 0;
    for (;;) {
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        if (c == '\n') {
            line[len] = '\0';
            return 0;
        }
        if (len + 1 < cap) line[len++] = c;
    }
}

static void *serve_one(void *arg) {
    int fd = (int)(intptr_t)arg;
    char line[600];
    int authed = 0;
    while (read_line(fd, line, sizeof line) == 0) {
        if (strncmp(line, "auth ", 5) == 0) {
            authed = strcmp(line + 5, TOKEN) == 0;
            write_all(fd, authed ? "OK\n.\n" : "ERR bad token\n.\n", authed ? 5 : 16);
        } else if (!authed && strcmp(line, "version") != 0) {
            write_all(fd, "ERR authenticate first\n.\n", 25);
        } else if (strcmp(line, "version") == 0) {
            write_all(fd, "OK byebyedpi 1\n.\n", 17);
        } else if (strcmp(line, "status") == 0) {
            /* the answer arrives in pieces, with a dot inside a line that is not the end */
            write_all(fd, "OK\nrunning=1\n", 13);
            usleep(20000);
            write_all(fd, "note=a.b\n.hidden=1\n", 19);
            usleep(20000);
            write_all(fd, ".", 1);
            usleep(20000);
            write_all(fd, "\n", 1);
        } else if (strcmp(line, "big") == 0) {
            static char big[20000];
            memset(big, 'x', sizeof big);
            write_all(fd, "OK\n", 3);
            for (size_t i = 0; i < 20; ++i) { big[999] = '\n'; write_all(fd, big, 1000); }
            write_all(fd, ".\n", 2);
        } else if (strcmp(line, "silent") == 0) {
            usleep(1500000);
        } else if (strcmp(line, "hangup") == 0) {
            break;
        } else {
            write_all(fd, "OK echo\n", 8);
            write_all(fd, line, strlen(line));
            write_all(fd, "\n.\n", 3);
        }
    }
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

static void write_token(const char *text) {
    FILE *file = fopen(token_path, "w");
    CHECK(file != NULL);
    if (!file) return;
    fputs(text, file);
    fclose(file);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    CHECK(mkdtemp(dir) != NULL);
    snprintf(sock_path, sizeof sock_path, "%s/ctl.sock", dir);
    CHECK(bye_client_token_path(sock_path, token_path, sizeof token_path) == 0);
    CHECK(strcmp(token_path + strlen(dir), "/ctl.token") == 0);

    char tiny[8];
    CHECK(bye_client_token_path(sock_path, tiny, sizeof tiny) == -1);
    CHECK(bye_client_token_path(NULL, token_path, 10) == -1);
    char plain[64];
    CHECK(bye_client_token_path("/tmp/odd", plain, sizeof plain) == 0 && strcmp(plain, "/tmp/odd.token") == 0);

    listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", sock_path);
    CHECK(bind(listen_fd, (struct sockaddr *)&addr, sizeof addr) == 0);
    CHECK(listen(listen_fd, 8) == 0);
    pthread_t t;
    pthread_create(&t, NULL, accept_loop, NULL);
    pthread_detach(t);

    char error[BYE_CLIENT_ERROR_MAX], answer[4096];
    bye_client_t c;

    /* no token file yet */
    CHECK(bye_client_open(&c, sock_path, 1, 1000, error, sizeof error) == -1);
    CHECK(strstr(error, "cannot read") != NULL && c.fd == -1);
    CHECK(c.failure == BYE_CLIENT_NO_TOKEN);

    /* a token of the wrong length, then the wrong token */
    write_token("short\n");
    CHECK(bye_client_open(&c, sock_path, 1, 1000, error, sizeof error) == -1);
    CHECK(strstr(error, "not a token") != NULL && c.fd == -1);
    CHECK(c.failure == BYE_CLIENT_TOKEN_BAD);
    write_token("ffffffffffffffffffffffffffffffff\n");
    CHECK(bye_client_open(&c, sock_path, 1, 1000, error, sizeof error) == -1);
    CHECK(strstr(error, "refused the token") != NULL && c.fd == -1);
    CHECK(c.failure == BYE_CLIENT_TOKEN_REFUSED);
    write_token("");
    CHECK(bye_client_open(&c, sock_path, 1, 1000, error, sizeof error) == -1);
    CHECK(strstr(error, "empty") != NULL);
    CHECK(c.failure == BYE_CLIENT_TOKEN_BAD);
    if (geteuid() != 0) {
        /* a token the user may not read */
        write_token("0123456789abcdef0123456789abcdef\n");
        CHECK(chmod(token_path, 0) == 0);
        CHECK(bye_client_open(&c, sock_path, 1, 1000, error, sizeof error) == -1);
        CHECK(c.failure == BYE_CLIENT_TOKEN_DENIED);
        CHECK(chmod(token_path, 0600) == 0);
    }

    /* no daemon at that path */
    char gone[120];
    snprintf(gone, sizeof gone, "%s/none.sock", dir);
    CHECK(bye_client_open(&c, gone, 0, 1000, error, sizeof error) == -1);
    CHECK(strstr(error, "cannot reach") != NULL);
    CHECK(c.failure == BYE_CLIENT_NO_SOCKET);
    {
        /* a socket file with nothing listening behind it: a daemon that died */
        char dead[100];
        snprintf(dead, sizeof dead, "%s/dead.sock", dir);
        int dead_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un dead_addr;
        memset(&dead_addr, 0, sizeof dead_addr);
        dead_addr.sun_family = AF_UNIX;
        snprintf(dead_addr.sun_path, sizeof dead_addr.sun_path, "%s", dead);
        CHECK(bind(dead_fd, (struct sockaddr *)&dead_addr, sizeof dead_addr) == 0);
        close(dead_fd);
        CHECK(bye_client_open(&c, dead, 0, 1000, error, sizeof error) == -1);
        CHECK(c.failure == BYE_CLIENT_REFUSED);
        if (geteuid() != 0) {
            /* and one the user may not connect to */
            CHECK(chmod(dead, 0) == 0);
            CHECK(bye_client_open(&c, dead, 0, 1000, error, sizeof error) == -1);
            CHECK(c.failure == BYE_CLIENT_DENIED);
        }
        unlink(dead);
    }
    char longpath[300];
    memset(longpath, 'a', sizeof longpath - 1);
    longpath[sizeof longpath - 1] = '\0';
    CHECK(bye_client_open(&c, longpath, 0, 1000, error, sizeof error) == -1);
    CHECK(c.failure == BYE_CLIENT_NO_SOCKET);

    /* a good token */
    char good[64];
    snprintf(good, sizeof good, "%s\n", TOKEN);
    write_token(good);
    CHECK(bye_client_open(&c, sock_path, 1, 1000, error, sizeof error) == 0 && c.fd >= 0);
    CHECK(c.failure == BYE_CLIENT_OK);
    long n = bye_client_call(&c, "status", answer, sizeof answer, error, sizeof error);
    CHECK(n == (long)strlen("OK\nrunning=1\nnote=a.b\n.hidden=1\n") &&
          strcmp(answer, "OK\nrunning=1\nnote=a.b\n.hidden=1\n") == 0);
    n = bye_client_call(&c, "set quic pass", answer, sizeof answer, error, sizeof error);
    CHECK(n > 0 && strcmp(answer, "OK echo\nset quic pass\n") == 0);

    /* an answer larger than the buffer is an error */
    CHECK(bye_client_call(&c, "big", answer, sizeof answer, error, sizeof error) == -1);
    CHECK(strstr(error, "too large") != NULL);
    CHECK(c.failure == BYE_CLIENT_TOO_LARGE);
    bye_client_close(&c);
    CHECK(c.fd == -1);
    CHECK(bye_client_open(&c, sock_path, 1, 1000, error, sizeof error) == 0);
    static char large[40000];
    n = bye_client_call(&c, "big", large, sizeof large, error, sizeof error);
    CHECK(n == 3 + 20 * 1000);

    /* a command that is not one line is refused before it is sent */
    CHECK(bye_client_call(&c, "status\nstop", answer, sizeof answer, error, sizeof error) == -1);
    CHECK(c.failure == BYE_CLIENT_BAD_COMMAND);
    CHECK(bye_client_call(&c, "", answer, sizeof answer, error, sizeof error) == -1);
    char huge[BYE_CLIENT_LINE_MAX + 2];
    memset(huge, 'q', sizeof huge - 1);
    huge[sizeof huge - 1] = '\0';
    CHECK(bye_client_call(&c, huge, answer, sizeof answer, error, sizeof error) == -1);
    memset(huge, 'q', BYE_CLIENT_LINE_MAX);
    huge[BYE_CLIENT_LINE_MAX] = '\0';
    CHECK(bye_client_call(&c, huge, answer, sizeof answer, error, sizeof error) > 0);
    CHECK(bye_client_call(&c, "x", answer, 3, error, sizeof error) == -1);
    CHECK(bye_client_call(NULL, "x", answer, sizeof answer, error, sizeof error) == -1);
    CHECK(bye_client_call(&c, NULL, answer, sizeof answer, error, sizeof error) == -1);

    /* the daemon does not answer in time, and the connection is then in an unknown state */
    bye_client_close(&c);
    CHECK(bye_client_open(&c, sock_path, 1, 300, error, sizeof error) == 0);
    CHECK(bye_client_call(&c, "silent", answer, sizeof answer, error, sizeof error) == -1);
    CHECK(strstr(error, "did not answer in time") != NULL);
    CHECK(c.failure == BYE_CLIENT_TIMEOUT);
    bye_client_close(&c);

    /* the daemon hangs up in the middle of a call */
    CHECK(bye_client_open(&c, sock_path, 1, 1000, error, sizeof error) == 0);
    CHECK(bye_client_call(&c, "hangup", answer, sizeof answer, error, sizeof error) == -1);
    CHECK(strstr(error, "closed the connection") != NULL);
    CHECK(c.failure == BYE_CLIENT_CLOSED);
    CHECK(bye_client_call(&c, "status", answer, sizeof answer, error, sizeof error) == -1);
    bye_client_close(&c);
    bye_client_close(&c);

    /* version needs no token */
    CHECK(bye_client_open(&c, sock_path, 0, 1000, error, sizeof error) == 0);
    n = bye_client_call(&c, "version", answer, sizeof answer, error, sizeof error);
    CHECK(n > 0 && strncmp(answer, "OK byebyedpi", 12) == 0);
    n = bye_client_call(&c, "status", answer, sizeof answer, error, sizeof error);
    CHECK(n > 0 && strncmp(answer, "ERR authenticate first", 22) == 0);
    bye_client_close(&c);

    close(listen_fd);
    unlink(sock_path);
    unlink(token_path);
    rmdir(dir);
    if (!failed) puts("test_client ok");
    return failed;
}

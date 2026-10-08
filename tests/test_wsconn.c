#include "bye_wsconn.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"

static int server_port;
static FILE *server_pipe;
static pid_t server_pid;
static const char *stage = "start";
static char dir[] = "/tmp/bye-wsconn-XXXXXX";
static char cert[256], key[256], other_cert[256];

static void make_cert(const char *cert_path, const char *key_path, const char *name) {
    char cmd[1024];
    snprintf(cmd, sizeof cmd,
             "openssl req -x509 -newkey rsa:2048 -nodes -keyout %s -out %s -days 2 "
             "-subj /CN=%s -addext subjectAltName=DNS:%s >/dev/null 2>&1",
             key_path, cert_path, name, name);
    CHECK(system(cmd) == 0);
}

static int start_server(void) {
    CHECK(mkdtemp(dir) != NULL);
    char other_key[256];
    snprintf(cert, sizeof cert, "%s/cert.pem", dir);
    snprintf(key, sizeof key, "%s/key.pem", dir);
    snprintf(other_cert, sizeof other_cert, "%s/other.pem", dir);
    snprintf(other_key, sizeof other_key, "%s/other.key", dir);
    make_cert(cert, key, "localhost");
    make_cert(other_cert, other_key, "localhost");
    int fds[2], life[2];
    if (pipe(fds) != 0 || pipe(life) != 0) return -1;
    server_pid = fork();
    if (server_pid < 0) return -1;
    if (server_pid == 0) {
        dup2(fds[1], STDOUT_FILENO);
        dup2(life[0], STDIN_FILENO);
        close(fds[0]);
        close(fds[1]);
        close(life[0]);
        close(life[1]);
        execlp("python3", "python3", "ws_server.py", cert, key, (char *)NULL);
        _exit(127);
    }
    close(fds[1]);
    close(life[0]); /* the write end stays open until this test ends */
    server_pipe = fdopen(fds[0], "r");
    if (!server_pipe) return -1;
    char line[64];
    if (!fgets(line, sizeof line, server_pipe) || sscanf(line, "PORT %d", &server_port) != 1)
        return -1;
    return 0;
}

static void stop_server(void) {
    if (server_pid > 0) {
        kill(server_pid, SIGTERM);
        waitpid(server_pid, NULL, 0);
    }
    if (server_pipe) fclose(server_pipe);
    char cmd[300];
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
    if (system(cmd) != 0) fprintf(stderr, "cleanup of %s failed\n", dir);
}

static int dial(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons((uint16_t)server_port);
    inet_pton(AF_INET, "127.0.0.1", &to.sin_addr);
    CHECK(connect(fd, (struct sockaddr *)&to, sizeof to) == 0);
    int flags = fcntl(fd, F_GETFL, 0);
    CHECK(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
    return fd;
}

/* decrypted bytes the tls layer already holds do not wake the socket */
static void wait_for(int fd, bye_wsconn_status_t want) {
    struct pollfd p = { fd, want == BYE_WSCONN_WANT_WRITE ? POLLOUT : POLLIN, 0 };
    int ready = poll(&p, 1, 5000);
    if (ready != 1) fprintf(stderr, "stuck in %s waiting for %d\n", stage, (int)want);
    CHECK(ready == 1);
}

static bye_wsconn_status_t finish_handshake(bye_wsconn_t *c, int fd) {
    for (int i = 0; i < 200; ++i) {
        bye_wsconn_status_t s = bye_wsconn_handshake(c);
        if (s == BYE_WSCONN_OK || s == BYE_WSCONN_ERR || s == BYE_WSCONN_CLOSED) return s;
        wait_for(fd, s);
    }
    return BYE_WSCONN_ERR;
}

static bye_wsconn_status_t flush_all(bye_wsconn_t *c, int fd) {
    for (int i = 0; i < 100000; ++i) {
        bye_wsconn_status_t s = bye_wsconn_flush(c);
        if (s != BYE_WSCONN_WANT_WRITE && s != BYE_WSCONN_WANT_READ) return s;
        wait_for(fd, s);
    }
    return BYE_WSCONN_ERR;
}

/* reads until want bytes arrived or the stream ended */
static bye_wsconn_status_t read_n(bye_wsconn_t *c, int fd, uint8_t *out, size_t want, size_t step) {
    size_t have = 0;
    while (have < want) {
        size_t got = 0;
        size_t room = want - have < step ? want - have : step;
        bye_wsconn_status_t s = bye_wsconn_read(c, out + have, room, &got);
        have += got;
        /* a pong queued by the read has to leave for the server to go on */
        bye_wsconn_status_t sent = bye_wsconn_flush(c);
        CHECK(sent != BYE_WSCONN_ERR && sent != BYE_WSCONN_CLOSED);
        if (s == BYE_WSCONN_WANT_READ || s == BYE_WSCONN_WANT_WRITE) {
            if (!bye_wsconn_buffered(c)) wait_for(fd, s);
            continue;
        }
        if (s != BYE_WSCONN_OK) return s;
    }
    return BYE_WSCONN_OK;
}

static void test_session(void) {
    char error[BYE_WSCONN_ERROR_MAX];
    bye_wsconn_ctx_t *ctx = bye_wsconn_ctx_new(cert, error, sizeof error);
    CHECK(ctx != NULL);
    int fd = dial();
    bye_wsconn_t *c = bye_wsconn_new(ctx, fd, "localhost", "/echo");
    CHECK(c != NULL);
    CHECK(bye_wsconn_send(c, (const uint8_t *)"x", 1) == -1); /* not open yet */
    stage = "handshake";
    CHECK(finish_handshake(c, fd) == BYE_WSCONN_OK);
    stage = "hello";

    /* the server pinged on open; our pong makes it send "got-pong", which
       follows the echo because the message was queued before the pong */
    uint8_t buf[200000];
    CHECK(bye_wsconn_send(c, (const uint8_t *)"hello", 5) == 0);
    CHECK(bye_wsconn_pending(c) > 0);
    CHECK(flush_all(c, fd) == BYE_WSCONN_OK);
    CHECK(bye_wsconn_pending(c) == 0);
    CHECK(read_n(c, fd, buf, 5 + 8, 4096) == BYE_WSCONN_OK);
    CHECK(memcmp(buf, "hello", 5) == 0 && memcmp(buf + 5, "got-pong", 8) == 0);

    stage = "big";
    /* a big message, read back in small slices from a fragmented echo */
    static uint8_t big[150000];
    for (size_t i = 0; i < sizeof big; ++i) big[i] = (uint8_t)(i * 7 + (i >> 8));
    CHECK(bye_wsconn_send(c, big, sizeof big) == 0);
    CHECK(flush_all(c, fd) == BYE_WSCONN_OK);
    static uint8_t back[150000];
    CHECK(read_n(c, fd, back, sizeof back, 700) == BYE_WSCONN_OK);
    CHECK(memcmp(back, big, sizeof big) == 0);

    stage = "empty";
    /* an empty message is legal and the echo of it is nothing */
    CHECK(bye_wsconn_send(c, (const uint8_t *)"", 0) == 0);
    CHECK(bye_wsconn_ping(c) == 0);
    CHECK(flush_all(c, fd) == BYE_WSCONN_OK);

    stage = "limit";
    /* the queue refuses a message past its limit and keeps working */
    static uint8_t huge[BYE_WSCONN_TX_MAX + 1];
    CHECK(bye_wsconn_send(c, huge, sizeof huge) == -1);
    CHECK(bye_wsconn_send(c, (const uint8_t *)"again", 5) == 0);
    CHECK(flush_all(c, fd) == BYE_WSCONN_OK);
    CHECK(read_n(c, fd, buf, 5, 100) == BYE_WSCONN_OK && memcmp(buf, "again", 5) == 0);

    stage = "close";
    /* the server closes on request */
    CHECK(bye_wsconn_send(c, (const uint8_t *)"close", 5) == 0);
    CHECK(flush_all(c, fd) == BYE_WSCONN_OK);
    size_t got = 0;
    bye_wsconn_status_t s = BYE_WSCONN_WANT_READ;
    for (int i = 0; i < 50 && (s == BYE_WSCONN_WANT_READ); ++i) {
        s = bye_wsconn_read(c, buf, sizeof buf, &got);
        if (s == BYE_WSCONN_WANT_READ && !bye_wsconn_buffered(c)) wait_for(fd, s);
    }
    CHECK(s == BYE_WSCONN_CLOSED);
    bye_wsconn_free(c);
    close(fd);
    bye_wsconn_ctx_free(ctx);
}

static void test_refused(void) {
    char error[BYE_WSCONN_ERROR_MAX];
    bye_wsconn_ctx_t *ctx = bye_wsconn_ctx_new(cert, error, sizeof error);
    CHECK(ctx != NULL);

    /* a path the server answers with 404 */
    int fd = dial();
    bye_wsconn_t *c = bye_wsconn_new(ctx, fd, "localhost", "/nothing");
    CHECK(c != NULL);
    CHECK(finish_handshake(c, fd) == BYE_WSCONN_ERR);
    CHECK(strstr(bye_wsconn_error(c), "http 404") != NULL);
    CHECK(bye_wsconn_handshake(c) == BYE_WSCONN_ERR);
    bye_wsconn_free(c);
    close(fd);

    /* a certificate for another name */
    fd = dial();
    c = bye_wsconn_new(ctx, fd, "kws2.web.telegram.org", "/echo");
    CHECK(c != NULL);
    CHECK(finish_handshake(c, fd) == BYE_WSCONN_ERR);
    CHECK(strstr(bye_wsconn_error(c), "certificate") != NULL);
    bye_wsconn_free(c);
    close(fd);
    bye_wsconn_ctx_free(ctx);

    /* the right name, signed by nobody this client trusts */
    ctx = bye_wsconn_ctx_new(other_cert, error, sizeof error);
    CHECK(ctx != NULL);
    fd = dial();
    c = bye_wsconn_new(ctx, fd, "localhost", "/echo");
    CHECK(c != NULL);
    CHECK(finish_handshake(c, fd) == BYE_WSCONN_ERR);
    CHECK(strstr(bye_wsconn_error(c), "certificate") != NULL);
    bye_wsconn_free(c);
    close(fd);
    bye_wsconn_ctx_free(ctx);

    CHECK(bye_wsconn_ctx_new("/nonexistent/roots.pem", error, sizeof error) == NULL);
    CHECK(strstr(error, "trust roots") != NULL);
    CHECK(bye_wsconn_new(NULL, 3, "h", "/p") == NULL);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    if (start_server() != 0) {
        fprintf(stderr, "cannot start the python server\n");
        return 1;
    }
    test_session();
    test_refused();
    stop_server();
    if (!failed) puts("test_wsconn ok");
    return failed;
}

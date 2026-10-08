#include "bye_client.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

static void fail(char *error, size_t cap, const char *what, int value) {
    if (!error || !cap) return;
    if (value) snprintf(error, cap, "%s (errno %d %s)", what, value, strerror(value));
    else snprintf(error, cap, "%s", what);
}

int bye_client_token_path(const char *socket_path, char *out, size_t cap) {
    if (!socket_path || !out || !cap) return -1;
    size_t len = strlen(socket_path);
    if (len > 5 && strcmp(socket_path + len - 5, ".sock") == 0) len -= 5;
    int n = snprintf(out, cap, "%.*s.token", (int)len, socket_path);
    return n > 0 && (size_t)n < cap ? 0 : -1;
}

static void record(bye_client_t *client, int code) {
    if (client) client->failure = code;
}

static int read_token(bye_client_t *client, const char *socket_path, char *token, char *error, size_t error_cap) {
    char path[256];
    if (bye_client_token_path(socket_path, path, sizeof path) != 0) {
        fail(error, error_cap, "the socket path is too long", 0);
        return -1;
    }
    FILE *file = fopen(path, "r");
    if (!file) {
        char what[300];
        snprintf(what, sizeof what, "cannot read %s", path);
        record(client, errno == ENOENT ? BYE_CLIENT_NO_TOKEN
                     : errno == EACCES || errno == EPERM ? BYE_CLIENT_TOKEN_DENIED : BYE_CLIENT_IO);
        fail(error, error_cap, what, errno);
        return -1;
    }
    char line[BYE_CLIENT_TOKEN_LEN + 8];
    char *got = fgets(line, sizeof line, file);
    fclose(file);
    if (!got) {
        record(client, BYE_CLIENT_TOKEN_BAD);
        fail(error, error_cap, "the token file is empty", 0);
        return -1;
    }
    line[strcspn(line, "\r\n")] = '\0';
    if (strlen(line) != BYE_CLIENT_TOKEN_LEN) {
        record(client, BYE_CLIENT_TOKEN_BAD);
        fail(error, error_cap, "the token file is not a token", 0);
        return -1;
    }
    memcpy(token, line, BYE_CLIENT_TOKEN_LEN + 1);
    return 0;
}

void bye_client_close(bye_client_t *client) {
    if (!client) return;
    if (client->fd >= 0) close(client->fd);
    client->fd = -1;
}

static int send_all(int fd, const char *data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t sent = write(fd, data + off, len - off);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) return -1;
        off += (size_t)sent;
    }
    return 0;
}

long bye_client_call(bye_client_t *client, const char *command, char *answer, size_t cap,
                     char *error, size_t error_cap) {
    if (error && error_cap) error[0] = '\0';
    if (!client || client->fd < 0 || !command || !answer || cap < 4) {
        record(client, BYE_CLIENT_CLOSED);
        fail(error, error_cap, "the client is not connected", 0);
        return -1;
    }
    client->failure = BYE_CLIENT_OK;
    size_t command_len = strlen(command);
    /* a newline inside would run a second command on the daemon's side */
    if (command_len == 0 || command_len > BYE_CLIENT_LINE_MAX || strpbrk(command, "\r\n")) {
        record(client, BYE_CLIENT_BAD_COMMAND);
        fail(error, error_cap, "the command is empty, too long, or has a line break", 0);
        return -1;
    }
    char line[BYE_CLIENT_LINE_MAX + 2];
    memcpy(line, command, command_len);
    line[command_len] = '\n';
    if (send_all(client->fd, line, command_len + 1) != 0) {
        record(client, errno == EPIPE || errno == ECONNRESET ? BYE_CLIENT_CLOSED
                     : errno == EAGAIN || errno == EWOULDBLOCK ? BYE_CLIENT_TIMEOUT : BYE_CLIENT_IO);
        fail(error, error_cap, "cannot send to the daemon", errno);
        return -1;
    }
    size_t len = 0;
    answer[0] = '\0';
    for (;;) {
        if (len + 1 >= cap) {
            record(client, BYE_CLIENT_TOO_LARGE);
            fail(error, error_cap, "the daemon's answer is too large", 0);
            return -1;
        }
        ssize_t got = read(client->fd, answer + len, cap - len - 1);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            record(client, BYE_CLIENT_TIMEOUT);
            fail(error, error_cap, "the daemon did not answer in time", 0);
            return -1;
        }
        if (got <= 0) {
            record(client, got < 0 && errno != ECONNRESET ? BYE_CLIENT_IO : BYE_CLIENT_CLOSED);
            fail(error, error_cap, "the daemon closed the connection", got < 0 ? errno : 0);
            return -1;
        }
        len += (size_t)got;
        answer[len] = '\0';
        /* the answer ends with a line that is one dot */
        if (len >= 2 && answer[len - 1] == '\n' && answer[len - 2] == '.' &&
            (len == 2 || answer[len - 3] == '\n')) {
            len -= 2;
            answer[len] = '\0';
            return (long)len;
        }
    }
}

int bye_client_open(bye_client_t *client, const char *socket_path, int authenticate,
                    uint32_t timeout_ms, char *error, size_t error_cap) {
    if (error && error_cap) error[0] = '\0';
    if (!client || !socket_path) return -1;
    client->fd = -1;
    client->failure = BYE_CLIENT_OK;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof addr.sun_path) {
        record(client, BYE_CLIENT_NO_SOCKET);
        fail(error, error_cap, "the socket path is too long", 0);
        return -1;
    }
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", socket_path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        record(client, BYE_CLIENT_IO);
        fail(error, error_cap, "cannot create a socket", errno);
        return -1;
    }
#ifdef SO_NOSIGPIPE
    /* a daemon that went away must not kill the app with a signal */
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &(int){ 1 }, sizeof(int));
#endif
    if (timeout_ms) {
        struct timeval limit;
        limit.tv_sec = (time_t)(timeout_ms / 1000u);
        limit.tv_usec = (suseconds_t)((timeout_ms % 1000u) * 1000u);
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof limit);
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof limit);
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        char what[300];
        snprintf(what, sizeof what, "cannot reach %s", socket_path);
        record(client, errno == ENOENT || errno == ENOTDIR ? BYE_CLIENT_NO_SOCKET
                     : errno == ECONNREFUSED ? BYE_CLIENT_REFUSED
                     : errno == EACCES || errno == EPERM ? BYE_CLIENT_DENIED : BYE_CLIENT_IO);
        fail(error, error_cap, what, errno);
        close(fd);
        return -1;
    }
    client->fd = fd;
    if (!authenticate) return 0;

    char token[BYE_CLIENT_TOKEN_LEN + 1];
    if (read_token(client, socket_path, token, error, error_cap) != 0) {
        bye_client_close(client);
        return -1;
    }
    char command[BYE_CLIENT_TOKEN_LEN + 8], answer[128];
    snprintf(command, sizeof command, "auth %s", token);
    long got = bye_client_call(client, command, answer, sizeof answer, error, error_cap);
    memset(token, 0, sizeof token);
    memset(command, 0, sizeof command);
    if (got < 0) {
        bye_client_close(client);
        return -1;
    }
    if (strncmp(answer, "OK", 2) != 0) {
        record(client, BYE_CLIENT_TOKEN_REFUSED);
        fail(error, error_cap, "the daemon refused the token", 0);
        bye_client_close(client);
        return -1;
    }
    return 0;
}

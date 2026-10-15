#define _DEFAULT_SOURCE

#include "bye_ctl.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/* the group of the app's user */
#define MOBILE_GID 501
#define MOBILE_UID 501

typedef struct {
    int    fd;
    int    authed;
    char   in[BYE_CTL_LINE_MAX];
    size_t in_len;
    int    discarding; /* a line longer than the limit, dropped to its end */
    char   out[BYE_CTL_REPLY_MAX];
    size_t out_len;
    size_t out_off;
} client_t;

struct bye_ctl {
    int                listen_fd;
    int                lock_fd;
    int                revive_errno;
    char               lock_path[160];
    char               token_path[160];
    char               socket_path[108];
    char               token[BYE_CTL_TOKEN_LEN + 1];
    bye_ctl_handler_fn handler;
    void              *ctx;
    client_t           clients[BYE_CTL_CLIENTS_MAX];
};

static int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void fail(char *error, size_t cap, const char *what, int value) {
    if (error && cap) snprintf(error, cap, "%s (errno %d %s)", what, value, strerror(value));
}

static int write_token(const char *path, char *token) {
    unsigned char raw[BYE_CTL_TOKEN_LEN / 2];
    int random = open("/dev/urandom", O_RDONLY);
    ssize_t got = random >= 0 ? read(random, raw, sizeof raw) : -1;
    if (random >= 0) close(random);
    if (got != (ssize_t)sizeof raw) return -1;
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof raw; ++i) {
        token[i * 2] = hex[raw[i] >> 4];
        token[i * 2 + 1] = hex[raw[i] & 0xf];
    }
    token[BYE_CTL_TOKEN_LEN] = '\0';

    char tmp[160];
    if (snprintf(tmp, sizeof tmp, "%s.%ld.tmp", path, (long)getpid()) >= (int)sizeof tmp) return -1;
    (void)unlink(tmp);
    int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int fd = open(tmp, flags, 0640);
    if (fd < 0) return -1;
    char line[BYE_CTL_TOKEN_LEN + 2];
    int len = snprintf(line, sizeof line, "%s\n", token);
    int ok = write(fd, line, (size_t)len) == len && fchmod(fd, 0640) == 0;
    /* running unprivileged is the host test case, where the owner stays */
    if (fchown(fd, 0, MOBILE_GID) != 0 && geteuid() == 0) ok = 0;
    if (close(fd) != 0) ok = 0;
    if (!ok || rename(tmp, path) != 0) {
        (void)unlink(tmp);
        return -1;
    }
    return 0;
}

/* hold the inode until teardown so launchd and the installer cannot both own the socket */
static int lock_socket(const char *socket_path) {
    char path[160];
    if (snprintf(path, sizeof path, "%s.lock", socket_path) >= (int)sizeof path) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1 || (st.st_mode & 0022)) {
        close(fd);
        errno = EACCES;
        return -1;
    }
    struct flock lock;
    memset(&lock, 0, sizeof lock);
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    if (fcntl(fd, F_SETLK, &lock) != 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

static int remove_stale(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return errno == ENOENT ? 0 : -1;
    if (!S_ISSOCK(st.st_mode)) return -1;
    return unlink(path);
}

/* a listening socket at the path, restricted to root and mobile */
static int open_listener(const char *socket_path, char *error, size_t error_cap) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fail(error, error_cap, "cannot create the control socket", errno);
        return -1;
    }
    if (remove_stale(socket_path) != 0) {
        fail(error, error_cap, "cannot replace the old control socket", errno);
        goto fail;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", socket_path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        fail(error, error_cap, "cannot bind the control socket", errno);
        goto fail;
    }
    if ((chown(socket_path, 0, MOBILE_GID) != 0 && geteuid() == 0) || chmod(socket_path, 0660) != 0) {
        fail(error, error_cap, "cannot restrict the control socket", errno);
        goto fail_bound;
    }
    if (listen(fd, BYE_CTL_CLIENTS_MAX) != 0 || set_nonblock(fd) != 0) {
        fail(error, error_cap, "cannot listen on the control socket", errno);
        goto fail_bound;
    }
    return fd;
fail_bound:
    (void)unlink(socket_path);
fail:
    close(fd);
    return -1;
}

bye_ctl_t *bye_ctl_open(const char *socket_path, const char *token_path,
                        bye_ctl_handler_fn handler, void *ctx, char *error, size_t error_cap) {
    if (error && error_cap) error[0] = '\0';
    if (!socket_path || !token_path || !handler) return NULL;
    bye_ctl_t *ctl = calloc(1, sizeof *ctl);
    if (!ctl) {
        fail(error, error_cap, "out of memory", ENOMEM);
        return NULL;
    }
    ctl->listen_fd = -1;
    ctl->lock_fd = -1;
    for (size_t i = 0; i < BYE_CTL_CLIENTS_MAX; ++i) ctl->clients[i].fd = -1;
    ctl->handler = handler;
    ctl->ctx = ctx;
    if (strlen(socket_path) >= sizeof ctl->socket_path) {
        fail(error, error_cap, "the socket path is too long", ENAMETOOLONG);
        goto fail;
    }
    if (strlen(token_path) >= sizeof ctl->token_path) {
        fail(error, error_cap, "the token path is too long", ENAMETOOLONG);
        goto fail;
    }
    snprintf(ctl->socket_path, sizeof ctl->socket_path, "%s", socket_path);
    snprintf(ctl->token_path, sizeof ctl->token_path, "%s", token_path);
    snprintf(ctl->lock_path, sizeof ctl->lock_path, "%s.lock", socket_path);
    ctl->lock_fd = lock_socket(socket_path);
    if (ctl->lock_fd < 0) {
        fail(error, error_cap, "cannot own the control socket", errno);
        goto fail;
    }
    ctl->listen_fd = open_listener(socket_path, error, error_cap);
    if (ctl->listen_fd < 0) goto fail;
    if (write_token(token_path, ctl->token) != 0) {
        fail(error, error_cap, "cannot write the control token", errno);
        (void)unlink(socket_path);
        goto fail;
    }
    return ctl;
fail:
    if (ctl->listen_fd >= 0) close(ctl->listen_fd);
    if (ctl->lock_fd >= 0) close(ctl->lock_fd);
    free(ctl);
    return NULL;
}

static int path_is(const char *path, int fd) {
    struct stat on_disk, held;
    return lstat(path, &on_disk) == 0 && fstat(fd, &held) == 0 &&
           on_disk.st_dev == held.st_dev && on_disk.st_ino == held.st_ino;
}

int bye_ctl_revive(bye_ctl_t *ctl, char *error, size_t error_cap) {
    if (error && error_cap) error[0] = '\0';
    if (!ctl) return 0;
    struct stat st;
    int socket_gone = lstat(ctl->socket_path, &st) != 0 && errno == ENOENT;
    int token_gone = lstat(ctl->token_path, &st) != 0 && errno == ENOENT;
    if (!socket_gone && !token_gone) {
        ctl->revive_errno = 0;
        return 0;
    }
    int saved = 0;
    const char *what = NULL;
    /* the lock file lives in the same directory and may be gone too, and a lock on an
       unlinked inode no longer keeps a second daemon out */
    if (!path_is(ctl->lock_path, ctl->lock_fd)) {
        if (ctl->lock_fd >= 0) close(ctl->lock_fd);
        ctl->lock_fd = -1;
        int fresh = lock_socket(ctl->socket_path);
        if (fresh < 0) {
            saved = errno;
            what = "cannot own the control socket again";
        } else {
            ctl->lock_fd = fresh;
        }
    }
    if (!what && socket_gone) {
        int fd = open_listener(ctl->socket_path, NULL, 0);
        if (fd < 0) {
            saved = errno;
            what = "cannot bind the control socket again";
        } else {
            close(ctl->listen_fd);
            ctl->listen_fd = fd;
        }
    }
    if (!what && write_token(ctl->token_path, ctl->token) != 0) {
        saved = errno;
        what = "cannot write the control token again";
    }
    if (!what) {
        ctl->revive_errno = 0;
        return 1;
    }
    /* once per cause, the loop calls this every second */
    if (ctl->revive_errno == saved) return 0;
    ctl->revive_errno = saved;
    fail(error, error_cap, what, saved);
    return -1;
}

static void drop_client(client_t *client) {
    if (client->fd >= 0) close(client->fd);
    memset(client, 0, sizeof *client);
    client->fd = -1;
}

void bye_ctl_close(bye_ctl_t *ctl) {
    if (!ctl) return;
    for (size_t i = 0; i < BYE_CTL_CLIENTS_MAX; ++i) drop_client(&ctl->clients[i]);
    if (ctl->listen_fd >= 0) close(ctl->listen_fd);
    (void)unlink(ctl->socket_path);
    (void)unlink(ctl->token_path);
    if (ctl->lock_fd >= 0) close(ctl->lock_fd);
    free(ctl);
}

static int peer_allowed(int fd) {
#if defined(__APPLE__)
    uid_t uid = (uid_t)-1;
    gid_t gid = 0;
    /* an old ios may not report the peer, the token still guards the commands */
    if (getpeereid(fd, &uid, &gid) != 0) return 1;
    return uid == 0 || uid == MOBILE_UID;
#else
    (void)fd;
    return 1;
#endif
}

static void accept_one(bye_ctl_t *ctl) {
    int fd = accept(ctl->listen_fd, NULL, NULL);
    if (fd < 0) return;
    if (!peer_allowed(fd) || set_nonblock(fd) != 0 || fd >= FD_SETSIZE) {
        close(fd);
        return;
    }
    for (size_t i = 0; i < BYE_CTL_CLIENTS_MAX; ++i) {
        if (ctl->clients[i].fd < 0) {
            memset(&ctl->clients[i], 0, sizeof ctl->clients[i]);
            ctl->clients[i].fd = fd;
            return;
        }
    }
    static const char busy[] = "ERR too many control connections\n.\n";
    if (write(fd, busy, sizeof busy - 1) < 0) fprintf(stderr, "byedpid: control busy reply lost\n");
    close(fd);
}

static int token_equal(const char *a, const char *b) {
    size_t al = strlen(a), bl = strlen(b);
    unsigned char diff = (unsigned char)(al ^ bl);
    size_t n = al > bl ? al : bl;
    for (size_t i = 0; i < n; ++i)
        diff |= (unsigned char)((i < al ? a[i] : 0) ^ (i < bl ? b[i] : 0));
    return diff == 0;
}

static void reply(client_t *client, const char *text) {
    size_t len = strlen(text);
    if (len > sizeof client->out - client->out_len) len = sizeof client->out - client->out_len;
    memcpy(client->out + client->out_len, text, len);
    client->out_len += len;
}

static void run_line(bye_ctl_t *ctl, client_t *client, char *line) {
    if (strcmp(line, "version") == 0) {
        reply(client, "OK byebyedpi 1\n.\n");
        return;
    }
    if (strncmp(line, "auth ", 5) == 0) {
        client->authed = token_equal(line + 5, ctl->token);
        reply(client, client->authed ? "OK\n.\n" : "ERR bad token\n.\n");
        return;
    }
    if (!client->authed) {
        reply(client, "ERR authenticate first\n.\n");
        return;
    }
    char out[BYE_CTL_REPLY_MAX];
    size_t len = ctl->handler(ctl->ctx, line, out, sizeof out);
    if (len == 0 || len >= sizeof out) {
        reply(client, "ERR no answer\n.\n");
        return;
    }
    out[len] = '\0';
    reply(client, out);
}

static void flush_client(client_t *client) {
    while (client->out_off < client->out_len) {
        ssize_t sent = write(client->fd, client->out + client->out_off,
                             client->out_len - client->out_off);
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (sent <= 0) {
            drop_client(client);
            return;
        }
        client->out_off += (size_t)sent;
    }
    client->out_off = client->out_len = 0;
}

static void read_client(bye_ctl_t *ctl, client_t *client) {
    char chunk[256];
    ssize_t got = read(client->fd, chunk, sizeof chunk);
    if (got < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) return;
    if (got <= 0) {
        drop_client(client);
        return;
    }
    for (ssize_t i = 0; i < got; ++i) {
        char ch = chunk[i];
        if (ch == '\n') {
            if (client->discarding) {
                client->discarding = 0;
                reply(client, "ERR line too long\n.\n");
            } else {
                client->in[client->in_len] = '\0';
                if (client->in_len && client->in[client->in_len - 1] == '\r')
                    client->in[client->in_len - 1] = '\0';
                run_line(ctl, client, client->in);
            }
            client->in_len = 0;
        } else if (!client->discarding) {
            if (client->in_len + 1 < sizeof client->in) client->in[client->in_len++] = ch;
            else client->discarding = 1;
        }
    }
    flush_client(client);
}

void bye_ctl_prepare(bye_ctl_t *ctl, fd_set *readable, fd_set *writable, int *highest) {
    if (!ctl) return;
    FD_SET(ctl->listen_fd, readable);
    if (ctl->listen_fd > *highest) *highest = ctl->listen_fd;
    for (size_t i = 0; i < BYE_CTL_CLIENTS_MAX; ++i) {
        const client_t *client = &ctl->clients[i];
        if (client->fd < 0) continue;
        FD_SET(client->fd, readable);
        if (client->out_off < client->out_len) FD_SET(client->fd, writable);
        if (client->fd > *highest) *highest = client->fd;
    }
}

void bye_ctl_service(bye_ctl_t *ctl, const fd_set *readable, const fd_set *writable) {
    if (!ctl) return;
    if (FD_ISSET(ctl->listen_fd, readable)) accept_one(ctl);
    for (size_t i = 0; i < BYE_CTL_CLIENTS_MAX; ++i) {
        client_t *client = &ctl->clients[i];
        if (client->fd < 0) continue;
        if (FD_ISSET(client->fd, writable)) flush_client(client);
        if (client->fd >= 0 && FD_ISSET(client->fd, readable)) read_client(ctl, client);
    }
}

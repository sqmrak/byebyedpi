#define _DEFAULT_SOURCE
#include "bye_ctl.h"
#include "check.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static size_t handler(void *ctx, const char *line, char *out, size_t cap) {
    (void)ctx; (void)line;
    return (size_t)snprintf(out, cap, "OK\n.\n");
}

static void read_token(const char *path, char *out, size_t cap) {
    FILE *file = fopen(path, "r");
    CHECK(file != NULL);
    if (!file) { out[0] = 0; return; }
    CHECK(fgets(out, (int)cap, file) != NULL);
    CHECK(fclose(file) == 0);
}

int main(void) {
    char dir[] = "/tmp/bye-ctl-owner.XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    char socket_path[108], token_path[160], lock_path[160], target[160], error[256];
    snprintf(socket_path, sizeof socket_path, "%s/ctl.sock", dir);
    snprintf(token_path, sizeof token_path, "%s/ctl.token", dir);
    snprintf(lock_path, sizeof lock_path, "%s.lock", socket_path);
    snprintf(target, sizeof target, "%s/target", dir);
    bye_ctl_t *ctl = bye_ctl_open(socket_path, token_path, handler, NULL, error, sizeof error);
    CHECK(ctl != NULL);
    if (!ctl) return 1;
    char first[64], after[64];
    read_token(token_path, first, sizeof first);

    /* the rejected process must leave the first daemon's socket and token intact */
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        bye_ctl_t *other = bye_ctl_open(socket_path, token_path, handler, NULL, error, sizeof error);
        if (other) _exit(1);
        _exit(strstr(error, "cannot own the control socket") ? 0 : 2);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    struct stat st;
    CHECK(lstat(socket_path, &st) == 0 && S_ISSOCK(st.st_mode));
    read_token(token_path, after, sizeof after);
    CHECK(strcmp(first, after) == 0);

    bye_ctl_close(ctl);
    CHECK(access(socket_path, F_OK) != 0 && access(token_path, F_OK) != 0);
    /* keep the lock inode so a waiting launchd start cannot lock an unlinked file */
    CHECK(stat(lock_path, &st) == 0 && S_ISREG(st.st_mode));
    ctl = bye_ctl_open(socket_path, token_path, handler, NULL, error, sizeof error);
    CHECK(ctl != NULL);
    if (!ctl) return 1;

    /* a cleaner of /var/tmp removes all three files under a running daemon */
    CHECK(bye_ctl_revive(ctl, error, sizeof error) == 0);
    read_token(token_path, first, sizeof first);
    CHECK(unlink(socket_path) == 0 && unlink(token_path) == 0 && unlink(lock_path) == 0);
    CHECK(bye_ctl_revive(ctl, error, sizeof error) == 1);
    CHECK(lstat(socket_path, &st) == 0 && S_ISSOCK(st.st_mode) && (st.st_mode & 0777) == 0660);
    CHECK(lstat(token_path, &st) == 0 && lstat(lock_path, &st) == 0);
    read_token(token_path, after, sizeof after);
    CHECK(strlen(after) > 0 && strcmp(first, after) != 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", socket_path);
    int client = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(client >= 0 && connect(client, (struct sockaddr *)&addr, sizeof addr) == 0);
    close(client);
    CHECK(bye_ctl_revive(ctl, error, sizeof error) == 0);
    /* the new lock keeps a second daemon out again */
    child = fork();
    CHECK(child >= 0);
    if (child == 0) _exit(bye_ctl_open(socket_path, token_path, handler, NULL, error, sizeof error) ? 1 : 0);
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    /* only the token is gone: the socket stays the same inode */
    struct stat before;
    CHECK(lstat(socket_path, &before) == 0 && unlink(token_path) == 0);
    CHECK(bye_ctl_revive(ctl, error, sizeof error) == 1);
    CHECK(lstat(socket_path, &st) == 0 && st.st_ino == before.st_ino && lstat(token_path, &st) == 0);
    bye_ctl_close(ctl);

    CHECK(unlink(lock_path) == 0);
    int fd = open(target, O_WRONLY | O_CREAT | O_EXCL, 0600);
    CHECK(fd >= 0 && write(fd, "keep", 4) == 4 && close(fd) == 0);
    CHECK(symlink(target, lock_path) == 0);
    CHECK(bye_ctl_open(socket_path, token_path, handler, NULL, error, sizeof error) == NULL);
    CHECK(stat(target, &st) == 0 && st.st_size == 4);
    CHECK(unlink(lock_path) == 0);
    CHECK(link(target, lock_path) == 0);
    CHECK(bye_ctl_open(socket_path, token_path, handler, NULL, error, sizeof error) == NULL);
    CHECK(unlink(lock_path) == 0);
    CHECK(mkfifo(lock_path, 0600) == 0);
    CHECK(bye_ctl_open(socket_path, token_path, handler, NULL, error, sizeof error) == NULL);
    CHECK(unlink(lock_path) == 0);
    fd = open(lock_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    CHECK(fd >= 0 && close(fd) == 0 && chmod(lock_path, 0666) == 0);
    CHECK(bye_ctl_open(socket_path, token_path, handler, NULL, error, sizeof error) == NULL);
    CHECK(unlink(lock_path) == 0);
    CHECK(unlink(target) == 0 && rmdir(dir) == 0);
    puts("ctl owner checks passed");
    return failed ? 1 : 0;
}

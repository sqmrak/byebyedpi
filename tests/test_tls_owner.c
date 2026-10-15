#define _DEFAULT_SOURCE
#include "check.h"
#include <fcntl.h>
#include <stdlib.h>

#include "../daemon/bye_tls_owner.c"

static void put(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0640);
    CHECK(fd >= 0);
    if (fd < 0) return;
    CHECK(write(fd, text, strlen(text)) == (ssize_t)strlen(text));
    CHECK(close(fd) == 0);
}

int main(void) {
    char dir[] = "/tmp/bye-tls-owner.XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    char original[256], backup[256], own[256], target[256];
    snprintf(original, sizeof original, "%s/tlsfix.dylib", dir);
    snprintf(backup, sizeof backup, "%s/" BYE_TLS_DISABLED_NAME, dir);
    snprintf(own, sizeof own, "%s/byebyetlsfix.dylib", dir);
    snprintf(target, sizeof target, "%s/target", dir);
    put(original, "original tlsfix");
    CHECK(switch_dir(dir, 1) == 0);
    CHECK(access(original, F_OK) == 0 && access(backup, F_OK) != 0);
    put(own, "own tls shim");
    struct stat before, after;
    CHECK(lstat(original, &before) == 0);
    CHECK(switch_dir(dir, 1) == 1);
    CHECK(access(original, F_OK) != 0 && lstat(backup, &after) == 0);
    CHECK(before.st_ino == after.st_ino && before.st_mode == after.st_mode &&
          before.st_uid == after.st_uid && before.st_gid == after.st_gid &&
          before.st_size == after.st_size && before.st_mtime == after.st_mtime);
    CHECK(switch_dir(dir, 1) == 0);
    CHECK(switch_dir(dir, 0) == 1);
    CHECK(lstat(original, &after) == 0 && before.st_ino == after.st_ino);
    CHECK(switch_dir(dir, 0) == 0);

    /* never overwrite a saved shim or a replacement installed while running */
    put(backup, "another backup");
    CHECK(switch_dir(dir, 1) == -1);
    CHECK(lstat(original, &after) == 0 && before.st_ino == after.st_ino);
    CHECK(switch_dir(dir, 0) == -1);
    CHECK(unlink(backup) == 0);
    CHECK(switch_dir(dir, 1) == 1);
    put(original, "new package shim");
    CHECK(switch_dir(dir, 0) == -1);
    CHECK(lstat(backup, &after) == 0 && before.st_ino == after.st_ino);
    CHECK(unlink(original) == 0 && switch_dir(dir, 0) == 1);

    /* a crash between link and unlink leaves two names for the same inode */
    CHECK(link(original, backup) == 0 && switch_dir(dir, 1) == 1);
    CHECK(link(backup, original) == 0 && switch_dir(dir, 0) == 1);
    CHECK(unlink(original) == 0);
    put(target, "linked shim");
    CHECK(symlink(target, original) == 0 && switch_dir(dir, 1) == 1);
    CHECK(lstat(backup, &after) == 0 && S_ISLNK(after.st_mode));
    CHECK(switch_dir(dir, 0) == 1 && lstat(original, &after) == 0 && S_ISLNK(after.st_mode));
    /* a crash after the symlink copy leaves two equal symlinks, and a backup that points elsewhere is kept */
    CHECK(unlink(original) == 0);
    CHECK(symlink(target, backup) == 0 && symlink(target, original) == 0);
    CHECK(switch_dir(dir, 1) == 1 && lstat(original, &after) != 0);
    CHECK(lstat(backup, &after) == 0 && S_ISLNK(after.st_mode) && unlink(backup) == 0);
    CHECK(symlink(own, backup) == 0 && symlink(target, original) == 0 && switch_dir(dir, 1) == -1);
    CHECK(lstat(original, &after) == 0 && unlink(original) == 0 && unlink(backup) == 0);
    CHECK(mkfifo(original, 0600) == 0 && switch_dir(dir, 1) == -1);
    CHECK(unlink(original) == 0);
    CHECK(switch_dir(dir, 1) == 0);
    char long_dir[300];
    memset(long_dir, 'a', sizeof long_dir - 1);
    long_dir[sizeof long_dir - 1] = '\0';
    CHECK(switch_dir(long_dir, 1) == -1 && errno == ENAMETOOLONG);

    /* senko's copy is swapped the same way and both shims move in one call */
    char senko[256], senko_backup[256];
    snprintf(senko, sizeof senko, "%s/senkotlsfix.dylib", dir);
    snprintf(senko_backup, sizeof senko_backup, "%s/" BYE_SENKO_TLS_DISABLED_NAME, dir);
    put(senko, "senko tlsfix");
    put(original, "original tlsfix");
    CHECK(switch_dir(dir, 1) == 1);
    CHECK(access(senko, F_OK) != 0 && access(senko_backup, F_OK) == 0);
    CHECK(access(original, F_OK) != 0 && access(backup, F_OK) == 0);
    CHECK(switch_dir(dir, 0) == 1);
    CHECK(access(senko, F_OK) == 0 && access(senko_backup, F_OK) != 0);
    CHECK(access(original, F_OK) == 0 && access(backup, F_OK) != 0);
    CHECK(unlink(senko) == 0 && unlink(original) == 0);
    CHECK(unlink(target) == 0 && unlink(own) == 0 && rmdir(dir) == 0);
    puts("tls owner checks passed");
    return failed ? 1 : 0;
}

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#include "bye_tls_owner.h"
#include "bye_paths.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *hook_dirs[] = {
    "/Library/MobileSubstrate/DynamicLibraries",
    "/usr/lib/TweakInject"
};

/* darwin link() follows a symlink, so linking senkotlsfix.dylib (a symlink into /var/jb) from
   the root volume fails with EXDEV. a symlink gets a copy of itself, which is exclusive too */
static int copy_exclusive(const char *source, const struct stat *from, const char *target) {
    if (!S_ISLNK(from->st_mode)) return link(source, target);
    char text[512];
    ssize_t len = readlink(source, text, sizeof text - 1);
    if (len < 0) return -1;
    text[len] = '\0';
    return symlink(text, target);
}

/* a crash between the copy and the unlink leaves both names, and the retry finishes the move */
static int same_entry(const char *source, const struct stat *from, const char *target) {
    struct stat to;
    if (lstat(target, &to) != 0) return 0;
    if (!S_ISLNK(from->st_mode)) return from->st_dev == to.st_dev && from->st_ino == to.st_ino;
    if (!S_ISLNK(to.st_mode)) return 0;
    char a[512], b[512];
    ssize_t la = readlink(source, a, sizeof a - 1), lb = readlink(target, b, sizeof b - 1);
    return la >= 0 && la == lb && memcmp(a, b, (size_t)la) == 0;
}

/* copy first so a package upgrade cannot overwrite an existing backup */
static int move_exclusive(const char *source, const char *target) {
    struct stat from;
    if (lstat(source, &from) != 0) return errno == ENOENT ? 0 : -1;
    if (!S_ISREG(from.st_mode) && !S_ISLNK(from.st_mode)) {
        errno = EINVAL;
        return -1;
    }
    int created = copy_exclusive(source, &from, target) == 0;
    if (!created && (errno != EEXIST || !same_entry(source, &from, target))) return -1;
    if (unlink(source) == 0) return 1;
    int saved = errno;
    if (created && unlink(target) != 0)
        fprintf(stderr, "byedpid: cannot undo tlsfix backup %s (errno %d)\n", target, errno);
    errno = saved;
    return -1;
}

/* senko ships the same shim as senkotlsfix.dylib, and two shims on the securetransport
   functions would hook them twice */
static const struct {
    const char *name;
    const char *backup;
} shims[] = {
    { "tlsfix.dylib", BYE_TLS_DISABLED_NAME },
    { "senkotlsfix.dylib", BYE_SENKO_TLS_DISABLED_NAME }
};

static int switch_dir(const char *dir, int enabled) {
    char original[256], backup[256], own[256];
    int changed = 0;
    if (snprintf(own, sizeof own, "%s/byebyetlsfix.dylib", dir) >= (int)sizeof own) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (enabled && access(own, R_OK) != 0) {
        if (errno == ENOENT) return 0;
        return -1;
    }
    for (size_t i = 0; i < sizeof shims / sizeof shims[0]; ++i) {
        if (snprintf(original, sizeof original, "%s/%s", dir, shims[i].name) >= (int)sizeof original ||
            snprintf(backup, sizeof backup, "%s/%s", dir, shims[i].backup) >= (int)sizeof backup) {
            errno = ENAMETOOLONG;
            return -1;
        }
        int result = enabled ? move_exclusive(original, backup) : move_exclusive(backup, original);
        if (result < 0) return -1;
        if (result) changed = 1;
    }
    return changed;
}

int bye_tls_owner_set(int enabled, int *changed, char *error, size_t error_cap) {
    if (changed) *changed = 0;
    if (error && error_cap) error[0] = '\0';
    for (size_t i = 0; i < sizeof hook_dirs / sizeof hook_dirs[0]; ++i) {
        int result = switch_dir(hook_dirs[i], enabled);
        if (result < 0) {
            int saved = errno;
            if (error && error_cap)
                snprintf(error, error_cap, "cannot %s tlsfix in %s (errno %d: %s)",
                         enabled ? "disable" : "restore", hook_dirs[i], saved, strerror(saved));
            return -1;
        }
        if (result && changed) *changed = 1;
    }
    return 0;
}

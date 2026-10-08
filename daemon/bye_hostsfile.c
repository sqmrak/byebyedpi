#define _DEFAULT_SOURCE

#include "bye_hostsfile.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* without it a link in the app's directory would lead the root daemon anywhere */
#ifndef O_NOFOLLOW
#error O_NOFOLLOW is required
#endif

static int name_is_plain(const char *name) {
    size_t len = strlen(name);
    if (len == 0 || len > 64 || name[0] == '.') return 0;
    for (size_t i = 0; i < len; ++i) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-')) return 0;
    }
    return 1;
}

bye_hosts_t *bye_hostsfile_load(const char *dir, const char *name, char *reason, size_t cap) {
    if (reason && cap) reason[0] = '\0';
    if (!dir || !name || !reason || !cap) return NULL;
    /* the config checks this too; a caller that skipped it must not reach another file */
    if (!name_is_plain(name)) {
        snprintf(reason, cap, "the hosts list name is not a plain file name");
        return NULL;
    }
    char path[512];
    if (snprintf(path, sizeof path, "%s/%s", dir, name) >= (int)sizeof path) {
        snprintf(reason, cap, "the hosts list path is too long");
        return NULL;
    }
    /* O_NONBLOCK so that a pipe in its place cannot hold the daemon in open */
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        snprintf(reason, cap, "cannot read the hosts list %.60s (errno %d %s)", name, errno,
                 strerror(errno));
        return NULL;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        snprintf(reason, cap, "the hosts list %.60s is not a plain file", name);
        return NULL;
    }
    if (st.st_size > (off_t)BYE_HOSTS_FILE_MAX) {
        close(fd);
        snprintf(reason, cap, "the hosts list %.60s is larger than %u bytes", name,
                 (unsigned)BYE_HOSTS_FILE_MAX);
        return NULL;
    }
    char *text = malloc((size_t)BYE_HOSTS_FILE_MAX + 1);
    if (!text) {
        close(fd);
        snprintf(reason, cap, "not enough memory for the hosts list");
        return NULL;
    }
    size_t len = 0;
    int failed = 0;
    for (;;) {
        ssize_t got = read(fd, text + len, (size_t)BYE_HOSTS_FILE_MAX + 1 - len);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) {
            failed = 1;
            break;
        }
        if (got == 0) break;
        len += (size_t)got;
        if (len > BYE_HOSTS_FILE_MAX) break;
    }
    close(fd);
    bye_hosts_t *hosts = NULL;
    if (failed) {
        snprintf(reason, cap, "cannot read the hosts list %.60s", name);
    } else if (len > BYE_HOSTS_FILE_MAX) {
        /* the file grew while it was read */
        snprintf(reason, cap, "the hosts list %.60s is larger than %u bytes", name,
                 (unsigned)BYE_HOSTS_FILE_MAX);
    } else {
        char detail[BYE_HOSTS_ERROR_MAX];
        hosts = bye_hosts_parse(text, len, detail, sizeof detail);
        if (!hosts) snprintf(reason, cap, "hosts list %.60s, %s", name, detail);
    }
    free(text);
    return hosts;
}

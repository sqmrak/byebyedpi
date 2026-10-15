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

/* reads dir/name into buf, which holds max + 1 bytes: the whole file or nothing.
   `what` names the file kind in the reason */
static int read_plain_file(const char *dir, const char *name, const char *what, size_t max,
                           uint8_t *buf, size_t *len_out, char *reason, size_t cap) {
    *len_out = 0;
    /* the config checks this too; a caller that skipped it must not reach another file */
    if (!name_is_plain(name)) {
        snprintf(reason, cap, "the %s name is not a plain file name", what);
        return -1;
    }
    char path[512];
    if (snprintf(path, sizeof path, "%s/%s", dir, name) >= (int)sizeof path) {
        snprintf(reason, cap, "the %s path is too long", what);
        return -1;
    }
    /* O_NONBLOCK so that a pipe in its place cannot hold the daemon in open */
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        snprintf(reason, cap, "cannot read the %s %.60s (errno %d %s)", what, name, errno,
                 strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        snprintf(reason, cap, "the %s %.60s is not a plain file", what, name);
        return -1;
    }
    if (st.st_size > (off_t)max) {
        close(fd);
        snprintf(reason, cap, "the %s %.60s is larger than %u bytes", what, name, (unsigned)max);
        return -1;
    }
    size_t len = 0;
    for (;;) {
        ssize_t got = read(fd, buf + len, max + 1 - len);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) {
            close(fd);
            snprintf(reason, cap, "cannot read the %s %.60s", what, name);
            return -1;
        }
        if (got == 0) break;
        len += (size_t)got;
        if (len > max) break;
    }
    close(fd);
    if (len > max) {
        /* the file grew while it was read */
        snprintf(reason, cap, "the %s %.60s is larger than %u bytes", what, name, (unsigned)max);
        return -1;
    }
    *len_out = len;
    return 0;
}

bye_hosts_t *bye_hostsfile_load(const char *dir, const char *name, char *reason, size_t cap) {
    if (reason && cap) reason[0] = '\0';
    if (!dir || !name || !reason || !cap) return NULL;
    char *text = malloc((size_t)BYE_HOSTS_FILE_MAX + 1);
    if (!text) {
        snprintf(reason, cap, "not enough memory for the hosts list");
        return NULL;
    }
    size_t len;
    bye_hosts_t *hosts = NULL;
    if (read_plain_file(dir, name, "hosts list", BYE_HOSTS_FILE_MAX, (uint8_t *)text, &len, reason, cap) == 0) {
        char detail[BYE_HOSTS_ERROR_MAX];
        hosts = bye_hosts_parse(text, len, detail, sizeof detail);
        if (!hosts) snprintf(reason, cap, "hosts list %.60s, %s", name, detail);
    }
    free(text);
    return hosts;
}

int bye_hostsfile_read(const char *dir, const char *name, const char *what, uint8_t *out,
                       size_t out_cap, size_t *len, char *reason, size_t cap) {
    if (reason && cap) reason[0] = '\0';
    if (!dir || !name || !what || !out || !len || !reason || !cap || out_cap < 2) return -1;
    uint8_t *buf = malloc(out_cap + 1);
    if (!buf) {
        snprintf(reason, cap, "not enough memory for the %s", what);
        return -1;
    }
    int status = read_plain_file(dir, name, what, out_cap, buf, len, reason, cap);
    if (status == 0) memcpy(out, buf, *len);
    free(buf);
    return status;
}

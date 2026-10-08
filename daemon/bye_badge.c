#include "bye_badge.h"

#include "bye_paths.h"
#include "bye_status.h"

#include <stdio.h>
#include <string.h>

#if defined(__APPLE__)

#include <errno.h>
#include <fcntl.h>
#include <notify.h>
#include <unistd.h>

static void publish(int on, const char *ifname) {
    char line[BYE_STATUS_LINE_MAX];
    size_t len = bye_status_format(line, sizeof line, on, ifname);
    if (len == 0) len = bye_status_format(line, sizeof line, on, NULL);
    int fd = open(BYE_STATUS_STATE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fprintf(stderr, "byedpid: cannot write %s (errno %d %s)\n", BYE_STATUS_STATE, errno,
                strerror(errno));
        return;
    }
    if (write(fd, line, len) != (ssize_t)len)
        fprintf(stderr, "byedpid: cannot write %s (errno %d %s)\n", BYE_STATUS_STATE, errno,
                strerror(errno));
    close(fd);
    if (notify_post(BYE_STATUS_NOTIFY) != NOTIFY_STATUS_OK)
        fprintf(stderr, "byedpid: cannot post %s\n", BYE_STATUS_NOTIFY);
}

void bye_badge_on(const char *physical_ifname) {
    publish(1, physical_ifname);
}

void bye_badge_off(void) {
    publish(0, NULL);
}

#else

void bye_badge_on(const char *physical_ifname) {
    (void)physical_ifname;
}

void bye_badge_off(void) {
}

#endif

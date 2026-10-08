#include "direct_socket.h"

#include "route_socket.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined(__APPLE__)
/* xnu has had both since ios 5, but the armv7 sdk headers leave them out */
#ifndef IP_BOUND_IF
#define IP_BOUND_IF 25
#endif
#ifndef IPV6_BOUND_IF
#define IPV6_BOUND_IF 125
#endif
#endif

static int fail(int fd, char *error, size_t cap, const char *what) {
    int saved = errno;
    if (fd >= 0) close(fd);
    if (error && cap) {
        snprintf(error, cap, "%s", what);
        route_errno_append(error, cap, saved);
    }
    return -1;
}

int direct_socket_bound(void *ctx, int family, int type, char *error, size_t error_cap) {
    const direct_socket_iface_t *iface = ctx;
    if (error && error_cap) error[0] = '\0';
    if (!iface || iface->ifindex == 0) {
        if (error && error_cap)
            snprintf(error, error_cap, "no physical interface is known for direct traffic");
        return -1;
    }
    int fd = socket(family, type, 0);
    if (fd < 0) return fail(-1, error, error_cap, "cannot open a direct socket");
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 ||
        fcntl(fd, F_SETFD, FD_CLOEXEC) != 0)
        return fail(fd, error, error_cap, "cannot make the direct socket nonblocking");
#if defined(__APPLE__)
    int index = (int)iface->ifindex;
    int bound = family == AF_INET6
        ? setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &index, sizeof index)
        : setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index, sizeof index);
    if (bound != 0) {
        char what[64];
        snprintf(what, sizeof what, "cannot bind the direct socket to %s", iface->ifname);
        return fail(fd, error, error_cap, what);
    }
    int on = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof on);
#else
    /* host builds run the tests, where no tunnel owns the default route */
    (void)family;
#endif
    return fd;
}

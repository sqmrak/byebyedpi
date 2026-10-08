#ifndef SENKO_DIRECT_SOCKET_H
#define SENKO_DIRECT_SOCKET_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* a socket for a flow the rules send straight out of the physical interface.
   the tunnel's split defaults cover every destination, so a plain socket from
   byedpid would be routed back into utun; binding it to the interface makes
   the kernel use that interface's scoped route instead.

   returns a nonblocking, close-on-exec descriptor, or -1 with the reason in
   error. type is SOCK_STREAM or SOCK_DGRAM */
typedef int (*direct_socket_fn)(void *ctx, int family, int type,
                                char *error, size_t error_cap);

typedef struct {
    unsigned ifindex; /* the physical interface, 0 when it is unknown */
    char     ifname[16];
} direct_socket_iface_t;

/* ctx is a direct_socket_iface_t */
int direct_socket_bound(void *ctx, int family, int type, char *error, size_t error_cap);

#ifdef __cplusplus
}
#endif

#endif

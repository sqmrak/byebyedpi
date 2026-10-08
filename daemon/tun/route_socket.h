#ifndef SENKO_ROUTE_SOCKET_H
#define SENKO_ROUTE_SOCKET_H

#include <stddef.h>
#include <stdint.h>

#include "core/route_message.h"

#ifdef __cplusplus
extern "C" {
#endif

/* one request and its reply on the routing socket. all the parts that are
   easy to get wrong live here behind an injectable io interface, so the
   sequence matching, the foreign reply skipping, the deadline and the errno
   rules are covered by host tests instead of only by a device */

/* wide enough to hold the longest explanation after two ipv6 addresses, so
   the errno at the end is never the part that gets cut off */
#define ROUTE_ERROR_MAX 320
#define ROUTE_SOCKET_DEFAULT_TIMEOUT_MS 2000

typedef enum {
    ROUTE_SOCKET_OK = 0,
    /* a delete of a route the kernel does not have. the route is gone either
       way, which is what the caller wanted */
    ROUTE_SOCKET_ALREADY_GONE = 1,
    ROUTE_SOCKET_ERR_ARG     = -1,
    ROUTE_SOCKET_ERR_BUILD   = -2,
    ROUTE_SOCKET_ERR_WRITE   = -3,
    ROUTE_SOCKET_ERR_READ    = -4,
    ROUTE_SOCKET_ERR_TIMEOUT = -5,
    ROUTE_SOCKET_ERR_REPLY   = -6, /* the reply was malformed or truncated */
    /* an add that collided with a route already in the table. never treated
       as success: the existing route belongs to someone else, and a rollback
       that deleted it would take out a route this daemon never installed */
    ROUTE_SOCKET_ERR_EXISTS  = -7,
    ROUTE_SOCKET_ERR_KERNEL  = -8
} route_socket_status_t;

typedef struct {
    route_socket_status_t status;
    int  kernel_errno; /* rtm_errno, or the errno of a failed read or write */
    /* a finished sentence naming the operation, the cause in plain words and
       the exact code, e.g.
       add route 0.0.0.0/1 via utun3 failed: a route for this destination
       already exists (errno 17 EEXIST) */
    char message[ROUTE_ERROR_MAX];
} route_error_t;

typedef struct {
    /* write the whole message. returns the byte count, or -1 with the errno
       in *out_errno */
    long (*write_message)(void *ctx, const uint8_t *data, size_t len, int *out_errno);
    /* read one message, waiting no longer than deadline_ms on the clock this
       interface provides. returns the byte count, 0 when the deadline passed
       with nothing to read, or -1 with the errno in *out_errno */
    long (*read_message)(void *ctx, uint8_t *buf, size_t cap, int64_t deadline_ms,
                         int *out_errno);
    int64_t (*now_ms)(void *ctx);
    void   *ctx;
    int32_t pid; /* what the kernel will stamp our replies with */
} route_io_t;

/* send one route message and wait for the reply that carries our pid and
   sequence, skipping replies belonging to other writers on the socket */
route_socket_status_t route_socket_transact(const route_io_t *io,
                                            const route_message_spec_t *spec,
                                            int64_t timeout_ms,
                                            route_message_reply_t *out_reply,
                                            route_error_t *out_error);

/* the sequence number of the next request. every request gets its own, so a
   late reply to an earlier one is recognised as stale rather than accepted */
int32_t route_socket_next_seq(void);

const char *route_socket_status_name(route_socket_status_t status);

/* "203.0.113.7/32 via 192.168.0.1" or "0.0.0.0/1 via interface 14", for log
   lines and error messages */
void route_socket_describe(const route_message_spec_t *spec, char *out, size_t cap);

/* the name of an errno, e.g. 17 -> "EEXIST", or "" for codes without a
   name here */
const char *route_errno_name(int value);

/* appends " (errno 17 EEXIST)", or " (errno 99)" without a name, so a
   message never loses the number */
void route_errno_append(char *out, size_t cap, int value);

#ifdef __cplusplus
}
#endif

#endif

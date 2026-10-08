#ifndef SENKO_TUN_STACK_H
#define SENKO_TUN_STACK_H

#include <stddef.h>
#include <stdint.h>

#include "core/tun_flow.h"
#include "core/tun_nat.h"
#include "core/utun_frame.h"

#ifdef __cplusplus
extern "C" {
#endif

/* the only place senko touches the vendored ip stack. it takes frames from
   the utun device, captures the app's tcp connections with their original
   destinations, and hands the stack's answers back as frames. no servers, no
   policies, no transports and no routes live here.

   the frame is the unit at this boundary: this module parses the four byte
   family header of every inbound frame once and writes it for every outbound
   frame once. the device below only moves whole frames.

   one thread owns everything here: the device, every lwip call, the timers,
   the pending queue and the flow callbacks. lwip in this port has no locking
   of its own, so every entry point checks the caller. other threads talk to
   the owner through daemon/tun_loop.c.

   capture works by bounded translation, see core/tun_nat.h. a new syn is
   held and reported to the owner, who accepts it (the stack then answers the
   app from the original destination) or rejects it (the app gets a reset from
   that destination). the stack never completes a handshake the owner has not
   agreed to */

#define TUN_STACK_QUEUE_MAX 16
#define TUN_STACK_PACKET_MAX 1600
#define TUN_STACK_FRAME_MAX (UTUN_FRAME_HEADER_LEN + TUN_STACK_PACKET_MAX)
#define TUN_STACK_DEFAULT_QUEUE_PACKETS 8
#define TUN_STACK_DEFAULT_QUEUE_BYTES (64u * 1024u)
#define TUN_STACK_DEFAULT_QUEUE_AGE_MS 2000u
#define TUN_STACK_DEFAULT_PENDING_MS 10000u
#define TUN_STACK_DEFAULT_LISTEN_PORT 7

typedef enum {
    TUN_STACK_OK        =  0,
    TUN_STACK_QUEUED    =  1, /* the device was busy, the frame is pending */
    TUN_STACK_ERR_ARG   = -1,
    TUN_STACK_ERR_STATE = -2, /* not started, already stopped, or wrong thread */
    TUN_STACK_ERR_FRAME = -3, /* the framing or the ip header was not valid */
    TUN_STACK_ERR_OVERSIZE = -4, /* larger than the interface may carry */
    TUN_STACK_ERR_MEMORY = -5, /* the stack had no pbuf left */
    TUN_STACK_ERR_QUEUE  = -6, /* the pending queue is full */
    TUN_STACK_ERR_IO     = -7, /* the device refused the write */
    TUN_STACK_ERR_STACK  = -8, /* lwip refused the packet */
    TUN_STACK_ERR_CAPTURE = -9, /* capture dropped it, see the capture counters */
    TUN_STACK_ERR_FLOW   = -10 /* the flow id is stale or in the wrong state */
} tun_stack_status_t;

typedef enum {
    /* a syn arrived for a new tuple. the owner must call accept or reject;
       until then the syn is held and the app sees nothing */
    TUN_STACK_FLOW_REQUESTED = 0,
    /* the three way handshake with the app completed */
    TUN_STACK_FLOW_OPEN,
    /* bytes from the app, or its fin, wait in tun_stack_flow_peek() */
    TUN_STACK_FLOW_READABLE,
    /* the app acknowledged data, so tun_stack_flow_writable() grew */
    TUN_STACK_FLOW_WRITABLE,
    /* the flow is gone for good. every REQUESTED is followed by exactly one
       CLOSED, whatever ended it */
    TUN_STACK_FLOW_CLOSED
} tun_stack_flow_event_t;

typedef void (*tun_stack_flow_fn)(void *ctx, tun_stack_flow_event_t event,
                                  uint64_t flow_id, const tun_flow_key_t *key);

/* the callback must consume or copy the payload before it returns, because
   the device read buffer is reused for the next frame */
typedef int (*tun_stack_udp_fn)(void *ctx, const tun_flow_key_t *key,
                                const uint8_t *payload, size_t payload_len);

typedef struct {
    char     ifname[16]; /* for diagnostics, the device owns the real name */
    uint16_t mtu;        /* explicit, never inferred. 1500 unless told otherwise */

    uint8_t  address4[4];    /* the stack's own address */
    uint8_t  netmask4[4];
    uint8_t  synthetic4[4];  /* the reserved peer captured flows appear to use */
    int      have_ipv4;

    uint8_t  address6[16];
    uint8_t  synthetic6[16];
    int      have_ipv6;

    uint16_t listen_port;    /* 0 picks TUN_STACK_DEFAULT_LISTEN_PORT */

    /* the pending queue is bounded three ways at once, because any one of
       them alone still allows a stall to grow without limit */
    size_t   queue_max_packets;
    size_t   queue_max_bytes;
    uint64_t queue_max_age_ms;

    /* how long a held syn waits for the owner before it is dropped */
    uint64_t pending_max_ms;

    /* flow events, called on the owning thread. with no callback every new
       flow is rejected, so an app never waits on a flow nobody will serve */
    tun_stack_flow_fn flow_event;
    void             *flow_ctx;
    tun_stack_udp_fn  udp_packet;
    void             *udp_ctx;
} tun_stack_config_t;

typedef struct {
    uint64_t frames_in;        /* frames handed to the stack */
    uint64_t frames_out;       /* frames written to the device */
    uint64_t bytes_in;
    uint64_t bytes_out;

    uint64_t dropped_frame;    /* bad framing, family or ip header */
    uint64_t dropped_oversize; /* larger than mtu */
    uint64_t dropped_no_pbuf;  /* the stack had no buffer */
    uint64_t dropped_by_stack; /* lwip took it and refused it */
    uint64_t dropped_capture;  /* see tun_stack_capture() for the reasons */
    uint64_t dropped_outbound; /* the stack sent something capture could not map */

    uint64_t queued;           /* frames parked because the device blocked */
    uint64_t queue_full;       /* frames refused because the queue was full */
    uint64_t queue_expired;    /* frames dropped for sitting too long */
    uint64_t write_errors;     /* failed descriptor */
    uint64_t short_writes;     /* the device took part of a frame */

    uint64_t flows_requested;
    uint64_t flows_opened;
    uint64_t flows_rejected;
    uint64_t flows_closed;
    uint64_t udp_received;
    uint64_t udp_sent;
    uint64_t udp_refused;

    size_t   queue_packets;    /* what is pending right now */
    size_t   queue_bytes;
    size_t   queue_peak_packets;
} tun_stack_stats_t;

typedef enum {
    TUN_STACK_WRITE_DONE = 0,
    TUN_STACK_WRITE_BLOCKED, /* no room right now, try again when writable */
    TUN_STACK_WRITE_SHORT,   /* part of the frame went out: the frame is lost */
    TUN_STACK_WRITE_FAILED   /* the descriptor is broken */
} tun_stack_write_t;

/* how the adapter reaches the device. daemon/tun_loop.c binds this to the
   utun descriptor; a test can bind it to anything */
typedef struct {
    /* write one whole frame, family header included. EINTR is handled below
       this call. *out_errno is set for TUN_STACK_WRITE_FAILED */
    tun_stack_write_t (*write_frame)(void *ctx, const uint8_t *frame, size_t len,
                                     int *out_errno);
    int64_t (*now_ms)(void *ctx);
    /* close the device. called once by shutdown, may be NULL when the caller
       keeps ownership of the descriptor */
    void (*close_device)(void *ctx);
    void *ctx;
} tun_stack_io_t;

typedef struct tun_stack tun_stack_t;

/* the handle is allocated by the caller, so nothing here allocates at runtime */
size_t tun_stack_size(void);

tun_stack_status_t tun_stack_init(tun_stack_t *stack, const tun_stack_config_t *config,
                                  const tun_stack_io_t *io);

/* one frame as it came off the device, family header included. the frame is
   rewritten in place when it belongs to a captured flow, so the caller hands
   over its read buffer and must not reuse its contents afterwards */
tun_stack_status_t tun_stack_input_frame(tun_stack_t *stack, uint8_t *frame,
                                         size_t frame_len);

/* the owner's answer to TUN_STACK_FLOW_REQUESTED */
tun_stack_status_t tun_stack_flow_accept(tun_stack_t *stack, uint64_t flow_id);
tun_stack_status_t tun_stack_flow_reject(tun_stack_t *stack, uint64_t flow_id);

/* close an accepted flow from senko's side */
tun_stack_status_t tun_stack_flow_close(tun_stack_t *stack, uint64_t flow_id);

/* the byte stream of an open flow. the app's bytes are handed out without a
   copy and acknowledged only once the owner has taken them, so a busy owner
   closes the app's tcp window instead of dropping anything, and the stack
   never holds more than one window per flow.

   *data points into the stack and stays valid until the next call into the
   stack. *len is what can be read in one piece; more may follow after
   tun_stack_flow_consume(). *eof turns true once the app has closed its side
   and every byte before the fin was consumed */
tun_stack_status_t tun_stack_flow_peek(tun_stack_t *stack, uint64_t flow_id,
                                       const uint8_t **data, size_t *len, int *eof);
tun_stack_status_t tun_stack_flow_consume(tun_stack_t *stack, uint64_t flow_id,
                                          size_t len);

/* bytes the flow can take toward the app right now */
size_t tun_stack_flow_writable(tun_stack_t *stack, uint64_t flow_id);

/* queue bytes toward the app. *accepted may be short of len when the app's
   window is full; the rest is the caller's to keep */
tun_stack_status_t tun_stack_flow_write(tun_stack_t *stack, uint64_t flow_id,
                                        const uint8_t *data, size_t len,
                                        size_t *accepted);

/* no more bytes toward the app: a fin follows what is queued, and the app can
   still send */
tun_stack_status_t tun_stack_flow_shutdown(tun_stack_t *stack, uint64_t flow_id);

/* the flow failed: the app gets a reset and the flow is gone at once */
tun_stack_status_t tun_stack_flow_abort(tun_stack_t *stack, uint64_t flow_id);

/* answers a captured datagram with icmp port unreachable from its destination */
tun_stack_status_t tun_stack_udp_unreachable(tun_stack_t *stack, const tun_flow_key_t *key,
                                             size_t payload_len);

/* reply to a captured UDP tuple from its original remote address */
tun_stack_status_t tun_stack_udp_reply(tun_stack_t *stack, const tun_flow_key_t *key,
                                       const uint8_t *payload, size_t payload_len);

/* the device can take data again: drain what is pending. returns
   TUN_STACK_QUEUED while frames remain */
tun_stack_status_t tun_stack_on_writable(tun_stack_t *stack);

/* whether frames are waiting for the device */
int tun_stack_has_pending(const tun_stack_t *stack);

/* lwip's timers, held syn expiry and release of finished flows. must be
   called regularly by the owning thread */
void tun_stack_run_timers(tun_stack_t *stack);

/* milliseconds until tun_stack_run_timers() has work, for the owner's poll */
uint32_t tun_stack_timer_wait_ms(const tun_stack_t *stack);

/* stop taking frames, abort every flow and every stack connection that
   belongs to the listener, close the listener, remove the interface, drop what
   is pending and close the device exactly once. safe to call twice */
void tun_stack_shutdown(tun_stack_t *stack);

const tun_stack_stats_t *tun_stack_stats(const tun_stack_t *stack);

/* capture counters and drop reasons, for diagnostics */
const tun_nat_t *tun_stack_capture(const tun_stack_t *stack);

/* the last failure, in the plain words the rest of the daemon uses */
const char *tun_stack_last_error(const tun_stack_t *stack);

const char *tun_stack_status_name(tun_stack_status_t status);

#ifdef __cplusplus
}
#endif

#endif

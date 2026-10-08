#ifndef BYE_MTP_H
#define BYE_MTP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* the obfuscated mtproto stream between a telegram client and a datacenter.

   the client opens with 64 bytes that carry its keys, its protocol tag and
   the datacenter it wants, then everything after is aes-256-ctr. the bridge
   reads those bytes, builds the 64 bytes the datacenter expects, and
   re-encrypts the stream in both directions. the stream carries on over
   whatever transport the caller picked, a websocket or a plain socket.

   a secret of 1 to 16 bytes is the mtproxy secret the client was given. no
   secret means the client talks to the datacenter directly, where the keys are
   used as they are */

#define BYE_MTP_INIT_LEN 64
#define BYE_MTP_SECRET_MAX 16
/* the largest packet the splitter holds. uploads go in parts of at most 512 KiB */
#define BYE_MTP_PACKET_MAX (1u << 20)

#define BYE_MTP_TAG_ABRIDGED     0xEFEFEFEFu
#define BYE_MTP_TAG_INTERMEDIATE 0xEEEEEEEEu
#define BYE_MTP_TAG_PADDED       0xDDDDDDDDu

typedef enum {
    BYE_MTP_OK          =  0,
    BYE_MTP_ERR_ARG     = -1,
    BYE_MTP_ERR_INIT    = -2, /* not an obfuscated mtproto stream */
    BYE_MTP_ERR_HTTP    = -3, /* an http request, a client on the http transport */
    BYE_MTP_ERR_MEMORY  = -4,
    BYE_MTP_ERR_CRYPTO  = -5,
    BYE_MTP_ERR_PACKET  = -6, /* a packet longer than BYE_MTP_PACKET_MAX */
    BYE_MTP_ERR_EMIT    = -7  /* the caller's emit refused a message */
} bye_mtp_status_t;

typedef struct {
    int      dc;       /* 1 and up, the sign of the client's value removed */
    int      is_media; /* the client asked for the media connection */
    uint32_t proto;    /* one of the BYE_MTP_TAG values */
} bye_mtp_route_t;

typedef struct bye_mtp bye_mtp_t;

/* one whole message of the client's stream, for a transport that keeps message
   borders, like a websocket frame. return 0 to go on */
typedef int (*bye_mtp_emit_fn)(void *ctx, const uint8_t *msg, size_t len);

/* reads the client's 64 bytes. on success relay_init holds the 64 bytes to send
   to the datacenter before anything else */
bye_mtp_status_t bye_mtp_open(bye_mtp_t **out, const uint8_t *secret, size_t secret_len,
                              const uint8_t client_init[BYE_MTP_INIT_LEN],
                              bye_mtp_route_t *route,
                              uint8_t relay_init[BYE_MTP_INIT_LEN]);

void bye_mtp_close(bye_mtp_t *mtp);

/* client to datacenter, in place. with an emit the bytes come out as whole
   packets, each in one call: a packet that spans reads is held until it is
   complete. without one the bytes are only transformed and the caller sends
   them as they are */
bye_mtp_status_t bye_mtp_up(bye_mtp_t *mtp, uint8_t *data, size_t len,
                            bye_mtp_emit_fn emit, void *ctx);

/* the client closed: the held part of a packet goes out as it is */
bye_mtp_status_t bye_mtp_up_flush(bye_mtp_t *mtp, bye_mtp_emit_fn emit, void *ctx);

/* datacenter to client, in place */
bye_mtp_status_t bye_mtp_down(bye_mtp_t *mtp, uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif

#ifndef BYE_WS_H
#define BYE_WS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* the client side of a websocket (rfc 6455), split from any socket so every
   byte of it can be tested. the telegram gateway answers only a request that
   offers the binary subprotocol, so the upgrade always asks for it */

#define BYE_WS_KEY_LEN 25      /* base64 of 16 bytes, with the nul */
#define BYE_WS_ACCEPT_LEN 29   /* base64 of a sha-1, with the nul */
#define BYE_WS_REQUEST_MAX 512
#define BYE_WS_HEADER_MAX 14   /* 2 + 8 length bytes + 4 mask bytes */
#define BYE_WS_CONTROL_MAX 125
#define BYE_WS_RESPONSE_MAX 2048

#define BYE_WS_OP_CONT   0x0
#define BYE_WS_OP_TEXT   0x1
#define BYE_WS_OP_BINARY 0x2
#define BYE_WS_OP_CLOSE  0x8
#define BYE_WS_OP_PING   0x9
#define BYE_WS_OP_PONG   0xA

typedef enum {
    BYE_WS_OK          =  0,
    BYE_WS_NEED_MORE   =  1,
    BYE_WS_CLOSED      =  2, /* the server sent a close frame */
    BYE_WS_ERR_ARG     = -1,
    BYE_WS_ERR_SPACE   = -2,
    BYE_WS_ERR_HOST    = -3, /* a host or path with characters that break the request */
    BYE_WS_ERR_RANDOM  = -4,
    BYE_WS_ERR_STATUS  = -5, /* the upgrade was refused, see the status out value */
    BYE_WS_ERR_HEADERS = -6, /* a 101 that does not answer this request */
    BYE_WS_ERR_FRAME   = -7, /* the server broke the framing rules */
    BYE_WS_ERR_SINK    = -8  /* a sink callback asked to stop */
} bye_ws_status_t;

/* builds the upgrade request and the key it sent, from 16 random bytes */
bye_ws_status_t bye_ws_request(char *out, size_t cap, size_t *out_len, const char *host,
                               const char *path, const uint8_t random[16],
                               char key[BYE_WS_KEY_LEN]);

/* checks the server's answer to that request. NEED_MORE until the blank line
   arrives. on OK, *consumed is the length of the answer, and any bytes after
   it already belong to the frame stream. *http_status is set whenever a status
   line was read */
bye_ws_status_t bye_ws_response(const uint8_t *buf, size_t len, const char key[BYE_WS_KEY_LEN],
                                size_t *consumed, int *http_status);

/* a masked frame: header, mask and payload. returns the length written */
bye_ws_status_t bye_ws_frame(uint8_t *out, size_t cap, size_t *out_len, uint8_t opcode,
                             const uint8_t *payload, size_t len, const uint8_t mask[4]);

size_t bye_ws_frame_size(size_t payload_len);

/* the bytes of the server's frames, handed out as they arrive. data frames go
   to on_data in slices, whatever their size, control frames come whole */
typedef struct {
    int (*on_data)(void *ctx, const uint8_t *data, size_t len);
    int (*on_ping)(void *ctx, const uint8_t *data, size_t len);
    void *ctx;
} bye_ws_sink_t;

typedef struct {
    uint8_t  head[BYE_WS_HEADER_MAX];
    size_t   head_len;
    uint8_t  opcode;
    uint64_t left;       /* payload bytes of the current frame still to come */
    int      in_frame;
    uint8_t  control[BYE_WS_CONTROL_MAX];
    size_t   control_len;
    int      in_message; /* a data message is open: the next data frame continues it */
} bye_ws_rx_t;

void bye_ws_rx_init(bye_ws_rx_t *rx);

/* a sink callback returns 0 to go on, anything else ends the feed with
   ERR_SINK. OK once every byte is used, CLOSED at a close frame, ERR_FRAME on
   a frame a server may not send */
bye_ws_status_t bye_ws_rx_feed(bye_ws_rx_t *rx, const uint8_t *data, size_t len,
                               const bye_ws_sink_t *sink);

#ifdef __cplusplus
}
#endif

#endif

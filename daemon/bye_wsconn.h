#ifndef BYE_WSCONN_H
#define BYE_WSCONN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* a websocket over tls on a socket the caller connected and keeps. every call
   returns at once: when the socket is not ready it says which way to wait.
   the server's certificate is checked against the trust roots and the host
   name, there is no way to turn that off */

/* the largest message the send queue holds, with room for control frames */
#define BYE_WSCONN_TX_MAX (1024u * 1024u + 128u * 1024u)
#define BYE_WSCONN_ERROR_MAX 160

typedef enum {
    BYE_WSCONN_OK         =  0,
    BYE_WSCONN_WANT_READ  =  1,
    BYE_WSCONN_WANT_WRITE =  2,
    BYE_WSCONN_CLOSED     =  3, /* the server ended the stream */
    BYE_WSCONN_ERR        = -1  /* see bye_wsconn_error() */
} bye_wsconn_status_t;

typedef struct bye_wsconn_ctx bye_wsconn_ctx_t;
typedef struct bye_wsconn bye_wsconn_t;

/* ca_file is a pem bundle; NULL uses the host's default roots, for tests and
   desktop builds. returns NULL with the reason in error */
bye_wsconn_ctx_t *bye_wsconn_ctx_new(const char *ca_file, char *error, size_t error_cap);
void bye_wsconn_ctx_free(bye_wsconn_ctx_t *ctx);

/* the connection does not close fd. host is the name the certificate must
   match and the Host header, path the request target */
bye_wsconn_t *bye_wsconn_new(bye_wsconn_ctx_t *ctx, int fd, const char *host, const char *path);
void bye_wsconn_free(bye_wsconn_t *conn);

/* tls, then the upgrade. OK once the socket carries websocket frames */
bye_wsconn_status_t bye_wsconn_handshake(bye_wsconn_t *conn);

/* queues one binary message. -1 when the queue cannot take it */
int bye_wsconn_send(bye_wsconn_t *conn, const uint8_t *msg, size_t len);
int bye_wsconn_ping(bye_wsconn_t *conn);

/* bytes still queued for the socket */
size_t bye_wsconn_pending(const bye_wsconn_t *conn);

/* writes what is queued. OK once the queue is empty */
bye_wsconn_status_t bye_wsconn_flush(bye_wsconn_t *conn);

/* moves payload bytes into out, at most cap. OK with *got bytes, WANT_READ
   when none are ready. control frames are answered inside */
bye_wsconn_status_t bye_wsconn_read(bye_wsconn_t *conn, uint8_t *out, size_t cap, size_t *got);

/* the reason for the last BYE_WSCONN_ERR */
const char *bye_wsconn_error(const bye_wsconn_t *conn);

/* the tls layer holds bytes the socket has already delivered */
int bye_wsconn_buffered(const bye_wsconn_t *conn);

#ifdef __cplusplus
}
#endif

#endif

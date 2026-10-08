#ifndef BYE_SNIFF_H
#define BYE_SNIFF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* finds the server name in the first bytes an app sends: the SNI of a TLS
   ClientHello or the Host header of an HTTP request. nothing is copied, the
   result is a range inside the caller's buffer */

typedef enum {
    BYE_SNIFF_OK         =  0,
    BYE_SNIFF_NEED_MORE  =  1, /* a valid prefix: wait for more bytes */
    BYE_SNIFF_NO_MATCH   = -1, /* another protocol */
    BYE_SNIFF_MALFORMED  = -2, /* right protocol, impossible lengths */
    BYE_SNIFF_NO_NAME    = -3  /* a complete message without a name */
} bye_sniff_status_t;

typedef struct {
    size_t record_len; /* tls: record header plus body, 0 for http */
    size_t name_off;
    size_t name_len;
} bye_sniff_t;

/* the hello must sit in one record, as every client sends it */
bye_sniff_status_t bye_sniff_tls(const uint8_t *buf, size_t len, bye_sniff_t *out);
bye_sniff_status_t bye_sniff_http(const uint8_t *buf, size_t len, bye_sniff_t *out);

#ifdef __cplusplus
}
#endif

#endif

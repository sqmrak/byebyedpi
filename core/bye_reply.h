#ifndef BYE_REPLY_H
#define BYE_REPLY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* an answer of the daemon's control socket: a first line that starts with OK
   or ERR and may carry a detail, then lines of "key=value" (the config reply
   writes "key = value"), then a line with one dot that the client has already
   cut off. the reply points into the caller's text, nothing is copied */

#define BYE_REPLY_DETAIL_MAX 160

typedef struct {
    int         ok;
    char        detail[BYE_REPLY_DETAIL_MAX]; /* the rest of the first line */
    const char *body;                         /* the lines after the first */
    size_t      body_len;
} bye_reply_t;

/* 0 when the text has a status line, -1 for anything else (empty text, no OK
   or ERR). a detail longer than the field is cut, never overrun */
int bye_reply_parse(const char *text, size_t len, bye_reply_t *out);

/* the value of the first line with that key, trimmed. 1 when found; the value
   is cut to cap - 1 bytes and always ends with a NUL */
int bye_reply_value(const bye_reply_t *reply, const char *key, char *out, size_t cap);

/* the lines in order: *cursor starts at 0. 1 with the next key and value, 0
   at the end. a line with no "=" is skipped */
int bye_reply_next(const bye_reply_t *reply, size_t *cursor, char *key, size_t key_cap,
                   char *value, size_t value_cap);

/* a probe report's "candidate.N" value: "2/2 366ms tlsrec=name+1;split=1,name+1".
   1 when it has that shape and the numbers are plain digits */
typedef struct {
    unsigned ok;
    unsigned tried;
    unsigned ms;
    char     spec[1024];
} bye_reply_candidate_t;

int bye_reply_candidate(const char *value, bye_reply_candidate_t *out);

#ifdef __cplusplus
}
#endif

#endif

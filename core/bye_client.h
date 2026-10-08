#ifndef BYE_CLIENT_H
#define BYE_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* a client of the daemon's control socket, for byebyectl and for the app. one
   connection carries many commands; every call waits for its whole answer.
   the token file sits beside the socket, see bye_ctl.h for the protocol */

#define BYE_CLIENT_TOKEN_LEN 32
#define BYE_CLIENT_LINE_MAX 1279  /* the daemon reads 1280 bytes with the newline */
#define BYE_CLIENT_ERROR_MAX 160

/* why the last open or call failed, for a caller that explains it to a person. the text in
   the error buffer says what happened, this says which kind of thing it was */
typedef enum {
    BYE_CLIENT_OK = 0,
    BYE_CLIENT_NO_SOCKET,     /* nothing at the socket path: the daemon is not running */
    BYE_CLIENT_REFUSED,       /* the socket is there and nothing listens: the daemon died */
    BYE_CLIENT_DENIED,        /* the user may not use the socket */
    BYE_CLIENT_NO_TOKEN,      /* the token file does not exist yet */
    BYE_CLIENT_TOKEN_DENIED,  /* the user may not read the token file */
    BYE_CLIENT_TOKEN_BAD,     /* the token file is empty or is not a token */
    BYE_CLIENT_TOKEN_REFUSED, /* the daemon did not accept the token */
    BYE_CLIENT_TIMEOUT,       /* no answer in time */
    BYE_CLIENT_CLOSED,        /* the daemon ended the connection */
    BYE_CLIENT_TOO_LARGE,     /* the answer did not fit */
    BYE_CLIENT_BAD_COMMAND,   /* the command was not one plain line */
    BYE_CLIENT_IO             /* any other failure of the socket */
} bye_client_failure_t;

typedef struct {
    int fd;
    int failure; /* a bye_client_failure_t, BYE_CLIENT_OK after a success */
} bye_client_t;

/* the token file of a socket: its name with ".sock" swapped for ".token" */
int bye_client_token_path(const char *socket_path, char *out, size_t cap);

/* connects, and with authenticate reads the token and sends it. 0 on success;
   -1 with the reason in error, and the client closed. timeout_ms bounds every
   later wait, 0 waits forever */
int bye_client_open(bye_client_t *client, const char *socket_path, int authenticate,
                    uint32_t timeout_ms, char *error, size_t error_cap);

/* sends one command line and reads the answer up to its closing dot line,
   without the dot. returns the length, or -1 with the reason in error. an
   answer that does not fit in cap is an error, not a cut text */
long bye_client_call(bye_client_t *client, const char *command, char *answer, size_t cap,
                     char *error, size_t error_cap);

void bye_client_close(bye_client_t *client);

#ifdef __cplusplus
}
#endif

#endif

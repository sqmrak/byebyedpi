#ifndef BYE_CTL_H
#define BYE_CTL_H

#include <stddef.h>
#include <sys/select.h>

#ifdef __cplusplus
extern "C" {
#endif

/* the control socket the app and byebyectl talk to. the daemon runs as root
   and the app does not, so the socket is open to root and mobile only, and a
   client must also present the token in a file only those two can read.

   the protocol is one command per line. an answer is a first line that starts
   with OK or ERR, any number of payload lines, and a line with a single dot.
   "auth TOKEN" must come first; only "version" works before it */

#define BYE_CTL_LINE_MAX 1280
#define BYE_CTL_REPLY_MAX 4096
#define BYE_CTL_CLIENTS_MAX 4
#define BYE_CTL_TOKEN_LEN 32

/* writes the answer for one command line into out and returns its length,
   with the status line first. nothing is added by the server */
typedef size_t (*bye_ctl_handler_fn)(void *ctx, const char *line, char *out, size_t cap);

typedef struct bye_ctl bye_ctl_t;

/* binds the socket and writes the token file. NULL with the reason in error */
bye_ctl_t *bye_ctl_open(const char *socket_path, const char *token_path,
                        bye_ctl_handler_fn handler, void *ctx, char *error, size_t error_cap);
void bye_ctl_close(bye_ctl_t *ctl);

/* ios 6.1.3 empties /var/tmp some time after boot, and the socket, the token and
   the lock go with it while the daemon keeps running. this makes them again, with
   a new token. 1 when something was rebuilt, 0 when nothing was missing (or the
   same failure was already reported), -1 with the reason in error */
int bye_ctl_revive(bye_ctl_t *ctl, char *error, size_t error_cap);

/* adds the socket's descriptors to the sets, like the tunnel loop's hooks */
void bye_ctl_prepare(bye_ctl_t *ctl, fd_set *readable, fd_set *writable, int *highest);
void bye_ctl_service(bye_ctl_t *ctl, const fd_set *readable, const fd_set *writable);

#ifdef __cplusplus
}
#endif

#endif

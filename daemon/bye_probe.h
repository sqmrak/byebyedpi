#ifndef BYE_PROBE_H
#define BYE_PROBE_H

#include <stddef.h>
#include <stdint.h>

#include "bye_desync.h"
#include "tun/direct_socket.h"

#ifdef __cplusplus
extern "C" {
#endif

/* finds which strategies get a tls hello through to a server. for each name
   it opens a real connection per strategy, sends a hello cut that way and
   waits for the server's handshake record. it needs the network but not the
   tunnel: while the tunnel runs the sockets leave by the physical interface,
   as the relays' do.

   a probe runs on a thread of its own, one at a time. the report is read while
   it runs */

#define BYE_PROBE_NAMES_MAX 4
#define BYE_PROBE_NAME_MAX 64
#define BYE_PROBE_CANDIDATES_MAX 14
/* as long as a config value, so the options of ciadpi in use can be a candidate */
#define BYE_PROBE_SPEC_MAX 1024
#define BYE_PROBE_WAIT_MS 3000
#define BYE_PROBE_REPORT_MAX 4096
#define BYE_PROBE_APP_HELLO_MAX 2048

typedef enum {
    BYE_PROBE_ANSWERED = 0, /* a handshake record came back */
    BYE_PROBE_RESET,        /* the connection was reset or closed with no answer */
    BYE_PROBE_SILENT,       /* nothing came back in time */
    BYE_PROBE_OTHER,        /* something that is not a handshake record came back */
    BYE_PROBE_UNREACHABLE,  /* the connection was not made */
    BYE_PROBE_FAILED        /* a local failure: socket, memory, hello */
} bye_probe_result_t;

typedef struct {
    char     names[BYE_PROBE_NAMES_MAX][BYE_PROBE_NAME_MAX];
    size_t   name_count;
    /* the strategies in use, as a config's spec list: they are tried first */
    char     configured[1024];
    uint16_t port;      /* 0 for 443; a test aims at a local server */
    uint32_t wait_ms;   /* 0 for BYE_PROBE_WAIT_MS */
    /* with bound set the sockets leave by iface, as the relays' do while the
       tunnel runs; otherwise by the default route */
    int                   bound;
    direct_socket_iface_t iface;
    /* a flow of an app that got no answer: the server name and address it went to and the
       hello bytes the app sent. every strategy is also tried with that hello at that
       address, next to a hello of this library for the same name and address, so the
       report says whether the app, the address or the cut is what fails. 0 bytes for none */
    char                  app_name[BYE_PROBE_NAME_MAX];
    uint8_t               app_addr[4];
    uint8_t               app_hello[BYE_PROBE_APP_HELLO_MAX];
    size_t                app_hello_len;
} bye_probe_request_t;

/* a tls client hello for host, from the same library the daemon speaks tls
   with. 0 with the bytes in out, -1 when it does not fit or cannot be made */
int bye_probe_hello(const char *host, uint8_t *out, size_t cap, size_t *len);

/* one connection: connects to addr (ipv4), sends the hello cut by strategy,
   waits for the answer. ms is the time it took */
bye_probe_result_t bye_probe_attempt(const bye_probe_request_t *request, const uint8_t *addr,
                                     const char *host, const bye_desync_t *strategy,
                                     uint32_t *ms);

/* the same with the hello bytes given, port from the request */
bye_probe_result_t bye_probe_attempt_hello(const bye_probe_request_t *request, const uint8_t *addr,
                                          const uint8_t *hello, size_t hello_len,
                                          const bye_desync_t *strategy, uint32_t *ms);

/* a nonblocking socket that leaves by the default route */
int bye_probe_plain_socket(void *ctx, int family, int type, char *error, size_t error_cap);

typedef struct bye_probe bye_probe_t;

size_t bye_probe_size(void);

/* zeroed storage of bye_probe_size() bytes */
void bye_probe_init(bye_probe_t *probe);

/* starts a probe. -1 with the reason in error when one runs, or the request
   is not usable. the request is copied */
int bye_probe_start(bye_probe_t *probe, const bye_probe_request_t *request, char *error,
                    size_t error_cap);

/* asks a running probe to stop after its current connection */
void bye_probe_cancel(bye_probe_t *probe);

/* waits for the thread. a running probe is cancelled first */
void bye_probe_destroy(bye_probe_t *probe);

/* 1 while the thread runs */
int bye_probe_running(bye_probe_t *probe);

/* the report as "key=value" lines, the length written */
size_t bye_probe_report(bye_probe_t *probe, char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif

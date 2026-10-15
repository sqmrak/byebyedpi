#ifndef BYE_BACKEND_H
#define BYE_BACKEND_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "bye_config.h"
#include "bye_fakesend.h"
#include "bye_hosts.h"
#include "bye_iface.h"
#include "bye_tcp.h"
#include "bye_udp.h"
#include "bye_wsconn.h"
#include "tun/core/tun_plan.h"
#include "tun/direct_socket.h"
#include "tun/tun_loop.h"
#include "tun/utun_device.h"
#include "tun/utun_dns.h"

#ifdef __cplusplus
extern "C" {
#endif

/* start and stop share the daemon thread so routing and packet processing change together
   reverse cleanup must also cover a failed start so it leaves no routes or resolver entry */

typedef struct {
    bye_config_t config;
    const char  *ca_file;  /* pem trust roots for the telegram gateway */
    const char  *hosts_dir; /* where host lists are read from, NULL for BYE_HOSTS_DIR */
    int          trace;    /* one log line per flow */
} bye_backend_options_t;

typedef struct {
    bye_tcp_stats_t   tcp;
    bye_udp_stats_t   udp;
    tun_stack_stats_t stack;
} bye_backend_snapshot_t;

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    int initialized;
    int active;          /* routes are installed */
    int thread_started;
    int loop_initialized;
    int ready;
    int ended;
    pthread_t thread;
    uint64_t generation;
    utun_device_t device;
    bye_iface_t iface;
    tun_plan_t plan;
    tun_loop_t *loop;
    bye_tcp_t *tcp;
    bye_udp_t *udp;
    bye_wsconn_ctx_t *tls;
    bye_hosts_t *hosts;
    bye_fakesend_t *fake;
    direct_socket_iface_t direct;
    utun_dns_t dns;
    tun_loop_result_t result;
    bye_backend_snapshot_t snapshot; /* guarded by lock */
    uint64_t snapshot_seq;
    char error[256];
    char warning[192];   /* the tunnel runs, but something is off */
    char dns_state[192];
    int ended_pipe[2];   /* a byte lands here when the loop thread returns */
} bye_backend_t;

/* removes the routes a killed daemon left behind */
int bye_backend_init(bye_backend_t *backend);

/* 0 when the tunnel carries traffic, -1 with the reason in reason */
int bye_backend_start(bye_backend_t *backend, const bye_backend_options_t *options,
                      char *reason, size_t reason_cap);
void bye_backend_stop(bye_backend_t *backend);
void bye_backend_destroy(bye_backend_t *backend);

int bye_backend_running(bye_backend_t *backend);
int bye_backend_ended_fd(const bye_backend_t *backend);
void bye_backend_drain_ended(bye_backend_t *backend);

/* why the loop ended on its own, empty while it runs */
void bye_backend_end_reason(bye_backend_t *backend, char *out, size_t cap);

/* 0 with the counters copied from the loop thread, -1 when the tunnel is down */
int bye_backend_snapshot(bye_backend_t *backend, bye_backend_snapshot_t *out);

/* whether the interface direct traffic leaves by is still up with an address.
   a wifi that dropped, or a switch to the cellular link, shows here */
int bye_backend_network_ok(const bye_backend_t *backend);

/* 0 with the physical interface the tunnel's sockets leave by, -1 while the
   tunnel is down */
int bye_backend_direct(const bye_backend_t *backend, direct_socket_iface_t *out);

/* the bound interface while routes are installed, otherwise the kernel's route
   to 1.1.1.1. no interface name is preferred over another */
int bye_backend_external_interface(const bye_backend_t *backend, char *out, size_t cap,
                                    char *reason, size_t reason_cap);

/* looks up kws2.<domain> for each domain of a config relay value, all at once, and
   gives up on the slow ones after a few seconds. returns how many resolved,
   with their names and addresses in the arrays. a failure is said in warning */
size_t bye_resolve_relays(const char *list, char names[][BYE_TCP_RELAY_NAME_MAX],
                          uint8_t addrs[][4], size_t max, char *warning, size_t warning_cap);

/* bounded lookups before routing changes; missing names keep the pinned fallback */
void bye_resolve_gateways(bye_tg_ws_addresses_t *out);

const char *bye_backend_warning(const bye_backend_t *backend);
const char *bye_backend_dns_state(const bye_backend_t *backend);
const char *bye_backend_ifname(const bye_backend_t *backend);

#ifdef __cplusplus
}
#endif

#endif

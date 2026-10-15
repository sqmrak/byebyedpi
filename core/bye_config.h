#ifndef BYE_CONFIG_H
#define BYE_CONFIG_H

#include <stddef.h>

#include "bye_desync.h"
#include "bye_hosts.h"

#ifdef __cplusplus
extern "C" {
#endif

/* the daemon's settings file: one "key = value" per line, "#" starts a comment
   line. a key the daemon does not know is an error, so a typo is not silently
   ignored

     desync.spec = ...      auto (the default, a built-in list that moves to the
                            next item when a hello gets no answer), or one
                            strategy as a native spec or the command line of
                            the original ByeDPI, see bye_desync.h. a text of
                            its own is used as it is: only the groups it names
                            with -A are tried after a failure. an older file
                            with a list split by '|' keeps its first item
     hosts = NAME|none      a list of domain names in the hosts directory
     hosts.mode = only|except  cut only the listed names, or all but them
     telegram = on|off      carry telegram over the websocket gateway, for
                            every app on the device, through the tunnel
     telegram.pool = 0..2   websocket connections kept ready for each
                            datacenter that was used lately
     quic = block|pass      refuse udp 443 so apps fall back to tcp
     dns = ADDRESS|system   an ipv4 resolver, or the system's (the default)
     relay = D[,D...]|none  up to four cloudflare domains that carry kwsN.D to
                            telegram, tried before telegram's own addresses
     autostart = on|off     start the tunnel when the daemon starts
     proxy = on|off         an mtproxy on 127.0.0.1 for telegram's own proxy
                            setting. it works with the tunnel up or down
     proxy.port = 1..65535  its port
     proxy.secret = HEX|auto  32 hex digits the client is given as dd<hex>,
                            auto makes the daemon draw one and keep it

   some networks drop every tcp connection to telegram's addresses, and then
   the gateway on those addresses is out of reach as well. a relay is a domain
   whose kwsN host reaches the same gateway through cloudflare. whoever runs
   the domain sees the addresses and timing of the connections, not their
   content, which stays mtproto encrypted. the default is the three community
   domains below, tried before telegram's own addresses, so a network that
   drops those works at once. `relay = none` turns them off.

   a file below the current `version` was written by an older build. it is
   replaced by the defaults once, so a choice made there cannot outlive the
   upgrade */

#define BYE_CONFIG_VERSION 6
#define BYE_CONFIG_RELAY_DEFAULT "pclead.co.uk,lovetrue.co.uk,kartoshka.co.uk"

#define BYE_CONFIG_SPEC_MAX 1024
#define BYE_CONFIG_HOSTS_NAME_MAX 48
#define BYE_CONFIG_POOL_MAX 2
#define BYE_CONFIG_DNS_MAX 16
#define BYE_CONFIG_RELAY_MAX 256
#define BYE_CONFIG_RELAYS 4
#define BYE_CONFIG_RELAY_NAME_MAX 48
#define BYE_CONFIG_PROXY_PORT_DEFAULT 1082
#define BYE_CONFIG_SECRET_LEN 32
#define BYE_CONFIG_FILE_MAX 4096
#define BYE_CONFIG_ERROR_MAX 160

typedef struct {
    char         desync_spec[BYE_CONFIG_SPEC_MAX];
    bye_strategies_t desync_strategies; /* desync_spec, parsed */
    char         hosts[BYE_CONFIG_HOSTS_NAME_MAX]; /* empty: no list */
    int          hosts_only;
    int          telegram;
    int          pool;
    int          block_quic;
    char         dns[BYE_CONFIG_DNS_MAX]; /* empty: the system resolver stays */
    char         relay[BYE_CONFIG_RELAY_MAX]; /* empty: no relay */
    int          autostart;
    int          proxy;
    int          proxy_port;
    char         proxy_secret[BYE_CONFIG_SECRET_LEN + 1]; /* empty: not drawn yet */
    int          version; /* of the file this came from, see BYE_CONFIG_VERSION */
    int          spec_reduced; /* the last parse cut a list down to its first strategy */
} bye_config_t;

typedef enum {
    BYE_CONFIG_OK        =  0,
    BYE_CONFIG_ERR_ARG   = -1,
    BYE_CONFIG_ERR_PARSE = -2
} bye_config_status_t;

void bye_config_defaults(bye_config_t *config);

/* 1 when an old file was reset to the defaults, 0 when it already uses this version */
int bye_config_migrate(bye_config_t *config);

/* a failure leaves *config as it was and names the line in error */
bye_config_status_t bye_config_parse(const char *text, size_t len, bye_config_t *config,
                                     char *error, size_t error_cap);

/* the file's text for a config; 0 on success, -1 if cap is too small */
int bye_config_render(const bye_config_t *config, char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif

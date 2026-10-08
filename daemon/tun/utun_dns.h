#ifndef SENKO_UTUN_DNS_H
#define SENKO_UTUN_DNS_H

#include <stddef.h>

/* the system resolver keeps asking the wifi router, which sits on the local
   net and never enters the tunnel's split defaults. ios 5-11 need a primary
   configd service; ios 12+ use a default supplemental resolver so springboard
   keeps wifi as the primary interface.

   the keys are temporary configd values: they vanish with the session, so a
   daemon that dies does not leave the device resolving through a dead tunnel */

typedef struct {
    void *store; /* SCDynamicStoreRef while published */
    char diagnostic[256]; /* retained after a failed start for the app's report */
} utun_dns_t;

void utun_dns_init(utun_dns_t *dns);

/* 0 once tunnel dns is published, -1 with the reason in reason */
int utun_dns_publish(utun_dns_t *dns, const char *ifname, const char *local4,
                     const char *peer4, const char *dns_server,
                     char *reason, size_t reason_cap);

/* removes the keys; safe to call when nothing was published */
void utun_dns_withdraw(utun_dns_t *dns);

#endif

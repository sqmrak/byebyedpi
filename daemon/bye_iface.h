#ifndef BYE_IFACE_H
#define BYE_IFACE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* gives a fresh utun its addresses and brings it up, without touching the
   routing table. the interface goes away with the descriptor, so there is no
   matching call to take it down. only built for darwin: a host build
   returns -1 */

typedef struct {
    char     ifname[16];
    char     local4[16];
    char     peer4[16];
    char     local6[48]; /* empty for no ipv6 */
    uint16_t mtu;
} bye_iface_t;

/* 0 on success, -1 with errno set */
int bye_iface_up(const bye_iface_t *iface);

/* brighton carries the guest's uplink over utun, with a temporary configd service */
int bye_iface_brighton_link(const char *ifname, const uint8_t *gateway4);

#ifdef __cplusplus
}
#endif

#endif

#ifndef BYE_RESOLVER_H
#define BYE_RESOLVER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BYE_RESOLVER_FOUND = 0,
    BYE_RESOLVER_NONE,      /* the system has no dns server at all */
    BYE_RESOLVER_IPV6_ONLY  /* every server is ipv6, the configd entry takes ipv4 only */
} bye_resolver_status_t;

/* the first ipv4 resolver the system is using now, with its text in out.
   a host build answers BYE_RESOLVER_NONE */
bye_resolver_status_t bye_resolver_system(char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif

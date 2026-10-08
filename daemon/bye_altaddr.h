#ifndef BYE_ALTADDR_H
#define BYE_ALTADDR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* a network can block only part of a site's address set, so a failed flow can try another ipv4 address
   dns runs on a separate thread to avoid blocking the packet loop
   the cache outlives individual flows because their lookups can finish after closure */

#define BYE_ALT_ADDRS_MAX 6
#define BYE_ALT_NAME_MAX 64

/* replaces the lookup, for tests: fills out with up to max addresses of name and returns
   how many, 0 for none */
typedef size_t (*bye_altaddr_resolver_fn)(const char *name, uint8_t out[][4], size_t max);
void bye_altaddr_set_resolver(bye_altaddr_resolver_fn fn);

/* asks for the addresses of name unless they were asked for in the last ten minutes. the
   addresses of the name itself come first, then the ones of the name without its first
   label ("youtube.com" for "www.youtube.com") when that keeps two labels */
void bye_altaddr_request(const char *name);

/* 1 when the lookup is done, with the addresses in out and their count (0 for none), 0
   while it runs or was never asked */
int bye_altaddr_get(const char *name, uint8_t out[][4], size_t max, size_t *count);

#ifdef __cplusplus
}
#endif

#endif

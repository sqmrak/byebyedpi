#ifndef BYE_CIADPI_H
#define BYE_CIADPI_H

#include <stddef.h>

#include "bye_desync.h"

#ifdef __cplusplus
extern "C" {
#endif

/* reads the command line of ciadpi (the original ByeDPI) as a strategy list.
   every -A starts a group, the options before the first one are the first group.

   used as they work in ciadpi:
     -s -d -o -q  split, disorder, oob and disoob parts, offset[:repeats[:skip]][+flags]
     -r           tls record cuts      -M  mod-http       -m  tls minor version
     -e           the urgent byte      -K  protocols      -A  groups with triggers t r s n
     -T           the wait for an answer     -g  the ttl a socket gets back
   -f cuts like -s: a fake packet needs a splice of the kernel's own buffer, which
   xnu does not have. the options for proxy mode, fake packets, udp, linux sockets
   and the host or address filters are read and left out, each with a line in
   notes. an option that does not exist is an error */
bye_desync_status_t bye_ciadpi_parse(const char *text, bye_strategies_t *out, char *error,
                                     size_t error_cap);

#ifdef __cplusplus
}
#endif

#endif

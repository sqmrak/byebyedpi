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
     -f           a fake packet of the part's length, sent raw with the sequence
                  numbers of the real bytes (see bye_fake.h), then the part itself
     -t -n -l -O -Q -S  its ttl, name, data file, offset, hello changes, md5 option
   -l takes a file name in the list directory, never a path. -Q takes r o m d.
   the options for proxy mode, udp, linux sockets and the host or address
   filters are read and left out, each with a line in notes. an option that does
   not exist is an error */
bye_desync_status_t bye_ciadpi_parse(const char *text, bye_strategies_t *out, char *error,
                                     size_t error_cap);

#ifdef __cplusplus
}
#endif

#endif

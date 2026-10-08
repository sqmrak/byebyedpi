#ifndef BYE_HOSTSFILE_H
#define BYE_HOSTSFILE_H

#include <stddef.h>

#include "bye_hosts.h"

#ifdef __cplusplus
extern "C" {
#endif

/* reads the host list dir/name, the whole file or nothing. the directory is
   writable by the app's user, so the daemon, which runs as root, opens only a
   plain file there: a link, a device or a pipe in its place is refused. NULL
   with the reason in reason, which says why the tunnel does not start */
bye_hosts_t *bye_hostsfile_load(const char *dir, const char *name, char *reason, size_t cap);

#ifdef __cplusplus
}
#endif

#endif

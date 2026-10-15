#ifndef BYE_TLS_OWNER_H
#define BYE_TLS_OWNER_H

#include <stddef.h>

/* the backup remains beside the shim so a killed daemon can restore it */
int bye_tls_owner_set(int enabled, int *changed, char *error, size_t error_cap);

#endif

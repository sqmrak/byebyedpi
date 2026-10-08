#ifndef BYE_STATUS_H
#define BYE_STATUS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* the line the daemon leaves for the springboard hook: "0\n" while the tunnel
   is down, "1 en0\n" while it runs and carries traffic out through en0 */

#define BYE_STATUS_LINE_MAX 32
#define BYE_STATUS_IFNAME_MAX 15

/* the length written, 0 when the interface name is not a plain name or the
   buffer is too small. an empty or NULL name gives "1\n" */
size_t bye_status_format(char *out, size_t cap, int on, const char *ifname);

#ifdef __cplusplus
}
#endif

#endif

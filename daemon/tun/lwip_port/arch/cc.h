#ifndef SENKO_LWIP_ARCH_CC_H
#define SENKO_LWIP_ARCH_CC_H

/* limits.h first: lwip decides whether to declare its own ssize_t by looking
   for SSIZE_MAX, and without it every file that later includes unistd.h gets
   two conflicting definitions */
#include <limits.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* lwip reads the byte order from here rather than guessing. every device
   senko supports is little endian, on both armv7 and arm64 */
#ifndef BYTE_ORDER
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321
#define BYTE_ORDER LITTLE_ENDIAN
#endif

/* a failed assertion inside the stack means the packet loop is about to work
   on state it does not understand. the daemon stops the tunnel rather than
   keep forwarding from there, so this is deliberately loud */
#define LWIP_PLATFORM_ASSERT(message) \
    do { \
        fprintf(stderr, "byedpid: lwip assertion failed: %s at %s:%d\n", \
                (message), __FILE__, __LINE__); \
        abort(); \
    } while (0)

/* lwip's own notices go to the same place the daemon's other lines do */
#define LWIP_PLATFORM_DIAG(argument) \
    do { \
        printf argument; \
    } while (0)

/* the darwin sdks already define htons and friends as macros, and lwip's
   convenience copies of the same names would redefine them in every file that
   sees both. lwip itself only needs its own lwip_htons */
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1

#define LWIP_RAND() ((u32_t)senko_lwip_random())

/* a random source for tcp initial sequence numbers and ipv6 identifiers.
   implemented by the senko adapter, not by lwip */
uint32_t senko_lwip_random(void);

#endif

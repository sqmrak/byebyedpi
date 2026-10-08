/* the two things lwip asks the platform for when NO_SYS is 1: a clock and a
   random source. everything else it does itself */

#include <stdio.h>

#include "lwip/arch.h"
#include "lwip/sys.h"

#include "core/senko_time.h"

#if defined(__APPLE__)
#include <stdlib.h> /* arc4random */
#endif

/* lwip measures timeouts as unsigned 32 bit milliseconds and handles the wrap
   itself, so the monotonic clock is simply truncated. it must be the same
   clock the rest of the daemon uses, otherwise a retransmit timer and a
   connect deadline would disagree about how much time passed */
u32_t sys_now(void) {
    return (u32_t)senko_now_ms();
}

/* tcp initial sequence numbers and ipv6 fragment identifiers come from here.
   a predictable sequence would let anyone who can guess it inject into a
   flow, so this is not a place for a counter seeded from the clock */
uint32_t senko_lwip_random(void) {
#if defined(__APPLE__)
    return (uint32_t)arc4random();
#else
    static FILE *urandom;
    if (!urandom) urandom = fopen("/dev/urandom", "rb");
    uint32_t value = 0;
    if (urandom && fread(&value, sizeof value, 1, urandom) == 1) return value;
    /* a host build with no /dev/urandom is a test run, never a device */
    return (uint32_t)senko_now_ms();
#endif
}

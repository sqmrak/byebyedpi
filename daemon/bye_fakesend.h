#ifndef BYE_FAKESEND_H
#define BYE_FAKESEND_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* what a fake part (-f of ciadpi) needs from the system: a bpf watcher that keeps
   the syn and syn-ack of the connections made on the physical interface, and a raw
   socket bound to the same interface that sends the fake. see core/bye_fake.h.
   the watcher runs a thread of its own until bye_fakesend_stop() */

typedef struct bye_fakesend bye_fakesend_t;

/* NULL with the reason in reason when bpf or the raw socket cannot be opened */
bye_fakesend_t *bye_fakesend_start(const char *ifname, char *reason, size_t reason_cap);
void bye_fakesend_stop(bye_fakesend_t *fake);

/* a bye_fake_send_fn, ctx is the bye_fakesend_t */
int bye_fakesend_send(void *ctx, int fd, uint32_t offset, const uint8_t *payload, size_t len,
                      uint8_t ttl, int md5sig);

#ifdef __cplusplus
}
#endif

#endif

#ifndef SENKO_TUN_NAT_H
#define SENKO_TUN_NAT_H

#include <stddef.h>
#include <stdint.h>

#include "tun_flow.h"

#ifdef __cplusplus
extern "C" {
#endif

/* transparent capture at the edge of the ip stack.

   lwip only accepts packets addressed to its own interface, and a listener
   only matches one exact port. an application connecting to 203.0.113.7:443
   is neither, so without help the stack drops the syn as not for us.

   instead of changing lwip, every captured flow gets a table entry and its
   packets are rewritten on the way in and out:

     app -> stack   A:a -> D:d     becomes   S:s -> L:P
     stack -> app   L:P -> S:s     becomes   D:d -> A:a

   L:P is the one listener the stack has, S is a reserved synthetic peer
   address and s is a port that belongs to the entry's slot, so every flow is
   a distinct connection inside the stack even when two apps talk to the same
   destination port. the original tuple is never lost: it is the entry's key,
   and the stack's own tcp does all of the tcp work.

   the translation is bounded by the table and applies only to packets that
   belong to an entry. nothing here touches lwip, so the rules are tested on
   the host with real packet bytes */

#define TUN_NAT_TCP_MAX TUN_FLOW_MAX_TCP
#define TUN_NAT_SYN_MAX 160
/* synthetic ports are TUN_NAT_PORT_BASE + slot, far from the listener port */
#define TUN_NAT_PORT_BASE 40000u

typedef enum {
    TUN_NAT_FREE = 0,
    TUN_NAT_PENDING,  /* a syn is held until the owner accepts or rejects it */
    TUN_NAT_ACTIVE,
    TUN_NAT_DRAINING  /* closed by the owner, the stack may still hold the pcb */
} tun_nat_state_t;

typedef enum {
    TUN_NAT_PASS = 0, /* hand the (possibly rewritten) packet on */
    TUN_NAT_NEW,      /* a syn opened a pending flow; it is held, not passed */
    TUN_NAT_HELD,     /* a repeated syn for a flow still waiting on a decision */
    TUN_NAT_DROP
} tun_nat_verdict_t;

typedef enum {
    TUN_NAT_DROP_NONE = 0,
    TUN_NAT_DROP_MALFORMED,  /* headers do not fit or disagree with the length */
    TUN_NAT_DROP_CHECKSUM,   /* ip header or syn checksum is wrong */
    TUN_NAT_DROP_FRAGMENT,   /* ip fragments are not reassembled here */
    TUN_NAT_DROP_EXTENSION,  /* ipv6 routing, ah, esp or another header chain */
    TUN_NAT_DROP_PROTOCOL,   /* a protocol that is not captured */
    TUN_NAT_DROP_NO_FLOW,    /* a segment for a tuple with no entry */
    TUN_NAT_DROP_PENDING,    /* a non-syn segment while the flow awaits a decision */
    TUN_NAT_DROP_TABLE_FULL,
    TUN_NAT_DROP_RESERVED,   /* aimed at the stack's own ports or the synthetic peer */
    TUN_NAT_DROP_REASON_COUNT
} tun_nat_drop_t;

typedef struct {
    tun_nat_state_t state;
    tun_flow_key_t  key;        /* the original tuple, as the app sent it */
    uint64_t        generation; /* bumps on every reuse of the slot */
    uint64_t        touched_ms;
    size_t          syn_len;
    uint8_t         syn[TUN_NAT_SYN_MAX]; /* the held syn, untranslated */
} tun_nat_entry_t;

typedef struct {
    uint8_t  local4[4];       /* the stack's own address */
    uint8_t  local6[16];
    uint8_t  synthetic4[4];   /* the reserved peer every flow appears to come from */
    uint8_t  synthetic6[16];
    int      have_ipv4;
    int      have_ipv6;
    uint16_t listen_port;     /* the stack's single tcp listener */
    size_t   limit;           /* runtime limit, at most TUN_NAT_TCP_MAX */
} tun_nat_config_t;

typedef struct {
    tun_nat_config_t config;
    uint64_t         next_generation;
    tun_nat_entry_t  entries[TUN_NAT_TCP_MAX];
    uint64_t         dropped[TUN_NAT_DROP_REASON_COUNT];
    uint64_t         opened;
    uint64_t         closed;
    uint64_t         expired;
} tun_nat_t;

typedef enum {
    TUN_NAT_OK        =  0,
    TUN_NAT_ERR_ARG   = -1,
    TUN_NAT_ERR_STATE = -2, /* the slot is not in the state the call needs */
    TUN_NAT_ERR_SPACE = -3
} tun_nat_status_t;

typedef enum {
    TUN_NAT_UDP_OTHER = 0,
    TUN_NAT_UDP_PACKET = 1,
    TUN_NAT_UDP_DROP = -1
} tun_nat_udp_result_t;

/* UDP keeps its original tuple and datagram boundary; it does not enter the
   TCP translation table or lwip's TCP listener */
tun_nat_udp_result_t tun_nat_udp_inbound(tun_nat_t *nat, uint8_t *packet,
                                         size_t len, tun_flow_key_t *out_key,
                                         const uint8_t **out_payload,
                                         size_t *out_payload_len,
                                         tun_nat_drop_t *out_reason);

/* answer one captured datagram from its original destination to its app */
tun_nat_status_t tun_nat_udp_reply(const tun_flow_key_t *key,
                                   const uint8_t *payload, size_t payload_len,
                                   uint8_t *out, size_t cap, size_t *out_len);

/* refuse one captured datagram the way a closed port does: icmp port
   unreachable from the original destination to the app, quoting the datagram's
   headers. an app on a connected udp socket sees the failure at once instead of
   waiting out a timeout. payload_len only sets the quoted length field */
tun_nat_status_t tun_nat_udp_unreachable(const tun_flow_key_t *key, size_t payload_len,
                                         uint8_t *out, size_t cap, size_t *out_len);

tun_nat_status_t tun_nat_init(tun_nat_t *nat, const tun_nat_config_t *config);

/* a packet from the app. on TUN_NAT_PASS it may have been rewritten in place
   for the stack; on TUN_NAT_NEW the syn is held in the entry and *out_slot
   names it, for the owner to accept or reject */
tun_nat_verdict_t tun_nat_inbound(tun_nat_t *nat, uint8_t *packet, size_t len,
                                  uint64_t now_ms, size_t *out_slot,
                                  tun_nat_drop_t *out_reason);

/* a packet from the stack, rewritten in place back to the app's view */
tun_nat_verdict_t tun_nat_outbound(tun_nat_t *nat, uint8_t *packet, size_t len,
                                   uint64_t now_ms, size_t *out_slot,
                                   tun_nat_drop_t *out_reason);

/* the owner took the flow: the held syn comes back translated, ready for the
   stack, and the entry becomes active */
tun_nat_status_t tun_nat_accept(tun_nat_t *nat, size_t slot, uint8_t *out,
                                size_t cap, size_t *out_len);

/* the owner refused the flow: the entry is freed and *out gets a reset for
   the app, sent from the original destination, so the app fails at once
   instead of retrying its syn for a minute */
tun_nat_status_t tun_nat_reject(tun_nat_t *nat, size_t slot, uint8_t *out,
                                size_t cap, size_t *out_len);

/* the owner is done with an active flow. the entry stays until the stack no
   longer holds a pcb for it, so its synthetic port cannot be handed to a new
   flow while an old connection still answers to it */
void tun_nat_close(tun_nat_t *nat, size_t slot);
void tun_nat_release(tun_nat_t *nat, size_t slot);

/* pending entries older than max_ms are freed; their slots are written to
   out_slots so the owner can forget them. returns how many expired */
size_t tun_nat_expire_pending(tun_nat_t *nat, uint64_t now_ms, uint64_t max_ms,
                              size_t *out_slots, size_t cap);
/* ms until the oldest pending entry reaches max_ms, 0 when one already has,
   UINT64_MAX when nothing is pending */
uint64_t tun_nat_pending_wait_ms(const tun_nat_t *nat, uint64_t now_ms,
                                 uint64_t max_ms);

const tun_nat_entry_t *tun_nat_entry(const tun_nat_t *nat, size_t slot);
uint16_t tun_nat_synthetic_port(size_t slot);
int tun_nat_slot_for_port(const tun_nat_t *nat, uint16_t port, size_t *out_slot);

/* a flow id the owner can hold: slot and generation together, so an id that
   outlived its flow never reaches the entry that reused the slot */
uint64_t tun_nat_flow_id(const tun_nat_t *nat, size_t slot);
int tun_nat_slot_for_id(const tun_nat_t *nat, uint64_t id, size_t *out_slot);

/* what a drop reason means, in words for the diagnostics screen */
const char *tun_nat_drop_text(tun_nat_drop_t reason);

#ifdef __cplusplus
}
#endif

#endif

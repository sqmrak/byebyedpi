#include "tun_stack.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip6_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"

#define TUN_STACK_ERROR_MAX 256

typedef struct {
    uint8_t  frame[TUN_STACK_FRAME_MAX];
    size_t   len;
    uint64_t queued_at_ms;
} tun_stack_pending_t;

/* what the stack knows about one capture slot beyond the translation entry:
   the connection lwip handed over, and whether the owner was told about it */
typedef struct {
    struct tun_stack *stack;
    size_t            slot;
    struct tcp_pcb   *pcb;
    struct pbuf      *rx;       /* the app's bytes the owner has not taken yet */
    int               rx_eof;   /* the app's fin arrived behind rx */
    int               reported; /* REQUESTED was sent, so CLOSED is owed */
    unsigned          pending;  /* events raised inside lwip, not yet delivered */
    uint64_t          flow_id;
    tun_flow_key_t    key;
} tun_stack_flow_t;

struct tun_stack {
    pthread_t owner;
    int       started;
    int       device_closed;
    int       lwip_depth; /* > 0 while lwip is running a callback of ours */

    struct netif    netif;
    struct tcp_pcb *listener;
    tun_nat_t       nat;
    tun_stack_flow_t flows[TUN_NAT_TCP_MAX];

    tun_stack_config_t config;
    tun_stack_io_t     io;
    tun_stack_stats_t  stats;

    tun_stack_pending_t queue[TUN_STACK_QUEUE_MAX];
    size_t queue_head; /* oldest pending frame */

    char last_error[TUN_STACK_ERROR_MAX];
};

size_t tun_stack_size(void) {
    return sizeof(struct tun_stack);
}

const char *tun_stack_status_name(tun_stack_status_t status) {
    switch (status) {
    case TUN_STACK_OK:          return "ok";
    case TUN_STACK_QUEUED:      return "queued";
    case TUN_STACK_ERR_ARG:     return "arg";
    case TUN_STACK_ERR_STATE:   return "state";
    case TUN_STACK_ERR_FRAME:   return "frame";
    case TUN_STACK_ERR_OVERSIZE: return "oversize";
    case TUN_STACK_ERR_MEMORY:  return "memory";
    case TUN_STACK_ERR_QUEUE:   return "queue";
    case TUN_STACK_ERR_IO:      return "io";
    case TUN_STACK_ERR_STACK:   return "stack";
    case TUN_STACK_ERR_CAPTURE: return "capture";
    case TUN_STACK_ERR_FLOW:    return "flow";
    }
    return "unknown";
}

const tun_stack_stats_t *tun_stack_stats(const tun_stack_t *stack) {
    return stack ? &stack->stats : NULL;
}

const tun_nat_t *tun_stack_capture(const tun_stack_t *stack) {
    return stack ? &stack->nat : NULL;
}

const char *tun_stack_last_error(const tun_stack_t *stack) {
    return stack ? stack->last_error : "";
}

static void set_error(tun_stack_t *stack, const char *text) {
    snprintf(stack->last_error, sizeof stack->last_error, "%s", text);
}

/* every entry point runs on the thread that called init. lwip has no locking
   in this port, so a call from anywhere else is a defect to report, not a
   race to survive */
static int wrong_thread(tun_stack_t *stack) {
    if (pthread_equal(stack->owner, pthread_self())) return 0;
    set_error(stack, "the tunnel stack was called from a thread that does not"
                     " own it, which would corrupt lwip state");
    return 1;
}

static uint64_t now_ms(const tun_stack_t *stack) {
    int64_t now = stack->io.now_ms(stack->io.ctx);
    return now > 0 ? (uint64_t)now : 0;
}


/* an owner that hears about a flow may close or reset it on the spot. inside
   an lwip callback that pcb is still being worked on by lwip itself, so events
   raised there wait as flags on the flow and are delivered once lwip has
   returned. a flow that closed drops whatever else was waiting: its id is dead */
#define PENDING_OPEN     (1u << 0)
#define PENDING_READABLE (1u << 1)
#define PENDING_WRITABLE (1u << 2)
#define PENDING_CLOSED   (1u << 3)

static void deliver(tun_stack_t *stack, tun_stack_flow_event_t event, tun_stack_flow_t *flow) {
    if (stack->config.flow_event)
        stack->config.flow_event(stack->config.flow_ctx, event, flow->flow_id, &flow->key);
}

static void emit(tun_stack_t *stack, tun_stack_flow_event_t event, tun_stack_flow_t *flow) {
    if (stack->lwip_depth == 0 || event == TUN_STACK_FLOW_REQUESTED) {
        deliver(stack, event, flow);
        return;
    }
    switch (event) {
    case TUN_STACK_FLOW_OPEN:     flow->pending |= PENDING_OPEN; break;
    case TUN_STACK_FLOW_READABLE: flow->pending |= PENDING_READABLE; break;
    case TUN_STACK_FLOW_WRITABLE: flow->pending |= PENDING_WRITABLE; break;
    case TUN_STACK_FLOW_CLOSED:   flow->pending = PENDING_CLOSED; break;
    default: break;
    }
}

static void flush_pending(tun_stack_t *stack) {
    for (size_t slot = 0; slot < TUN_NAT_TCP_MAX; ++slot) {
        tun_stack_flow_t *flow = &stack->flows[slot];
        unsigned pending = flow->pending;
        if (!pending) continue;
        flow->pending = 0;
        if (pending & PENDING_CLOSED) {
            deliver(stack, TUN_STACK_FLOW_CLOSED, flow);
            continue;
        }
        if (pending & PENDING_OPEN) deliver(stack, TUN_STACK_FLOW_OPEN, flow);
        if (pending & PENDING_READABLE) deliver(stack, TUN_STACK_FLOW_READABLE, flow);
        if (pending & PENDING_WRITABLE) deliver(stack, TUN_STACK_FLOW_WRITABLE, flow);
    }
}

static void lwip_enter(tun_stack_t *stack) {
    ++stack->lwip_depth;
}

static void lwip_leave(tun_stack_t *stack) {
    if (--stack->lwip_depth == 0) flush_pending(stack);
}

/* the slot is finished: lwip holds nothing for it any more. the owner hears
   CLOSED exactly once for every flow it was told about */
static void drop_received(tun_stack_flow_t *flow) {
    if (flow->rx) pbuf_free(flow->rx);
    flow->rx = NULL;
    flow->rx_eof = 0;
}

static void finish_slot(tun_stack_t *stack, size_t slot) {
    tun_stack_flow_t *flow = &stack->flows[slot];
    int owed = flow->reported;
    flow->reported = 0;
    flow->pcb = NULL;
    drop_received(flow);
    tun_nat_release(&stack->nat, slot);
    if (owed) {
        ++stack->stats.flows_closed;
        emit(stack, TUN_STACK_FLOW_CLOSED, flow);
    }
}

static void detach_pcb(struct tcp_pcb *pcb) {
    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_err(pcb, NULL);
}

/* the connection lwip made for an accepted syn whose handshake has not
   completed yet. the flow has no pcb of its own until the app's ack arrives */
static struct tcp_pcb *handshaking_pcb(const tun_stack_t *stack, size_t slot) {
    uint16_t port = tun_nat_synthetic_port(slot);
    for (struct tcp_pcb *pcb = tcp_active_pcbs; pcb; pcb = pcb->next)
        if (pcb->local_port == stack->config.listen_port && pcb->remote_port == port)
            return pcb;
    return NULL;
}

/* whether lwip still keeps a connection for this slot's synthetic port, in
   any state from syn-received to time-wait */
static int stack_holds_slot(const tun_stack_t *stack, size_t slot) {
    uint16_t port = tun_nat_synthetic_port(slot);
    uint16_t listen = stack->config.listen_port;
    for (struct tcp_pcb *pcb = tcp_active_pcbs; pcb; pcb = pcb->next)
        if (pcb->local_port == listen && pcb->remote_port == port) return 1;
    for (struct tcp_pcb *pcb = tcp_tw_pcbs; pcb; pcb = pcb->next)
        if (pcb->local_port == listen && pcb->remote_port == port) return 1;
    return 0;
}


static void queue_pop_front(tun_stack_t *stack) {
    tun_stack_pending_t *front = &stack->queue[stack->queue_head];
    stack->stats.queue_bytes -= front->len;
    front->len = 0;
    stack->queue_head = (stack->queue_head + 1u) % TUN_STACK_QUEUE_MAX;
    --stack->stats.queue_packets;
}

static tun_stack_status_t queue_push(tun_stack_t *stack, const uint8_t *frame,
                                     size_t len) {
    size_t max_packets = stack->config.queue_max_packets;
    if (max_packets > TUN_STACK_QUEUE_MAX) max_packets = TUN_STACK_QUEUE_MAX;

    /* a full queue refuses the frame. dropping an older one instead would
       throw away a segment the peer is already waiting on, and the stack can
       retransmit this one once the device drains */
    if (stack->stats.queue_packets >= max_packets ||
        stack->stats.queue_bytes + len > stack->config.queue_max_bytes) {
        ++stack->stats.queue_full;
        set_error(stack, "the tunnel device is not draining and the pending"
                         " queue is full, so the stack was asked to hold the"
                         " packet and send it again later");
        return TUN_STACK_ERR_QUEUE;
    }

    size_t index = (stack->queue_head + stack->stats.queue_packets) % TUN_STACK_QUEUE_MAX;
    tun_stack_pending_t *slot = &stack->queue[index];
    memcpy(slot->frame, frame, len);
    slot->len = len;
    slot->queued_at_ms = now_ms(stack);

    ++stack->stats.queue_packets;
    stack->stats.queue_bytes += len;
    ++stack->stats.queued;
    if (stack->stats.queue_packets > stack->stats.queue_peak_packets)
        stack->stats.queue_peak_packets = stack->stats.queue_packets;
    return TUN_STACK_QUEUED;
}

/* a frame that has waited longer than the budget is stale: the peer has
   given up on it or retransmitted it already. dropping it is counted, never
   silent */
static void queue_expire(tun_stack_t *stack) {
    uint64_t current = now_ms(stack);
    while (stack->stats.queue_packets > 0) {
        tun_stack_pending_t *front = &stack->queue[stack->queue_head];
        if (current < front->queued_at_ms) break; /* clock moved backwards */
        if (current - front->queued_at_ms < stack->config.queue_max_age_ms) break;
        queue_pop_front(stack);
        ++stack->stats.queue_expired;
    }
}


static tun_stack_write_t write_frame(tun_stack_t *stack, const uint8_t *frame,
                                     size_t len) {
    int write_errno = 0;
    tun_stack_write_t result = stack->io.write_frame(stack->io.ctx, frame, len,
                                                     &write_errno);
    char text[TUN_STACK_ERROR_MAX];
    switch (result) {
    case TUN_STACK_WRITE_DONE:
        ++stack->stats.frames_out;
        stack->stats.bytes_out += len;
        break;
    case TUN_STACK_WRITE_BLOCKED:
        break;
    case TUN_STACK_WRITE_SHORT:
        /* a cut frame is not a packet, and the rest of it written on its own
           would be a fragment with no ip header */
        ++stack->stats.short_writes;
        snprintf(text, sizeof text, "the tunnel device took only part of a %zu byte"
                 " frame, so the packet was lost rather than sent in pieces", len);
        set_error(stack, text);
        break;
    case TUN_STACK_WRITE_FAILED:
    default:
        ++stack->stats.write_errors;
        snprintf(text, sizeof text, "writing a %zu byte frame to the tunnel device"
                 " failed (errno %d)", len, write_errno);
        set_error(stack, text);
        result = TUN_STACK_WRITE_FAILED;
        break;
    }
    return result;
}

/* hand a finished frame to the device, or park it when the device is busy.
   anything already waiting goes first, or this frame would overtake it and
   the tunnel would invent reordering */
static tun_stack_status_t send_frame(tun_stack_t *stack, const uint8_t *frame, size_t len) {
    if (stack->stats.queue_packets > 0) return queue_push(stack, frame, len);
    switch (write_frame(stack, frame, len)) {
    case TUN_STACK_WRITE_DONE:
        return TUN_STACK_OK;
    case TUN_STACK_WRITE_BLOCKED:
        return queue_push(stack, frame, len);
    case TUN_STACK_WRITE_SHORT:
    case TUN_STACK_WRITE_FAILED:
    default:
        return TUN_STACK_ERR_IO;
    }
}


static err_t send_from_stack(tun_stack_t *stack, struct pbuf *p) {
    if (!stack->started) return ERR_IF;
    if (p->tot_len > stack->config.mtu || p->tot_len > TUN_STACK_PACKET_MAX) {
        ++stack->stats.dropped_oversize;
        set_error(stack, "the stack produced a packet larger than the tunnel"
                         " mtu, which the device cannot carry");
        return ERR_VAL;
    }

    /* the frame is built once: header, then the pbuf chain copied behind it */
    uint8_t frame[TUN_STACK_FRAME_MAX];
    uint8_t *packet = frame + UTUN_FRAME_HEADER_LEN;
    size_t len = p->tot_len;
    if (pbuf_copy_partial(p, packet, (u16_t)len, 0) != len ||
        utun_frame_header(packet[0], frame) != UTUN_FRAME_OK) {
        ++stack->stats.dropped_by_stack;
        set_error(stack, "an outbound packet could not be assembled from the"
                         " stack's buffers");
        return ERR_BUF;
    }

    tun_nat_drop_t reason = TUN_NAT_DROP_NONE;
    if (tun_nat_outbound(&stack->nat, packet, len, now_ms(stack), NULL, &reason) !=
        TUN_NAT_PASS) {
        /* dropped on purpose and counted: telling lwip the send failed would
           only make it try the same unmappable packet again */
        ++stack->stats.dropped_outbound;
        char text[TUN_STACK_ERROR_MAX];
        snprintf(text, sizeof text, "a packet from the stack was not sent to the"
                 " app because %s", tun_nat_drop_text(reason));
        set_error(stack, text);
        return ERR_OK;
    }

    switch (send_frame(stack, frame, len + UTUN_FRAME_HEADER_LEN)) {
    case TUN_STACK_OK:
    case TUN_STACK_QUEUED:
        return ERR_OK;
    case TUN_STACK_ERR_QUEUE:
        /* ERR_MEM tells lwip to keep the segment and try again */
        return ERR_MEM;
    default:
        return ERR_IF;
    }
}

static err_t output4(struct netif *netif, struct pbuf *p, const ip4_addr_t *address) {
    (void)address; /* a point to point tunnel has no next hop to resolve */
    return send_from_stack((tun_stack_t *)netif->state, p);
}

#if LWIP_IPV6
static err_t output6(struct netif *netif, struct pbuf *p, const ip6_addr_t *address) {
    (void)address;
    return send_from_stack((tun_stack_t *)netif->state, p);
}
#endif

static err_t netif_setup(struct netif *netif) {
    tun_stack_t *stack = netif->state;
    netif->name[0] = 'u';
    netif->name[1] = 't';
    netif->mtu = stack->config.mtu;
    netif->output = output4;
#if LWIP_IPV6
    netif->output_ip6 = output6;
#endif
    /* bare ip on a point to point link: no ethernet, no arp, no broadcast */
    netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}


static void on_flow_error(void *arg, err_t err) {
    (void)err;
    tun_stack_flow_t *flow = arg;
    if (!flow) return;
    /* lwip has already freed the pcb; nothing may touch it */
    flow->pcb = NULL;
    finish_slot(flow->stack, flow->slot);
}

/* the app's bytes are kept as lwip delivered them and acknowledged only when
   the owner consumes them, so the window the app sees is exactly what the
   owner has not taken yet */
static err_t on_flow_receive(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    tun_stack_flow_t *flow = arg;
    (void)err;
    if (!flow) {
        if (p) pbuf_free(p);
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    if (p) {
        if (flow->rx) pbuf_cat(flow->rx, p);
        else flow->rx = p;
    } else {
        flow->rx_eof = 1;
    }
    emit(flow->stack, TUN_STACK_FLOW_READABLE, flow);
    return ERR_OK;
}

static err_t on_flow_sent(void *arg, struct tcp_pcb *pcb, u16_t len) {
    tun_stack_flow_t *flow = arg;
    (void)pcb;
    (void)len;
    if (flow) emit(flow->stack, TUN_STACK_FLOW_WRITABLE, flow);
    return ERR_OK;
}

static err_t on_accept(void *arg, struct tcp_pcb *pcb, err_t err) {
    tun_stack_t *stack = arg;
    size_t slot;
    if (err != ERR_OK || !pcb || !stack) return ERR_VAL;

    const tun_nat_entry_t *entry = NULL;
    if (tun_nat_slot_for_port(&stack->nat, pcb->remote_port, &slot))
        entry = tun_nat_entry(&stack->nat, slot);
    if (!entry || entry->state != TUN_NAT_ACTIVE || stack->flows[slot].pcb) {
        /* a connection that no captured flow asked for: refuse it */
        tcp_abort(pcb);
        return ERR_ABRT;
    }

    tun_stack_flow_t *flow = &stack->flows[slot];
    flow->pcb = pcb;
    /* this tcp hop stays inside the device. waiting for an app ack before
       sending a short tail stalls tls records and small replies */
    tcp_nagle_disable(pcb);
    tcp_arg(pcb, flow);
    tcp_recv(pcb, on_flow_receive);
    tcp_sent(pcb, on_flow_sent);
    tcp_err(pcb, on_flow_error);
    ++stack->stats.flows_opened;
    emit(stack, TUN_STACK_FLOW_OPEN, flow);
    return ERR_OK;
}


tun_stack_status_t tun_stack_init(tun_stack_t *stack, const tun_stack_config_t *config,
                                  const tun_stack_io_t *io) {
    if (!stack || !config || !io || !io->write_frame || !io->now_ms)
        return TUN_STACK_ERR_ARG;
    if (config->mtu == 0 || config->mtu > TUN_STACK_PACKET_MAX) return TUN_STACK_ERR_ARG;
    if (!config->have_ipv4 && !config->have_ipv6) return TUN_STACK_ERR_ARG;

    memset(stack, 0, sizeof *stack);
    stack->owner = pthread_self();
    stack->config = *config;
    stack->io = *io;
    if (!stack->config.listen_port) stack->config.listen_port = TUN_STACK_DEFAULT_LISTEN_PORT;
    if (!stack->config.queue_max_packets)
        stack->config.queue_max_packets = TUN_STACK_DEFAULT_QUEUE_PACKETS;
    if (!stack->config.queue_max_bytes)
        stack->config.queue_max_bytes = TUN_STACK_DEFAULT_QUEUE_BYTES;
    if (!stack->config.queue_max_age_ms)
        stack->config.queue_max_age_ms = TUN_STACK_DEFAULT_QUEUE_AGE_MS;
    if (!stack->config.pending_max_ms)
        stack->config.pending_max_ms = TUN_STACK_DEFAULT_PENDING_MS;

    /* the capture table never holds more flows than lwip has pcbs for */
    tun_nat_config_t capture;
    memset(&capture, 0, sizeof capture);
    memcpy(capture.local4, config->address4, 4);
    memcpy(capture.synthetic4, config->synthetic4, 4);
    memcpy(capture.local6, config->address6, 16);
    memcpy(capture.synthetic6, config->synthetic6, 16);
    capture.have_ipv4 = config->have_ipv4;
    capture.have_ipv6 = config->have_ipv6;
    capture.listen_port = stack->config.listen_port;
    capture.limit = MEMP_NUM_TCP_PCB < TUN_NAT_TCP_MAX ? MEMP_NUM_TCP_PCB : TUN_NAT_TCP_MAX;
    if (tun_nat_init(&stack->nat, &capture) != TUN_NAT_OK) {
        set_error(stack, "the capture addresses or listener port are unusable:"
                         " the synthetic peer must differ from the stack address"
                         " and the port must sit outside the synthetic range");
        return TUN_STACK_ERR_ARG;
    }
    for (size_t i = 0; i < TUN_NAT_TCP_MAX; ++i) {
        stack->flows[i].stack = stack;
        stack->flows[i].slot = i;
    }

    /* lwip has no teardown of its own, so it is brought up once per process
       and the interface is what comes and goes */
    static int lwip_ready;
    if (!lwip_ready) {
        lwip_init();
        lwip_ready = 1;
    }

    ip4_addr_t address, netmask, gateway;
    ip4_addr_set_zero(&address);
    ip4_addr_set_zero(&netmask);
    ip4_addr_set_zero(&gateway);
    if (config->have_ipv4) {
        memcpy(&address.addr, config->address4, 4);
        memcpy(&netmask.addr, config->netmask4, 4);
    }
    if (!netif_add(&stack->netif, &address, &netmask, &gateway, stack, netif_setup,
                   ip_input)) {
        set_error(stack, "the tunnel interface could not be created inside the"
                         " ip stack");
        return TUN_STACK_ERR_STACK;
    }
#if LWIP_IPV6
    if (config->have_ipv6) {
        ip6_addr_t address6;
        memset(&address6, 0, sizeof address6);
        memcpy(&address6.addr, config->address6, 16);
        netif_ip6_addr_set(&stack->netif, 0, &address6);
        netif_ip6_addr_set_state(&stack->netif, 0, IP6_ADDR_PREFERRED);
    }
#endif
    netif_set_default(&stack->netif);
    netif_set_link_up(&stack->netif);
    netif_set_up(&stack->netif);

    /* one listener, for both families, on one port. captured flows arrive at
       it translated; nothing else can reach it */
    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (!pcb || tcp_bind(pcb, IP_ANY_TYPE, stack->config.listen_port) != ERR_OK) {
        if (pcb) tcp_abort(pcb);
        netif_remove(&stack->netif);
        set_error(stack, "the stack could not bind its capture listener");
        return TUN_STACK_ERR_STACK;
    }
    stack->listener = tcp_listen(pcb);
    if (!stack->listener) {
        tcp_abort(pcb);
        netif_remove(&stack->netif);
        set_error(stack, "the stack could not start its capture listener");
        return TUN_STACK_ERR_STACK;
    }
    tcp_arg(stack->listener, stack);
    tcp_accept(stack->listener, on_accept);

    stack->started = 1;
    return TUN_STACK_OK;
}

static tun_stack_status_t inject(tun_stack_t *stack, const uint8_t *packet, size_t len) {
    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_POOL);
    if (!p) {
        ++stack->stats.dropped_no_pbuf;
        set_error(stack, "the ip stack has no buffer left, so an inbound packet"
                         " was dropped and the sender will have to resend it");
        return TUN_STACK_ERR_MEMORY;
    }
    if (pbuf_take(p, packet, (u16_t)len) != ERR_OK) {
        pbuf_free(p);
        ++stack->stats.dropped_no_pbuf;
        set_error(stack, "an inbound packet did not fit the buffer the ip stack"
                         " provided");
        return TUN_STACK_ERR_MEMORY;
    }
    /* ip_input owns the pbuf from here, including freeing it */
    lwip_enter(stack);
    err_t taken = stack->netif.input(p, &stack->netif);
    if (taken != ERR_OK) pbuf_free(p);
    lwip_leave(stack);
    if (taken != ERR_OK) {
        ++stack->stats.dropped_by_stack;
        set_error(stack, "the ip stack refused an inbound packet");
        return TUN_STACK_ERR_STACK;
    }
    return TUN_STACK_OK;
}

static void reject_now(tun_stack_t *stack, size_t slot) {
    uint8_t frame[UTUN_FRAME_HEADER_LEN + 80];
    size_t len = 0;
    if (tun_nat_reject(&stack->nat, slot, frame + UTUN_FRAME_HEADER_LEN,
                       sizeof frame - UTUN_FRAME_HEADER_LEN, &len) != TUN_NAT_OK)
        return;
    ++stack->stats.flows_rejected;
    if (utun_frame_header(frame[UTUN_FRAME_HEADER_LEN], frame) == UTUN_FRAME_OK)
        (void)send_frame(stack, frame, len + UTUN_FRAME_HEADER_LEN);
    /* tun_nat_reject already freed the entry; this only settles the event */
    tun_stack_flow_t *flow = &stack->flows[slot];
    int owed = flow->reported;
    flow->reported = 0;
    flow->pcb = NULL;
    if (owed) {
        ++stack->stats.flows_closed;
        emit(stack, TUN_STACK_FLOW_CLOSED, flow);
    }
}

tun_stack_status_t tun_stack_input_frame(tun_stack_t *stack, uint8_t *frame,
                                         size_t frame_len) {
    if (!stack || !frame) return TUN_STACK_ERR_ARG;
    if (wrong_thread(stack)) return TUN_STACK_ERR_STATE;
    if (!stack->started) {
        set_error(stack, "a packet arrived after the tunnel stack was stopped");
        return TUN_STACK_ERR_STATE;
    }

    /* the device never hands over more than one frame, and a frame larger
       than the interface may carry is a defect somewhere above */
    if (frame_len > (size_t)stack->config.mtu + UTUN_FRAME_HEADER_LEN) {
        ++stack->stats.dropped_oversize;
        char text[TUN_STACK_ERROR_MAX];
        snprintf(text, sizeof text,
                 "a %zu byte frame arrived from the tunnel device, larger than"
                 " the %u byte mtu allows", frame_len, stack->config.mtu);
        set_error(stack, text);
        return TUN_STACK_ERR_OVERSIZE;
    }

    const uint8_t *checked = NULL;
    size_t packet_len = 0;
    uint8_t address_len = 0;
    utun_frame_status_t framing = utun_frame_parse(frame, frame_len, &checked,
                                                   &packet_len, &address_len);
    if (framing != UTUN_FRAME_OK) {
        ++stack->stats.dropped_frame;
        char text[TUN_STACK_ERROR_MAX];
        snprintf(text, sizeof text,
                 "a frame from the tunnel device was dropped: %s",
                 framing == UTUN_FRAME_ERR_FAMILY
                    ? "its address family header is neither ipv4 nor ipv6"
                    : framing == UTUN_FRAME_ERR_VERSION
                        ? "its ip version does not match the family header"
                        : framing == UTUN_FRAME_ERR_LENGTH
                            ? "its ip length field disagrees with the frame"
                            : "it ends before its ip header does");
        set_error(stack, text);
        return TUN_STACK_ERR_FRAME;
    }
    uint8_t *packet = frame + UTUN_FRAME_HEADER_LEN;

    ++stack->stats.frames_in;
    stack->stats.bytes_in += packet_len;

    tun_flow_key_t udp_key;
    const uint8_t *udp_payload = NULL;
    size_t udp_len = 0;
    tun_nat_drop_t udp_reason = TUN_NAT_DROP_NONE;
    tun_nat_udp_result_t udp = tun_nat_udp_inbound(&stack->nat, packet, packet_len,
        &udp_key, &udp_payload, &udp_len, &udp_reason);
    if (udp == TUN_NAT_UDP_PACKET) {
        if (stack->config.udp_packet &&
            stack->config.udp_packet(stack->config.udp_ctx, &udp_key,
                                     udp_payload, udp_len) == 0) {
            ++stack->stats.udp_received;
            return TUN_STACK_OK;
        }
        ++stack->stats.udp_refused;
        ++stack->stats.dropped_capture;
        set_error(stack, "a UDP datagram was refused because no relay owns it or"
                         " the relay has no queue space");
        return TUN_STACK_ERR_CAPTURE;
    }
    if (udp == TUN_NAT_UDP_DROP) {
        ++stack->stats.dropped_capture;
        char text[TUN_STACK_ERROR_MAX];
        snprintf(text, sizeof text, "a UDP datagram was dropped because %s",
                 tun_nat_drop_text(udp_reason));
        set_error(stack, text);
        return TUN_STACK_ERR_CAPTURE;
    }

    size_t slot = SIZE_MAX;
    tun_nat_drop_t reason = TUN_NAT_DROP_NONE;
    switch (tun_nat_inbound(&stack->nat, packet, packet_len, now_ms(stack), &slot,
                            &reason)) {
    case TUN_NAT_PASS:
        return inject(stack, packet, packet_len);
    case TUN_NAT_HELD:
        return TUN_STACK_OK;
    case TUN_NAT_NEW: {
        tun_stack_flow_t *flow = &stack->flows[slot];
        flow->pcb = NULL;
        flow->key = tun_nat_entry(&stack->nat, slot)->key;
        flow->flow_id = tun_nat_flow_id(&stack->nat, slot);
        ++stack->stats.flows_requested;
        if (!stack->config.flow_event) {
            reject_now(stack, slot);
            return TUN_STACK_OK;
        }
        flow->reported = 1;
        emit(stack, TUN_STACK_FLOW_REQUESTED, flow);
        return TUN_STACK_OK;
    }
    case TUN_NAT_DROP:
    default: {
        ++stack->stats.dropped_capture;
        char text[TUN_STACK_ERROR_MAX];
        snprintf(text, sizeof text, "a packet from an app was dropped because %s",
                 tun_nat_drop_text(reason));
        set_error(stack, text);
        return TUN_STACK_ERR_CAPTURE;
    }
    }
}

tun_stack_status_t tun_stack_udp_reply(tun_stack_t *stack, const tun_flow_key_t *key,
                                       const uint8_t *payload, size_t payload_len) {
    if (!stack || !key || (payload_len && !payload)) return TUN_STACK_ERR_ARG;
    if (wrong_thread(stack) || !stack->started) return TUN_STACK_ERR_STATE;
    if ((key->address_len == 4 && !stack->config.have_ipv4) ||
        (key->address_len == 16 && !stack->config.have_ipv6)) return TUN_STACK_ERR_ARG;
    uint8_t frame[TUN_STACK_FRAME_MAX];
    uint8_t *packet = frame + UTUN_FRAME_HEADER_LEN;
    size_t packet_len = 0;
    if (tun_nat_udp_reply(key, payload, payload_len, packet,
                          stack->config.mtu, &packet_len) != TUN_NAT_OK) {
        set_error(stack, "the UDP reply does not fit the tunnel mtu or its tuple"
                         " is invalid");
        return TUN_STACK_ERR_OVERSIZE;
    }
    if (utun_frame_header(packet[0], frame) != UTUN_FRAME_OK)
        return TUN_STACK_ERR_FRAME;
    tun_stack_status_t sent = send_frame(stack, frame,
                                        packet_len + UTUN_FRAME_HEADER_LEN);
    if (sent == TUN_STACK_OK || sent == TUN_STACK_QUEUED) ++stack->stats.udp_sent;
    return sent;
}

tun_stack_status_t tun_stack_udp_unreachable(tun_stack_t *stack, const tun_flow_key_t *key,
                                             size_t payload_len) {
    if (!stack || !key) return TUN_STACK_ERR_ARG;
    if (wrong_thread(stack) || !stack->started) return TUN_STACK_ERR_STATE;
    if ((key->address_len == 4 && !stack->config.have_ipv4) ||
        (key->address_len == 16 && !stack->config.have_ipv6)) return TUN_STACK_ERR_ARG;
    uint8_t frame[TUN_STACK_FRAME_MAX];
    uint8_t *packet = frame + UTUN_FRAME_HEADER_LEN;
    size_t packet_len = 0;
    if (tun_nat_udp_unreachable(key, payload_len, packet, stack->config.mtu,
                                &packet_len) != TUN_NAT_OK) {
        set_error(stack, "the icmp refusal does not fit the tunnel mtu or its tuple is invalid");
        return TUN_STACK_ERR_OVERSIZE;
    }
    if (utun_frame_header(packet[0], frame) != UTUN_FRAME_OK) return TUN_STACK_ERR_FRAME;
    return send_frame(stack, frame, packet_len + UTUN_FRAME_HEADER_LEN);
}

static int resolve_flow(tun_stack_t *stack, uint64_t flow_id, size_t *out_slot) {
    if (tun_nat_slot_for_id(&stack->nat, flow_id, out_slot)) return 1;
    set_error(stack, "a flow was addressed that no longer exists; its connection"
                     " ended before the call arrived");
    return 0;
}

tun_stack_status_t tun_stack_flow_accept(tun_stack_t *stack, uint64_t flow_id) {
    if (!stack) return TUN_STACK_ERR_ARG;
    if (wrong_thread(stack) || !stack->started) return TUN_STACK_ERR_STATE;
    size_t slot;
    if (!resolve_flow(stack, flow_id, &slot)) return TUN_STACK_ERR_FLOW;

    uint8_t syn[TUN_NAT_SYN_MAX];
    size_t len = 0;
    if (tun_nat_accept(&stack->nat, slot, syn, sizeof syn, &len) != TUN_NAT_OK) {
        set_error(stack, "a flow was accepted twice, or after it was rejected");
        return TUN_STACK_ERR_FLOW;
    }
    /* the held syn goes to the listener now, and the stack answers the app */
    tun_stack_status_t injected = inject(stack, syn, len);
    if (injected != TUN_STACK_OK) {
        /* nothing reached lwip, so nothing of this flow remains inside it */
        finish_slot(stack, slot);
        return injected;
    }
    return TUN_STACK_OK;
}

tun_stack_status_t tun_stack_flow_reject(tun_stack_t *stack, uint64_t flow_id) {
    if (!stack) return TUN_STACK_ERR_ARG;
    if (wrong_thread(stack) || !stack->started) return TUN_STACK_ERR_STATE;
    size_t slot;
    if (!resolve_flow(stack, flow_id, &slot)) return TUN_STACK_ERR_FLOW;
    if (tun_nat_entry(&stack->nat, slot)->state != TUN_NAT_PENDING) {
        set_error(stack, "only a flow that is still waiting can be rejected; an"
                         " accepted one has to be closed");
        return TUN_STACK_ERR_FLOW;
    }
    reject_now(stack, slot);
    return TUN_STACK_OK;
}

tun_stack_status_t tun_stack_flow_close(tun_stack_t *stack, uint64_t flow_id) {
    if (!stack) return TUN_STACK_ERR_ARG;
    if (wrong_thread(stack) || !stack->started) return TUN_STACK_ERR_STATE;
    size_t slot;
    if (!resolve_flow(stack, flow_id, &slot)) return TUN_STACK_ERR_FLOW;
    tun_stack_flow_t *flow = &stack->flows[slot];
    if (tun_nat_entry(&stack->nat, slot)->state == TUN_NAT_PENDING) {
        set_error(stack, "a flow that is still waiting has to be rejected, not"
                         " closed");
        return TUN_STACK_ERR_FLOW;
    }
    struct tcp_pcb *pcb = flow->pcb;
    flow->pcb = NULL;
    drop_received(flow);
    tun_nat_close(&stack->nat, slot);
    if (pcb) {
        detach_pcb(pcb);
        if (tcp_close(pcb) != ERR_OK) tcp_abort(pcb);
    }
    /* the slot is released by the timer sweep once lwip lets go of it */
    return TUN_STACK_OK;
}

/* the flow of an open connection, or NULL with the reason set */
static tun_stack_flow_t *open_flow(tun_stack_t *stack, uint64_t flow_id) {
    size_t slot;
    if (!resolve_flow(stack, flow_id, &slot)) return NULL;
    tun_stack_flow_t *flow = &stack->flows[slot];
    if (!flow->pcb) {
        set_error(stack, "the flow has no open connection with the app: it is"
                         " still waiting to be accepted, or already closing");
        return NULL;
    }
    return flow;
}

tun_stack_status_t tun_stack_flow_peek(tun_stack_t *stack, uint64_t flow_id,
                                       const uint8_t **data, size_t *len, int *eof) {
    if (data) *data = NULL;
    if (len) *len = 0;
    if (eof) *eof = 0;
    if (!stack || !data || !len || !eof) return TUN_STACK_ERR_ARG;
    if (wrong_thread(stack) || !stack->started) return TUN_STACK_ERR_STATE;
    tun_stack_flow_t *flow = open_flow(stack, flow_id);
    if (!flow) return TUN_STACK_ERR_FLOW;
    if (flow->rx) {
        *data = (const uint8_t *)flow->rx->payload;
        *len = flow->rx->len;
    } else {
        *eof = flow->rx_eof;
    }
    return TUN_STACK_OK;
}

tun_stack_status_t tun_stack_flow_consume(tun_stack_t *stack, uint64_t flow_id,
                                          size_t len) {
    if (!stack) return TUN_STACK_ERR_ARG;
    if (wrong_thread(stack) || !stack->started) return TUN_STACK_ERR_STATE;
    tun_stack_flow_t *flow = open_flow(stack, flow_id);
    if (!flow) return TUN_STACK_ERR_FLOW;
    if (len == 0) return TUN_STACK_OK;
    if (!flow->rx || len > flow->rx->tot_len || len > 0xffffu) {
        set_error(stack, "more bytes were consumed from a flow than the app sent");
        return TUN_STACK_ERR_ARG;
    }
    flow->rx = pbuf_free_header(flow->rx, (u16_t)len);
    /* only now does the app get the window back */
    tcp_recved(flow->pcb, (u16_t)len);
    return TUN_STACK_OK;
}

size_t tun_stack_flow_writable(tun_stack_t *stack, uint64_t flow_id) {
    if (!stack || wrong_thread(stack) || !stack->started) return 0;
    tun_stack_flow_t *flow = open_flow(stack, flow_id);
    if (!flow) return 0;
    /* the send queue can run out of segments before the byte budget does */
    if (tcp_sndqueuelen(flow->pcb) >= TCP_SND_QUEUELEN) return 0;
    return tcp_sndbuf(flow->pcb);
}

tun_stack_status_t tun_stack_flow_write(tun_stack_t *stack, uint64_t flow_id,
                                        const uint8_t *data, size_t len,
                                        size_t *accepted) {
    if (accepted) *accepted = 0;
    if (!stack || (!data && len) || !accepted) return TUN_STACK_ERR_ARG;
    if (wrong_thread(stack) || !stack->started) return TUN_STACK_ERR_STATE;
    tun_stack_flow_t *flow = open_flow(stack, flow_id);
    if (!flow) return TUN_STACK_ERR_FLOW;
    size_t room = tun_stack_flow_writable(stack, flow_id);
    size_t take = len < room ? len : room;
    if (take == 0) return TUN_STACK_OK;
    err_t queued = tcp_write(flow->pcb, data, (u16_t)take, TCP_WRITE_FLAG_COPY);
    if (queued == ERR_MEM) return TUN_STACK_OK; /* no segment free: the same as a full window */
    if (queued != ERR_OK) {
        set_error(stack, "the ip stack refused bytes for an open flow");
        return TUN_STACK_ERR_STACK;
    }
    tcp_output(flow->pcb);
    *accepted = take;
    return TUN_STACK_OK;
}

tun_stack_status_t tun_stack_flow_shutdown(tun_stack_t *stack, uint64_t flow_id) {
    if (!stack) return TUN_STACK_ERR_ARG;
    if (wrong_thread(stack) || !stack->started) return TUN_STACK_ERR_STATE;
    tun_stack_flow_t *flow = open_flow(stack, flow_id);
    if (!flow) return TUN_STACK_ERR_FLOW;
    if (tcp_shutdown(flow->pcb, 0, 1) != ERR_OK) {
        set_error(stack, "the ip stack could not send a fin on an open flow");
        return TUN_STACK_ERR_STACK;
    }
    return TUN_STACK_OK;
}

tun_stack_status_t tun_stack_flow_abort(tun_stack_t *stack, uint64_t flow_id) {
    if (!stack) return TUN_STACK_ERR_ARG;
    if (wrong_thread(stack) || !stack->started) return TUN_STACK_ERR_STATE;
    size_t slot;
    if (!resolve_flow(stack, flow_id, &slot)) return TUN_STACK_ERR_FLOW;
    tun_stack_flow_t *flow = &stack->flows[slot];
    if (tun_nat_entry(&stack->nat, slot)->state == TUN_NAT_PENDING) {
        reject_now(stack, slot);
        return TUN_STACK_OK;
    }
    /* an accepted flow can fail before the app's ack completes its handshake.
       lwip's connection for it has to be reset now, while the translation
       still exists, or the reset could never reach the app and its ack would
       arrive for a tuple nobody knows */
    struct tcp_pcb *pcb = flow->pcb ? flow->pcb : handshaking_pcb(stack, slot);
    flow->pcb = NULL;
    if (pcb) {
        detach_pcb(pcb);
        tcp_abort(pcb); /* sends the reset and frees the pcb at once */
    }
    finish_slot(stack, slot);
    return TUN_STACK_OK;
}

tun_stack_status_t tun_stack_on_writable(tun_stack_t *stack) {
    if (!stack) return TUN_STACK_ERR_ARG;
    if (wrong_thread(stack)) return TUN_STACK_ERR_STATE;
    if (!stack->started) return TUN_STACK_ERR_STATE;

    queue_expire(stack);
    while (stack->stats.queue_packets > 0) {
        tun_stack_pending_t *front = &stack->queue[stack->queue_head];
        switch (write_frame(stack, front->frame, front->len)) {
        case TUN_STACK_WRITE_DONE:
            queue_pop_front(stack);
            continue;
        case TUN_STACK_WRITE_BLOCKED:
            return TUN_STACK_QUEUED;
        case TUN_STACK_WRITE_SHORT:
        case TUN_STACK_WRITE_FAILED:
        default:
            /* the frame cannot be written and holding it would block every
               frame behind it forever */
            queue_pop_front(stack);
            return TUN_STACK_ERR_IO;
        }
    }
    return TUN_STACK_OK;
}

int tun_stack_has_pending(const tun_stack_t *stack) {
    return stack && stack->stats.queue_packets > 0;
}

uint32_t tun_stack_timer_wait_ms(const tun_stack_t *stack) {
    if (!stack || !stack->started) return SYS_TIMEOUTS_SLEEPTIME_INFINITE;
    uint32_t wait = sys_timeouts_sleeptime();
/* held syns expire on their own deadline. a finished flow needs none: its
   slot is swept by tun_stack_run_timers, which the loop calls after every
   event, and lwip drops time-wait connections from its own timer */
    uint64_t held = tun_nat_pending_wait_ms(&stack->nat, now_ms(stack),
                                            stack->config.pending_max_ms);
    if (held < wait) wait = (uint32_t)held;
    return wait;
}

void tun_stack_run_timers(tun_stack_t *stack) {
    if (!stack || !stack->started || wrong_thread(stack)) return;
    lwip_enter(stack);
    sys_check_timeouts();
    lwip_leave(stack);

    size_t expired[TUN_NAT_TCP_MAX];
    size_t count = tun_nat_expire_pending(&stack->nat, now_ms(stack),
                                          stack->config.pending_max_ms,
                                          expired, TUN_NAT_TCP_MAX);
    for (size_t i = 0; i < count && i < TUN_NAT_TCP_MAX; ++i) {
        tun_stack_flow_t *flow = &stack->flows[expired[i]];
        if (!flow->reported) continue;
        flow->reported = 0;
        ++stack->stats.flows_closed;
        emit(stack, TUN_STACK_FLOW_CLOSED, flow);
    }

    /* a slot whose connection lwip has let go of is free again. until then
       its synthetic port stays taken, so a new flow can never be delivered to
       an old connection that is still in time-wait */
    for (size_t slot = 0; slot < stack->nat.config.limit; ++slot) {
        const tun_nat_entry_t *entry = tun_nat_entry(&stack->nat, slot);
        if (!entry || entry->state == TUN_NAT_FREE || entry->state == TUN_NAT_PENDING)
            continue;
        if (stack->flows[slot].pcb) continue;
        if (stack_holds_slot(stack, slot)) continue;
        finish_slot(stack, slot);
    }
}

/* every connection lwip keeps on the listener's port, whether a flow still
   points at it or not: syn-received, established, closing and time-wait */
static void abort_listener_connections(tun_stack_t *stack) {
    uint16_t listen = stack->config.listen_port;
    int again = 1;
    while (again) {
        again = 0;
        for (struct tcp_pcb *pcb = tcp_active_pcbs; pcb; pcb = pcb->next) {
            if (pcb->local_port != listen) continue;
            detach_pcb(pcb);
            tcp_abort(pcb);
            again = 1;
            break;
        }
    }
    again = 1;
    while (again) {
        again = 0;
        for (struct tcp_pcb *pcb = tcp_tw_pcbs; pcb; pcb = pcb->next) {
            if (pcb->local_port != listen) continue;
            tcp_abort(pcb);
            again = 1;
            break;
        }
    }
}

void tun_stack_shutdown(tun_stack_t *stack) {
    if (!stack) return;
    if (!stack->started && stack->device_closed) return;

    /* stop accepting first, so nothing that runs during teardown can hand the
       interface another packet or open another flow */
    int was_started = stack->started;
    stack->started = 0;

    if (was_started) {
        /* flows first: every pcb is detached before it is aborted, so no lwip
           callback can run against state that is being torn down */
        for (size_t slot = 0; slot < TUN_NAT_TCP_MAX; ++slot) {
            tun_stack_flow_t *flow = &stack->flows[slot];
            if (flow->pcb) {
                struct tcp_pcb *pcb = flow->pcb;
                flow->pcb = NULL;
                detach_pcb(pcb);
                tcp_abort(pcb);
            }
            drop_received(flow);
        }
        abort_listener_connections(stack);
        if (stack->listener) {
            tcp_arg(stack->listener, NULL);
            tcp_accept(stack->listener, NULL);
            tcp_close(stack->listener);
            stack->listener = NULL;
        }
        for (size_t slot = 0; slot < stack->nat.config.limit; ++slot)
            if (tun_nat_entry(&stack->nat, slot)->state != TUN_NAT_FREE)
                finish_slot(stack, slot);

        netif_set_down(&stack->netif);
        netif_remove(&stack->netif);
        memset(&stack->netif, 0, sizeof stack->netif);
    }

    while (stack->stats.queue_packets > 0) queue_pop_front(stack);
    stack->stats.queue_bytes = 0;

    if (!stack->device_closed) {
        stack->device_closed = 1;
        if (stack->io.close_device) stack->io.close_device(stack->io.ctx);
    }
}

/* the adapter with the real ip stack behind it: frames in, captured flows
   reported with their original tuples, the stack's answers going back from
   the original destination, a bounded queue when the device blocks, and a
   teardown after which the stack can be brought up again cleanly */

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lwip/timeouts.h"
#include "packet_fixture.h"
#include "tun_stack.h"

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

static const uint8_t APP4[4]   = { 198, 18, 0, 1 };
static const uint8_t LOCAL4[4] = { 198, 18, 0, 2 };
static const uint8_t SYNTH4[4] = { 198, 18, 0, 3 };
static const uint8_t DEST4A[4] = { 203, 0, 113, 7 };
static const uint8_t DEST4B[4] = { 203, 0, 113, 8 };
static const uint8_t APP6[16]   = { 0xfd, 0, 0x5e, 0x4b, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
static const uint8_t LOCAL6[16] = { 0xfd, 0, 0x5e, 0x4b, 0,0,0,0, 0,0,0,0, 0,0,0,2 };
static const uint8_t SYNTH6[16] = { 0xfd, 0, 0x5e, 0x4b, 0,0,0,0, 0,0,0,0, 0,0,0,3 };
static const uint8_t DEST6[16]  = { 0x20, 0x01, 0x0d, 0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,7 };

/* ---- a device that records frames --------------------------------------- */

#define SENT_MAX 96

typedef struct {
    uint8_t  frames[SENT_MAX][TUN_STACK_FRAME_MAX];
    size_t   lengths[SENT_MAX];
    size_t   count;
    int      block;
    int      fail_errno;
    int      short_write;
    int      closed;
    int64_t  now;
} fake_device_t;

static fake_device_t device;

static tun_stack_write_t fake_write(void *ctx, const uint8_t *frame, size_t len,
                                    int *out_errno) {
    fake_device_t *d = ctx;
    *out_errno = 0;
    if (d->block) return TUN_STACK_WRITE_BLOCKED;
    if (d->fail_errno) {
        *out_errno = d->fail_errno;
        return TUN_STACK_WRITE_FAILED;
    }
    if (d->short_write) return TUN_STACK_WRITE_SHORT;
    if (d->count < SENT_MAX) {
        memcpy(d->frames[d->count], frame, len);
        d->lengths[d->count] = len;
        ++d->count;
    }
    return TUN_STACK_WRITE_DONE;
}

static int64_t fake_now(void *ctx) { return ((fake_device_t *)ctx)->now; }
static void fake_close(void *ctx) { ++((fake_device_t *)ctx)->closed; }

static void device_reset(void) {
    int64_t now = device.now;
    memset(&device, 0, sizeof device);
    device.now = now;
}

static const uint8_t *last_packet(size_t *len) {
    if (device.count == 0) return NULL;
    *len = device.lengths[device.count - 1] - 4;
    return device.frames[device.count - 1] + 4;
}

/* ---- an owner that records flow events ---------------------------------- */

#define EVENT_MAX 128

typedef struct {
    tun_stack_flow_event_t event;
    uint64_t id;
    tun_flow_key_t key;
} event_t;

static tun_stack_t *stack;
static event_t events[EVENT_MAX];
static size_t event_count;
static int accept_on_request;
/* when set, the owner takes every byte the app sends and closes on its fin,
   the way a relay that has nowhere to put the bytes would */
static int drain_on_readable = 1;
static size_t drained;
static size_t udp_seen;
static tun_flow_key_t last_udp_key;

static int on_udp(void *ctx, const tun_flow_key_t *key,
                  const uint8_t *payload, size_t payload_len) {
    (void)ctx;
    ++udp_seen;
    last_udp_key = *key;
    return tun_stack_udp_reply(stack, key, payload, payload_len) == TUN_STACK_OK
        ? 0 : -1;
}

static void on_flow(void *ctx, tun_stack_flow_event_t event, uint64_t id,
                    const tun_flow_key_t *key) {
    (void)ctx;
    if (event_count < EVENT_MAX) {
        events[event_count].event = event;
        events[event_count].id = id;
        events[event_count].key = *key;
        ++event_count;
    }
    if (event == TUN_STACK_FLOW_REQUESTED && accept_on_request)
        tun_stack_flow_accept(stack, id);
    if (event == TUN_STACK_FLOW_READABLE && drain_on_readable) {
        const uint8_t *data;
        size_t len;
        int eof;
        while (tun_stack_flow_peek(stack, id, &data, &len, &eof) == TUN_STACK_OK && len) {
            drained += len;
            tun_stack_flow_consume(stack, id, len);
        }
        if (eof) tun_stack_flow_close(stack, id);
    }
}

static size_t count_events(tun_stack_flow_event_t event) {
    size_t n = 0;
    for (size_t i = 0; i < event_count; ++i) n += events[i].event == event;
    return n;
}

static const event_t *last_event(tun_stack_flow_event_t event) {
    for (size_t i = event_count; i > 0; --i)
        if (events[i - 1].event == event) return &events[i - 1];
    return NULL;
}

static tun_stack_config_t config_for(void) {
    tun_stack_config_t c;
    memset(&c, 0, sizeof c);
    snprintf(c.ifname, sizeof c.ifname, "utun3");
    c.mtu = 1500;
    c.have_ipv4 = 1;
    memcpy(c.address4, LOCAL4, 4);
    memcpy(c.synthetic4, SYNTH4, 4);
    c.netmask4[0] = c.netmask4[1] = c.netmask4[2] = c.netmask4[3] = 255;
    c.have_ipv6 = 1;
    memcpy(c.address6, LOCAL6, 16);
    memcpy(c.synthetic6, SYNTH6, 16);
    c.queue_max_packets = 4;
    c.queue_max_bytes = 8192;
    c.queue_max_age_ms = 1000;
    c.pending_max_ms = 5000;
    c.flow_event = on_flow;
    c.udp_packet = on_udp;
    return c;
}

static tun_stack_io_t io_for(void) {
    tun_stack_io_t io;
    memset(&io, 0, sizeof io);
    io.write_frame = fake_write;
    io.now_ms = fake_now;
    io.close_device = fake_close;
    io.ctx = &device;
    return io;
}

static tun_stack_status_t feed(const uint8_t *packet, size_t len) {
    uint8_t frame[TUN_STACK_FRAME_MAX];
    size_t frame_len = pkt_frame(frame, packet, len);
    return tun_stack_input_frame(stack, frame, frame_len);
}

/* the syn-ack the stack sent for a syn from sport with sequence seq */
static int check_syn_ack(const char *label, const uint8_t *dest, size_t alen,
                         const uint8_t *app, uint16_t sport, uint32_t seq,
                         uint32_t *out_their_seq) {
    size_t len;
    const uint8_t *p = last_packet(&len);
    char name[160];
    if (!p) {
        snprintf(name, sizeof name, "%s: a syn-ack was sent", label);
        ok(name, 0);
        return 0;
    }
    const uint8_t *frame = p - 4;
    size_t l4 = pkt_l4(p, len);
    snprintf(name, sizeof name, "%s: the frame header names the right family", label);
    ok(name, frame[3] == (alen == 4 ? 2 : 30));
    snprintf(name, sizeof name, "%s: it comes from the original destination", label);
    ok(name, memcmp(pkt_src(p), dest, alen) == 0 && pkt_rd16(p + l4) == 443);
    snprintf(name, sizeof name, "%s: it goes back to the app", label);
    ok(name, memcmp(pkt_dst(p), app, alen) == 0 && pkt_rd16(p + l4 + 2) == sport);
    snprintf(name, sizeof name, "%s: it is a syn-ack for the app's syn", label);
    ok(name, p[l4 + 13] == (PKT_SYN | PKT_ACK) && pkt_rd32(p + l4 + 8) == seq + 1);
    snprintf(name, sizeof name, "%s: its checksums are valid", label);
    ok(name, pkt_l4_valid(p, len) && (alen != 4 || pkt_ip4_valid(p)));
    if (out_their_seq) *out_their_seq = pkt_rd32(p + l4 + 4);
    return 1;
}

static void *call_from_other_thread(void *arg) {
    uint8_t *frame = arg;
    return (void *)(intptr_t)tun_stack_input_frame(stack, frame, 32);
}

int main(void) {
    stack = malloc(tun_stack_size());
    if (!stack) return 1;
    tun_stack_config_t config = config_for();
    tun_stack_io_t io = io_for();
    ok("the stack starts", tun_stack_init(stack, &config, &io) == TUN_STACK_OK);
    const tun_stack_stats_t *stats = tun_stack_stats(stack);

    uint8_t p[256];
    size_t len;

    /* the stack answers a ping to its own address, through the same framing */
    len = pkt_echo4(p, APP4, LOCAL4, 1);
    ok("a ping to the stack is accepted", feed(p, len) == TUN_STACK_OK);
    const uint8_t *reply = last_packet(&len);
    ok("the ping is answered", device.count == 1 && reply && reply[20] == 0);
    ok("the answer frame carries the inet family", device.frames[0][3] == 2);

    len = pkt_echo6(p, APP6, LOCAL6, 2);
    ok("a v6 ping to the stack is accepted", feed(p, len) == TUN_STACK_OK);
    reply = last_packet(&len);
    ok("the v6 ping is answered", device.count == 2 && reply && reply[40] == 129);
    ok("the v6 answer frame carries the darwin inet6 family", device.frames[1][3] == 30);

    static const uint8_t udp_bytes[] = { 'o', 'k' };
    len = pkt_udp4(p, APP4, 53000, DEST4A, 53, udp_bytes, sizeof udp_bytes);
    ok("udp reaches the owner and returns through the device",
       feed(p, len) == TUN_STACK_OK && udp_seen == 1 &&
       last_udp_key.destination_port == 53 &&
       stats->udp_received == 1 && stats->udp_sent == 1);
    reply = last_packet(&len);
    ok("udp reply preserves the original tuple and checksums",
       reply && memcmp(pkt_src(reply), DEST4A, 4) == 0 &&
       memcmp(pkt_dst(reply), APP4, 4) == 0 &&
       pkt_rd16(reply + 20) == 53 && pkt_rd16(reply + 22) == 53000 &&
       pkt_ip4_valid(reply) && pkt_l4_valid(reply, len));

    len = pkt_udp6(p, APP6, 53001, DEST6, 53, udp_bytes, sizeof udp_bytes);
    ok("ipv6 udp reaches the owner",
       feed(p, len) == TUN_STACK_OK && udp_seen == 2 &&
       last_udp_key.address_len == 16);
    reply = last_packet(&len);
    ok("ipv6 udp reply preserves the original tuple",
       reply && memcmp(pkt_src(reply), DEST6, 16) == 0 &&
       memcmp(pkt_dst(reply), APP6, 16) == 0 && pkt_l4_valid(reply, len));

    /* a syn to an address out on the internet becomes a flow request with the
       original tuple, and the app sees nothing until the owner decides */
    device_reset();
    len = pkt_tcp4(p, APP4, 50001, DEST4A, 443, PKT_SYN, 1000, 0, 0);
    ok("a syn to the internet is captured", feed(p, len) == TUN_STACK_OK);
    const event_t *requested = last_event(TUN_STACK_FLOW_REQUESTED);
    ok("the owner is asked about it", requested != NULL);
    ok("the request carries the original destination",
       requested && requested->key.address_len == 4 &&
       memcmp(requested->key.destination, DEST4A, 4) == 0 &&
       requested->key.destination_port == 443);
    ok("the request carries the app's address and port",
       requested && memcmp(requested->key.source, APP4, 4) == 0 &&
       requested->key.source_port == 50001);
    ok("no handshake happens before the owner agrees", device.count == 0);

    /* the app repeats its syn while the owner is still deciding: that is the
       same flow, not a second one */
    size_t requests_before = count_events(TUN_STACK_FLOW_REQUESTED);
    len = pkt_tcp4(p, APP4, 50001, DEST4A, 443, PKT_SYN, 1000, 0, 0);
    ok("a repeated syn is held", feed(p, len) == TUN_STACK_OK);
    ok("a repeated syn does not ask the owner twice",
       count_events(TUN_STACK_FLOW_REQUESTED) == requests_before);
    ok("a repeated syn still gets no answer", device.count == 0);

    uint64_t flow_a = requested ? requested->id : 0;
    ok("accept", tun_stack_flow_accept(stack, flow_a) == TUN_STACK_OK);
    uint32_t their_a = 0;
    check_syn_ack("v4 flow", DEST4A, 4, APP4, 50001, 1000, &their_a);

    len = pkt_tcp4(p, APP4, 50001, DEST4A, 443, PKT_ACK, 1001, their_a + 1, 0);
    ok("the app's ack is taken", feed(p, len) == TUN_STACK_OK);
    const event_t *opened = last_event(TUN_STACK_FLOW_OPEN);
    ok("the flow opens", opened && opened->id == flow_a);

    /* the app's bytes reach the owner without a copy and are acknowledged
       only as the owner takes them */
    drain_on_readable = 0;
    device_reset();
    size_t readable_before = count_events(TUN_STACK_FLOW_READABLE);
    len = pkt_tcp4(p, APP4, 50001, DEST4A, 443, PKT_ACK, 1001, their_a + 1, 10);
    ok("the app's bytes are taken", feed(p, len) == TUN_STACK_OK);
    ok("the owner is told there is something to read",
       count_events(TUN_STACK_FLOW_READABLE) == readable_before + 1);
    const uint8_t *data = NULL;
    size_t data_len = 0;
    int eof = 1;
    ok("peek", tun_stack_flow_peek(stack, flow_a, &data, &data_len, &eof) == TUN_STACK_OK);
    ok("the owner sees exactly what the app sent",
       data_len == 10 && data && memcmp(data, "abcdefghij", 10) == 0 && !eof);
    ok("consuming part of it", tun_stack_flow_consume(stack, flow_a, 4) == TUN_STACK_OK);
    tun_stack_flow_peek(stack, flow_a, &data, &data_len, &eof);
    ok("leaves the rest in place", data_len == 6 && memcmp(data, "efghij", 6) == 0);
    ok("consuming more than there is is refused",
       tun_stack_flow_consume(stack, flow_a, 7) == TUN_STACK_ERR_ARG);
    tun_stack_flow_consume(stack, flow_a, 6);
    tun_stack_flow_peek(stack, flow_a, &data, &data_len, &eof);
    ok("nothing is left once all of it was taken", data_len == 0 && !eof);

    /* bytes toward the app go out from the original destination */
    device_reset();
    size_t accepted = 0;
    ok("the flow can take bytes toward the app", tun_stack_flow_writable(stack, flow_a) > 5);
    ok("write", tun_stack_flow_write(stack, flow_a, (const uint8_t *)"hello", 5,
                                     &accepted) == TUN_STACK_OK && accepted == 5);
    const uint8_t *out = last_packet(&len);
    ok("the app receives the bytes from the original destination",
       out && memcmp(pkt_src(out), DEST4A, 4) == 0 && len == 45 &&
       memcmp(out + 40, "hello", 5) == 0 && pkt_l4_valid(out, len));
    uint32_t stack_seq = out ? pkt_rd32(out + 24) : 0;
    len = pkt_tcp4(p, APP4, 50001, DEST4A, 443, PKT_ACK, 1011, stack_seq + 5, 0);
    size_t writable_before = count_events(TUN_STACK_FLOW_WRITABLE);
    feed(p, len);
    ok("the app's acknowledgement tells the owner there is room again",
       count_events(TUN_STACK_FLOW_WRITABLE) == writable_before + 1);
    drain_on_readable = 1;

    /* two connections on the same port to different addresses stay apart */
    device_reset();
    accept_on_request = 1;
    len = pkt_tcp4(p, APP4, 50002, DEST4A, 443, PKT_SYN, 5000, 0, 0);
    feed(p, len);
    check_syn_ack("first of two", DEST4A, 4, APP4, 50002, 5000, NULL);
    len = pkt_tcp4(p, APP4, 50002, DEST4B, 443, PKT_SYN, 6000, 0, 0);
    feed(p, len);
    check_syn_ack("second of two", DEST4B, 4, APP4, 50002, 6000, NULL);
    ok("they are two different flows",
       count_events(TUN_STACK_FLOW_REQUESTED) >= 3 &&
       events[event_count - 1].id != events[event_count - 2].id);

    /* ipv6 end to end */
    device_reset();
    len = pkt_tcp6(p, APP6, 60001, DEST6, 443, PKT_SYN, 77, 0, 0, 0, 0);
    ok("a v6 syn is captured", feed(p, len) == TUN_STACK_OK);
    uint32_t their_six = 0;
    check_syn_ack("v6 flow", DEST6, 16, APP6, 60001, 77, &their_six);
    len = pkt_tcp6(p, APP6, 60001, DEST6, 443, PKT_ACK, 78, their_six + 1, 0, 0, 0);
    size_t open_before = count_events(TUN_STACK_FLOW_OPEN);
    feed(p, len);
    ok("the v6 flow opens", count_events(TUN_STACK_FLOW_OPEN) == open_before + 1);

    /* the app closes first: the stack closes too, and the owner hears CLOSED
       once lwip has let go */
    device_reset();
    len = pkt_tcp4(p, APP4, 50001, DEST4A, 443, PKT_FIN | PKT_ACK, 1011, stack_seq + 5, 0);
    feed(p, len);
    size_t fin_len;
    const uint8_t *fin = last_packet(&fin_len);
    ok("the owner closes on the app's fin, and the fin goes out from the destination",
       fin && (fin[20 + 13] & PKT_FIN) && memcmp(pkt_src(fin), DEST4A, 4) == 0);
    uint32_t fin_seq = fin ? pkt_rd32(fin + 24) : 0;
    len = pkt_tcp4(p, APP4, 50001, DEST4A, 443, PKT_ACK, 1012, fin_seq + 1, 0);
    feed(p, len);
    size_t closed_before = count_events(TUN_STACK_FLOW_CLOSED);
    tun_stack_run_timers(stack);
    const event_t *closed = last_event(TUN_STACK_FLOW_CLOSED);
    ok("the owner hears the flow close",
       count_events(TUN_STACK_FLOW_CLOSED) == closed_before + 1 && closed &&
       closed->id == flow_a);
    ok("a stale id is refused afterwards",
       tun_stack_flow_close(stack, flow_a) == TUN_STACK_ERR_FLOW);

    /* the owner closes first: the fin goes out from the original destination */
    device_reset();
    uint64_t second = events[0].id;
    for (size_t i = 0; i < event_count; ++i)
        if (events[i].event == TUN_STACK_FLOW_OPEN &&
            events[i].key.address_len == 16) second = events[i].id;
    ok("the owner can close an open flow", tun_stack_flow_close(stack, second) == TUN_STACK_OK);
    fin = last_packet(&fin_len);
    ok("its fin comes from the original v6 destination",
       fin && memcmp(pkt_src(fin), DEST6, 16) == 0 && (fin[40 + 13] & PKT_FIN));

    /* half close toward the app, then a reset */
    device_reset();
    accept_on_request = 1;
    len = pkt_tcp4(p, APP4, 50050, DEST4A, 443, PKT_SYN, 700, 0, 0);
    feed(p, len);
    uint32_t their_h = 0;
    check_syn_ack("half close flow", DEST4A, 4, APP4, 50050, 700, &their_h);
    len = pkt_tcp4(p, APP4, 50050, DEST4A, 443, PKT_ACK, 701, their_h + 1, 0);
    feed(p, len);
    uint64_t half = last_event(TUN_STACK_FLOW_OPEN)->id;
    device_reset();
    ok("shutdown", tun_stack_flow_shutdown(stack, half) == TUN_STACK_OK);
    out = last_packet(&len);
    ok("a half close sends a fin to the app", out && (out[33] & PKT_FIN));
    len = pkt_tcp4(p, APP4, 50050, DEST4A, 443, PKT_ACK, 701, their_h + 2, 3);
    drained = 0;
    feed(p, len);
    ok("the app can still send after its peer's fin", drained == 3);
    device_reset();
    size_t closed_now = count_events(TUN_STACK_FLOW_CLOSED);
    ok("abort", tun_stack_flow_abort(stack, half) == TUN_STACK_OK);
    out = last_packet(&len);
    ok("an abort sends a reset from the destination",
       out && (out[33] & PKT_RST) && memcmp(pkt_src(out), DEST4A, 4) == 0);
    ok("an aborted flow is closed at once for the owner",
       count_events(TUN_STACK_FLOW_CLOSED) == closed_now + 1);
    ok("an aborted flow's id is dead", tun_stack_flow_write(stack, half,
       (const uint8_t *)"x", 1, &accepted) == TUN_STACK_ERR_FLOW);
    /* a flow that fails after it was accepted but before the app's ack
       completed its handshake still answers the app with a reset */
    device_reset();
    len = pkt_tcp4(p, APP4, 50060, DEST4A, 443, PKT_SYN, 900, 0, 0);
    feed(p, len);
    check_syn_ack("abort before ack", DEST4A, 4, APP4, 50060, 900, NULL);
    uint64_t early_abort = last_event(TUN_STACK_FLOW_REQUESTED)->id;
    device_reset();
    ok("a flow can be aborted before its handshake completes",
       tun_stack_flow_abort(stack, early_abort) == TUN_STACK_OK);
    out = last_packet(&len);
    ok("the half open app gets a reset from the destination",
       out && (out[33] & PKT_RST) && memcmp(pkt_src(out), DEST4A, 4) == 0 &&
       pkt_rd16(out + 22) == 50060);
    accept_on_request = 0;

    /* a refused flow gets a reset from the destination it asked for */
    accept_on_request = 0;
    device_reset();
    len = pkt_tcp4(p, APP4, 50010, DEST4A, 8443, PKT_SYN, 9, 0, 0);
    feed(p, len);
    requested = last_event(TUN_STACK_FLOW_REQUESTED);
    ok("reject", requested && tun_stack_flow_reject(stack, requested->id) == TUN_STACK_OK);
    const uint8_t *reset = last_packet(&len);
    ok("the app gets a reset from the original destination",
       reset && memcmp(pkt_src(reset), DEST4A, 4) == 0 && pkt_rd16(reset + 20) == 8443 &&
       (reset[33] & PKT_RST) && pkt_l4_valid(reset, len));
    ok("a rejected flow is closed for the owner",
       last_event(TUN_STACK_FLOW_CLOSED) &&
       last_event(TUN_STACK_FLOW_CLOSED)->id == requested->id);

    /* capture refusals are reported with the reason, never silently */
    len = pkt_tcp4(p, APP4, 50011, DEST4A, 443, PKT_SYN, 9, 0, 0);
    p[36] ^= 0x33;
    ok("a syn with a bad checksum is refused",
       feed(p, len) == TUN_STACK_ERR_CAPTURE &&
       tun_stack_capture(stack)->dropped[TUN_NAT_DROP_CHECKSUM] == 1);
    ok("the refusal is explained", strstr(tun_stack_last_error(stack), "checksum") != NULL);
    len = pkt_tcp4(p, APP4, 50012, DEST4A, 443, PKT_SYN, 9, 0, 0);
    pkt_wr16(p + 6, 0x2000);
    pkt_fill_ip4(p);
    ok("a fragment is refused as a fragment",
       feed(p, len) == TUN_STACK_ERR_CAPTURE &&
       strstr(tun_stack_last_error(stack), "fragment") != NULL);
    len = pkt_tcp6(p, APP6, 60010, DEST6, 443, PKT_SYN, 1, 0, 0, 1, 43);
    ok("a v6 routing header is refused",
       feed(p, len) == TUN_STACK_ERR_CAPTURE &&
       tun_stack_capture(stack)->dropped[TUN_NAT_DROP_EXTENSION] == 1);

    /* the table fills up to what lwip has pcbs for, and no further */
    size_t limit = tun_stack_capture(stack)->config.limit;
    size_t live = 0;
    for (size_t i = 0; i < limit; ++i)
        if (tun_nat_entry(tun_stack_capture(stack), i)->state != TUN_NAT_FREE) ++live;
    size_t filled = 0;
    for (uint16_t port = 51000; filled + live < limit; ++port, ++filled) {
        len = pkt_tcp4(p, APP4, port, DEST4A, 443, PKT_SYN, 1, 0, 0);
        if (feed(p, len) != TUN_STACK_OK) break;
    }
    len = pkt_tcp4(p, APP4, 52000, DEST4A, 443, PKT_SYN, 1, 0, 0);
    ok("one flow past the limit is refused as table full",
       feed(p, len) == TUN_STACK_ERR_CAPTURE &&
       tun_stack_capture(stack)->dropped[TUN_NAT_DROP_TABLE_FULL] == 1);

    /* flows nobody decided on expire, and the owner hears it */
    size_t closed_count = count_events(TUN_STACK_FLOW_CLOSED);
    /* the loop sleeps until the oldest held syn is due, not on a fixed beat */
    device.now += 4999;
    ok("held syns bound the loop's wait to their expiry",
       tun_stack_timer_wait_ms(stack) <= 1);
    device.now += 1001;
    tun_stack_run_timers(stack);
    ok("undecided flows expire and are reported closed",
       count_events(TUN_STACK_FLOW_CLOSED) == closed_count + filled);

    /* a blocked device parks whole frames and loses none of them */
    device_reset();
    device.block = 1;
    accept_on_request = 1;
    len = pkt_tcp4(p, APP4, 50020, DEST4A, 443, PKT_SYN, 300, 0, 0);
    feed(p, len);
    ok("a syn-ack for a blocked device is parked", stats->queue_packets == 1);
    device.block = 0;
    ok("a writable device drains the queue", tun_stack_on_writable(stack) == TUN_STACK_OK);
    check_syn_ack("parked syn-ack", DEST4A, 4, APP4, 50020, 300, NULL);
    ok("the queue is empty again", stats->queue_packets == 0 && stats->queue_bytes == 0);

    /* a short write and a failed descriptor are told apart */
    device_reset();
    device.short_write = 1;
    len = pkt_echo4(p, APP4, LOCAL4, 3);
    feed(p, len);
    ok("a short write is counted as one", stats->short_writes == 1 && stats->write_errors == 0);
    ok("the message says the frame was not sent in pieces",
       strstr(tun_stack_last_error(stack), "in pieces") != NULL);
    device_reset();
    device.fail_errno = EBADF;
    len = pkt_echo4(p, APP4, LOCAL4, 4);
    feed(p, len);
    ok("a failed descriptor is counted as one", stats->write_errors == 1);

    /* framing problems keep their own reasons */
    device_reset();
    uint8_t frame[TUN_STACK_FRAME_MAX];
    len = pkt_echo4(p, APP4, LOCAL4, 5);
    size_t frame_len = pkt_frame(frame, p, len);
    frame[3] = 77;
    ok("an unknown family is refused",
       tun_stack_input_frame(stack, frame, frame_len) == TUN_STACK_ERR_FRAME &&
       strstr(tun_stack_last_error(stack), "family") != NULL);
    ok("a frame larger than the mtu is refused",
       tun_stack_input_frame(stack, frame, 1505) == TUN_STACK_ERR_OVERSIZE);

    /* another thread may not touch the stack */
    frame_len = pkt_frame(frame, p, len);
    pthread_t other;
    void *result = NULL;
    pthread_create(&other, NULL, call_from_other_thread, frame);
    pthread_join(other, &result);
    ok("a call from another thread is refused",
       (tun_stack_status_t)(intptr_t)result == TUN_STACK_ERR_STATE);

    /* teardown with open flows and a full queue */
    device_reset();
    device.block = 1;
    len = pkt_tcp4(p, APP4, 50030, DEST4A, 443, PKT_SYN, 10, 0, 0);
    feed(p, len);
    len = pkt_tcp4(p, APP4, 50031, DEST4B, 443, PKT_SYN, 20, 0, 0);
    feed(p, len);
    ok("frames are pending before teardown", stats->queue_packets > 0);
    size_t requested_total = count_events(TUN_STACK_FLOW_REQUESTED);
    tun_stack_shutdown(stack);
    ok("every requested flow was closed for the owner",
       count_events(TUN_STACK_FLOW_CLOSED) == requested_total);
    ok("the queue is released", stats->queue_packets == 0 && stats->queue_bytes == 0);
    ok("the device is closed exactly once", device.closed == 1);
    len = pkt_echo4(p, APP4, LOCAL4, 6);
    frame_len = pkt_frame(frame, p, len);
    ok("frames after teardown are refused",
       tun_stack_input_frame(stack, frame, frame_len) == TUN_STACK_ERR_STATE);
    tun_stack_shutdown(stack);
    ok("a second teardown does not close the device again", device.closed == 1);

    /* the handle is freed while lwip keeps running its timers: nothing inside
       lwip may still point at it. then a new stack comes up on the same
       process-wide lwip and serves a flow from scratch */
    free(stack);
    sys_check_timeouts();
    stack = malloc(tun_stack_size());
    device_reset();
    config = config_for();
    ok("a second stack starts on the same lwip", tun_stack_init(stack, &config, &io) ==
       TUN_STACK_OK);
    accept_on_request = 1;
    len = pkt_tcp4(p, APP4, 50001, DEST4A, 443, PKT_SYN, 4242, 0, 0);
    ok("a flow with a tuple the old stack used works again", feed(p, len) == TUN_STACK_OK);
    check_syn_ack("after restart", DEST4A, 4, APP4, 50001, 4242, NULL);
    tun_stack_shutdown(stack);

    /* with nobody to serve flows, every syn is refused at once */
    device_reset();
    config = config_for();
    config.flow_event = NULL;
    tun_stack_init(stack, &config, &io);
    len = pkt_tcp4(p, APP4, 50040, DEST4A, 443, PKT_SYN, 1, 0, 0);
    feed(p, len);
    reset = last_packet(&len);
    ok("without an owner a syn gets a reset", reset && (reset[33] & PKT_RST));
    tun_stack_shutdown(stack);

    /* configurations that cannot work are refused before anything starts */
    config = config_for();
    config.mtu = 0;
    ok("an mtu of zero is refused", tun_stack_init(stack, &config, &io) == TUN_STACK_ERR_ARG);
    config = config_for();
    memcpy(config.synthetic4, LOCAL4, 4);
    ok("a synthetic peer equal to the stack address is refused",
       tun_stack_init(stack, &config, &io) == TUN_STACK_ERR_ARG);

    free(stack);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("all tun_stack checks passed");
    return 0;
}

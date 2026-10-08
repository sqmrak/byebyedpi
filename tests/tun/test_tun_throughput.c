/* byte-correct output, delayed app acks and fixed-pool exhaustion */
#include "tun_stack.h"
#include "packet_fixture.h"
#include "check.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t APP[4] = {198, 18, 0, 1};
static const uint8_t DEST[4] = {203, 0, 113, 7};
static tun_stack_t *stack;
static uint64_t latest_id;
static uint32_t latest_seq;
static uint8_t received[65536];
static size_t received_len;
static uint8_t expected[32768];
static size_t packets;

static tun_stack_write_t capture(void *ctx, const uint8_t *frame, size_t len, int *error) {
    (void)ctx;
    *error = 0;
    const uint8_t *p = frame + 4;
    len -= 4;
    CHECK(pkt_ip4_valid(p) && pkt_l4_valid(p, len));
    const uint8_t *t = p + pkt_l4(p, len);
    latest_seq = pkt_rd32(t + 4);
    size_t header = (t[12] >> 4) * 4;
    size_t payload = len - pkt_l4(p, len) - header;
    if (payload) {
        CHECK(received_len + payload <= sizeof received);
        if (received_len + payload <= sizeof received) {
            memcpy(received + received_len, t + header, payload);
            received_len += payload;
        }
        ++packets;
    }
    return TUN_STACK_WRITE_DONE;
}

static int64_t now_ms(void *ctx) { (void)ctx; return 1; }

static void event(void *ctx, tun_stack_flow_event_t type, uint64_t id, const tun_flow_key_t *key) {
    (void)ctx; (void)key;
    if (type == TUN_STACK_FLOW_REQUESTED) {
        latest_id = id;
        CHECK(tun_stack_flow_accept(stack, id) == TUN_STACK_OK);
    }
}

static void feed(uint16_t port, uint8_t flags, uint32_t seq, uint32_t ack) {
    uint8_t packet[128], frame[132];
    size_t len = pkt_tcp4(packet, APP, port, DEST, 443, flags, seq, ack, 0);
    pkt_wr16(packet + 34, 65535);
    pkt_fill_l4(packet, len, 16);
    len = pkt_frame(frame, packet, len);
    CHECK(tun_stack_input_frame(stack, frame, len) == TUN_STACK_OK);
}

static uint64_t open_flow(uint16_t port, uint32_t *seq) {
    feed(port, PKT_SYN, 1000, 0);
    *seq = latest_seq + 1;
    feed(port, PKT_ACK, 1001, *seq);
    return latest_id;
}

int main(void) {
    tun_stack_config_t config;
    tun_stack_io_t io;
    memset(&config, 0, sizeof config);
    memset(&io, 0, sizeof io);
    config.mtu = 1500;
    config.have_ipv4 = 1;
    memcpy(config.address4, (const uint8_t[]){198, 18, 0, 2}, 4);
    memcpy(config.synthetic4, (const uint8_t[]){198, 18, 0, 3}, 4);
    memset(config.netmask4, 255, 4);
    config.flow_event = event;
    io.write_frame = capture;
    io.now_ms = now_ms;
    stack = malloc(tun_stack_size());
    CHECK(stack && tun_stack_init(stack, &config, &io) == TUN_STACK_OK);
    if (!stack) return 1;
    for (size_t i = 0; i < sizeof expected; ++i) expected[i] = (uint8_t)(i * 31 + (i >> 8));
    uint32_t seq;
    uint64_t id = open_flow(50000, &seq);
    size_t accepted = 0;
    CHECK(tun_stack_flow_write(stack, id, expected, 5, &accepted) == TUN_STACK_OK && accepted == 5);
    CHECK(tun_stack_flow_write(stack, id, expected + 5, 7, &accepted) == TUN_STACK_OK && accepted == 7);
    CHECK(packets == 2 && received_len == 12 && memcmp(received, expected, 12) == 0);
    feed(50000, PKT_ACK, 1001, seq + 12);
    CHECK(tun_stack_flow_abort(stack, id) == TUN_STACK_OK);

    packets = received_len = 0;
    id = open_flow(50001, &seq);
    CHECK(tun_stack_flow_write(stack, id, expected, 16000, &accepted) == TUN_STACK_OK);
    CHECK(accepted == 16000);
    size_t queued = accepted;
    size_t batches = 0;
    while (received_len < queued && batches < 100) {
        feed(50001, PKT_ACK, 1001, seq + (uint32_t)received_len);
        ++batches;
    }
    CHECK(received_len == queued && memcmp(received, expected, queued) == 0);
    printf("local tcp: %zu bytes queued before app ack, %zu ack batches, %zu packets\n",
           queued, batches, packets);
    CHECK(tun_stack_flow_abort(stack, id) == TUN_STACK_OK);

    /* all flows share the fixed heap and segments. an exhausted pool must
       accept no bytes, then recover after another flow releases its queue */
    uint64_t ids[12];
    size_t blocked = 12;
    for (size_t i = 0; i < 12; ++i) {
        ids[i] = open_flow((uint16_t)(50100 + i), &seq);
        CHECK(tun_stack_flow_write(stack, ids[i], expected, 16000, &accepted) == TUN_STACK_OK);
        if (!accepted && blocked == 12) blocked = i;
    }
    CHECK(blocked < 12);
    for (size_t i = 0; i < 12; ++i)
        if (i != blocked) CHECK(tun_stack_flow_abort(stack, ids[i]) == TUN_STACK_OK);
    if (blocked < 12) {
        CHECK(tun_stack_flow_write(stack, ids[blocked], expected, 16000, &accepted) == TUN_STACK_OK);
        CHECK(accepted == 16000);
        CHECK(tun_stack_flow_abort(stack, ids[blocked]) == TUN_STACK_OK);
    }
    tun_stack_shutdown(stack);
    free(stack);
    if (!failed) puts("test_tun_throughput ok");
    return failed;
}

/* real desync plans and relay state, with a pbuf-sized input and captured sends */
#define _DEFAULT_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "bye_tcp.h"
#include "bye_sniff.h"
#include "check.h"
#include "hello_openssl.inc"
#include "hello_fixture.h"

struct tun_stack {
    uint8_t input[20000];
    size_t len;
    size_t off;
    size_t piece;
    int eof;
};

static uint8_t wire[20000];
static size_t wire_len;
static size_t send_limit;
static int send_block;
static size_t app_room;

static ssize_t capture_send(int fd, const void *data, size_t len, int flags) {
    (void)fd;
    CHECK(flags == 0);
    if (send_block) { errno = EAGAIN; return -1; }
    if (send_limit && len > send_limit) len = send_limit;
    CHECK(len <= sizeof wire - wire_len);
    if (len > sizeof wire - wire_len) { errno = ENOBUFS; return -1; }
    memcpy(wire + wire_len, data, len);
    wire_len += len;
    return (ssize_t)len;
}

#define send capture_send
#include "../daemon/bye_tcp.c"
#undef send

tun_stack_status_t tun_stack_flow_peek(tun_stack_t *stack, uint64_t id,
                                       const uint8_t **data, size_t *len, int *eof) {
    (void)id;
    *data = stack->input + stack->off;
    *len = stack->len - stack->off;
    if (*len > stack->piece) *len = stack->piece;
    *eof = !*len && stack->eof;
    return TUN_STACK_OK;
}

tun_stack_status_t tun_stack_flow_consume(tun_stack_t *stack, uint64_t id, size_t len) {
    (void)id;
    CHECK(len <= stack->len - stack->off);
    stack->off += len;
    return TUN_STACK_OK;
}

tun_stack_status_t tun_stack_flow_abort(tun_stack_t *stack, uint64_t id) {
    (void)stack; (void)id;
    return TUN_STACK_OK;
}

tun_stack_status_t tun_stack_flow_reject(tun_stack_t *stack, uint64_t id) {
    (void)stack; (void)id;
    return TUN_STACK_OK;
}

size_t tun_stack_flow_writable(tun_stack_t *stack, uint64_t id) {
    (void)stack; (void)id;
    return app_room;
}

static struct bye_tcp tcp;
static struct tun_stack input;
static relay_t relay;

static void reset(const char *spec, size_t piece) {
    release(&tcp, &relay);
    memset(&tcp, 0, sizeof tcp);
    memset(&input, 0, sizeof input);
    input.piece = piece;
    tcp.stack = &input;
    CHECK(bye_strategies_parse(spec, &tcp.config.strategies, NULL, 0) == BYE_DESYNC_OK);
    memset(&relay, 0, sizeof relay);
    relay.fd = -1;
    relay.state = R_RUNNING;
    relay.accepted = 1;
    relay.dest_len = 4;
    relay.dest_port = 443;
    memcpy(relay.dest, (const uint8_t[]){203, 0, 113, 8}, 4);
    wire_len = send_limit = send_block = 0;
}


static void check_plan(const bye_desync_t *strategy, size_t len) {
    uint8_t expected[20000];
    bye_plan_t plan;
    CHECK(bye_desync_build(strategy, input.input, len, expected, sizeof expected, &plan) == BYE_DESYNC_OK);
    CHECK(wire_len == plan.total);
    CHECK(wire_len == plan.total && memcmp(wire, expected, wire_len) == 0);
}

int main(void) {
    relay.fd = -1;
    const size_t padding[] = {0, 6000, 16384 - (sizeof hello_openssl - 5) - 4};
    for (size_t i = 0; i < sizeof padding / sizeof padding[0]; ++i) {
        reset("auto", 1300);
        size_t len = padded_hello(input.input, sizeof input.input, padding[i]);
        input.len = 2;
        CHECK(first_payload(&tcp, &relay) == 1 && wire_len == 0);
        input.len = len;
        CHECK(first_payload(&tcp, &relay) == 0 && relay.first_done && relay.probing);
        CHECK(input.off == len && relay.replay_len == len && tcp.stats.bytes_up == len);
        check_plan(&tcp.config.strategies.item[0], len);
        CHECK(relay.replay && relay.replay_len == len && memcmp(relay.replay, input.input, len) == 0);
        wire_len = 0;
        relay.first_done = 0;
        relay.probe_replay = 1;
        CHECK(first_payload(&tcp, &relay) == 0 && tcp.stats.bytes_up == len);
        check_plan(&tcp.config.strategies.item[0], len);
    }

    reset("auto", 1300);
    memcpy(input.input, hello_openssl, hello_openssl_len);
    input.len = hello_openssl_len;
    bye_sniff_t name;
    CHECK(bye_sniff_tls(input.input, input.len, &name) == BYE_SNIFF_OK);
    relay_t previous;
    memset(&previous, 0, sizeof previous);
    memcpy(previous.name, input.input + name.name_off, name.name_len);
    hint_store(&tcp, &previous, 1);
    CHECK(first_payload(&tcp, &relay) == 0 && relay.strategy == 1);
    check_plan(&tcp.config.strategies.item[1], input.len);

    reset("auto", 1300);
    const char *long_name = "rr4---sn-abcdefghijklmnopqrstuvwxyz-abcdefghijklmnopqrstuvwxyz.googlevideo.com";
    input.len = named_hello(input.input, sizeof input.input, long_name);
    CHECK(input.len > 0);
    memset(&previous, 0, sizeof previous);
    strcpy(previous.name, "rr1---sn-other.googlevideo.com");
    hint_store(&tcp, &previous, 1);
    CHECK(first_payload(&tcp, &relay) == 0 && relay.strategy == 1);
    CHECK(strcmp(relay.name, long_name) == 0 && !alt_possible(&relay));
    check_plan(&tcp.config.strategies.item[1], input.len);

    reset(BYE_DESYNC_DEFAULT_SPEC, 7);
    memcpy(input.input, hello_openssl, hello_openssl_len);
    input.len = hello_openssl_len;
    send_block = 1;
    CHECK(first_payload(&tcp, &relay) == 0 && relay.pending_len > 0 && !relay.replay);
    send_block = 0;
    send_limit = 13;
    CHECK(flush_pending(&tcp, &relay) == 0 && !relay.pending);
    check_plan(&tcp.config.strategies.item[0], input.len);

    reset("auto", 1);
    memcpy(input.input, hello_openssl, 2);
    input.len = 2;
    CHECK(first_payload(&tcp, &relay) == 1 && wire_len == 0);
    relay.first_since_ms = senko_now_ms() - FIRST_WAIT_MS;
    CHECK(first_payload(&tcp, &relay) == 0 && wire_len == 2 && !relay.replay && !relay.probing);
    CHECK(memcmp(wire, input.input, 2) == 0);

    reset("auto", 7);
    memcpy(input.input, hello_openssl, 4);
    input.len = 4;
    input.eof = 1;
    CHECK(first_payload(&tcp, &relay) == 0 && wire_len == 4 && !relay.replay);
    CHECK(memcmp(wire, input.input, 4) == 0);

    reset("auto", 1300);
    memcpy(input.input, hello_openssl, hello_openssl_len);
    input.len = hello_openssl_len;
    char error[128];
    tcp.config.hosts = bye_hosts_parse("other.example\n", 14, error, sizeof error);
    CHECK(tcp.config.hosts != NULL);
    tcp.config.hosts_only = 1;
    CHECK(first_payload(&tcp, &relay) == 0 && !relay.probing && !relay.replay);
    CHECK(wire_len == input.len && memcmp(wire, input.input, wire_len) == 0);
    CHECK(tcp.stats.hosts_skipped == 1);
    bye_hosts_free((bye_hosts_t *)tcp.config.hosts);
    tcp.relays[0] = relay;
    tcp.relays[0].fd = 7;
    fd_set readable, writable;
    FD_ZERO(&readable); FD_ZERO(&writable);
    int highest = 0;
    uint32_t wait = 1000;
    app_room = 0;
    on_prepare(&tcp, &readable, &writable, &highest, &wait);
    CHECK(!FD_ISSET(7, &readable));
    app_room = 1;
    on_prepare(&tcp, &readable, &writable, &highest, &wait);
    CHECK(FD_ISSET(7, &readable));
    memset(&tcp.relays[0], 0, sizeof tcp.relays[0]);
    release(&tcp, &relay);
    if (!failed) puts("test_tcp_first ok");
    return failed;
}

/* MSG_DONTWAIT and poll sit behind the default feature set under -std=c99 */
#define _DEFAULT_SOURCE

/* the owning thread end to end, through the same descriptor calls the device
   uses: one end of an AF_UNIX datagram socketpair stands in for the utun
   descriptor, the loop runs on its own thread, and this test plays the kernel
   and the apps from the other end */

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "lwip/timeouts.h"
#include "packet_fixture.h"
#include "tun_loop.h"

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

static const uint8_t APP4[4]   = { 198, 18, 0, 1 };
static const uint8_t LOCAL4[4] = { 198, 18, 0, 2 };
static const uint8_t SYNTH4[4] = { 198, 18, 0, 3 };
static const uint8_t DEST4[4]  = { 203, 0, 113, 7 };
static const uint8_t APP6[16]   = { 0xfd, 0, 0x5e, 0x4b, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
static const uint8_t LOCAL6[16] = { 0xfd, 0, 0x5e, 0x4b, 0,0,0,0, 0,0,0,0, 0,0,0,2 };
static const uint8_t SYNTH6[16] = { 0xfd, 0, 0x5e, 0x4b, 0,0,0,0, 0,0,0,0, 0,0,0,3 };
static const uint8_t DEST6[16]  = { 0x20, 0x01, 0x0d, 0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,7 };

#define GENERATION 41

typedef struct {
    tun_loop_t       *loop;
    utun_device_t     device;
    int               peer; /* the test's end: the kernel and the apps */
    pthread_t         thread;
    tun_loop_result_t result;
    tun_loop_status_t status;
} fixture_t;

/* written on the loop thread, read by the test after the loop has ended or
   under the lock */
static pthread_mutex_t seen_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t command_thread;
static uint64_t command_argument;
static size_t flows_requested;
static size_t flows_closed;
static fixture_t *current;
static int failed_owner_stopped;
static int ready_count;
static int retain_device;

static void on_ready(void *ctx) {
    (void)ctx;
    pthread_mutex_lock(&seen_lock);
    ++ready_count;
    pthread_mutex_unlock(&seen_lock);
}

static int fail_owner_start(void *ctx, tun_stack_t *stack,
                            char *error, size_t error_cap) {
    (void)ctx;
    (void)stack;
    snprintf(error, error_cap, "the server pool has no worker threads");
    return -1;
}

static void failed_owner_stop(void *ctx) {
    (void)ctx;
    ++failed_owner_stopped;
}

static void on_flow(void *ctx, tun_stack_flow_event_t event, uint64_t id,
                    const tun_flow_key_t *key) {
    (void)ctx;
    (void)key;
    pthread_mutex_lock(&seen_lock);
    if (event == TUN_STACK_FLOW_REQUESTED) ++flows_requested;
    if (event == TUN_STACK_FLOW_CLOSED) ++flows_closed;
    pthread_mutex_unlock(&seen_lock);
    /* the owner decides on the loop thread, as the transport bridge will */
    if (event == TUN_STACK_FLOW_REQUESTED)
        tun_stack_flow_accept(tun_loop_stack(current->loop), id);
}

static void on_command(void *ctx, tun_stack_t *stack, const tun_loop_command_t *command) {
    (void)ctx;
    (void)stack;
    pthread_mutex_lock(&seen_lock);
    command_thread = pthread_self();
    command_argument = command->argument;
    pthread_mutex_unlock(&seen_lock);
}

static void *run_loop(void *arg) {
    fixture_t *f = arg;
    f->status = tun_loop_run(f->loop, &f->result);
    return NULL;
}

static tun_loop_config_t loop_config(size_t capacity) {
    tun_loop_config_t c;
    memset(&c, 0, sizeof c);
    c.generation = GENERATION;
    c.command_capacity = capacity;
    c.on_command = on_command;
    c.on_ready = on_ready;
    c.retain_device_until_destroy = retain_device;
    tun_stack_config_t *s = &c.stack;
    snprintf(s->ifname, sizeof s->ifname, "utun9");
    s->mtu = 1500;
    s->have_ipv4 = 1;
    memcpy(s->address4, LOCAL4, 4);
    memcpy(s->synthetic4, SYNTH4, 4);
    s->netmask4[0] = s->netmask4[1] = s->netmask4[2] = s->netmask4[3] = 255;
    s->have_ipv6 = 1;
    memcpy(s->address6, LOCAL6, 16);
    memcpy(s->synthetic6, SYNTH6, 16);
    s->queue_max_packets = 8;
    s->flow_event = on_flow;
    return c;
}

/* start a loop on a fresh socketpair. sndbuf shrinks the loop's send buffer
   so a test can make the device refuse writes */
static int fixture_start_with_owner(fixture_t *f, int type, int sndbuf,
                                    size_t capacity, int start_thread,
                                    int fail_owner) {
    memset(f, 0, sizeof *f);
    int fds[2];
    if (socketpair(AF_UNIX, type, 0, fds) != 0) return -1;
    if (sndbuf) setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf);
    f->peer = fds[1];
    utun_device_init(&f->device);
    if (utun_device_adopt(&f->device, fds[0], "utun9") != UTUN_DEVICE_OK) return -1;
    f->loop = malloc(tun_loop_size());
    tun_loop_config_t config = loop_config(capacity);
    if (fail_owner) {
        config.hooks.start = fail_owner_start;
        config.hooks.stop = failed_owner_stop;
    }
    if (tun_loop_init(f->loop, &config, &f->device) != TUN_LOOP_OK) return -1;
    current = f;
    if (start_thread) pthread_create(&f->thread, NULL, run_loop, f);
    return 0;
}

static int fixture_start(fixture_t *f, int type, int sndbuf, size_t capacity,
                         int start_thread) {
    return fixture_start_with_owner(f, type, sndbuf, capacity, start_thread, 0);
}

static tun_loop_status_t post(fixture_t *f, int type, uint64_t generation, uint64_t arg) {
    tun_loop_command_t command;
    command.type = type;
    command.generation = generation;
    command.argument = arg;
    return tun_loop_post(f->loop, &command);
}

static void fixture_stop(fixture_t *f) {
    post(f, TUN_LOOP_CMD_STOP, GENERATION, 0);
    pthread_join(f->thread, NULL);
}

static void fixture_free(fixture_t *f) {
    tun_loop_destroy(f->loop);
    free(f->loop);
    f->loop = NULL;
    close(f->peer);
}

static void send_packet(fixture_t *f, const uint8_t *packet, size_t len) {
    uint8_t frame[TUN_STACK_FRAME_MAX];
    size_t frame_len = pkt_frame(frame, packet, len);
    ssize_t sent = send(f->peer, frame, frame_len, 0);
    (void)sent;
}

/* the next frame the loop wrote, or 0 when none came within wait_ms */
static size_t receive_frame(fixture_t *f, uint8_t *frame, size_t cap, int wait_ms) {
    struct pollfd pfd = { f->peer, POLLIN, 0 };
    if (poll(&pfd, 1, wait_ms) <= 0) return 0;
    ssize_t got = recv(f->peer, frame, cap, 0);
    return got > 0 ? (size_t)got : 0;
}

int main(void) {
    fixture_t f;
    uint8_t p[256], frame[TUN_STACK_FRAME_MAX];
    size_t len;

    /* ---- ping in, answer out, with the right family header ---- */
    ok("a loop starts on a socketpair", fixture_start(&f, SOCK_DGRAM, 0, 0, 1) == 0);
    len = pkt_echo4(p, APP4, LOCAL4, 1);
    send_packet(&f, p, len);
    size_t got = receive_frame(&f, frame, sizeof frame, 2000);
    ok("a v4 ping is answered through the descriptor", got == 4 + 28 && frame[24] == 0);
    ok("the v4 answer carries the inet family header",
       got >= 4 && frame[0] == 0 && frame[1] == 0 && frame[2] == 0 && frame[3] == 2);
    uint64_t bytes_in = 0, bytes_out = 0;
    tun_loop_byte_counts(f.loop, &bytes_in, &bytes_out);
    ok("packet counters are available to the control thread",
       bytes_in >= 4 + len && bytes_out >= got);

    len = pkt_echo6(p, APP6, LOCAL6, 2);
    send_packet(&f, p, len);
    got = receive_frame(&f, frame, sizeof frame, 2000);
    ok("a v6 ping is answered through the descriptor", got == 4 + 48 && frame[44] == 129);
    ok("the v6 answer carries the darwin inet6 family header",
       got >= 4 && frame[0] == 0 && frame[1] == 0 && frame[2] == 0 && frame[3] == 30);

    /* ---- a captured connection, decided on the loop thread ---- */
    len = pkt_tcp4(p, APP4, 50001, DEST4, 443, PKT_SYN, 1000, 0, 0);
    send_packet(&f, p, len);
    got = receive_frame(&f, frame, sizeof frame, 2000);
    const uint8_t *answer = frame + 4;
    ok("a syn to the internet is answered through the loop",
       got == 4 + 44 && answer[33] == (PKT_SYN | PKT_ACK));
    ok("the answer comes from the original destination",
       got && memcmp(answer + 12, DEST4, 4) == 0 && pkt_rd16(answer + 20) == 443);

    len = pkt_tcp6(p, APP6, 60001, DEST6, 443, PKT_SYN, 5, 0, 0, 0, 0);
    send_packet(&f, p, len);
    got = receive_frame(&f, frame, sizeof frame, 2000);
    ok("a v6 syn is answered from its original destination",
       got && frame[3] == 30 && memcmp(frame + 4 + 8, DEST6, 16) == 0);

    /* ---- commands from another thread run on the loop thread ---- */
    ok("a command for this run is taken", post(&f, TUN_LOOP_CMD_OWNER, GENERATION, 77) ==
       TUN_LOOP_OK);
    ok("a command for another run is refused",
       post(&f, TUN_LOOP_CMD_OWNER, GENERATION + 1, 78) == TUN_LOOP_ERR_STALE);
    for (int i = 0; i < 200; ++i) {
        pthread_mutex_lock(&seen_lock);
        uint64_t seen = command_argument;
        pthread_mutex_unlock(&seen_lock);
        if (seen == 77) break;
        struct pollfd none = { -1, 0, 0 };
        poll(&none, 0, 5);
    }
    pthread_mutex_lock(&seen_lock);
    ok("the command ran", command_argument == 77);
    ok("the command ran on the loop thread", pthread_equal(command_thread, f.thread));
    pthread_mutex_unlock(&seen_lock);

    fixture_stop(&f);
    ok("the loop ended because it was told to", f.status == TUN_LOOP_OK &&
       f.result.end == TUN_LOOP_ENDED_STOP);
    ok("ready was reported after stack startup", ready_count == 1);
    ok("the end is explained", strstr(f.result.message, "asked to") != NULL);
    ok("every requested flow was closed at stop", flows_requested == flows_closed &&
       flows_requested == 2);
    ok("commands after the end are refused",
       post(&f, TUN_LOOP_CMD_OWNER, GENERATION, 1) == TUN_LOOP_ERR_STOPPED);
    ok("the device was closed", f.device.fd == -1);
    fixture_free(&f);

    retain_device = 1;
    ok("a route-owned device loop starts",
       fixture_start(&f, SOCK_DGRAM, 0, 0, 1) == 0);
    fixture_stop(&f);
    ok("the route owner still has the interface after the packet loop exits",
       f.device.fd >= 0);
    fixture_free(&f);
    ok("the route-owned device closes at destroy", f.device.fd == -1);
    retain_device = 0;

    /* a failed owner cannot leave an idle but apparently running tunnel */
    ok("a loop is set up for a failed owner",
       fixture_start_with_owner(&f, SOCK_DGRAM, 0, 0, 0, 1) == 0);
    failed_owner_stopped = 0;
    f.status = tun_loop_run(f.loop, &f.result);
    ok("owner startup failure is returned", f.status == TUN_LOOP_ERR_OWNER &&
       f.result.end == TUN_LOOP_ENDED_START_FAILED);
    ok("failed owner never reported ready", ready_count == 2);
    ok("owner startup reason survives", strstr(f.result.message,
       "no worker threads") != NULL);
    ok("partial owner startup is cleaned up", failed_owner_stopped == 1 &&
       f.device.fd == -1);
    fixture_free(&f);

    /* ---- a busy device: blocked writes are parked and none of the parked
       frames is lost ---- */
    ok("a loop starts with a small send buffer",
       fixture_start(&f, SOCK_DGRAM, 1, 0, 1) == 0);
    for (uint16_t i = 0; i < 24; ++i) {
        len = pkt_echo4(p, APP4, LOCAL4, (uint16_t)(100 + i));
        send_packet(&f, p, len);
    }
    /* let the loop hit the full buffer before anything is read */
    struct pollfd none = { -1, 0, 0 };
    poll(&none, 0, 200);
    size_t received = 0;
    while (receive_frame(&f, frame, sizeof frame, 300)) ++received;
    fixture_stop(&f);
    const tun_stack_stats_t *stats = tun_stack_stats(tun_loop_stack(f.loop));
    ok("the device refused writes at some point", stats->queued > 0);
    ok("every frame the stack wrote arrived", received == stats->frames_out);
    ok("nothing parked was lost or expired", stats->queue_expired == 0 &&
       stats->write_errors == 0 && stats->short_writes == 0);
    fixture_free(&f);

    /* ---- stop while frames are parked and flows are open ---- */
    flows_requested = flows_closed = 0;
    ok("a loop starts for the stop test", fixture_start(&f, SOCK_DGRAM, 1, 0, 1) == 0);
    for (uint16_t i = 0; i < 16; ++i) {
        len = pkt_tcp4(p, APP4, (uint16_t)(51000 + i), DEST4, 443, PKT_SYN, 1, 0, 0);
        send_packet(&f, p, len);
    }
    poll(&none, 0, 200);
    fixture_stop(&f);
    stats = tun_stack_stats(tun_loop_stack(f.loop));
    ok("frames were parked when the stop came", stats->queued > 0);
    ok("the parked frames were released", stats->queue_packets == 0);
    ok("every flow was closed at stop", flows_requested == flows_closed && flows_requested > 0);
    ok("the device is closed", f.device.fd == -1);
    errno = 0;
    ok("the other end sees the descriptor gone",
       send(f.peer, "x", 1, MSG_DONTWAIT) < 0 && errno == ECONNREFUSED);
    fixture_free(&f);
    /* nothing inside lwip may still point at the freed loop */
    sys_check_timeouts();

    /* ---- a fresh loop on the same process-wide lwip works from scratch ---- */
    ok("a new loop starts after the old one was freed",
       fixture_start(&f, SOCK_DGRAM, 0, 0, 1) == 0);
    len = pkt_tcp4(p, APP4, 51000, DEST4, 443, PKT_SYN, 9, 0, 0);
    send_packet(&f, p, len);
    got = receive_frame(&f, frame, sizeof frame, 2000);
    ok("a tuple the old loop used is served again", got && frame[4 + 33] == (PKT_SYN | PKT_ACK));
    fixture_stop(&f);
    ok("a second stop is harmless", post(&f, TUN_LOOP_CMD_STOP, GENERATION, 0) ==
       TUN_LOOP_ERR_STOPPED);
    tun_loop_destroy(f.loop);
    fixture_free(&f); /* destroys a second time */

    /* ---- the command queue is bounded, and fills before the loop runs ---- */
    ok("a loop is set up without running", fixture_start(&f, SOCK_DGRAM, 0, 2, 0) == 0);
    ok("first command queued", post(&f, TUN_LOOP_CMD_OWNER, GENERATION, 1) == TUN_LOOP_OK);
    ok("second command queued", post(&f, TUN_LOOP_CMD_OWNER, GENERATION, 2) == TUN_LOOP_OK);
    ok("a third is refused, the queue is full",
       post(&f, TUN_LOOP_CMD_OWNER, GENERATION, 3) == TUN_LOOP_ERR_FULL);
    tun_loop_request_stop(f.loop);
    f.status = tun_loop_run(f.loop, &f.result);
    ok("stop bypasses a full command queue",
       f.status == TUN_LOOP_OK && f.result.end == TUN_LOOP_ENDED_STOP &&
       f.result.commands_dropped == 2);
    tun_loop_destroy(f.loop);
    ok("the stopped loop closes its device", f.device.fd == -1);
    fixture_free(&f);

    /* ---- the other end going away ends the loop and says why ---- */
    ok("a loop starts on a seqpacket pair", fixture_start(&f, SOCK_SEQPACKET, 0, 0, 1) == 0);
    close(f.peer);
    f.peer = -1;
    pthread_join(f.thread, NULL);
    ok("the loop ends when the other end goes away",
       f.result.end == TUN_LOOP_ENDED_DEVICE_EOF &&
       strstr(f.result.message, "other side") != NULL);
    tun_loop_destroy(f.loop);
    free(f.loop);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("all tun_loop checks passed");
    return 0;
}

#include "bye_fakesend.h"

#include "bye_fake.h"
#include "bye_tcp.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef __APPLE__

bye_fakesend_t *bye_fakesend_start(const char *ifname, char *reason, size_t reason_cap) {
    (void)ifname;
    snprintf(reason, reason_cap, "fake packets need bpf and raw sockets of darwin");
    return NULL;
}

void bye_fakesend_stop(bye_fakesend_t *fake) {
    (void)fake;
}

int bye_fakesend_send(void *ctx, int fd, uint32_t offset, const uint8_t *payload, size_t len,
                      uint8_t ttl, int md5sig) {
    (void)ctx; (void)fd; (void)offset; (void)payload; (void)len; (void)ttl; (void)md5sig;
    return BYE_FAKE_SEND_OFF;
}

#else

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>

/* the sdk ships no net/bpf.h. these are the numbers and layouts of xnu's, which
   have not changed since ios 2 */
typedef struct {
    uint16_t code;
    uint8_t  jt, jf;
    uint32_t k;
} bpf_insn_t;

typedef struct {
    unsigned    len;
    bpf_insn_t *insns;
} bpf_program_t;

/* the header of a record is 18 bytes (a timestamp of two int32, two lengths, the header length);
   a struct of those fields would be padded to 20, so the fields are read at their offsets */
#define BPF_HDR_SIZE 18u

#define BYE_BIOCGBLEN     _IOR('B', 102, unsigned)
#define BYE_BIOCSBLEN     _IOWR('B', 102, unsigned)
#define BYE_BIOCSETF      _IOW('B', 103, bpf_program_t)
#define BYE_BIOCGDLT      _IOR('B', 106, unsigned)
#define BYE_BIOCSETIF     _IOW('B', 108, struct ifreq)
#define BYE_BIOCIMMEDIATE _IOW('B', 112, unsigned)
#define BYE_BIOCSSEESENT  _IOW('B', 119, unsigned)

#ifndef IP_BOUND_IF
#define IP_BOUND_IF 25
#endif

#define BPF_BUFFER 32768u
#define BPF_DEVICES 100

struct bye_fakesend {
    int             bpf;
    int             raw;
    int             stop_pipe[2];
    unsigned        link;
    unsigned        blen;   /* the buffer the kernel gave: a read of any other size is refused */
    pthread_t       thread;
    int             running;
    pthread_mutex_t lock;
    bye_fake_track_t track;
    uint16_t        next_id;
};

static int open_bpf(void) {
    char path[32];
    for (int i = 0; i < BPF_DEVICES; ++i) {
        snprintf(path, sizeof path, "/dev/bpf%d", i);
        int fd = open(path, O_RDONLY);
        if (fd >= 0) return fd;
        /* a busy device is taken by another capture, the next one is free */
        if (errno != EBUSY) return -1;
    }
    return -1;
}

static void take_records(bye_fakesend_t *fake, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off + BPF_HDR_SIZE <= len) {
        uint32_t caplen;
        uint16_t hdrlen;
        memcpy(&caplen, buf + off + 8, sizeof caplen);
        memcpy(&hdrlen, buf + off + 16, sizeof hdrlen);
        if (hdrlen < BPF_HDR_SIZE || off + hdrlen + caplen > len) return;
        bye_fake_syn_t syn;
        if (bye_fake_syn_parse(fake->link, buf + off + hdrlen, caplen, &syn)) {
            pthread_mutex_lock(&fake->lock);
            bye_fake_track_note(&fake->track, &syn);
            pthread_mutex_unlock(&fake->lock);
        }
        /* each record starts on a 4 byte boundary */
        off += ((size_t)hdrlen + caplen + 3u) & ~(size_t)3u;
    }
}

static void *watch(void *arg) {
    bye_fakesend_t *fake = arg;
    uint8_t *buf = malloc(fake->blen);
    if (!buf) return NULL;
    for (;;) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fake->bpf, &fds);
        FD_SET(fake->stop_pipe[0], &fds);
        int top = fake->bpf > fake->stop_pipe[0] ? fake->bpf : fake->stop_pipe[0];
        int ready = select(top + 1, &fds, NULL, NULL, NULL);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || FD_ISSET(fake->stop_pipe[0], &fds)) break;
        ssize_t got = read(fake->bpf, buf, fake->blen);
        if (got < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        /* the interface went away: the next fake finds no syn and says so */
        if (got <= 0) {
            fprintf(stderr, "byedpid: the bpf watcher stopped (read %zd, errno %d %s)\n", got, errno, strerror(errno));
            break;
        }
        take_records(fake, buf, (size_t)got);
    }
    free(buf);
    return NULL;
}

bye_fakesend_t *bye_fakesend_start(const char *ifname, char *reason, size_t reason_cap) {
    if (reason && reason_cap) reason[0] = '\0';
    if (!ifname || !reason || !reason_cap) return NULL;
    bye_fakesend_t *fake = calloc(1, sizeof *fake);
    if (!fake) {
        snprintf(reason, reason_cap, "not enough memory");
        return NULL;
    }
    fake->bpf = fake->raw = fake->stop_pipe[0] = fake->stop_pipe[1] = -1;
    pthread_mutex_init(&fake->lock, NULL);
    bye_fake_track_init(&fake->track);
    unsigned index = if_nametoindex(ifname);
    if (index == 0) {
        snprintf(reason, reason_cap, "no interface %.20s", ifname);
        goto failed;
    }
    fake->bpf = open_bpf();
    if (fake->bpf < 0) {
        snprintf(reason, reason_cap, "cannot open a bpf device (errno %d %s)", errno, strerror(errno));
        goto failed;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", ifname);
    unsigned blen = BPF_BUFFER, on = 1;
    bpf_insn_t program[BYE_BPF_FILTER_MAX];
    /* the buffer size has to be set before the interface is attached */
    if (ioctl(fake->bpf, BYE_BIOCSBLEN, &blen) != 0 || ioctl(fake->bpf, BYE_BIOCSETIF, &ifr) != 0 ||
        ioctl(fake->bpf, BYE_BIOCGDLT, &fake->link) != 0 || ioctl(fake->bpf, BYE_BIOCGBLEN, &blen) != 0 ||
        ioctl(fake->bpf, BYE_BIOCIMMEDIATE, &on) != 0 || ioctl(fake->bpf, BYE_BIOCSSEESENT, &on) != 0) {
        snprintf(reason, reason_cap, "bpf refused %.20s (errno %d %s)", ifname, errno, strerror(errno));
        goto failed;
    }
    fake->blen = blen;
    bye_bpf_insn_t filter[BYE_BPF_FILTER_MAX];
    size_t count = bye_fake_bpf_filter(fake->link, filter, BYE_BPF_FILTER_MAX);
    if (count == 0) {
        snprintf(reason, reason_cap, "%.20s has link type %u, which the watcher does not read",
                 ifname, fake->link);
        goto failed;
    }
    for (size_t i = 0; i < count; ++i) {
        program[i].code = filter[i].code;
        program[i].jt = filter[i].jt;
        program[i].jf = filter[i].jf;
        program[i].k = filter[i].k;
    }
    bpf_program_t prog = { (unsigned)count, program };
    if (ioctl(fake->bpf, BYE_BIOCSETF, &prog) != 0) {
        snprintf(reason, reason_cap, "bpf refused its filter (errno %d %s)", errno, strerror(errno));
        goto failed;
    }
    fake->raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int one = 1;
    int bound = (int)index;
    if (fake->raw < 0 || setsockopt(fake->raw, IPPROTO_IP, IP_HDRINCL, &one, sizeof one) != 0 ||
        setsockopt(fake->raw, IPPROTO_IP, IP_BOUND_IF, &bound, sizeof bound) != 0) {
        snprintf(reason, reason_cap, "cannot open a raw socket on %.20s (errno %d %s)", ifname, errno,
                 strerror(errno));
        goto failed;
    }
    if (pipe(fake->stop_pipe) != 0) {
        snprintf(reason, reason_cap, "cannot make a pipe (errno %d)", errno);
        goto failed;
    }
    if (pthread_create(&fake->thread, NULL, watch, fake) != 0) {
        snprintf(reason, reason_cap, "cannot start the watcher thread");
        goto failed;
    }
    fake->running = 1;
    return fake;
failed:
    bye_fakesend_stop(fake);
    return NULL;
}

void bye_fakesend_stop(bye_fakesend_t *fake) {
    if (!fake) return;
    if (fake->running) {
        char byte = 0;
        ssize_t ignored = write(fake->stop_pipe[1], &byte, 1);
        (void)ignored;
        pthread_join(fake->thread, NULL);
    }
    if (fake->bpf >= 0) close(fake->bpf);
    if (fake->raw >= 0) close(fake->raw);
    if (fake->stop_pipe[0] >= 0) close(fake->stop_pipe[0]);
    if (fake->stop_pipe[1] >= 0) close(fake->stop_pipe[1]);
    pthread_mutex_destroy(&fake->lock);
    free(fake);
}

int bye_fakesend_send(void *ctx, int fd, uint32_t offset, const uint8_t *payload, size_t len,
                      uint8_t ttl, int md5sig) {
    bye_fakesend_t *fake = ctx;
    if (!fake || !payload) return BYE_FAKE_SEND_OFF;
    struct sockaddr_in local, remote;
    socklen_t local_len = sizeof local, remote_len = sizeof remote;
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) != 0 ||
        getpeername(fd, (struct sockaddr *)&remote, &remote_len) != 0 ||
        local.sin_family != AF_INET || remote.sin_family != AF_INET)
        return BYE_FAKE_SEND_OFF;
    bye_fake_packet_t packet;
    memset(&packet, 0, sizeof packet);
    memcpy(packet.src, &local.sin_addr, 4);
    memcpy(packet.dst, &remote.sin_addr, 4);
    packet.sport = ntohs(local.sin_port);
    packet.dport = ntohs(remote.sin_port);
    uint32_t isn, sisn;
    pthread_mutex_lock(&fake->lock);
    int known = bye_fake_track_find(&fake->track, packet.src, packet.sport, packet.dst, packet.dport,
                                    &isn, &sisn);
    packet.id = fake->next_id++;
    pthread_mutex_unlock(&fake->lock);
    if (!known) return BYE_FAKE_SEND_UNKNOWN;
    packet.seq = isn + 1u + offset;
    packet.ack = sisn + 1u;
    packet.ttl = ttl;
    packet.md5sig = md5sig;
    packet.payload = payload;
    packet.len = len;
    uint8_t out[BYE_FAKE_PACKET_MAX];
    size_t size = bye_fake_packet_build(&packet, 1, out, sizeof out);
    if (size == 0) return BYE_FAKE_SEND_FAILED;
    ssize_t sent;
    do sent = sendto(fake->raw, out, size, 0, (struct sockaddr *)&remote, remote_len);
    while (sent < 0 && errno == EINTR);
    return sent == (ssize_t)size ? BYE_FAKE_SEND_OK : BYE_FAKE_SEND_FAILED;
}

#endif

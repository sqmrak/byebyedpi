#ifndef SENKO_UTUN_DEVICE_H
#define SENKO_UTUN_DEVICE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* the utun descriptor and nothing else: no servers, no dns, no policies, no
   transports, and no framing either. frames go in and out whole, with their
   four byte family header, and daemon/tun_stack.c is the only place that
   reads or writes that header. keeping the parse and the build in one place
   means a packet is checked once on the way in and packed once on the way
   out.

   reading and writing are plain descriptor calls, so a host test can hand
   this module one end of an AF_UNIX datagram socketpair and exercise the very
   code the device uses. only opening the kernel control socket is darwin
   specific. the vless and amneziawg tunnels both open their device here;
   daemon/awg_utun.c is left only for senko-core on ios 12 and later */

#define UTUN_DEVICE_MAX_UNITS 16

typedef enum {
    UTUN_DEVICE_OK          =  0,
    UTUN_DEVICE_AGAIN       =  1, /* nothing to read, or no room to write, yet */
    UTUN_DEVICE_EOF         =  2, /* the other end went away */
    UTUN_DEVICE_ERR_ARG     = -1,
    UTUN_DEVICE_ERR_UNSUPPORTED = -2, /* built without darwin kernel control */
    UTUN_DEVICE_ERR_CONTROL = -3, /* utun_control id lookup refused */
    UTUN_DEVICE_ERR_OPEN    = -4,
    UTUN_DEVICE_ERR_CONNECT = -5, /* every unit in range was taken */
    UTUN_DEVICE_ERR_NAME    = -6, /* kernel gave no interface name */
    UTUN_DEVICE_ERR_NONBLOCK = -7,
    UTUN_DEVICE_ERR_IO      = -8, /* the descriptor itself failed */
    /* the kernel took part of a frame. the rest is not a packet on its own,
       so it is never written after it */
    UTUN_DEVICE_ERR_SHORT   = -9
} utun_device_status_t;

typedef struct {
    int      fd; /* -1 when closed */
    char     ifname[16];
    unsigned unit;
    int      last_errno;
    /* the write was refused for lack of kernel buffers rather than because
       the descriptor is not writable. select() still reports such a
       descriptor as writable, so the owner has to wait on a timer instead */
    int      last_block_nobufs;
    uint64_t frames_in;
    uint64_t frames_out;
    uint64_t bytes_in;
    uint64_t bytes_out;
} utun_device_t;

void utun_device_init(utun_device_t *device);

/* open the control socket and claim a unit. first_unit 0 asks the kernel to
   pick, which ios 5 kernels do not all honour, so the caller still gets a
   walk over the explicit units when the automatic pick is refused */
utun_device_status_t utun_device_open(utun_device_t *device, unsigned first_unit);

/* take over a descriptor that is already open and switch it to nonblocking.
   a host test passes one end of a datagram socketpair here */
utun_device_status_t utun_device_adopt(utun_device_t *device, int fd,
                                       const char *ifname);

/* one frame, family header included, exactly as the kernel delivered it.
   cap should exceed the largest frame the interface may carry, so an
   oversized frame shows up as too long instead of silently cut */
utun_device_status_t utun_device_read_frame(utun_device_t *device, uint8_t *frame,
                                            size_t cap, size_t *frame_len);

/* one frame in one write. EINTR is retried here; blocking, a short write and
   a failed descriptor come back as three different results */
utun_device_status_t utun_device_write_frame(utun_device_t *device,
                                             const uint8_t *frame, size_t len);

/* close the descriptor once. calling it again does nothing */
void utun_device_close(utun_device_t *device);

const char *utun_device_status_name(utun_device_status_t status);

#ifdef __cplusplus
}
#endif

#endif

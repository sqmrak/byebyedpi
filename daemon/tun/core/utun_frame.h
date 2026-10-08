#ifndef SENKO_UTUN_FRAME_H
#define SENKO_UTUN_FRAME_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* darwin utun prepends a four byte address family to every packet, in network
   byte order. everything that reads or writes that framing lives here so the
   device module in daemon/ stays a socket wrapper and the rules can be tested
   on the host */

#define UTUN_FRAME_HEADER_LEN 4
#define UTUN_PACKET_MAX 65535
#define UTUN_FRAME_MAX (UTUN_FRAME_HEADER_LEN + UTUN_PACKET_MAX)
#define UTUN_MTU_DEFAULT 1500

/* the on-wire family values, not the host AF_INET/AF_INET6 constants: an
   armv7 sdk and an arm64 sdk agree on these numbers, and the header is
   written by the kernel, not by the local libc */
#define UTUN_FAMILY_INET  2u
#define UTUN_FAMILY_INET6 30u

typedef enum {
    UTUN_FRAME_OK          =  0,
    UTUN_FRAME_ERR_ARG     = -1,
    UTUN_FRAME_ERR_SHORT   = -2, /* frame ends before the ip header does */
    UTUN_FRAME_ERR_FAMILY  = -3, /* family header is neither inet nor inet6 */
    UTUN_FRAME_ERR_VERSION = -4, /* ip version disagrees with the family header */
    UTUN_FRAME_ERR_LENGTH  = -5, /* ip length field disagrees with the frame */
    UTUN_FRAME_ERR_SPACE   = -6  /* output buffer too small */
} utun_frame_status_t;

/* validate one frame read from the device and point at the ip packet inside
   it. address_len reports 4 or 16 so the caller can route without re-reading
   the version nibble */
utun_frame_status_t utun_frame_parse(const uint8_t *frame, size_t frame_len,
                                     const uint8_t **packet, size_t *packet_len,
                                     uint8_t *address_len);

/* the four byte family header for an outbound ip packet, chosen from its
   version nibble. only the header is written: the packet itself was produced
   by the local stack, so it is copied straight behind the header once rather
   than validated and copied a second time */
utun_frame_status_t utun_frame_header(uint8_t first_byte,
                                      uint8_t header[UTUN_FRAME_HEADER_LEN]);

const char *utun_frame_status_name(utun_frame_status_t status);

#ifdef __cplusplus
}
#endif

#endif

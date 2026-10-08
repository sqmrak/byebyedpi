#include "utun_frame.h"

#include <string.h>

static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void write_be32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/* the length fields have to agree with the frame the kernel handed us: a
   shorter one leaves trailing bytes nobody owns, a longer one would make the
   stack read past the read() result */
static utun_frame_status_t check_v4(const uint8_t *packet, size_t len) {
    if (len < 20) return UTUN_FRAME_ERR_SHORT;
    if ((packet[0] >> 4) != 4) return UTUN_FRAME_ERR_VERSION;
    size_t ihl = (size_t)(packet[0] & 0x0f) * 4u;
    if (ihl < 20 || ihl > len) return UTUN_FRAME_ERR_LENGTH;
    size_t total = read_be16(packet + 2);
    if (total != len || total < ihl) return UTUN_FRAME_ERR_LENGTH;
    return UTUN_FRAME_OK;
}

static utun_frame_status_t check_v6(const uint8_t *packet, size_t len) {
    if (len < 40) return UTUN_FRAME_ERR_SHORT;
    if ((packet[0] >> 4) != 6) return UTUN_FRAME_ERR_VERSION;
    size_t payload = read_be16(packet + 4);
    if (payload + 40u != len) return UTUN_FRAME_ERR_LENGTH;
    return UTUN_FRAME_OK;
}

utun_frame_status_t utun_frame_parse(const uint8_t *frame, size_t frame_len,
                                     const uint8_t **packet, size_t *packet_len,
                                     uint8_t *address_len) {
    if (packet) *packet = NULL;
    if (packet_len) *packet_len = 0;
    if (address_len) *address_len = 0;
    if (!frame || !packet || !packet_len || !address_len) return UTUN_FRAME_ERR_ARG;
    if (frame_len <= UTUN_FRAME_HEADER_LEN) return UTUN_FRAME_ERR_SHORT;
    if (frame_len > UTUN_FRAME_MAX) return UTUN_FRAME_ERR_LENGTH;

    const uint8_t *body = frame + UTUN_FRAME_HEADER_LEN;
    size_t body_len = frame_len - UTUN_FRAME_HEADER_LEN;
    uint32_t family = read_be32(frame);

    utun_frame_status_t status;
    if (family == UTUN_FAMILY_INET) {
        status = check_v4(body, body_len);
        if (status != UTUN_FRAME_OK) return status;
        *address_len = 4;
    } else if (family == UTUN_FAMILY_INET6) {
        status = check_v6(body, body_len);
        if (status != UTUN_FRAME_OK) return status;
        *address_len = 16;
    } else {
        return UTUN_FRAME_ERR_FAMILY;
    }

    *packet = body;
    *packet_len = body_len;
    return UTUN_FRAME_OK;
}

utun_frame_status_t utun_frame_header(uint8_t first_byte,
                                      uint8_t header[UTUN_FRAME_HEADER_LEN]) {
    if (!header) return UTUN_FRAME_ERR_ARG;
    unsigned version = first_byte >> 4;
    if (version == 4) {
        write_be32(header, UTUN_FAMILY_INET);
        return UTUN_FRAME_OK;
    }
    if (version == 6) {
        write_be32(header, UTUN_FAMILY_INET6);
        return UTUN_FRAME_OK;
    }
    return UTUN_FRAME_ERR_VERSION;
}

const char *utun_frame_status_name(utun_frame_status_t status) {
    switch (status) {
    case UTUN_FRAME_OK:          return "ok";
    case UTUN_FRAME_ERR_ARG:     return "arg";
    case UTUN_FRAME_ERR_SHORT:   return "short";
    case UTUN_FRAME_ERR_FAMILY:  return "family";
    case UTUN_FRAME_ERR_VERSION: return "version";
    case UTUN_FRAME_ERR_LENGTH:  return "length";
    case UTUN_FRAME_ERR_SPACE:   return "space";
    }
    return "unknown";
}

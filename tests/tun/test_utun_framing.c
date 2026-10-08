#include "utun_frame.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

/* a minimal but real udp over ipv4 packet: 20 byte header, 8 byte udp header */
static size_t build_v4(uint8_t *out, size_t payload_len) {
    size_t total = 20 + 8 + payload_len;
    memset(out, 0, total);
    out[0] = 0x45;
    out[2] = (uint8_t)(total >> 8);
    out[3] = (uint8_t)total;
    out[8] = 64;   /* ttl */
    out[9] = 17;   /* udp */
    out[12] = 192; out[13] = 0; out[14] = 2; out[15] = 10;   /* source */
    out[16] = 203; out[17] = 0; out[18] = 113; out[19] = 7;  /* destination */
    out[20] = 0xc0; out[21] = 0x00; /* source port 49152 */
    out[22] = 0x00; out[23] = 0x35; /* destination port 53 */
    out[24] = (uint8_t)((8 + payload_len) >> 8);
    out[25] = (uint8_t)(8 + payload_len);
    return total;
}

static size_t build_v6(uint8_t *out, size_t payload_len) {
    size_t total = 40 + 8 + payload_len;
    memset(out, 0, total);
    out[0] = 0x60;
    out[4] = (uint8_t)((8 + payload_len) >> 8);
    out[5] = (uint8_t)(8 + payload_len);
    out[6] = 17;  /* next header udp */
    out[7] = 64;  /* hop limit */
    out[8] = 0x20; out[9] = 0x01; out[10] = 0x0d; out[11] = 0xb8;
    out[23] = 1;  /* source 2001:db8::1 */
    out[24] = 0x20; out[25] = 0x01; out[26] = 0x0d; out[27] = 0xb8;
    out[39] = 2;  /* destination 2001:db8::2 */
    return total;
}

static size_t frame_v4(uint8_t *out, size_t payload_len) {
    uint8_t packet[256];
    size_t packet_len = build_v4(packet, payload_len);
    out[0] = 0; out[1] = 0; out[2] = 0; out[3] = UTUN_FAMILY_INET;
    memcpy(out + 4, packet, packet_len);
    return packet_len + 4;
}

int main(void) {
    uint8_t frame[512];
    const uint8_t *packet = NULL;
    size_t packet_len = 0;
    uint8_t address_len = 0;

    size_t frame_len = frame_v4(frame, 4);
    ok("v4 frame parses",
       utun_frame_parse(frame, frame_len, &packet, &packet_len, &address_len) ==
       UTUN_FRAME_OK);
    ok("v4 family reported as 4 bytes", address_len == 4);
    ok("v4 packet length excludes the header", packet_len == frame_len - 4);
    ok("v4 packet points past the family header", packet == frame + 4);

    /* an empty read and a header-only read are both short, not silently empty
       packets the stack would have to guess about */
    ok("empty frame rejected",
       utun_frame_parse(frame, 0, &packet, &packet_len, &address_len) ==
       UTUN_FRAME_ERR_SHORT);
    ok("header only frame rejected",
       utun_frame_parse(frame, 4, &packet, &packet_len, &address_len) ==
       UTUN_FRAME_ERR_SHORT);
    ok("truncated ip header rejected",
       utun_frame_parse(frame, 4 + 12, &packet, &packet_len, &address_len) ==
       UTUN_FRAME_ERR_SHORT);

    /* the family header the kernel writes is the only thing that says which
       stack owns the packet, so an unknown value cannot be guessed from the
       version nibble */
    frame_len = frame_v4(frame, 4);
    frame[3] = 99;
    ok("unknown family rejected",
       utun_frame_parse(frame, frame_len, &packet, &packet_len, &address_len) ==
       UTUN_FRAME_ERR_FAMILY);

    /* a v4 packet long enough to pass the v6 length floor must still be
       refused when the family header claims v6 */
    frame_len = frame_v4(frame, 24);
    frame[3] = UTUN_FAMILY_INET6;
    ok("family and version mismatch rejected",
       utun_frame_parse(frame, frame_len, &packet, &packet_len, &address_len) ==
       UTUN_FRAME_ERR_VERSION);

    /* total length shorter than the frame leaves trailing bytes nobody owns */
    frame_len = frame_v4(frame, 4);
    frame[4 + 2] = 0; frame[4 + 3] = 24;
    ok("v4 short total length rejected",
       utun_frame_parse(frame, frame_len, &packet, &packet_len, &address_len) ==
       UTUN_FRAME_ERR_LENGTH);

    frame_len = frame_v4(frame, 4);
    frame[4 + 2] = 0xff; frame[4 + 3] = 0xff;
    ok("v4 long total length rejected",
       utun_frame_parse(frame, frame_len, &packet, &packet_len, &address_len) ==
       UTUN_FRAME_ERR_LENGTH);

    /* an ihl below five cannot hold an ipv4 header at all */
    frame_len = frame_v4(frame, 4);
    frame[4] = 0x43;
    ok("v4 short ihl rejected",
       utun_frame_parse(frame, frame_len, &packet, &packet_len, &address_len) ==
       UTUN_FRAME_ERR_LENGTH);

    /* ipv6 */
    uint8_t v6packet[256];
    size_t v6len = build_v6(v6packet, 4);
    memset(frame, 0, sizeof frame);
    frame[3] = UTUN_FAMILY_INET6;
    memcpy(frame + 4, v6packet, v6len);
    ok("v6 frame parses",
       utun_frame_parse(frame, v6len + 4, &packet, &packet_len, &address_len) ==
       UTUN_FRAME_OK);
    ok("v6 family reported as 16 bytes", address_len == 16);

    frame[4 + 5] = 0xff;
    ok("v6 payload length mismatch rejected",
       utun_frame_parse(frame, v6len + 4, &packet, &packet_len, &address_len) ==
       UTUN_FRAME_ERR_LENGTH);

    /* the header for an outbound packet, and the round trip back through the
       parser: header plus the packet copied once behind it */
    uint8_t packet_v4[256];
    size_t packet_v4_len = build_v4(packet_v4, 8);
    uint8_t out[512];
    ok("v4 header written", utun_frame_header(packet_v4[0], out) == UTUN_FRAME_OK);
    ok("the v4 header carries the inet family",
       out[0] == 0 && out[1] == 0 && out[2] == 0 && out[3] == UTUN_FAMILY_INET);
    memcpy(out + UTUN_FRAME_HEADER_LEN, packet_v4, packet_v4_len);
    ok("round trip keeps the packet byte exact",
       utun_frame_parse(out, packet_v4_len + UTUN_FRAME_HEADER_LEN, &packet,
                        &packet_len, &address_len) == UTUN_FRAME_OK &&
       packet_len == packet_v4_len && memcmp(packet, packet_v4, packet_len) == 0);

    ok("v6 header written", utun_frame_header(v6packet[0], out) == UTUN_FRAME_OK);
    ok("the v6 header carries the darwin inet6 family",
       out[0] == 0 && out[1] == 0 && out[2] == 0 && out[3] == UTUN_FAMILY_INET6);
    ok("a header for a non ip packet is refused",
       utun_frame_header(0x33, out) == UTUN_FRAME_ERR_VERSION);
    ok("a header without a buffer is refused",
       utun_frame_header(0x45, NULL) == UTUN_FRAME_ERR_ARG);

    /* a frame larger than the biggest ip packet is rejected before any copy */
    ok("oversized frame rejected",
       utun_frame_parse(frame, UTUN_FRAME_MAX + 1, &packet, &packet_len,
                        &address_len) == UTUN_FRAME_ERR_LENGTH);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("all utun framing checks passed");
    return 0;
}

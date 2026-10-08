#ifndef SENKO_TEST_PACKET_FIXTURE_H
#define SENKO_TEST_PACKET_FIXTURE_H

/* real ipv4 and ipv6 packets for the capture and dataplane tests, with an
   independent ones complement checksum. it is written plainly on purpose, so
   a mistake in the code under test cannot hide behind the same mistake here */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum { PKT_FIN = 0x01, PKT_SYN = 0x02, PKT_RST = 0x04, PKT_ACK = 0x10 };

static inline uint16_t pkt_rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static inline uint32_t pkt_rd32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static inline void pkt_wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static inline void pkt_wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

static inline uint32_t pkt_add(const uint8_t *d, size_t n, uint32_t s) {
    for (size_t i = 0; i < n; i += 2)
        s += (uint32_t)(d[i] << 8) | (i + 1 < n ? d[i + 1] : 0);
    return s;
}
static inline uint16_t pkt_finish(uint32_t s) {
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

static inline int pkt_is_v4(const uint8_t *p) { return (p[0] >> 4) == 4; }
static inline const uint8_t *pkt_src(const uint8_t *p) { return pkt_is_v4(p) ? p + 12 : p + 8; }
static inline const uint8_t *pkt_dst(const uint8_t *p) { return pkt_is_v4(p) ? p + 16 : p + 24; }

/* offset of the transport header, walking the destination options the
   builders below can add */
static inline size_t pkt_l4(const uint8_t *p, size_t len) {
    if (pkt_is_v4(p)) return (size_t)(p[0] & 0x0f) * 4;
    size_t off = 40;
    uint8_t next = p[6];
    while ((next == 0 || next == 60) && off + 8 <= len) {
        next = p[off];
        off += ((size_t)p[off + 1] + 1) * 8;
    }
    return off;
}

static inline uint8_t pkt_proto(const uint8_t *p, size_t len) {
    if (pkt_is_v4(p)) return p[9];
    size_t off = 40;
    uint8_t next = p[6];
    while ((next == 0 || next == 60) && off + 8 <= len) {
        next = p[off];
        off += ((size_t)p[off + 1] + 1) * 8;
    }
    return next;
}

static inline uint32_t pkt_pseudo(const uint8_t *p, size_t len, uint8_t proto) {
    size_t alen = pkt_is_v4(p) ? 4 : 16;
    size_t l4len = len - pkt_l4(p, len);
    uint32_t s = pkt_add(pkt_src(p), alen, 0);
    s = pkt_add(pkt_dst(p), alen, s);
    s += proto;
    s += (uint32_t)l4len;
    return s;
}

static inline int pkt_l4_valid(const uint8_t *p, size_t len) {
    size_t off = pkt_l4(p, len);
    uint8_t proto = pkt_proto(p, len);
    uint32_t s = proto == 1 ? 0 : pkt_pseudo(p, len, proto); /* icmpv4 has no pseudo header */
    return pkt_finish(pkt_add(p + off, len - off, s)) == 0;
}

static inline int pkt_ip4_valid(const uint8_t *p) {
    return pkt_finish(pkt_add(p, (size_t)(p[0] & 0x0f) * 4, 0)) == 0;
}

static inline void pkt_fill_l4(uint8_t *p, size_t len, size_t check_at) {
    size_t off = pkt_l4(p, len);
    uint8_t proto = pkt_proto(p, len);
    pkt_wr16(p + off + check_at, 0);
    uint32_t s = proto == 1 ? 0 : pkt_pseudo(p, len, proto);
    pkt_wr16(p + off + check_at, pkt_finish(pkt_add(p + off, len - off, s)));
}

static inline void pkt_fill_ip4(uint8_t *p) {
    pkt_wr16(p + 10, 0);
    pkt_wr16(p + 10, pkt_finish(pkt_add(p, (size_t)(p[0] & 0x0f) * 4, 0)));
}

static inline size_t pkt_ip4(uint8_t *p, const uint8_t src[4], const uint8_t dst[4],
                             uint8_t proto, size_t l4len) {
    size_t len = 20 + l4len;
    memset(p, 0, len);
    p[0] = 0x45;
    pkt_wr16(p + 2, (uint16_t)len);
    p[8] = 64;
    p[9] = proto;
    memcpy(p + 12, src, 4);
    memcpy(p + 16, dst, 4);
    pkt_fill_ip4(p);
    return len;
}

/* extensions: how many 8 byte headers of type first_extension sit before the
   transport; they chain as destination options */
static inline size_t pkt_ip6(uint8_t *p, const uint8_t src[16], const uint8_t dst[16],
                             uint8_t proto, size_t l4len, int extensions,
                             uint8_t first_extension) {
    size_t ext = (size_t)extensions * 8;
    size_t len = 40 + ext + l4len;
    memset(p, 0, len);
    p[0] = 0x60;
    pkt_wr16(p + 4, (uint16_t)(len - 40));
    p[6] = extensions ? first_extension : proto;
    p[7] = 64;
    memcpy(p + 8, src, 16);
    memcpy(p + 24, dst, 16);
    for (int i = 0; i < extensions; ++i) {
        uint8_t *e = p + 40 + (size_t)i * 8;
        e[0] = i + 1 < extensions ? 60 : proto;
        e[2] = 1; /* padn */
        e[3] = 4;
    }
    return len;
}

static inline void pkt_tcp_fields(uint8_t *t, uint16_t sport, uint16_t dport,
                                  uint8_t flags, uint32_t seq, uint32_t ack,
                                  size_t data) {
    pkt_wr16(t, sport);
    pkt_wr16(t + 2, dport);
    pkt_wr32(t + 4, seq);
    pkt_wr32(t + 8, ack);
    t[12] = 0x50;
    t[13] = flags;
    pkt_wr16(t + 14, 65535);
    for (size_t i = 0; i < data; ++i) t[20 + i] = (uint8_t)('a' + i % 26);
}

static inline size_t pkt_tcp4(uint8_t *p, const uint8_t src[4], uint16_t sport,
                              const uint8_t dst[4], uint16_t dport, uint8_t flags,
                              uint32_t seq, uint32_t ack, size_t data) {
    size_t len = pkt_ip4(p, src, dst, 6, 20 + data);
    pkt_tcp_fields(p + 20, sport, dport, flags, seq, ack, data);
    pkt_fill_l4(p, len, 16);
    return len;
}

static inline size_t pkt_tcp6(uint8_t *p, const uint8_t src[16], uint16_t sport,
                              const uint8_t dst[16], uint16_t dport, uint8_t flags,
                              uint32_t seq, uint32_t ack, size_t data, int extensions,
                              uint8_t first_extension) {
    size_t len = pkt_ip6(p, src, dst, 6, 20 + data, extensions, first_extension);
    pkt_tcp_fields(p + pkt_l4(p, len), sport, dport, flags, seq, ack, data);
    pkt_fill_l4(p, len, 16);
    return len;
}

static inline size_t pkt_udp4(uint8_t *p, const uint8_t src[4], uint16_t sport,
                              const uint8_t dst[4], uint16_t dport,
                              const uint8_t *payload, size_t payload_len) {
    size_t len = pkt_ip4(p, src, dst, 17, 8 + payload_len);
    uint8_t *u = p + 20;
    pkt_wr16(u, sport);
    pkt_wr16(u + 2, dport);
    pkt_wr16(u + 4, (uint16_t)(8 + payload_len));
    if (payload_len) memcpy(u + 8, payload, payload_len);
    pkt_fill_l4(p, len, 6);
    return len;
}

static inline size_t pkt_udp6(uint8_t *p, const uint8_t src[16], uint16_t sport,
                              const uint8_t dst[16], uint16_t dport,
                              const uint8_t *payload, size_t payload_len) {
    size_t len = pkt_ip6(p, src, dst, 17, 8 + payload_len, 0, 0);
    uint8_t *u = p + 40;
    pkt_wr16(u, sport);
    pkt_wr16(u + 2, dport);
    pkt_wr16(u + 4, (uint16_t)(8 + payload_len));
    if (payload_len) memcpy(u + 8, payload, payload_len);
    pkt_fill_l4(p, len, 6);
    return len;
}

static inline size_t pkt_echo4(uint8_t *p, const uint8_t src[4], const uint8_t dst[4],
                               uint16_t sequence) {
    size_t len = pkt_ip4(p, src, dst, 1, 8);
    uint8_t *i = p + 20;
    i[0] = 8;
    pkt_wr16(i + 4, 0x1234);
    pkt_wr16(i + 6, sequence);
    pkt_fill_l4(p, len, 2);
    return len;
}

static inline size_t pkt_echo6(uint8_t *p, const uint8_t src[16], const uint8_t dst[16],
                               uint16_t sequence) {
    size_t len = pkt_ip6(p, src, dst, 58, 8, 0, 0);
    uint8_t *i = p + 40;
    i[0] = 128;
    pkt_wr16(i + 4, 0x1234);
    pkt_wr16(i + 6, sequence);
    pkt_fill_l4(p, len, 2);
    return len;
}

/* the darwin utun framing: four bytes of address family in network order */
static inline size_t pkt_frame(uint8_t *frame, const uint8_t *packet, size_t len) {
    frame[0] = 0;
    frame[1] = 0;
    frame[2] = 0;
    frame[3] = pkt_is_v4(packet) ? 2 : 30;
    memmove(frame + 4, packet, len);
    return len + 4;
}

#endif

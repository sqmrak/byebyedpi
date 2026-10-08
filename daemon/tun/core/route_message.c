#include "route_message.h"

#include <string.h>

/* darwin values, written out rather than taken from system headers so the
   armv7 and arm64 builds cannot disagree about them */
#define RTM_ADDRS_DST     0x01
#define RTM_ADDRS_GATEWAY 0x02
#define RTM_ADDRS_NETMASK 0x04
#define RTM_ADDRS_IFP     0x10

#define RTM_FLAG_UP      0x0001
#define RTM_FLAG_GATEWAY 0x0002
#define RTM_FLAG_HOST    0x0004
#define RTM_FLAG_STATIC  0x0800

#define ROUTE_AF_INET  2
#define ROUTE_AF_INET6 30
#define ROUTE_AF_LINK  18

#define SOCKADDR_IN_LEN   16
#define SOCKADDR_IN6_LEN  28
#define SOCKADDR_DL_MIN   8

/* offsets inside the 92 byte rt_msghdr */
#define OFF_MSGLEN  0
#define OFF_VERSION 2
#define OFF_TYPE    3
#define OFF_INDEX   4
#define OFF_FLAGS   8
#define OFF_ADDRS   12
#define OFF_PID     16
#define OFF_SEQ     20
#define OFF_ERRNO   24

const char *route_message_status_name(route_message_status_t status) {
    switch (status) {
    case ROUTE_MESSAGE_OK:          return "ok";
    case ROUTE_MESSAGE_ERR_ARG:     return "arg";
    case ROUTE_MESSAGE_ERR_SPACE:   return "space";
    case ROUTE_MESSAGE_ERR_TRUNCATED: return "truncated";
    case ROUTE_MESSAGE_ERR_VERSION: return "version";
    case ROUTE_MESSAGE_ERR_FOREIGN: return "foreign";
    case ROUTE_MESSAGE_ERR_KERNEL:  return "kernel";
    }
    return "unknown";
}

static void put16(uint8_t *p, uint16_t value) {
    memcpy(p, &value, sizeof value);
}

static void put32(uint8_t *p, int32_t value) {
    memcpy(p, &value, sizeof value);
}

static uint16_t get16(const uint8_t *p) {
    uint16_t value;
    memcpy(&value, p, sizeof value);
    return value;
}

static int32_t get32(const uint8_t *p) {
    int32_t value;
    memcpy(&value, p, sizeof value);
    return value;
}

/* the kernel walks the address list in four byte steps, and an empty
   sockaddr still takes one step (ROUNDUP32 in xnu's route code) */
static size_t round_sockaddr(size_t length) {
    return length ? (length + 3u) & ~(size_t)3u : 4u;
}

static size_t sockaddr_len_for(uint8_t address_len) {
    return address_len == 4 ? SOCKADDR_IN_LEN : SOCKADDR_IN6_LEN;
}

static void write_inet_sockaddr(uint8_t *out, uint8_t address_len,
                                const uint8_t *address) {
    size_t len = sockaddr_len_for(address_len);
    memset(out, 0, len);
    out[0] = (uint8_t)len;
    out[1] = address_len == 4 ? ROUTE_AF_INET : ROUTE_AF_INET6;
    /* sin_addr sits after len, family and port; sin6_addr after the flowinfo
       word as well */
    memcpy(out + (address_len == 4 ? 4 : 8), address, address_len);
}

static void write_link_sockaddr(uint8_t *out, uint16_t interface_index) {
    memset(out, 0, SOCKADDR_DL_MIN);
    out[0] = SOCKADDR_DL_MIN;
    out[1] = ROUTE_AF_LINK;
    put16(out + 2, interface_index);
}

static void netmask_bytes(uint8_t address_len, uint8_t prefix, uint8_t *mask) {
    memset(mask, 0, 16);
    unsigned whole = prefix / 8u;
    unsigned bits = prefix % 8u;
    if (whole > address_len) whole = address_len;
    memset(mask, 0xff, whole);
    if (bits && whole < address_len) mask[whole] = (uint8_t)(0xffu << (8u - bits));
}

route_message_status_t route_message_build(const route_message_spec_t *spec,
                                           uint8_t *out, size_t cap, size_t *out_len) {
    if (out_len) *out_len = 0;
    if (!spec || !out || !out_len) return ROUTE_MESSAGE_ERR_ARG;
    if (spec->address_len != 4 && spec->address_len != 16) return ROUTE_MESSAGE_ERR_ARG;
    if (spec->prefix > (spec->address_len == 4 ? 32u : 128u))
        return ROUTE_MESSAGE_ERR_ARG;
    if (spec->type != ROUTE_MESSAGE_ADD && spec->type != ROUTE_MESSAGE_DELETE &&
        spec->type != ROUTE_MESSAGE_GET)
        return ROUTE_MESSAGE_ERR_ARG;
    if (spec->target == ROUTE_TARGET_INTERFACE && spec->interface_index == 0)
        return ROUTE_MESSAGE_ERR_ARG;

    int host_route = spec->prefix == (spec->address_len == 4 ? 32u : 128u);
    size_t address_len = sockaddr_len_for(spec->address_len);

    /* a GET only carries the destination, and optionally asks which interface
       the kernel would use */
    int include_gateway = spec->type != ROUTE_MESSAGE_GET;
    int include_netmask = spec->type != ROUTE_MESSAGE_GET && !host_route;
    int include_ifp = spec->type == ROUTE_MESSAGE_GET && spec->want_interface;

    size_t total = ROUTE_MESSAGE_HEADER_LEN + round_sockaddr(address_len);
    if (include_gateway)
        total += round_sockaddr(spec->target == ROUTE_TARGET_INTERFACE
            ? SOCKADDR_DL_MIN : address_len);
    if (include_netmask) total += round_sockaddr(address_len);
    if (include_ifp) total += round_sockaddr(SOCKADDR_DL_MIN);
    if (total > cap) return ROUTE_MESSAGE_ERR_SPACE;
    if (total > ROUTE_MESSAGE_MAX) return ROUTE_MESSAGE_ERR_SPACE;

    memset(out, 0, total);
    int flags = RTM_FLAG_UP | RTM_FLAG_STATIC;
    if (host_route) flags |= RTM_FLAG_HOST;
    if (spec->target == ROUTE_TARGET_GATEWAY && include_gateway)
        flags |= RTM_FLAG_GATEWAY;

    int addrs = RTM_ADDRS_DST;
    if (include_gateway) addrs |= RTM_ADDRS_GATEWAY;
    if (include_netmask) addrs |= RTM_ADDRS_NETMASK;
    if (include_ifp) addrs |= RTM_ADDRS_IFP;

    put16(out + OFF_MSGLEN, (uint16_t)total);
    out[OFF_VERSION] = ROUTE_MESSAGE_VERSION;
    out[OFF_TYPE] = (uint8_t)spec->type;
    put16(out + OFF_INDEX, spec->target == ROUTE_TARGET_INTERFACE
        ? spec->interface_index : 0);
    put32(out + OFF_FLAGS, flags);
    put32(out + OFF_ADDRS, addrs);
    put32(out + OFF_PID, spec->pid);
    put32(out + OFF_SEQ, spec->seq);

    /* the address list must follow the bit order of rtm_addrs */
    size_t offset = ROUTE_MESSAGE_HEADER_LEN;
    write_inet_sockaddr(out + offset, spec->address_len, spec->destination);
    offset += round_sockaddr(address_len);

    if (include_gateway) {
        if (spec->target == ROUTE_TARGET_INTERFACE) {
            write_link_sockaddr(out + offset, spec->interface_index);
            offset += round_sockaddr(SOCKADDR_DL_MIN);
        } else {
            write_inet_sockaddr(out + offset, spec->address_len, spec->gateway);
            offset += round_sockaddr(address_len);
        }
    }
    if (include_netmask) {
        uint8_t mask[16];
        netmask_bytes(spec->address_len, spec->prefix, mask);
        write_inet_sockaddr(out + offset, spec->address_len, mask);
        offset += round_sockaddr(address_len);
    }
    if (include_ifp) {
        write_link_sockaddr(out + offset, 0);
        offset += round_sockaddr(SOCKADDR_DL_MIN);
    }

    *out_len = total;
    return ROUTE_MESSAGE_OK;
}

route_message_status_t route_message_parse(const uint8_t *reply, size_t len,
                                           int32_t expect_pid, int32_t expect_seq,
                                           route_message_reply_t *out) {
    if (out) memset(out, 0, sizeof *out);
    if (!reply || !out) return ROUTE_MESSAGE_ERR_ARG;

    /* ownership is decided before anything else. every writer on the routing
       socket sees every other writer's traffic, and a short or oddly
       versioned message from one of them must be skipped, not turned into a
       failure of our own request */
    if (len < OFF_ERRNO) return ROUTE_MESSAGE_ERR_FOREIGN;
    out->pid = get32(reply + OFF_PID);
    out->seq = get32(reply + OFF_SEQ);
    if (out->pid != expect_pid || out->seq != expect_seq)
        return ROUTE_MESSAGE_ERR_FOREIGN;

    if (len < ROUTE_MESSAGE_HEADER_LEN) return ROUTE_MESSAGE_ERR_TRUNCATED;
    if (reply[OFF_VERSION] != ROUTE_MESSAGE_VERSION) return ROUTE_MESSAGE_ERR_VERSION;
    uint16_t msglen = get16(reply + OFF_MSGLEN);
    if (msglen < ROUTE_MESSAGE_HEADER_LEN || msglen > len)
        return ROUTE_MESSAGE_ERR_TRUNCATED;

    out->kernel_errno = get32(reply + OFF_ERRNO);

    uint32_t addrs = (uint32_t)get32(reply + OFF_ADDRS);
    size_t offset = ROUTE_MESSAGE_HEADER_LEN;
    for (unsigned slot = 0; slot < ROUTE_ADDRESS_SLOTS && offset < msglen; ++slot) {
        uint32_t mask = 1u << slot;
        if (!(addrs & mask)) continue;

        const uint8_t *sa = reply + offset;
        size_t sa_len = sa[0];
        /* the default route's netmask comes back as an empty sockaddr; on
           ios 5 the interface name follows it, so the walk has to go on */
        if (round_sockaddr(sa_len) > (size_t)(msglen - offset))
            return ROUTE_MESSAGE_ERR_TRUNCATED;
        if (sa_len == 0) {
            offset += round_sockaddr(0);
            continue;
        }
        uint8_t family = sa[1];

        if (mask == RTM_ADDRS_GATEWAY) {
            if (family == ROUTE_AF_LINK) {
                out->gateway_is_link = 1;
                out->has_gateway = 1;
                if (sa_len >= 4) out->interface_index = get16(sa + 2);
            } else if (family == ROUTE_AF_INET && sa_len >= SOCKADDR_IN_LEN) {
                memcpy(out->gateway, sa + 4, 4);
                out->gateway_len = 4;
                out->has_gateway = 1;
            } else if (family == ROUTE_AF_INET6 && sa_len >= SOCKADDR_IN6_LEN) {
                memcpy(out->gateway, sa + 8, 16);
                out->gateway_len = 16;
                out->has_gateway = 1;
            }
        } else if (mask == RTM_ADDRS_IFP && family == ROUTE_AF_LINK) {
            /* sockaddr_dl: len, family, index, type, nlen, alen, slen, data */
            if (sa_len >= 8) {
                size_t name_len = sa[5];
                if (name_len > 0 && name_len < sizeof out->ifname &&
                    8u + name_len <= sa_len) {
                    memcpy(out->ifname, sa + 8, name_len);
                    out->ifname[name_len] = '\0';
                    out->has_interface = 1;
                    out->interface_index = get16(sa + 2);
                }
            }
        }
        offset += round_sockaddr(sa_len);
    }

    if (out->kernel_errno != 0) return ROUTE_MESSAGE_ERR_KERNEL;
    return ROUTE_MESSAGE_OK;
}

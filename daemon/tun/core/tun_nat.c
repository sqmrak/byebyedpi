#include "tun_nat.h"

#include <string.h>

#define PROTO_TCP    6
#define PROTO_UDP    17
#define PROTO_ICMP   1
#define PROTO_ICMP6  58

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

/* ipv6 extension headers walked before the transport header, and a bound on
   how many, so a crafted chain cannot keep the loop going */
#define V6_HOP_BY_HOP 0
#define V6_ROUTING    43
#define V6_FRAGMENT   44
#define V6_ESP        50
#define V6_AH         51
#define V6_NO_NEXT    59
#define V6_DEST_OPTS  60
#define V6_CHAIN_MAX  8

/* a generation takes the bits above the slot in a flow id */
#define SLOT_BITS 8

typedef struct {
    uint8_t  version;
    uint8_t  address_len;
    uint8_t  protocol;    /* the transport, after any extension headers */
    size_t   header_len;  /* the ip header, extensions included */
    uint8_t *source;
    uint8_t *destination;
    uint8_t *transport;
    size_t   transport_len;
} packet_view_t;

const char *tun_nat_drop_text(tun_nat_drop_t reason) {
    switch (reason) {
    case TUN_NAT_DROP_NONE:
        return "not dropped";
    case TUN_NAT_DROP_MALFORMED:
        return "its headers do not fit the packet or disagree with its length";
    case TUN_NAT_DROP_CHECKSUM:
        return "its checksum is wrong";
    case TUN_NAT_DROP_FRAGMENT:
        return "it is an ip fragment, and fragments are not reassembled before capture";
    case TUN_NAT_DROP_EXTENSION:
        return "it carries an ipv6 routing, ah or esp header, which changes where it is"
               " really going";
    case TUN_NAT_DROP_PROTOCOL:
        return "its protocol is not captured by the tunnel";
    case TUN_NAT_DROP_NO_FLOW:
        return "it belongs to a connection the tunnel has no record of";
    case TUN_NAT_DROP_PENDING:
        return "its connection is still waiting to be accepted";
    case TUN_NAT_DROP_TABLE_FULL:
        return "every connection slot is in use";
    case TUN_NAT_DROP_RESERVED:
        return "it is aimed at an address or port the tunnel keeps for itself";
    case TUN_NAT_DROP_REASON_COUNT:
        break;
    }
    return "it was dropped for an unknown reason";
}

static uint16_t read16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void write16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static uint32_t read32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void write32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}


static uint32_t sum_words(const uint8_t *data, size_t len, uint32_t sum) {
    size_t i = 0;
    for (; i + 1 < len; i += 2) sum += read16(data + i);
    if (i < len) sum += (uint32_t)data[i] << 8;
    return sum;
}

static uint16_t fold(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)sum;
}

/* rfc 1624 eqn 3: HC' = ~(~HC + ~m + m'), one 16 bit word at a time. a
   changed address or port is folded into the existing checksum, so a segment
   that arrived with a bad checksum keeps a bad checksum and the stack still
   refuses it */
static void checksum_replace(uint8_t *check, const uint8_t *before,
                             const uint8_t *after, size_t len) {
    uint32_t sum = (uint16_t)~read16(check);
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += (uint16_t)~read16(before + i);
        sum += read16(after + i);
    }
    write16(check, (uint16_t)~fold(sum));
}

static void ipv4_header_checksum(uint8_t *ip, size_t header_len) {
    write16(ip + 10, 0);
    write16(ip + 10, (uint16_t)~fold(sum_words(ip, header_len, 0)));
}

static int ipv4_header_checksum_ok(const uint8_t *ip, size_t header_len) {
    return fold(sum_words(ip, header_len, 0)) == 0xffffu;
}

static uint32_t pseudo_header_sum(const packet_view_t *view) {
    uint32_t sum = sum_words(view->source, view->address_len, 0);
    sum = sum_words(view->destination, view->address_len, sum);
    sum += view->protocol;
    sum += (uint32_t)(view->transport_len & 0xffffu);
    sum += (uint32_t)(view->transport_len >> 16);
    return sum;
}

static int transport_checksum_ok(const packet_view_t *view) {
    uint32_t sum = sum_words(view->transport, view->transport_len,
                             pseudo_header_sum(view));
    return fold(sum) == 0xffffu;
}

static void transport_checksum_fill(const packet_view_t *view, size_t check_offset) {
    write16(view->transport + check_offset, 0);
    uint32_t sum = sum_words(view->transport, view->transport_len,
                             pseudo_header_sum(view));
    write16(view->transport + check_offset, (uint16_t)~fold(sum));
}


static tun_nat_drop_t view_packet(uint8_t *packet, size_t len, packet_view_t *view) {
    memset(view, 0, sizeof *view);
    if (len < 20) return TUN_NAT_DROP_MALFORMED;
    unsigned version = packet[0] >> 4;

    if (version == 4) {
        size_t ihl = (size_t)(packet[0] & 0x0f) * 4u;
        if (ihl < 20 || ihl > len) return TUN_NAT_DROP_MALFORMED;
        if (read16(packet + 2) != len) return TUN_NAT_DROP_MALFORMED;
        /* rewriting the checksum would hide a corrupt header, so validate it first */
        if (!ipv4_header_checksum_ok(packet, ihl)) return TUN_NAT_DROP_CHECKSUM;
        uint16_t fragment = read16(packet + 6);
        if ((fragment & 0x2000u) || (fragment & 0x1fffu)) return TUN_NAT_DROP_FRAGMENT;
        view->version = 4;
        view->address_len = 4;
        view->protocol = packet[9];
        view->header_len = ihl;
        view->source = packet + 12;
        view->destination = packet + 16;
    } else if (version == 6) {
        if (len < 40) return TUN_NAT_DROP_MALFORMED;
        if ((size_t)read16(packet + 4) + 40u != len) return TUN_NAT_DROP_MALFORMED;
        uint8_t next = packet[6];
        size_t offset = 40;
        int walked = 0;
        for (;;) {
            if (next == PROTO_TCP || next == PROTO_UDP || next == PROTO_ICMP6) break;
            if (next == V6_FRAGMENT) return TUN_NAT_DROP_FRAGMENT;
            if (next == V6_ROUTING || next == V6_AH || next == V6_ESP)
                return TUN_NAT_DROP_EXTENSION;
            if (next != V6_HOP_BY_HOP && next != V6_DEST_OPTS) {
                if (next == V6_NO_NEXT) return TUN_NAT_DROP_PROTOCOL;
                break; /* a transport this module does not capture */
            }
            if (++walked > V6_CHAIN_MAX) return TUN_NAT_DROP_EXTENSION;
            if (offset + 8 > len) return TUN_NAT_DROP_MALFORMED;
            size_t extension_len = ((size_t)packet[offset + 1] + 1u) * 8u;
            if (offset + extension_len > len) return TUN_NAT_DROP_MALFORMED;
            next = packet[offset];
            offset += extension_len;
        }
        view->version = 6;
        view->address_len = 16;
        view->protocol = next;
        view->header_len = offset;
        view->source = packet + 8;
        view->destination = packet + 24;
    } else {
        return TUN_NAT_DROP_MALFORMED;
    }

    view->transport = packet + view->header_len;
    view->transport_len = len - view->header_len;
    if (view->protocol == PROTO_TCP) {
        if (view->transport_len < 20) return TUN_NAT_DROP_MALFORMED;
        size_t data_offset = (size_t)(view->transport[12] >> 4) * 4u;
        if (data_offset < 20 || data_offset > view->transport_len)
            return TUN_NAT_DROP_MALFORMED;
    }
    return TUN_NAT_DROP_NONE;
}


static const uint8_t *local_address(const tun_nat_t *nat, uint8_t address_len) {
    return address_len == 4 ? nat->config.local4 : nat->config.local6;
}

static const uint8_t *synthetic_address(const tun_nat_t *nat, uint8_t address_len) {
    return address_len == 4 ? nat->config.synthetic4 : nat->config.synthetic6;
}

static int family_enabled(const tun_nat_t *nat, uint8_t address_len) {
    return address_len == 4 ? nat->config.have_ipv4 : nat->config.have_ipv6;
}

uint16_t tun_nat_synthetic_port(size_t slot) {
    return (uint16_t)(TUN_NAT_PORT_BASE + slot);
}

int tun_nat_slot_for_port(const tun_nat_t *nat, uint16_t port, size_t *out_slot) {
    if (!nat || port < TUN_NAT_PORT_BASE) return 0;
    size_t slot = (size_t)(port - TUN_NAT_PORT_BASE);
    if (slot >= nat->config.limit) return 0;
    if (out_slot) *out_slot = slot;
    return 1;
}

uint64_t tun_nat_pending_wait_ms(const tun_nat_t *nat, uint64_t now_ms,
                                 uint64_t max_ms) {
    uint64_t wait = UINT64_MAX;
    if (!nat) return wait;
    for (size_t i = 0; i < nat->config.limit; ++i) {
        const tun_nat_entry_t *entry = &nat->entries[i];
        if (entry->state != TUN_NAT_PENDING) continue;
        /* a clock that went backwards restarts the wait, as expiry does */
        uint64_t age = now_ms > entry->touched_ms ? now_ms - entry->touched_ms : 0;
        uint64_t left = age >= max_ms ? 0 : max_ms - age;
        if (left < wait) wait = left;
    }
    return wait;
}

const tun_nat_entry_t *tun_nat_entry(const tun_nat_t *nat, size_t slot) {
    if (!nat || slot >= nat->config.limit) return NULL;
    return &nat->entries[slot];
}

uint64_t tun_nat_flow_id(const tun_nat_t *nat, size_t slot) {
    if (!nat || slot >= nat->config.limit) return 0;
    return (nat->entries[slot].generation << SLOT_BITS) | (uint64_t)slot;
}

int tun_nat_slot_for_id(const tun_nat_t *nat, uint64_t id, size_t *out_slot) {
    if (!nat) return 0;
    size_t slot = (size_t)(id & ((1u << SLOT_BITS) - 1u));
    if (slot >= nat->config.limit) return 0;
    const tun_nat_entry_t *entry = &nat->entries[slot];
    if (entry->state == TUN_NAT_FREE) return 0;
    if (entry->generation != (id >> SLOT_BITS)) return 0;
    if (out_slot) *out_slot = slot;
    return 1;
}

tun_nat_status_t tun_nat_init(tun_nat_t *nat, const tun_nat_config_t *config) {
    if (!nat || !config) return TUN_NAT_ERR_ARG;
    if (!config->have_ipv4 && !config->have_ipv6) return TUN_NAT_ERR_ARG;
    if (config->listen_port == 0) return TUN_NAT_ERR_ARG;
    if (config->limit > TUN_NAT_TCP_MAX || TUN_NAT_TCP_MAX > (1u << SLOT_BITS))
        return TUN_NAT_ERR_ARG;
    size_t limit = config->limit ? config->limit : TUN_NAT_TCP_MAX;
    /* the listener must never look like a synthetic port, or its own
       connections would be mistaken for captured ones */
    if (config->listen_port >= TUN_NAT_PORT_BASE &&
        config->listen_port < TUN_NAT_PORT_BASE + limit)
        return TUN_NAT_ERR_ARG;
    if (config->have_ipv4 && memcmp(config->local4, config->synthetic4, 4) == 0)
        return TUN_NAT_ERR_ARG;
    if (config->have_ipv6 && memcmp(config->local6, config->synthetic6, 16) == 0)
        return TUN_NAT_ERR_ARG;

    memset(nat, 0, sizeof *nat);
    nat->config = *config;
    nat->config.limit = limit;
    nat->next_generation = 1;
    return TUN_NAT_OK;
}

static int key_equal(const tun_flow_key_t *a, const tun_flow_key_t *b) {
    return a->protocol == b->protocol && a->address_len == b->address_len &&
        a->source_port == b->source_port &&
        a->destination_port == b->destination_port &&
        memcmp(a->source, b->source, a->address_len) == 0 &&
        memcmp(a->destination, b->destination, a->address_len) == 0;
}

/* a live entry wins over a draining one with the same tuple: an app that
   reconnects from the same port while the old connection drains gets a new
   entry, and its later segments must reach that one */
static int find_entry(const tun_nat_t *nat, const tun_flow_key_t *key,
                      size_t *out_slot) {
    size_t draining = SIZE_MAX;
    for (size_t i = 0; i < nat->config.limit; ++i) {
        const tun_nat_entry_t *entry = &nat->entries[i];
        if (entry->state == TUN_NAT_FREE || !key_equal(&entry->key, key)) continue;
        if (entry->state == TUN_NAT_DRAINING) {
            if (draining == SIZE_MAX) draining = i;
            continue;
        }
        *out_slot = i;
        return 1;
    }
    if (draining == SIZE_MAX) return 0;
    *out_slot = draining;
    return 1;
}

static int allocate_entry(tun_nat_t *nat, size_t *out_slot) {
    for (size_t i = 0; i < nat->config.limit; ++i) {
        if (nat->entries[i].state != TUN_NAT_FREE) continue;
        *out_slot = i;
        return 1;
    }
    return 0;
}

static void key_from_view(const packet_view_t *view, tun_flow_key_t *key) {
    memset(key, 0, sizeof *key);
    key->address_len = view->address_len;
    key->protocol = TUN_FLOW_TCP;
    memcpy(key->source, view->source, view->address_len);
    memcpy(key->destination, view->destination, view->address_len);
    key->source_port = read16(view->transport);
    key->destination_port = read16(view->transport + 2);
}

/* rewrite the addresses and ports of a tcp segment in place and fold every
   change into the checksums */
static void rewrite_tcp(packet_view_t *view, uint8_t *packet,
                        const uint8_t *source, uint16_t source_port,
                        const uint8_t *destination, uint16_t destination_port) {
    uint8_t *check = view->transport + 16;
    checksum_replace(check, view->source, source, view->address_len);
    checksum_replace(check, view->destination, destination, view->address_len);

    uint8_t ports_before[4], ports_after[4];
    memcpy(ports_before, view->transport, 4);
    write16(ports_after, source_port);
    write16(ports_after + 2, destination_port);
    checksum_replace(check, ports_before, ports_after, 4);

    memcpy(view->source, source, view->address_len);
    memcpy(view->destination, destination, view->address_len);
    memcpy(view->transport, ports_after, 4);
    if (view->version == 4) ipv4_header_checksum(packet, view->header_len);
}

static void to_stack(tun_nat_t *nat, size_t slot, packet_view_t *view,
                     uint8_t *packet) {
    rewrite_tcp(view, packet, synthetic_address(nat, view->address_len),
                tun_nat_synthetic_port(slot), local_address(nat, view->address_len),
                nat->config.listen_port);
}

static tun_nat_verdict_t drop(tun_nat_t *nat, tun_nat_drop_t reason,
                              tun_nat_drop_t *out_reason) {
    ++nat->dropped[reason];
    if (out_reason) *out_reason = reason;
    return TUN_NAT_DROP;
}

tun_nat_udp_result_t tun_nat_udp_inbound(tun_nat_t *nat, uint8_t *packet,
                                         size_t len, tun_flow_key_t *out_key,
                                         const uint8_t **out_payload,
                                         size_t *out_payload_len,
                                         tun_nat_drop_t *out_reason) {
    if (out_key) memset(out_key, 0, sizeof *out_key);
    if (out_payload) *out_payload = NULL;
    if (out_payload_len) *out_payload_len = 0;
    if (out_reason) *out_reason = TUN_NAT_DROP_NONE;
    if (!nat || !packet || !out_key || !out_payload || !out_payload_len)
        return TUN_NAT_UDP_DROP;

    packet_view_t view;
    tun_nat_drop_t problem = view_packet(packet, len, &view);
    if (problem != TUN_NAT_DROP_NONE) return TUN_NAT_UDP_OTHER;
    if (view.protocol != PROTO_UDP) return TUN_NAT_UDP_OTHER;
    if (!family_enabled(nat, view.address_len)) problem = TUN_NAT_DROP_PROTOCOL;
    else if (memcmp(view.destination, local_address(nat, view.address_len),
                    view.address_len) == 0 ||
             memcmp(view.destination, synthetic_address(nat, view.address_len),
                    view.address_len) == 0) problem = TUN_NAT_DROP_RESERVED;
    else if (view.transport_len < 8 || read16(view.transport + 4) != view.transport_len ||
             read16(view.transport) == 0 || read16(view.transport + 2) == 0)
        problem = TUN_NAT_DROP_MALFORMED;
    else if ((view.version == 6 || read16(view.transport + 6) != 0) &&
             !transport_checksum_ok(&view))
        problem = TUN_NAT_DROP_CHECKSUM;
    if (problem != TUN_NAT_DROP_NONE) {
        (void)drop(nat, problem, out_reason);
        return TUN_NAT_UDP_DROP;
    }

    out_key->address_len = view.address_len;
    out_key->protocol = TUN_FLOW_UDP;
    memcpy(out_key->source, view.source, view.address_len);
    memcpy(out_key->destination, view.destination, view.address_len);
    out_key->source_port = read16(view.transport);
    out_key->destination_port = read16(view.transport + 2);
    *out_payload = view.transport + 8;
    *out_payload_len = view.transport_len - 8;
    return TUN_NAT_UDP_PACKET;
}

tun_nat_status_t tun_nat_udp_reply(const tun_flow_key_t *key,
                                   const uint8_t *payload, size_t payload_len,
                                   uint8_t *out, size_t cap, size_t *out_len) {
    if (out_len) *out_len = 0;
    if (!key || !out || !out_len || (payload_len && !payload) ||
        key->protocol != TUN_FLOW_UDP ||
        (key->address_len != 4 && key->address_len != 16) ||
        !key->source_port || !key->destination_port) return TUN_NAT_ERR_ARG;
    size_t ip_len = key->address_len == 4 ? 20u : 40u;
    if (payload_len > 65535u - ip_len - 8u ||
        ip_len + 8u + payload_len > cap) return TUN_NAT_ERR_SPACE;

    size_t total = ip_len + 8u + payload_len;
    memset(out, 0, ip_len + 8u);
    packet_view_t view;
    memset(&view, 0, sizeof view);
    view.version = key->address_len == 4 ? 4 : 6;
    view.address_len = key->address_len;
    view.protocol = PROTO_UDP;
    view.header_len = ip_len;
    view.transport = out + ip_len;
    view.transport_len = 8u + payload_len;
    if (key->address_len == 4) {
        out[0] = 0x45;
        write16(out + 2, (uint16_t)total);
        out[8] = 64;
        out[9] = PROTO_UDP;
        view.source = out + 12;
        view.destination = out + 16;
    } else {
        out[0] = 0x60;
        write16(out + 4, (uint16_t)(total - 40u));
        out[6] = PROTO_UDP;
        out[7] = 64;
        view.source = out + 8;
        view.destination = out + 24;
    }
    memcpy(view.source, key->destination, key->address_len);
    memcpy(view.destination, key->source, key->address_len);
    write16(view.transport, key->destination_port);
    write16(view.transport + 2, key->source_port);
    write16(view.transport + 4, (uint16_t)(8u + payload_len));
    if (payload_len) memcpy(view.transport + 8, payload, payload_len);
    transport_checksum_fill(&view, 6);
    if (read16(view.transport + 6) == 0) write16(view.transport + 6, 0xffffu);
    if (view.version == 4) ipv4_header_checksum(out, ip_len);
    *out_len = total;
    return TUN_NAT_OK;
}

tun_nat_status_t tun_nat_udp_unreachable(const tun_flow_key_t *key, size_t payload_len,
                                         uint8_t *out, size_t cap, size_t *out_len) {
    if (out_len) *out_len = 0;
    if (!key || !out || !out_len || key->protocol != TUN_FLOW_UDP ||
        (key->address_len != 4 && key->address_len != 16) ||
        !key->source_port || !key->destination_port) return TUN_NAT_ERR_ARG;
    int v4 = key->address_len == 4;
    size_t ip_len = v4 ? 20u : 40u;
    size_t quote_len = ip_len + 8u;
    size_t icmp_len = 8u + quote_len;
    size_t total = ip_len + icmp_len;
    if (payload_len > 65535u - quote_len || total > cap) return TUN_NAT_ERR_SPACE;

    memset(out, 0, total);
    uint8_t *icmp = out + ip_len;
    uint8_t *quote = icmp + 8;
    uint8_t *source = v4 ? out + 12 : out + 8;
    uint8_t *destination = v4 ? out + 16 : out + 24;
    size_t datagram = quote_len + payload_len;
    if (v4) {
        out[0] = 0x45;
        write16(out + 2, (uint16_t)total);
        out[8] = 64;
        out[9] = PROTO_ICMP;
        quote[0] = 0x45;
        write16(quote + 2, (uint16_t)datagram);
        quote[8] = 64;
        quote[9] = PROTO_UDP;
        memcpy(quote + 12, key->source, 4);
        memcpy(quote + 16, key->destination, 4);
        ipv4_header_checksum(quote, 20);
        icmp[0] = 3;
        icmp[1] = 3;
    } else {
        out[0] = 0x60;
        write16(out + 4, (uint16_t)icmp_len);
        out[6] = PROTO_ICMP6;
        out[7] = 64;
        quote[0] = 0x60;
        write16(quote + 4, (uint16_t)(datagram - 40u));
        quote[6] = PROTO_UDP;
        quote[7] = 64;
        memcpy(quote + 8, key->source, 16);
        memcpy(quote + 24, key->destination, 16);
        icmp[0] = 1;
        icmp[1] = 4;
    }
    uint8_t *udp = quote + ip_len;
    write16(udp, key->source_port);
    write16(udp + 2, key->destination_port);
    write16(udp + 4, (uint16_t)(8u + payload_len));
    memcpy(source, key->destination, key->address_len);
    memcpy(destination, key->source, key->address_len);
    if (v4) {
        /* icmp for ipv4 has no pseudo header */
        write16(icmp + 2, (uint16_t)~fold(sum_words(icmp, icmp_len, 0)));
        ipv4_header_checksum(out, 20);
    } else {
        packet_view_t view;
        memset(&view, 0, sizeof view);
        view.address_len = 16;
        view.protocol = PROTO_ICMP6;
        view.source = source;
        view.destination = destination;
        view.transport = icmp;
        view.transport_len = icmp_len;
        transport_checksum_fill(&view, 2);
    }
    *out_len = total;
    return TUN_NAT_OK;
}

tun_nat_verdict_t tun_nat_inbound(tun_nat_t *nat, uint8_t *packet, size_t len,
                                  uint64_t now_ms, size_t *out_slot,
                                  tun_nat_drop_t *out_reason) {
    if (out_reason) *out_reason = TUN_NAT_DROP_NONE;
    if (out_slot) *out_slot = SIZE_MAX;
    if (!nat || !packet) return TUN_NAT_DROP;

    packet_view_t view;
    tun_nat_drop_t problem = view_packet(packet, len, &view);
    if (problem != TUN_NAT_DROP_NONE) return drop(nat, problem, out_reason);
    if (!family_enabled(nat, view.address_len))
        return drop(nat, TUN_NAT_DROP_PROTOCOL, out_reason);

    const uint8_t *local = local_address(nat, view.address_len);
    int to_local = memcmp(view.destination, local, view.address_len) == 0;
    int to_synthetic = memcmp(view.destination, synthetic_address(nat, view.address_len),
                              view.address_len) == 0;

    /* the stack answers pings to its own address itself. its tcp and udp
       ports are not for apps: the listener only serves captured flows */
    if (to_local) {
        if (view.protocol == PROTO_ICMP || view.protocol == PROTO_ICMP6)
            return TUN_NAT_PASS;
        return drop(nat, TUN_NAT_DROP_RESERVED, out_reason);
    }
    if (to_synthetic) return drop(nat, TUN_NAT_DROP_RESERVED, out_reason);
    if (view.protocol != PROTO_TCP) return drop(nat, TUN_NAT_DROP_PROTOCOL, out_reason);

    tun_flow_key_t key;
    key_from_view(&view, &key);
    uint8_t flags = view.transport[13];
    int opening = (flags & TCP_SYN) && !(flags & (TCP_ACK | TCP_RST));

    size_t slot = SIZE_MAX;
    int found = find_entry(nat, &key, &slot);
    tun_nat_entry_t *entry = found ? &nat->entries[slot] : NULL;

    if (entry && entry->state == TUN_NAT_PENDING) {
        if (out_slot) *out_slot = slot;
        if (opening) {
            entry->touched_ms = now_ms;
            return TUN_NAT_HELD;
        }
        return drop(nat, TUN_NAT_DROP_PENDING, out_reason);
    }

    /* a syn for an active entry is the app repeating itself because the
       syn-ack was lost, and the stack has to see it to answer again. a syn
       for a draining tuple is a new connection and gets its own entry */
    if (entry && (entry->state == TUN_NAT_ACTIVE || !opening)) {
        entry->touched_ms = now_ms;
        to_stack(nat, slot, &view, packet);
        if (out_slot) *out_slot = slot;
        return TUN_NAT_PASS;
    }

    if (!opening) return drop(nat, TUN_NAT_DROP_NO_FLOW, out_reason);

    /* a new entry is only spent on a syn that is really a syn */
    if (!transport_checksum_ok(&view)) return drop(nat, TUN_NAT_DROP_CHECKSUM, out_reason);

    /* only the headers of the syn are kept. data riding on it (tcp fast open)
       is left unacknowledged by the stack, and the app sends it again once
       the handshake completes, which is ordinary tcp behaviour */
    size_t data_offset = (size_t)(view.transport[12] >> 4) * 4u;
    size_t kept = view.header_len + data_offset;
    if (kept > TUN_NAT_SYN_MAX)
        return drop(nat, view.version == 6 ? TUN_NAT_DROP_EXTENSION
                                           : TUN_NAT_DROP_MALFORMED, out_reason);
    if (!allocate_entry(nat, &slot)) return drop(nat, TUN_NAT_DROP_TABLE_FULL, out_reason);

    entry = &nat->entries[slot];
    uint64_t previous_generation = entry->generation;
    memset(entry, 0, sizeof *entry);
    entry->state = TUN_NAT_PENDING;
    entry->key = key;
    entry->generation = previous_generation >= nat->next_generation
        ? previous_generation + 1 : nat->next_generation;
    nat->next_generation = entry->generation + 1;
    entry->touched_ms = now_ms;
    memcpy(entry->syn, packet, kept);
    entry->syn_len = kept;
    if (kept != len) {
        packet_view_t held;
        if (view.version == 4) {
            write16(entry->syn + 2, (uint16_t)kept);
            ipv4_header_checksum(entry->syn, view.header_len);
        } else {
            write16(entry->syn + 4, (uint16_t)(kept - 40u));
        }
        if (view_packet(entry->syn, kept, &held) != TUN_NAT_DROP_NONE) {
            tun_nat_release(nat, slot);
            return drop(nat, TUN_NAT_DROP_MALFORMED, out_reason);
        }
        transport_checksum_fill(&held, 16);
    }
    ++nat->opened;
    if (out_slot) *out_slot = slot;
    return TUN_NAT_NEW;
}

tun_nat_verdict_t tun_nat_outbound(tun_nat_t *nat, uint8_t *packet, size_t len,
                                   uint64_t now_ms, size_t *out_slot,
                                   tun_nat_drop_t *out_reason) {
    if (out_reason) *out_reason = TUN_NAT_DROP_NONE;
    if (out_slot) *out_slot = SIZE_MAX;
    if (!nat || !packet) return TUN_NAT_DROP;

    packet_view_t view;
    tun_nat_drop_t problem = view_packet(packet, len, &view);
    if (problem != TUN_NAT_DROP_NONE) return drop(nat, problem, out_reason);

    int to_synthetic = memcmp(view.destination, synthetic_address(nat, view.address_len),
                              view.address_len) == 0;

    /* replies the stack sends to a real app address, an echo reply for one,
       need no translation */
    if (!to_synthetic) return TUN_NAT_PASS;
    if (view.protocol != PROTO_TCP) return drop(nat, TUN_NAT_DROP_PROTOCOL, out_reason);

    size_t slot;
    if (read16(view.transport) != nat->config.listen_port ||
        memcmp(view.source, local_address(nat, view.address_len), view.address_len) != 0 ||
        !tun_nat_slot_for_port(nat, read16(view.transport + 2), &slot))
        return drop(nat, TUN_NAT_DROP_NO_FLOW, out_reason);

    tun_nat_entry_t *entry = &nat->entries[slot];
    if ((entry->state != TUN_NAT_ACTIVE && entry->state != TUN_NAT_DRAINING) ||
        entry->key.address_len != view.address_len)
        return drop(nat, TUN_NAT_DROP_NO_FLOW, out_reason);

    entry->touched_ms = now_ms;
    rewrite_tcp(&view, packet, entry->key.destination, entry->key.destination_port,
                entry->key.source, entry->key.source_port);
    if (out_slot) *out_slot = slot;
    return TUN_NAT_PASS;
}

tun_nat_status_t tun_nat_accept(tun_nat_t *nat, size_t slot, uint8_t *out,
                                size_t cap, size_t *out_len) {
    if (out_len) *out_len = 0;
    if (!nat || !out || !out_len || slot >= nat->config.limit) return TUN_NAT_ERR_ARG;
    tun_nat_entry_t *entry = &nat->entries[slot];
    if (entry->state != TUN_NAT_PENDING) return TUN_NAT_ERR_STATE;
    if (entry->syn_len > cap) return TUN_NAT_ERR_SPACE;

    memcpy(out, entry->syn, entry->syn_len);
    packet_view_t view;
    if (view_packet(out, entry->syn_len, &view) != TUN_NAT_DROP_NONE)
        return TUN_NAT_ERR_STATE;
    to_stack(nat, slot, &view, out);

    entry->state = TUN_NAT_ACTIVE;
    entry->syn_len = 0;
    *out_len = view.header_len + view.transport_len;
    return TUN_NAT_OK;
}

/* a stateless reset for a refused syn, the same answer a closed port gives:
   from the original destination, acknowledging the syn so the app accepts it */
tun_nat_status_t tun_nat_reject(tun_nat_t *nat, size_t slot, uint8_t *out,
                                size_t cap, size_t *out_len) {
    if (out_len) *out_len = 0;
    if (!nat || !out || !out_len || slot >= nat->config.limit) return TUN_NAT_ERR_ARG;
    tun_nat_entry_t *entry = &nat->entries[slot];
    if (entry->state != TUN_NAT_PENDING) return TUN_NAT_ERR_STATE;

    packet_view_t syn;
    if (view_packet(entry->syn, entry->syn_len, &syn) != TUN_NAT_DROP_NONE)
        return TUN_NAT_ERR_STATE;
    size_t header_len = syn.address_len == 4 ? 20u : 40u;
    size_t total = header_len + 20u;
    if (cap < total) return TUN_NAT_ERR_SPACE;

    size_t syn_data = syn.transport_len - (size_t)(syn.transport[12] >> 4) * 4u;
    uint32_t acknowledged = read32(syn.transport + 4) + 1u + (uint32_t)syn_data;

    memset(out, 0, total);
    packet_view_t reply;
    memset(&reply, 0, sizeof reply);
    reply.address_len = syn.address_len;
    reply.protocol = PROTO_TCP;
    if (syn.address_len == 4) {
        out[0] = 0x45;
        write16(out + 2, (uint16_t)total);
        out[8] = 64;
        out[9] = PROTO_TCP;
        reply.source = out + 12;
        reply.destination = out + 16;
    } else {
        out[0] = 0x60;
        write16(out + 4, 20);
        out[6] = PROTO_TCP;
        out[7] = 64;
        reply.source = out + 8;
        reply.destination = out + 24;
    }
    memcpy(reply.source, syn.destination, syn.address_len);
    memcpy(reply.destination, syn.source, syn.address_len);
    reply.transport = out + header_len;
    reply.transport_len = 20;
    memcpy(reply.transport, syn.transport + 2, 2);
    memcpy(reply.transport + 2, syn.transport, 2);
    write32(reply.transport + 8, acknowledged);
    reply.transport[12] = 0x50;
    reply.transport[13] = TCP_RST | TCP_ACK;
    transport_checksum_fill(&reply, 16);
    if (syn.address_len == 4) ipv4_header_checksum(out, 20);

    tun_nat_release(nat, slot);
    *out_len = total;
    return TUN_NAT_OK;
}

void tun_nat_close(tun_nat_t *nat, size_t slot) {
    if (!nat || slot >= nat->config.limit) return;
    if (nat->entries[slot].state == TUN_NAT_ACTIVE)
        nat->entries[slot].state = TUN_NAT_DRAINING;
}

void tun_nat_release(tun_nat_t *nat, size_t slot) {
    if (!nat || slot >= nat->config.limit) return;
    if (nat->entries[slot].state == TUN_NAT_FREE) return;
    uint64_t generation = nat->entries[slot].generation;
    memset(&nat->entries[slot], 0, sizeof nat->entries[slot]);
    /* the generation survives the release so a stale id stays stale */
    nat->entries[slot].generation = generation;
    ++nat->closed;
}

size_t tun_nat_expire_pending(tun_nat_t *nat, uint64_t now_ms, uint64_t max_ms,
                              size_t *out_slots, size_t cap) {
    if (!nat) return 0;
    size_t expired = 0;
    for (size_t i = 0; i < nat->config.limit; ++i) {
        tun_nat_entry_t *entry = &nat->entries[i];
        if (entry->state != TUN_NAT_PENDING) continue;
        if (now_ms < entry->touched_ms || now_ms - entry->touched_ms < max_ms) continue;
        if (out_slots && expired < cap) out_slots[expired] = i;
        ++expired;
        ++nat->expired;
        tun_nat_release(nat, i);
    }
    return expired;
}

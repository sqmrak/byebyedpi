#include "route_message.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

static uint16_t u16at(const uint8_t *p, size_t off) {
    uint16_t v;
    memcpy(&v, p + off, sizeof v);
    return v;
}

static int32_t i32at(const uint8_t *p, size_t off) {
    int32_t v;
    memcpy(&v, p + off, sizeof v);
    return v;
}

static route_message_spec_t v4_spec(route_message_type_t type, uint8_t prefix) {
    route_message_spec_t spec;
    memset(&spec, 0, sizeof spec);
    spec.type = type;
    spec.address_len = 4;
    spec.prefix = prefix;
    spec.destination[0] = 203; spec.destination[2] = 113; spec.destination[3] = 7;
    spec.gateway[0] = 192; spec.gateway[1] = 168; spec.gateway[3] = 1;
    spec.target = ROUTE_TARGET_GATEWAY;
    spec.pid = 4242;
    spec.seq = 7;
    return spec;
}

int main(void) {
    uint8_t buf[ROUTE_MESSAGE_MAX];
    size_t len = 0;

    /* an endpoint pin: host route through the physical gateway */
    route_message_spec_t pin = v4_spec(ROUTE_MESSAGE_ADD, 32);
    ok("v4 host route builds",
       route_message_build(&pin, buf, sizeof buf, &len) == ROUTE_MESSAGE_OK);
    ok("v4 host route length is header plus two sockaddrs", len == 92 + 16 + 16);
    ok("msglen matches what was written", u16at(buf, 0) == len);
    ok("version is the darwin routing version", buf[2] == ROUTE_MESSAGE_VERSION);
    ok("type is add", buf[3] == ROUTE_MESSAGE_ADD);
    ok("pid is carried", i32at(buf, 16) == 4242);
    ok("sequence is carried", i32at(buf, 20) == 7);

    /* a host route must not carry a netmask, and must say so in its flags */
    ok("host route addrs are destination and gateway", i32at(buf, 12) == (0x1 | 0x2));
    ok("host route sets up, gateway, host and static",
       i32at(buf, 8) == (0x0001 | 0x0002 | 0x0004 | 0x0800));

    ok("destination sockaddr is a 16 byte inet address",
       buf[92] == 16 && buf[93] == 2);
    ok("destination address bytes land after the port",
       buf[92 + 4] == 203 && buf[92 + 7] == 7);
    ok("gateway sockaddr follows the destination",
       buf[108] == 16 && buf[108 + 4] == 192 && buf[108 + 7] == 1);

    /* a split default: interface route with a netmask and no next hop */
    route_message_spec_t split = v4_spec(ROUTE_MESSAGE_ADD, 1);
    split.target = ROUTE_TARGET_INTERFACE;
    split.interface_index = 14;
    memset(split.destination, 0, sizeof split.destination);
    ok("v4 interface route builds",
       route_message_build(&split, buf, sizeof buf, &len) == ROUTE_MESSAGE_OK);
    ok("interface route carries dst, gateway and netmask",
       i32at(buf, 12) == (0x1 | 0x2 | 0x4));
    ok("interface route does not claim a gateway hop",
       (i32at(buf, 8) & 0x0002) == 0 && (i32at(buf, 8) & 0x0004) == 0);
    ok("interface route length is header, dst, link, netmask",
       len == 92 + 16 + 8 + 16);
    ok("the link sockaddr names the interface index",
       buf[108] == 8 && buf[109] == 18 && u16at(buf, 110) == 14);
    ok("rtm_index names the interface too", u16at(buf, 4) == 14);
    ok("a /1 netmask is 128.0.0.0",
       buf[116 + 4] == 128 && buf[116 + 5] == 0 &&
       buf[116 + 6] == 0 && buf[116 + 7] == 0);

    route_message_spec_t twentyfour = v4_spec(ROUTE_MESSAGE_ADD, 24);
    route_message_build(&twentyfour, buf, sizeof buf, &len);
    ok("a /24 netmask is 255.255.255.0",
       buf[108 + 16 + 4] == 255 && buf[108 + 16 + 5] == 255 &&
       buf[108 + 16 + 6] == 255 && buf[108 + 16 + 7] == 0);

    /* ipv6, the case the old executor refused outright */
    route_message_spec_t v6;
    memset(&v6, 0, sizeof v6);
    v6.type = ROUTE_MESSAGE_ADD;
    v6.address_len = 16;
    v6.prefix = 128;
    v6.destination[0] = 0x20; v6.destination[1] = 0x01; v6.destination[15] = 9;
    v6.gateway[0] = 0xfe; v6.gateway[1] = 0x80; v6.gateway[15] = 1;
    v6.target = ROUTE_TARGET_GATEWAY;
    v6.pid = 1; v6.seq = 2;
    ok("v6 host route builds",
       route_message_build(&v6, buf, sizeof buf, &len) == ROUTE_MESSAGE_OK);
    ok("v6 host route length is header plus two v6 sockaddrs",
       len == 92 + 28 + 28);
    ok("v6 sockaddr is 28 bytes of family 30", buf[92] == 28 && buf[93] == 30);
    ok("v6 address lands after the flowinfo word",
       buf[92 + 8] == 0x20 && buf[92 + 23] == 9);
    ok("v6 gateway follows", buf[120] == 28 && buf[120 + 8] == 0xfe);

    /* a get carries only the destination, plus the interface request */
    route_message_spec_t get = v4_spec(ROUTE_MESSAGE_GET, 32);
    get.want_interface = 1;
    ok("get builds", route_message_build(&get, buf, sizeof buf, &len) ==
       ROUTE_MESSAGE_OK);
    ok("get asks for destination and interface", i32at(buf, 12) == (0x1 | 0x10));
    ok("get length is header, dst and an empty link sockaddr",
       len == 92 + 16 + 8);

    /* refusals */
    route_message_spec_t bad = v4_spec(ROUTE_MESSAGE_ADD, 33);
    ok("a prefix past the family width is refused",
       route_message_build(&bad, buf, sizeof buf, &len) == ROUTE_MESSAGE_ERR_ARG);
    bad = v4_spec(ROUTE_MESSAGE_ADD, 32);
    bad.address_len = 7;
    ok("a bad address length is refused",
       route_message_build(&bad, buf, sizeof buf, &len) == ROUTE_MESSAGE_ERR_ARG);
    bad = v4_spec(ROUTE_MESSAGE_ADD, 24);
    bad.target = ROUTE_TARGET_INTERFACE;
    bad.interface_index = 0;
    ok("an interface route without an index is refused",
       route_message_build(&bad, buf, sizeof buf, &len) == ROUTE_MESSAGE_ERR_ARG);
    route_message_spec_t fits = v4_spec(ROUTE_MESSAGE_ADD, 32);
    ok("a short buffer is refused rather than overrun",
       route_message_build(&fits, buf, 100, &len) == ROUTE_MESSAGE_ERR_SPACE);

    /* replies: the routing socket is shared, so another writer's answer must
       never be read as ours */
    route_message_build(&pin, buf, sizeof buf, &len);
    route_message_reply_t reply;
    ok("our own reply parses",
       route_message_parse(buf, len, 4242, 7, &reply) == ROUTE_MESSAGE_OK);
    ok("the reply carries our pid and sequence",
       reply.pid == 4242 && reply.seq == 7);
    ok("a reply for another sequence is foreign",
       route_message_parse(buf, len, 4242, 8, &reply) == ROUTE_MESSAGE_ERR_FOREIGN);
    ok("a reply from another process is foreign",
       route_message_parse(buf, len, 999, 7, &reply) == ROUTE_MESSAGE_ERR_FOREIGN);

    ok("a truncated reply is rejected",
       route_message_parse(buf, 40, 4242, 7, &reply) == ROUTE_MESSAGE_ERR_TRUNCATED);
    uint8_t wrong_version[ROUTE_MESSAGE_MAX];
    memcpy(wrong_version, buf, len);
    wrong_version[2] = 3;
    ok("a reply of another routing version is rejected",
       route_message_parse(wrong_version, len, 4242, 7, &reply) ==
       ROUTE_MESSAGE_ERR_VERSION);

    /* a msglen larger than what was read must not make the walk run off */
    uint8_t lying[ROUTE_MESSAGE_MAX];
    memcpy(lying, buf, len);
    lying[0] = 0xff; lying[1] = 0x00;
    ok("a reply claiming more than was read is rejected",
       route_message_parse(lying, len, 4242, 7, &reply) ==
       ROUTE_MESSAGE_ERR_TRUNCATED);

    /* a foreign message is recognised as foreign before anything else is
       judged, otherwise another writer's odd message would end our request */
    uint8_t foreign[ROUTE_REPLY_MAX];
    memcpy(foreign, buf, len);
    int32_t other_pid = 5555;
    memcpy(foreign + 16, &other_pid, sizeof other_pid);
    foreign[2] = 3; /* and a routing version we do not read */
    ok("a foreign message of another version is skipped, not an error",
       route_message_parse(foreign, len, 4242, 7, &reply) == ROUTE_MESSAGE_ERR_FOREIGN);

    memcpy(foreign, buf, len);
    memcpy(foreign + 16, &other_pid, sizeof other_pid);
    uint16_t lying_len = 0xffff;
    memcpy(foreign, &lying_len, sizeof lying_len);
    ok("a foreign message with a bad length is skipped too",
       route_message_parse(foreign, len, 4242, 7, &reply) == ROUTE_MESSAGE_ERR_FOREIGN);

    memcpy(foreign, buf, len);
    memcpy(foreign + 16, &other_pid, sizeof other_pid);
    ok("a foreign message cut shorter than a header is skipped",
       route_message_parse(foreign, 30, 4242, 7, &reply) == ROUTE_MESSAGE_ERR_FOREIGN);

    /* a message too short to even carry a pid cannot be claimed as ours */
    ok("a runt message is skipped rather than blamed on us",
       route_message_parse(buf, 8, 4242, 7, &reply) == ROUTE_MESSAGE_ERR_FOREIGN);

    /* an RTM_GET that lands on the default route, as an iphone 4s on ios 5.1.1
       answered it: dst, gateway, an empty netmask that still takes four
       bytes, then the interface. stopping at the empty netmask lost en0 */
    uint8_t via_default[ROUTE_REPLY_MAX];
    memset(via_default, 0, sizeof via_default);
    memcpy(via_default, buf, 92);
    int32_t default_addrs = 0x1 | 0x2 | 0x4 | 0x10 | 0x20;
    memcpy(via_default + 12, &default_addrs, sizeof default_addrs);
    size_t pos = 92;
    via_default[pos] = 16; via_default[pos + 1] = 2;                 /* dst 0.0.0.0 */
    pos += 16;
    via_default[pos] = 16; via_default[pos + 1] = 2;                 /* gateway */
    via_default[pos + 4] = 192; via_default[pos + 5] = 168;
    via_default[pos + 6] = 0; via_default[pos + 7] = 1;
    pos += 16;
    pos += 4;                                                       /* empty netmask */
    via_default[pos] = 20; via_default[pos + 1] = 18;                /* sockaddr_dl */
    via_default[pos + 2] = 6; via_default[pos + 4] = 6;
    via_default[pos + 5] = 3; via_default[pos + 6] = 6;
    memcpy(via_default + pos + 8, "en0", 3);
    pos += 20;
    via_default[pos] = 16; via_default[pos + 1] = 2;                 /* ifa */
    via_default[pos + 4] = 192; via_default[pos + 5] = 168;
    via_default[pos + 7] = 181;
    pos += 16;
    uint16_t default_len = (uint16_t)pos;
    memcpy(via_default, &default_len, sizeof default_len);
    ok("the ios 5 default route reply is 164 bytes", default_len == 164);
    ok("an empty netmask does not hide the interface after it",
       route_message_parse(via_default, default_len, 4242, 7, &reply) ==
       ROUTE_MESSAGE_OK && reply.has_interface &&
       strcmp(reply.ifname, "en0") == 0 && reply.has_gateway &&
       reply.gateway_len == 4 && reply.gateway[0] == 192 && reply.gateway[3] == 1);
    /* a message that ends two bytes into the empty netmask's step */
    uint16_t cut_len = 92 + 16 + 16 + 2;
    memcpy(via_default, &cut_len, sizeof cut_len);
    ok("an empty sockaddr at the very end is still bounded",
       route_message_parse(via_default, cut_len, 4242, 7, &reply) ==
       ROUTE_MESSAGE_ERR_TRUNCATED);

    /* a full sized RTM_GET answer is larger than any request, and must still
       be read rather than refused */
    uint8_t big[ROUTE_REPLY_MAX];
    memset(big, 0, sizeof big);
    memcpy(big, buf, 92);
    int32_t many = 0x1 | 0x2 | 0x4 | 0x8 | 0x10;
    memcpy(big + 12, &many, sizeof many);
    many = 0xff; /* every slot the kernel may report */
    memcpy(big + 12, &many, sizeof many);
    size_t at = 92;
    for (int slot = 0; slot < 4; ++slot) { /* dst, gateway, netmask, genmask */
        big[at] = 28; big[at + 1] = 30;
        at += 28;
    }
    big[at] = 12; big[at + 1] = 18; big[at + 2] = 6; big[at + 5] = 3; /* ifp */
    memcpy(big + at + 8, "pdp", 3);
    at += 12;
    for (int slot = 5; slot < 8; ++slot) { /* author, brd and the rest */
        big[at] = 28; big[at + 1] = 30;
        at += 28;
    }
    uint16_t big_len = (uint16_t)at;
    memcpy(big, &big_len, sizeof big_len);
    ok("a large reply is accepted and its interface read",
       big_len > ROUTE_MESSAGE_MAX &&
       route_message_parse(big, big_len, 4242, 7, &reply) == ROUTE_MESSAGE_OK &&
       reply.has_interface && strcmp(reply.ifname, "pdp") == 0);

    /* the kernel refusing the route is reported, not hidden */
    uint8_t refused[ROUTE_MESSAGE_MAX];
    memcpy(refused, buf, len);
    int32_t err = 17;
    memcpy(refused + 24, &err, sizeof err);
    ok("a kernel errno is reported",
       route_message_parse(refused, len, 4242, 7, &reply) == ROUTE_MESSAGE_ERR_KERNEL &&
       reply.kernel_errno == 17);

    /* the gateway of a reply is read back, which is how the physical gateway
       is discovered before the split defaults go in */
    ok("a gateway address is read back",
       route_message_parse(buf, len, 4242, 7, &reply) == ROUTE_MESSAGE_OK &&
       reply.has_gateway && reply.gateway_len == 4 &&
       reply.gateway[0] == 192 && reply.gateway[3] == 1);

    /* an interface reply: this is what proves an endpoint does not resolve
       back into the tunnel */
    uint8_t ifp[ROUTE_MESSAGE_MAX];
    memset(ifp, 0, sizeof ifp);
    memcpy(ifp, buf, 92);
    int32_t addrs = 0x10;
    memcpy(ifp + 12, &addrs, sizeof addrs);
    uint8_t *dl = ifp + 92;
    dl[0] = 12;   /* len */
    dl[1] = 18;   /* AF_LINK */
    dl[2] = 5; dl[3] = 0; /* index */
    dl[5] = 3;    /* name length */
    memcpy(dl + 8, "en0", 3);
    uint16_t msglen = 92 + 12;
    memcpy(ifp, &msglen, sizeof msglen);
    ok("an interface name is read back",
       route_message_parse(ifp, msglen, 4242, 7, &reply) == ROUTE_MESSAGE_OK &&
       reply.has_interface && strcmp(reply.ifname, "en0") == 0 &&
       reply.interface_index == 5);

    /* a name length longer than the sockaddr must not be copied */
    dl[5] = 200;
    ok("an overlong interface name is ignored",
       route_message_parse(ifp, msglen, 4242, 7, &reply) == ROUTE_MESSAGE_OK &&
       !reply.has_interface);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("all route message checks passed");
    return 0;
}

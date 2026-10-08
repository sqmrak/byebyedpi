#include "tun_plan.h"

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    uint8_t     address[16];
    uint8_t     prefix;
    const char *label;
} reserved_net_t;

/* loopback is deliberately absent: 127/8 and ::1/128 are already more
   specific than a /1 split default, the kernel keeps routing them to lo0 on
   its own, and a route sending them to a gateway would be wrong */
static const reserved_net_t RESERVED_V4[] = {
    { { 169, 254, 0, 0 }, 16, "link-local4" },
    { { 224, 0, 0, 0 }, 4,  "multicast4" },
};

static const reserved_net_t RESERVED_V6[] = {
    { { 0xfe, 0x80 }, 10, "link-local6" },
    { { 0xff }, 8,  "multicast6" },
};

static int addr_len_ok(uint8_t len) {
    return len == 4 || len == 16;
}

static int prefix_ok(uint8_t len, uint8_t prefix) {
    return prefix <= (len == 4 ? 32u : 128u);
}

static int addr_equal(const tun_plan_addr_t *a, const tun_plan_addr_t *b) {
    return a->address_len == b->address_len &&
        memcmp(a->address, b->address, a->address_len) == 0;
}

static tun_plan_status_t append_op(tun_plan_t *plan, tun_plan_kind_t kind,
                                   const uint8_t *address, uint8_t address_len,
                                   uint8_t prefix, tun_plan_via_t via,
                                   const uint8_t *gateway, const char *label) {
    if (plan->count >= TUN_PLAN_MAX_OPS) return TUN_PLAN_ERR_FULL;
    tun_plan_op_entry_t *op = &plan->ops[plan->count];
    memset(op, 0, sizeof *op);
    op->op = TUN_PLAN_OP_ADD;
    op->kind = kind;
    memcpy(op->address, address, address_len);
    op->address_len = address_len;
    op->prefix = prefix;
    op->via = via;
    if (via == TUN_PLAN_VIA_GATEWAY) memcpy(op->gateway, gateway, address_len);
    snprintf(op->ifname, sizeof op->ifname, "%s",
             via == TUN_PLAN_VIA_TUNNEL ? plan->ifname : plan->physical_ifname);
    snprintf(op->label, sizeof op->label, "%s", label);
    ++plan->count;
    return TUN_PLAN_OK;
}

tun_plan_status_t tun_plan_build(const tun_plan_input_t *input, tun_plan_t *out_plan) {
    if (!out_plan) return TUN_PLAN_ERR_ARG;
    memset(out_plan, 0, sizeof *out_plan);
    if (!input || !input->ifname[0] ||
        !memchr(input->ifname, '\0', sizeof input->ifname) ||
        !memchr(input->physical_ifname, '\0', sizeof input->physical_ifname))
        return TUN_PLAN_ERR_ARG;
    int route4 = input->have_gateway4 || input->route_ipv4;
    int route6 = input->enable_ipv6;
    /* every route that is not the tunnel itself needs the interface it leaves
       by, so a plan without one can only ever be half applied */
    if ((route4 || route6 || input->endpoint_count || input->direct_policy_count) &&
        !input->physical_ifname[0])
        return TUN_PLAN_ERR_ARG;
    if (input->have_gateway6 && !route6) return TUN_PLAN_ERR_ARG;
    if (input->endpoint_count > TUN_PLAN_MAX_ENDPOINTS) return TUN_PLAN_ERR_FULL;
    if (input->direct_policy_count > TUN_PLAN_MAX_POLICIES) return TUN_PLAN_ERR_FULL;

    for (size_t i = 0; i < input->endpoint_count; ++i) {
        const tun_plan_addr_t *ep = &input->endpoints[i];
        if (!addr_len_ok(ep->address_len)) return TUN_PLAN_ERR_ADDRESS;
        if (ep->address_len == 16 && !route6) return TUN_PLAN_ERR_ARG;
        for (size_t j = 0; j < i; ++j)
            if (addr_equal(ep, &input->endpoints[j])) return TUN_PLAN_ERR_DUPLICATE;
    }
    for (size_t i = 0; i < input->direct_policy_count; ++i) {
        const tun_plan_cidr_t *p = &input->direct_policies[i];
        if (!addr_len_ok(p->address_len)) return TUN_PLAN_ERR_ADDRESS;
        if (!prefix_ok(p->address_len, p->prefix)) return TUN_PLAN_ERR_PREFIX;
        if (p->address_len == 16 && !route6) return TUN_PLAN_ERR_ARG;
    }

    snprintf(out_plan->ifname, sizeof out_plan->ifname, "%s", input->ifname);
    snprintf(out_plan->physical_ifname, sizeof out_plan->physical_ifname, "%s",
             input->physical_ifname);

    char label[32];
    for (size_t i = 0; i < input->endpoint_count; ++i) {
        const tun_plan_addr_t *ep = &input->endpoints[i];
        const uint8_t *gw = ep->address_len == 4 ? input->gateway4 : input->gateway6;
        int have_route = ep->address_len == 4 ? route4 : route6;
        int have_gw = ep->address_len == 4 ? input->have_gateway4 : input->have_gateway6;
        if (!have_route) return TUN_PLAN_ERR_NO_GATEWAY;
        snprintf(label, sizeof label, "endpoint[%zu]", i);
        tun_plan_status_t st = append_op(out_plan, TUN_PLAN_KIND_ENDPOINT_PIN,
            ep->address, ep->address_len, ep->address_len == 4 ? 32 : 128,
            have_gw ? TUN_PLAN_VIA_GATEWAY : TUN_PLAN_VIA_PHYSICAL, gw, label);
        if (st != TUN_PLAN_OK) return st;
    }

    for (size_t i = 0; i < input->direct_policy_count; ++i) {
        const tun_plan_cidr_t *p = &input->direct_policies[i];
        const uint8_t *gw = p->address_len == 4 ? input->gateway4 : input->gateway6;
        int have_route = p->address_len == 4 ? route4 : route6;
        int have_gw = p->address_len == 4 ? input->have_gateway4 : input->have_gateway6;
        if (!have_route) return TUN_PLAN_ERR_NO_GATEWAY;
        snprintf(label, sizeof label, "direct[%zu]", i);
        tun_plan_status_t st = append_op(out_plan, TUN_PLAN_KIND_DIRECT_POLICY,
            p->address, p->address_len, p->prefix,
            have_gw ? TUN_PLAN_VIA_GATEWAY : TUN_PLAN_VIA_PHYSICAL, gw, label);
        if (st != TUN_PLAN_OK) return st;
    }

    if (route4) {
        for (size_t i = 0; i < sizeof RESERVED_V4 / sizeof RESERVED_V4[0]; ++i) {
            const reserved_net_t *net = &RESERVED_V4[i];
            tun_plan_status_t st = append_op(out_plan, TUN_PLAN_KIND_RESERVED_BYPASS,
                net->address, 4, net->prefix, TUN_PLAN_VIA_PHYSICAL, NULL, net->label);
            if (st != TUN_PLAN_OK) return st;
        }
    }
    if (route6) {
        for (size_t i = 0; i < sizeof RESERVED_V6 / sizeof RESERVED_V6[0]; ++i) {
            const reserved_net_t *net = &RESERVED_V6[i];
            tun_plan_status_t st = append_op(out_plan, TUN_PLAN_KIND_RESERVED_BYPASS,
                net->address, 16, net->prefix, TUN_PLAN_VIA_PHYSICAL, NULL, net->label);
            if (st != TUN_PLAN_OK) return st;
        }
    }

    if (route4) {
        static const uint8_t lower4[4] = { 0, 0, 0, 0 };
        static const uint8_t upper4[4] = { 128, 0, 0, 0 };
        tun_plan_status_t st = append_op(out_plan, TUN_PLAN_KIND_SPLIT_DEFAULT,
            lower4, 4, 1, TUN_PLAN_VIA_TUNNEL, NULL, "split-default[0.0.0.0/1]");
        if (st != TUN_PLAN_OK) return st;
        st = append_op(out_plan, TUN_PLAN_KIND_SPLIT_DEFAULT,
            upper4, 4, 1, TUN_PLAN_VIA_TUNNEL, NULL, "split-default[128.0.0.0/1]");
        if (st != TUN_PLAN_OK) return st;
    }
    if (route6) {
        static const uint8_t lower6[16] = { 0 };
        static const uint8_t upper6[16] = { 0x80 };
        tun_plan_status_t st = append_op(out_plan, TUN_PLAN_KIND_SPLIT_DEFAULT,
            lower6, 16, 1, TUN_PLAN_VIA_TUNNEL, NULL, "split-default[::/1]");
        if (st != TUN_PLAN_OK) return st;
        st = append_op(out_plan, TUN_PLAN_KIND_SPLIT_DEFAULT,
            upper6, 16, 1, TUN_PLAN_VIA_TUNNEL, NULL, "split-default[8000::/1]");
        if (st != TUN_PLAN_OK) return st;
    }

    return TUN_PLAN_OK;
}

tun_plan_status_t tun_plan_rollback(const tun_plan_t *plan, tun_plan_t *out_rollback) {
    if (!out_rollback) return TUN_PLAN_ERR_ARG;
    memset(out_rollback, 0, sizeof *out_rollback);
    if (!plan) return TUN_PLAN_ERR_ARG;
    snprintf(out_rollback->ifname, sizeof out_rollback->ifname, "%s", plan->ifname);
    for (size_t i = plan->count; i > 0; --i) {
        const tun_plan_op_entry_t *src = &plan->ops[i - 1];
        tun_plan_op_entry_t *dst = &out_rollback->ops[out_rollback->count];
        *dst = *src;
        dst->op = TUN_PLAN_OP_DELETE;
        ++out_rollback->count;
    }
    return TUN_PLAN_OK;
}

static const char *kind_name(tun_plan_kind_t kind) {
    switch (kind) {
    case TUN_PLAN_KIND_ENDPOINT_PIN:    return "endpoint-pin";
    case TUN_PLAN_KIND_DIRECT_POLICY:   return "direct-policy";
    case TUN_PLAN_KIND_RESERVED_BYPASS: return "reserved-bypass";
    case TUN_PLAN_KIND_SPLIT_DEFAULT:   return "split-default";
    }
    return "unknown";
}

int tun_plan_render(const tun_plan_t *plan, char *buf, size_t cap) {
    if (!plan || !buf) return -1;
    size_t off = 0;
    for (size_t i = 0; i < plan->count; ++i) {
        const tun_plan_op_entry_t *op = &plan->ops[i];
        int family = op->address_len == 4 ? AF_INET : AF_INET6;
        char addrbuf[INET6_ADDRSTRLEN] = "?";
        inet_ntop(family, op->address, addrbuf, sizeof addrbuf);
        char gwbuf[INET6_ADDRSTRLEN] = "";
        if (op->via == TUN_PLAN_VIA_GATEWAY)
            inet_ntop(family, op->gateway, gwbuf, sizeof gwbuf);
        int n = snprintf(buf + (off < cap ? off : cap), off < cap ? cap - off : 0,
            "%s %s %s %s/%u via %s %s\n",
            op->op == TUN_PLAN_OP_ADD ? "add" : "delete",
            kind_name(op->kind), op->label, addrbuf, op->prefix,
            op->via == TUN_PLAN_VIA_GATEWAY ? "gateway" : "interface",
            op->via == TUN_PLAN_VIA_GATEWAY ? gwbuf : op->ifname);
        if (n < 0) return -1;
        off += (size_t)n;
    }
    return (int)off;
}

#define LEFTOVER_HEADER "byebyedpi-utun-routes 1\n"

int tun_plan_save_leftovers(const tun_plan_t *plan, char *buf, size_t cap) {
    if (!plan || !buf || cap == 0) return -1;
    int n = snprintf(buf, cap, "%s", LEFTOVER_HEADER);
    if (n < 0 || (size_t)n >= cap) return -1;
    size_t off = (size_t)n;
    for (size_t i = 0; i < plan->count; ++i) {
        const tun_plan_op_entry_t *op = &plan->ops[i];
        if (op->via == TUN_PLAN_VIA_TUNNEL || op->preexisting) continue;
        int family = op->address_len == 4 ? AF_INET : AF_INET6;
        char addrbuf[INET6_ADDRSTRLEN], gwbuf[INET6_ADDRSTRLEN] = "-";
        if (!inet_ntop(family, op->address, addrbuf, sizeof addrbuf)) return -1;
        if (op->via == TUN_PLAN_VIA_GATEWAY &&
            !inet_ntop(family, op->gateway, gwbuf, sizeof gwbuf)) return -1;
        n = snprintf(buf + off, cap - off, "%d %d %s %u %s %s %s\n",
                     (int)op->kind, (int)op->via, addrbuf, (unsigned)op->prefix,
                     gwbuf, op->ifname[0] ? op->ifname : "-", op->label);
        if (n < 0 || (size_t)n >= cap - off) return -1;
        off += (size_t)n;
    }
    return (int)off;
}

tun_plan_status_t tun_plan_load_leftovers(const char *text, size_t len,
                                          tun_plan_t *out) {
    if (!text || !out) return TUN_PLAN_ERR_ARG;
    memset(out, 0, sizeof *out);
    size_t header = sizeof LEFTOVER_HEADER - 1;
    if (len < header || memcmp(text, LEFTOVER_HEADER, header) != 0)
        return TUN_PLAN_ERR_ARG;
    size_t pos = header;
    while (pos < len) {
        const char *end = memchr(text + pos, '\n', len - pos);
        if (!end) return TUN_PLAN_ERR_ARG; /* a torn last line is not trusted */
        char line[160];
        size_t line_len = (size_t)(end - (text + pos));
        if (line_len >= sizeof line) return TUN_PLAN_ERR_ARG;
        memcpy(line, text + pos, line_len);
        line[line_len] = '\0';
        pos += line_len + 1;
        if (out->count >= TUN_PLAN_MAX_OPS) return TUN_PLAN_ERR_FULL;

        int kind, via;
        unsigned prefix;
        char addr[INET6_ADDRSTRLEN], gw[INET6_ADDRSTRLEN], ifname[16], label[32];
        if (sscanf(line, "%d %d %45s %u %45s %15s %31s", &kind, &via, addr, &prefix,
                   gw, ifname, label) != 7)
            return TUN_PLAN_ERR_ARG;
        if (kind < TUN_PLAN_KIND_ENDPOINT_PIN || kind > TUN_PLAN_KIND_RESERVED_BYPASS ||
            (via != TUN_PLAN_VIA_GATEWAY && via != TUN_PLAN_VIA_PHYSICAL))
            return TUN_PLAN_ERR_ARG;
        tun_plan_op_entry_t *op = &out->ops[out->count];
        int family = strchr(addr, ':') ? AF_INET6 : AF_INET;
        op->address_len = family == AF_INET ? 4 : 16;
        if (inet_pton(family, addr, op->address) != 1) return TUN_PLAN_ERR_ADDRESS;
        if (prefix > (op->address_len == 4 ? 32u : 128u)) return TUN_PLAN_ERR_PREFIX;
        if (via == TUN_PLAN_VIA_GATEWAY && inet_pton(family, gw, op->gateway) != 1)
            return TUN_PLAN_ERR_ADDRESS;
        if (strcmp(ifname, "-") == 0) return TUN_PLAN_ERR_ARG;
        op->op = TUN_PLAN_OP_ADD;
        op->kind = (tun_plan_kind_t)kind;
        op->via = (tun_plan_via_t)via;
        op->prefix = (uint8_t)prefix;
        snprintf(op->ifname, sizeof op->ifname, "%s", ifname);
        snprintf(op->label, sizeof op->label, "%s", label);
        ++out->count;
    }
    return TUN_PLAN_OK;
}

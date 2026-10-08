#include "tun_plan.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

static size_t count_kind(const tun_plan_t *plan, tun_plan_kind_t kind) {
    size_t n = 0;
    for (size_t i = 0; i < plan->count; ++i)
        if (plan->ops[i].kind == kind) ++n;
    return n;
}

static void set_v4(tun_plan_addr_t *a, uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3) {
    a->address_len = 4;
    a->address[0] = a0; a->address[1] = a1; a->address[2] = a2; a->address[3] = a3;
}

int main(void) {
    tun_plan_input_t input;
    tun_plan_t plan;

    /* minimal v4-only plan: one endpoint, physical gateway known */
    memset(&input, 0, sizeof input);
    snprintf(input.ifname, sizeof input.ifname, "utun3");
    snprintf(input.physical_ifname, sizeof input.physical_ifname, "en0");
    input.have_gateway4 = 1;
    input.gateway4[0] = 10; input.gateway4[1] = 0; input.gateway4[2] = 0; input.gateway4[3] = 1;
    set_v4(&input.endpoints[0], 203, 0, 113, 5);
    input.endpoint_count = 1;

    ok("v4 build ok", tun_plan_build(&input, &plan) == TUN_PLAN_OK);
    ok("v4 endpoint pin present", count_kind(&plan, TUN_PLAN_KIND_ENDPOINT_PIN) == 1);
    ok("v4 reserved bypass present", count_kind(&plan, TUN_PLAN_KIND_RESERVED_BYPASS) == 2);
    ok("v4 split default present", count_kind(&plan, TUN_PLAN_KIND_SPLIT_DEFAULT) == 2);
    ok("no v6 ops without enable_ipv6", plan.count == 1 + 2 + 2);

    /* loopback is never planned: it is already more specific than a split
       default and has no business going to a gateway */
    int loopback_planned = 0;
    for (size_t i = 0; i < plan.count; ++i)
        if (plan.ops[i].address_len == 4 && plan.ops[i].address[0] == 127)
            loopback_planned = 1;
    ok("loopback is not routed by the plan", !loopback_planned);

    /* every reserved net is an interface route on the physical link, because
       link local and multicast have no next hop to be handed to */
    int reserved_all_physical = 1;
    for (size_t i = 0; i < plan.count; ++i) {
        const tun_plan_op_entry_t *op = &plan.ops[i];
        if (op->kind != TUN_PLAN_KIND_RESERVED_BYPASS) continue;
        if (op->via != TUN_PLAN_VIA_PHYSICAL ||
            strcmp(op->ifname, "en0") != 0)
            reserved_all_physical = 0;
    }
    ok("reserved nets stay on the physical interface", reserved_all_physical);

    /* the tunnel routes name the tunnel, not the physical link */
    int split_on_tunnel = 1;
    for (size_t i = 0; i < plan.count; ++i) {
        const tun_plan_op_entry_t *op = &plan.ops[i];
        if (op->kind != TUN_PLAN_KIND_SPLIT_DEFAULT) continue;
        if (op->via != TUN_PLAN_VIA_TUNNEL || strcmp(op->ifname, "utun3") != 0)
            split_on_tunnel = 0;
    }
    ok("split defaults leave by the tunnel", split_on_tunnel);

    /* a plan that needs the physical link but was not told its name cannot
       be applied, so it is refused rather than built half usable */
    tun_plan_input_t nameless = input;
    nameless.physical_ifname[0] = '\0';
    tun_plan_t unused;
    ok("a missing physical interface is refused",
       tun_plan_build(&nameless, &unused) == TUN_PLAN_ERR_ARG);

    /* endpoint pin must land before any split default, so the server address
       can never transiently route into the tunnel it depends on */
    size_t first_split = SIZE_MAX, first_endpoint = SIZE_MAX;
    for (size_t i = 0; i < plan.count; ++i) {
        if (plan.ops[i].kind == TUN_PLAN_KIND_SPLIT_DEFAULT && first_split == SIZE_MAX)
            first_split = i;
        if (plan.ops[i].kind == TUN_PLAN_KIND_ENDPOINT_PIN && first_endpoint == SIZE_MAX)
            first_endpoint = i;
    }
    ok("endpoint pin precedes split default", first_endpoint < first_split);
    ok("endpoint pin is a host route", plan.ops[first_endpoint].prefix == 32);
    ok("endpoint pin goes via gateway", plan.ops[first_endpoint].via == TUN_PLAN_VIA_GATEWAY);
    ok("split default goes via tunnel", plan.ops[first_split].via == TUN_PLAN_VIA_TUNNEL);

    /* rollback is the add sequence reversed, as deletes */
    tun_plan_t rollback;
    ok("rollback ok", tun_plan_rollback(&plan, &rollback) == TUN_PLAN_OK);
    ok("rollback same length", rollback.count == plan.count);
    int reversed_matches = 1;
    for (size_t i = 0; i < plan.count; ++i) {
        const tun_plan_op_entry_t *a = &plan.ops[i];
        const tun_plan_op_entry_t *b = &rollback.ops[plan.count - 1 - i];
        if (a->kind != b->kind || a->address_len != b->address_len ||
            memcmp(a->address, b->address, a->address_len) != 0 ||
            b->op != TUN_PLAN_OP_DELETE)
            reversed_matches = 0;
    }
    ok("rollback reverses add order", reversed_matches);

    /* v6 enabled with both gateways doubles the reserved/split sets */
    memset(&input, 0, sizeof input);
    snprintf(input.ifname, sizeof input.ifname, "utun3");
    snprintf(input.physical_ifname, sizeof input.physical_ifname, "en0");
    input.have_gateway4 = 1;
    input.gateway4[0] = 10; input.gateway4[3] = 1;
    input.have_gateway6 = 1;
    input.gateway6[0] = 0xfe; input.gateway6[1] = 0x80; input.gateway6[15] = 1;
    input.enable_ipv6 = 1;
    ok("v6 build ok", tun_plan_build(&input, &plan) == TUN_PLAN_OK);
    ok("v6 reserved doubles", count_kind(&plan, TUN_PLAN_KIND_RESERVED_BYPASS) == 4);
    ok("v6 split doubles", count_kind(&plan, TUN_PLAN_KIND_SPLIT_DEFAULT) == 4);

    /* endpoint without a matching gateway family is rejected, not silently dropped */
    memset(&input, 0, sizeof input);
    snprintf(input.ifname, sizeof input.ifname, "utun3");
    snprintf(input.physical_ifname, sizeof input.physical_ifname, "en0");
    set_v4(&input.endpoints[0], 203, 0, 113, 5);
    input.endpoint_count = 1;
    ok("missing gateway rejected", tun_plan_build(&input, &plan) == TUN_PLAN_ERR_NO_GATEWAY);

    /* point-to-point physical routes have no IP next hop; the server pin and
       direct policy must stay on that interface before split defaults go up */
    input.route_ipv4 = 1;
    input.direct_policies[0].address_len = 4;
    input.direct_policies[0].address[0] = 192;
    input.direct_policies[0].address[1] = 0;
    input.direct_policies[0].address[2] = 2;
    input.direct_policies[0].prefix = 24;
    input.direct_policy_count = 1;
    ok("interface-only v4 plan builds", tun_plan_build(&input, &plan) == TUN_PLAN_OK);
    ok("interface-only endpoint is pinned physically",
       plan.ops[0].kind == TUN_PLAN_KIND_ENDPOINT_PIN &&
       plan.ops[0].via == TUN_PLAN_VIA_PHYSICAL &&
       strcmp(plan.ops[0].ifname, "en0") == 0);
    ok("interface-only direct policy stays physical",
       plan.ops[1].kind == TUN_PLAN_KIND_DIRECT_POLICY &&
       plan.ops[1].via == TUN_PLAN_VIA_PHYSICAL);
    ok("interface-only v4 keeps split defaults",
       count_kind(&plan, TUN_PLAN_KIND_SPLIT_DEFAULT) == 2);

    input.enable_ipv6 = 1;
    input.endpoints[1].address_len = 16;
    input.endpoints[1].address[0] = 0x20;
    input.endpoints[1].address[1] = 0x01;
    input.endpoints[1].address[2] = 0x0d;
    input.endpoints[1].address[3] = 0xb8;
    input.endpoints[1].address[15] = 7;
    input.endpoint_count = 2;
    ok("interface-only v6 plan builds", tun_plan_build(&input, &plan) == TUN_PLAN_OK);
    ok("interface-only v6 endpoint is pinned physically",
       plan.ops[1].kind == TUN_PLAN_KIND_ENDPOINT_PIN &&
       plan.ops[1].via == TUN_PLAN_VIA_PHYSICAL);
    ok("interface-only v6 keeps split defaults",
       count_kind(&plan, TUN_PLAN_KIND_SPLIT_DEFAULT) == 4);

    input.physical_ifname[0] = '\0';
    ok("interface-only route without a physical name is rejected",
       tun_plan_build(&input, &plan) == TUN_PLAN_ERR_ARG);

    memset(input.ifname, 'x', sizeof input.ifname);
    ok("unterminated tunnel name is rejected",
       tun_plan_build(&input, &plan) == TUN_PLAN_ERR_ARG);

    /* duplicate endpoint addresses are rejected rather than producing two
       identical host routes */
    memset(&input, 0, sizeof input);
    snprintf(input.ifname, sizeof input.ifname, "utun3");
    snprintf(input.physical_ifname, sizeof input.physical_ifname, "en0");
    input.have_gateway4 = 1;
    input.gateway4[3] = 1;
    set_v4(&input.endpoints[0], 203, 0, 113, 5);
    set_v4(&input.endpoints[1], 203, 0, 113, 5);
    input.endpoint_count = 2;
    ok("duplicate endpoint rejected", tun_plan_build(&input, &plan) == TUN_PLAN_ERR_DUPLICATE);

    /* a malformed address length is rejected, never silently truncated or padded */
    memset(&input, 0, sizeof input);
    snprintf(input.ifname, sizeof input.ifname, "utun3");
    snprintf(input.physical_ifname, sizeof input.physical_ifname, "en0");
    input.have_gateway4 = 1;
    input.gateway4[3] = 1;
    input.endpoints[0].address_len = 5;
    input.endpoint_count = 1;
    ok("bad address length rejected", tun_plan_build(&input, &plan) == TUN_PLAN_ERR_ADDRESS);

    /* an out of range prefix on a direct policy is rejected */
    memset(&input, 0, sizeof input);
    snprintf(input.ifname, sizeof input.ifname, "utun3");
    snprintf(input.physical_ifname, sizeof input.physical_ifname, "en0");
    input.have_gateway4 = 1;
    input.gateway4[3] = 1;
    input.direct_policies[0].address_len = 4;
    input.direct_policies[0].prefix = 33;
    input.direct_policy_count = 1;
    ok("bad prefix rejected", tun_plan_build(&input, &plan) == TUN_PLAN_ERR_PREFIX);

    /* an ipv6 endpoint without enable_ipv6 is rejected rather than silently
       treated as a v4 route with garbage bytes */
    memset(&input, 0, sizeof input);
    snprintf(input.ifname, sizeof input.ifname, "utun3");
    snprintf(input.physical_ifname, sizeof input.physical_ifname, "en0");
    input.have_gateway4 = 1;
    input.gateway4[3] = 1;
    input.have_gateway6 = 1;
    input.gateway6[15] = 1;
    input.endpoints[0].address_len = 16;
    input.endpoint_count = 1;
    ok("v6 endpoint without enable_ipv6 rejected",
       tun_plan_build(&input, &plan) == TUN_PLAN_ERR_ARG);

    /* maximum endpoint count still fits, one more overflows */
    memset(&input, 0, sizeof input);
    snprintf(input.ifname, sizeof input.ifname, "utun3");
    snprintf(input.physical_ifname, sizeof input.physical_ifname, "en0");
    input.have_gateway4 = 1;
    input.gateway4[3] = 1;
    for (size_t i = 0; i < TUN_PLAN_MAX_ENDPOINTS; ++i)
        set_v4(&input.endpoints[i], 203, 0, 113, (uint8_t)(1 + i));
    input.endpoint_count = TUN_PLAN_MAX_ENDPOINTS;
    ok("max endpoints build ok", tun_plan_build(&input, &plan) == TUN_PLAN_OK);
    ok("max endpoints all present",
       count_kind(&plan, TUN_PLAN_KIND_ENDPOINT_PIN) == TUN_PLAN_MAX_ENDPOINTS);

    input.endpoint_count = TUN_PLAN_MAX_ENDPOINTS + 1;
    ok("over max endpoints rejected", tun_plan_build(&input, &plan) == TUN_PLAN_ERR_FULL);

    /* an empty input still returns a defined, zeroed plan on failure */
    tun_plan_t zeroed;
    memset(&zeroed, 0xaa, sizeof zeroed);
    ok("null input zeroes the plan",
       tun_plan_build(NULL, &zeroed) == TUN_PLAN_ERR_ARG && zeroed.count == 0);

    /* render never overflows a short buffer and reports the full length like snprintf */
    memset(&input, 0, sizeof input);
    snprintf(input.ifname, sizeof input.ifname, "utun3");
    snprintf(input.physical_ifname, sizeof input.physical_ifname, "en0");
    input.have_gateway4 = 1;
    input.gateway4[3] = 1;
    set_v4(&input.endpoints[0], 203, 0, 113, 5);
    input.endpoint_count = 1;
    tun_plan_build(&input, &plan);
    char tiny[8];
    int want = tun_plan_render(&plan, tiny, sizeof tiny);
    ok("render reports full length even when truncated", want > (int)sizeof tiny);
    char full[4096];
    int got = tun_plan_render(&plan, full, sizeof full);
    ok("render fits and matches its own length", got > 0 && (size_t)got == strlen(full));

    /* leftovers after a killed daemon: only the routes that outlive the
       utun interface, minus a bypass the system already had */
    memset(&input, 0, sizeof input);
    snprintf(input.ifname, sizeof input.ifname, "utun0");
    snprintf(input.physical_ifname, sizeof input.physical_ifname, "en0");
    input.have_gateway4 = 1;
    input.gateway4[0] = 192; input.gateway4[1] = 168; input.gateway4[3] = 1;
    input.route_ipv4 = 1;
    set_v4(&input.endpoints[0], 104, 249, 18, 221);
    input.endpoint_count = 1;
    input.enable_ipv6 = 1;
    ok("leftover fixture builds", tun_plan_build(&input, &plan) == TUN_PLAN_OK);
    size_t outliving = 0;
    for (size_t i = 0; i < plan.count; ++i) {
        if (plan.ops[i].kind == TUN_PLAN_KIND_RESERVED_BYPASS &&
            plan.ops[i].address_len == 4 && plan.ops[i].address[0] == 169) {
            plan.ops[i].preexisting = 1;
            continue;
        }
        if (plan.ops[i].via != TUN_PLAN_VIA_TUNNEL) ++outliving;
    }
    char saved[2048];
    int saved_len = tun_plan_save_leftovers(&plan, saved, sizeof saved);
    tun_plan_t back;
    ok("leftovers save", saved_len > 0);
    ok("leftovers load", saved_len > 0 &&
       tun_plan_load_leftovers(saved, (size_t)saved_len, &back) == TUN_PLAN_OK);
    ok("only routes that outlive the tunnel are kept", back.count == outliving);
    int pin_back = 0, tunnel_back = 0, system_back = 0;
    for (size_t i = 0; i < back.count; ++i) {
        const tun_plan_op_entry_t *op = &back.ops[i];
        if (op->kind == TUN_PLAN_KIND_ENDPOINT_PIN && op->via == TUN_PLAN_VIA_GATEWAY &&
            op->address[0] == 104 && op->address[3] == 221 && op->prefix == 32 &&
            op->gateway[0] == 192 && op->gateway[3] == 1 && strcmp(op->ifname, "en0") == 0)
            pin_back = 1;
        if (op->via == TUN_PLAN_VIA_TUNNEL) tunnel_back = 1;
        if (op->address_len == 4 && op->address[0] == 169) system_back = 1;
    }
    ok("the server pin comes back intact", pin_back);
    ok("no tunnel route is kept", !tunnel_back);
    ok("the system's own bypass route is never listed", !system_back);
    ok("a short buffer is refused, not truncated",
       tun_plan_save_leftovers(&plan, saved, 24) == -1);
    ok("a torn last line is refused",
       tun_plan_load_leftovers(saved, (size_t)saved_len - 1, &back) != TUN_PLAN_OK);
    static const char tunnel_line[] = "byebyedpi-utun-routes 1\n3 0 0.0.0.0 1 - utun0 x\n";
    ok("a tunnel route in the file is refused",
       tun_plan_load_leftovers(tunnel_line, sizeof tunnel_line - 1, &back) != TUN_PLAN_OK);
    static const char wide_prefix[] = "byebyedpi-utun-routes 1\n0 1 10.0.0.1 33 10.0.0.2 en0 x\n";
    ok("an impossible prefix is refused",
       tun_plan_load_leftovers(wide_prefix, sizeof wide_prefix - 1, &back) ==
       TUN_PLAN_ERR_PREFIX);
    static const char other_version[] = "byebyedpi-utun-routes 2\n";
    ok("another file version is refused",
       tun_plan_load_leftovers(other_version, sizeof other_version - 1, &back) != TUN_PLAN_OK);
    static const char empty_list[] = "byebyedpi-utun-routes 1\n";
    ok("an empty list loads as nothing to undo",
       tun_plan_load_leftovers(empty_list, sizeof empty_list - 1, &back) == TUN_PLAN_OK &&
       back.count == 0);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("all tun_plan checks passed");
    return 0;
}

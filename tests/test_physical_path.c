#include "../daemon/bye_backend.c"
#include "check.h"

static utun_route_path_t ipv4, ipv6;
static int route4_error, route6_error;
static const char *service_ifname, *service_router;

/* supplied kernel replies and configd fields leave the host network untouched */
int utun_route_system_path(const uint8_t *address, uint8_t len,
                           utun_route_path_t *out, utun_route_error_t *error) {
    CHECK(address && (len == 4 || len == 16));
    memset(error, 0, sizeof *error);
    memset(out, 0, sizeof *out);
    if (len == 4 ? route4_error : route6_error) {
        error->code = ENETUNREACH;
        strcpy(error->message, "no route to the public address");
        return -1;
    }
    *out = len == 4 ? ipv4 : ipv6;
    return 0;
}

int bye_iface_brighton_link(const char *ifname, const uint8_t *gateway4) {
    return bye_route_brighton_link_matches(ifname, gateway4, service_ifname, service_router);
}

static void test_service_match(void) {
    const uint8_t gateway[4] = { 10, 0, 2, 2 };
    const struct { const char *name, *service, *router; int matches; } cases[] = {
        { "utun0", "utun0", "10.0.2.2", 1 },
        { "utun7", "utun7", "10.0.2.2", 1 },
        { "utun0", "utun1", "10.0.2.2", 0 },
        { "utun0", "utun0", "10.0.2.3", 0 },
        { "utun0", "utun0", "10.0.2.2x", 0 },
        { "utun0", "utun0", "::1", 0 },
        { "", "", "10.0.2.2", 0 },
        { "abcdefghijklmnop", "abcdefghijklmnop", "10.0.2.2", 0 },
        { NULL, "utun0", "10.0.2.2", 0 },
        { "utun0", NULL, "10.0.2.2", 0 },
        { "utun0", "utun0", NULL, 0 },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i)
        CHECK(bye_route_brighton_link_matches(cases[i].name, gateway,
                                             cases[i].service, cases[i].router) == cases[i].matches);
    CHECK(!bye_route_brighton_link_matches("utun0", NULL, "utun0", "10.0.2.2"));
}

int main(void) {
    test_service_match();
    ipv4.address_len = 4;
    ipv4.via_gateway = 1;
    memcpy(ipv4.gateway, (uint8_t[]){ 10, 0, 2, 2 }, 4);
    strcpy(ipv4.ifname, "utun0");
    service_ifname = "utun0";
    service_router = "10.0.2.2";
    route6_error = 1;
    tun_plan_input_t input;
    char error[160];
    CHECK(physical_path(&input, error, sizeof error) == 0);
    CHECK(!strcmp(input.physical_ifname, "utun0"));
    CHECK(input.route_ipv4 && input.have_gateway4 && !input.enable_ipv6);
    CHECK(!memcmp(input.gateway4, ipv4.gateway, 4));
    strcpy(input.ifname, "utun1");
    tun_plan_t plan;
    CHECK(tun_plan_build(&input, &plan) == TUN_PLAN_OK);
    CHECK(plan.count == 4);
    for (size_t i = 0; i < plan.count; ++i) {
        CHECK(plan.ops[i].address_len == 4);
        CHECK(!strcmp(plan.ops[i].ifname,
                      plan.ops[i].via == TUN_PLAN_VIA_TUNNEL ? "utun1" : "utun0"));
    }

    service_ifname = NULL;
    CHECK(physical_path(&input, error, sizeof error) == -1);
    CHECK(strstr(error, "another tunnel (utun0)") != NULL);
    service_ifname = "utun1";
    CHECK(physical_path(&input, error, sizeof error) == -1);
    service_ifname = "utun0";
    service_router = "10.0.2.3";
    CHECK(physical_path(&input, error, sizeof error) == -1);
    service_router = "10.0.2.2";
    ipv4.via_gateway = 0;
    CHECK(physical_path(&input, error, sizeof error) == -1);
    ipv4.via_gateway = 1;

    strcpy(ipv4.ifname, "en5");
    CHECK(physical_path(&input, error, sizeof error) == 0);
    CHECK(input.enable_ipv6 && !strcmp(input.physical_ifname, "en5"));
    route6_error = 0;
    ipv6.address_len = 16;
    strcpy(ipv6.ifname, "en5");
    CHECK(physical_path(&input, error, sizeof error) == 0 && input.enable_ipv6);
    strcpy(ipv6.ifname, "pdp_ip0");
    CHECK(physical_path(&input, error, sizeof error) == -1);
    CHECK(!strcmp(error, "IPv4 and IPv6 leave through different physical interfaces"));
    route4_error = 1;
    CHECK(physical_path(&input, error, sizeof error) == -1);
    CHECK(!strcmp(error, "no route to the public address"));
    if (!failed) puts("test_physical_path ok");
    return failed;
}

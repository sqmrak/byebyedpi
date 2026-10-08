#include "bye_tg.h"
#include "bye_route.h"

#include <string.h>

#include "check.h"

static int tg4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    uint8_t addr[4] = { a, b, c, d };
    return bye_tg_is_address(addr, 4);
}

static void test_tunnel_names(void) {
    CHECK(bye_route_is_tunnel_ifname("utun3") && bye_route_is_tunnel_ifname("ipsec0"));
    CHECK(bye_route_is_tunnel_ifname("ppp0") && bye_route_is_tunnel_ifname("tun1"));
    CHECK(!bye_route_is_tunnel_ifname("en0") && !bye_route_is_tunnel_ifname("pdp_ip0"));
    CHECK(!bye_route_is_tunnel_ifname("awdl0") && !bye_route_is_tunnel_ifname("") &&
          !bye_route_is_tunnel_ifname(NULL));
}

static void test_ranges(void) {
    CHECK(tg4(149, 154, 160, 0) && tg4(149, 154, 167, 51) && tg4(149, 154, 175, 255));
    CHECK(!tg4(149, 154, 159, 255) && !tg4(149, 154, 176, 0));
    CHECK(tg4(91, 108, 4, 0) && tg4(91, 108, 7, 255) && !tg4(91, 108, 3, 255));
    CHECK(tg4(91, 108, 8, 1) && tg4(91, 108, 11, 255) && !tg4(91, 108, 24, 0));
    CHECK(tg4(91, 108, 12, 1) && tg4(91, 108, 23, 255));
    CHECK(tg4(91, 108, 56, 0) && tg4(91, 108, 59, 255) && !tg4(91, 108, 60, 0));
    CHECK(tg4(91, 105, 192, 0) && tg4(91, 105, 193, 255) && !tg4(91, 105, 194, 0));
    CHECK(!tg4(91, 105, 191, 255));
    CHECK(tg4(185, 76, 151, 7) && !tg4(185, 76, 150, 255) && !tg4(185, 76, 152, 0));
    CHECK(!tg4(8, 8, 8, 8) && !tg4(10, 0, 0, 1) && !tg4(0, 0, 0, 0));

    /* every datacenter's own address is inside the ranges */
    static const int dcs[] = { 1, 2, 3, 4, 5, BYE_TG_DC_CDN };
    for (size_t i = 0; i < 6; ++i) {
        uint8_t a[4];
        CHECK(bye_tg_dc_address(dcs[i], a) == 0);
        CHECK(bye_tg_is_address(a, 4));
    }

    uint8_t v6[16] = { 0x20, 0x01, 0x0b, 0x28, 0xf2, 0x3c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a };
    CHECK(bye_tg_is_address(v6, 16));
    v6[5] = 0x3d; CHECK(bye_tg_is_address(v6, 16));
    v6[5] = 0x3f; CHECK(bye_tg_is_address(v6, 16));
    v6[5] = 0x3e; CHECK(!bye_tg_is_address(v6, 16));
    v6[5] = 0x3c; v6[3] = 0x29; CHECK(!bye_tg_is_address(v6, 16));
    uint8_t v6b[16] = { 0x20, 0x01, 0x06, 0x7c, 0x04, 0xe8, 0xff };
    CHECK(bye_tg_is_address(v6b, 16));
    v6b[4] = 0x04; v6b[5] = 0xe9; CHECK(!bye_tg_is_address(v6b, 16));
    uint8_t v6c[16] = { 0x2a, 0x0a, 0xf2, 0x80, 1, 2, 3 };
    CHECK(bye_tg_is_address(v6c, 16));
    v6c[3] = 0x81; CHECK(!bye_tg_is_address(v6c, 16));
    uint8_t v6d[16] = { 0x2a, 0x0a, 0xf2, 0x7f };
    CHECK(!bye_tg_is_address(v6d, 16));

    CHECK(!bye_tg_is_address(NULL, 4) && !bye_tg_is_address(v6, 5) && !bye_tg_is_address(v6, 0));
}

static void test_hosts(void) {
    char host[BYE_TG_WS_HOST_MAX];
    CHECK(bye_tg_ws_host(2, 0, 0, host, sizeof host) == 0 && !strcmp(host, "kws2.web.telegram.org"));
    CHECK(bye_tg_ws_host(2, 0, 1, host, sizeof host) == 0 && !strcmp(host, "kws2-1.web.telegram.org"));
    CHECK(bye_tg_ws_host(4, 1, 0, host, sizeof host) == 0 && !strcmp(host, "kws4-1.web.telegram.org"));
    CHECK(bye_tg_ws_host(4, 1, 1, host, sizeof host) == 0 && !strcmp(host, "kws4.web.telegram.org"));
    CHECK(bye_tg_ws_host(BYE_TG_DC_CDN, 0, 0, host, sizeof host) == 0 &&
          !strcmp(host, "kws2.web.telegram.org"));
    CHECK(bye_tg_ws_host(BYE_TG_DC_CDN, 1, 0, host, sizeof host) == 0 &&
          !strcmp(host, "kws2-1.web.telegram.org"));
    CHECK(bye_tg_ws_host(2, 0, 2, host, sizeof host) == -1);
    CHECK(bye_tg_ws_host(6, 0, 0, host, sizeof host) == -1);
    CHECK(bye_tg_ws_host(0, 0, 0, host, sizeof host) == -1);
    CHECK(bye_tg_ws_host(-2, 0, 0, host, sizeof host) == -1);
    CHECK(bye_tg_ws_host(2, 0, 0, host, 10) == -1);
    CHECK(bye_tg_ws_host(2, 0, 0, NULL, 10) == -1);
    CHECK(bye_tg_dc_known(1) && bye_tg_dc_known(203) && !bye_tg_dc_known(0) && !bye_tg_dc_known(6));
    uint8_t a[4];
    CHECK(bye_tg_dc_address(2, a) == 0 && a[0] == 149 && a[1] == 154 && a[2] == 167 && a[3] == 51);
    CHECK(bye_tg_dc_address(9, a) == -1);
}

static void test_gateways(void) {
    bye_tg_ws_addresses_t resolved;
    memset(&resolved, 0, sizeof resolved);
    bye_tg_gateway_t gateways[BYE_TG_GATEWAYS_MAX];
    CHECK(bye_tg_gateways(2, 0, &resolved, gateways, BYE_TG_GATEWAYS_MAX) == 2);
    CHECK(!strcmp(gateways[0].host, "kws2.web.telegram.org"));
    CHECK(gateways[0].address[3] == 51);
    CHECK(bye_tg_gateway_next(gateways, 2, 0, 1) == 2);
    CHECK(bye_tg_gateway_next(gateways, 2, 0, 0) == 1);
    for (size_t i = 0; i < 2; ++i) {
        resolved.dc[1][i].valid = 1;
        memcpy(resolved.dc[1][i].address, (const uint8_t[]){149, 154, 167, 99}, 4);
    }
    CHECK(bye_tg_gateways(2, 0, &resolved, gateways, BYE_TG_GATEWAYS_MAX) == 4);
    CHECK(gateways[0].address[3] == 99 && gateways[2].address[3] == 51);
    CHECK(bye_tg_gateway_next(gateways, 4, 0, 1) == 2);
    CHECK(bye_tg_gateway_next(gateways, 4, 2, 1) == 4);
    CHECK(bye_tg_gateways(203, 1, &resolved, gateways, BYE_TG_GATEWAYS_MAX) == 4);
    CHECK(!strcmp(gateways[0].host, "kws2-1.web.telegram.org"));
    CHECK(gateways[0].address[3] == 99);
    memcpy(resolved.dc[1][0].address, (const uint8_t[]){149, 154, 167, 51}, 4);
    resolved.dc[1][1].valid = 0;
    CHECK(bye_tg_gateways(2, 0, &resolved, gateways, BYE_TG_GATEWAYS_MAX) == 2);
    CHECK(bye_tg_gateways(2, 1, &resolved, gateways, BYE_TG_GATEWAYS_MAX) == 2);
    CHECK(!strcmp(gateways[0].host, "kws2.web.telegram.org"));
    CHECK(bye_tg_gateways(0, 0, &resolved, gateways, BYE_TG_GATEWAYS_MAX) == 0);
    CHECK(bye_tg_gateways(6, 0, &resolved, gateways, BYE_TG_GATEWAYS_MAX) == 0);
    CHECK(bye_tg_gateways(2, 0, NULL, gateways, BYE_TG_GATEWAYS_MAX) == 2);
    CHECK(bye_tg_gateways(2, 0, &resolved, NULL, BYE_TG_GATEWAYS_MAX) == 0);
    CHECK(bye_tg_gateways(2, 0, &resolved, gateways, 1) == 0);
    CHECK(bye_tg_gateways(2, 0, &resolved, gateways, 0) == 0);
    CHECK(bye_tg_gateway_next(gateways, 2, 2, 1) == 2);
    CHECK(bye_tg_gateway_next(NULL, 2, 0, 1) == 2);
}

static void test_route(void) {
    bye_route_policy_t on = { 1 }, off = { 0 };
    uint8_t tg[4] = { 149, 154, 167, 51 };
    uint8_t web[4] = { 93, 184, 216, 34 };
    uint8_t lan[4] = { 192, 168, 1, 10 };

    CHECK(bye_route_tcp(&on, tg, 4, 443) == BYE_PATH_TELEGRAM);
    CHECK(bye_route_tcp(&on, tg, 4, 80) == BYE_PATH_TELEGRAM);
    CHECK(bye_route_tcp(&on, tg, 4, 5222) == BYE_PATH_TELEGRAM);
    CHECK(bye_route_tcp(&on, tg, 4, 8080) == BYE_PATH_DIRECT);
    CHECK(bye_route_tcp(&off, tg, 4, 443) == BYE_PATH_DESYNC);
    CHECK(bye_route_tcp(&off, tg, 4, 5222) == BYE_PATH_DIRECT);
    CHECK(bye_route_tcp(&on, web, 4, 443) == BYE_PATH_DESYNC);
    CHECK(bye_route_tcp(&on, web, 4, 80) == BYE_PATH_DESYNC);
    CHECK(bye_route_tcp(&on, web, 4, 5222) == BYE_PATH_DIRECT);
    CHECK(bye_route_tcp(&on, web, 4, 22) == BYE_PATH_DIRECT);
    CHECK(bye_route_tcp(&on, lan, 4, 443) == BYE_PATH_DIRECT);
    CHECK(bye_route_tcp(NULL, web, 4, 443) == BYE_PATH_DIRECT);
    CHECK(bye_route_tcp(&on, NULL, 4, 443) == BYE_PATH_DIRECT);

    uint8_t v6[16] = { 0x20, 0x01, 0x0b, 0x28, 0xf2, 0x3c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    CHECK(bye_route_tcp(&on, v6, 16, 443) == BYE_PATH_TELEGRAM);
    uint8_t site6[16] = { 0x26, 0x06, 0x47, 0x00, 0x47, 0x00 };
    CHECK(bye_route_tcp(&on, site6, 16, 443) == BYE_PATH_DESYNC);

    static const uint8_t local4[][4] = {
        { 127, 0, 0, 1 }, { 10, 1, 2, 3 }, { 172, 16, 0, 1 }, { 172, 31, 255, 255 },
        { 169, 254, 1, 1 }, { 224, 0, 0, 251 }, { 255, 255, 255, 255 }, { 0, 0, 0, 0 }
    };
    for (size_t i = 0; i < sizeof local4 / sizeof local4[0]; ++i)
        CHECK(bye_route_is_local(local4[i], 4));
    CHECK(!bye_route_is_local((const uint8_t[]){ 172, 15, 0, 1 }, 4));
    CHECK(!bye_route_is_local((const uint8_t[]){ 172, 32, 0, 1 }, 4));
    CHECK(!bye_route_is_local((const uint8_t[]){ 8, 8, 8, 8 }, 4));
    uint8_t loop6[16] = { 0 };
    loop6[15] = 1;
    CHECK(bye_route_is_local(loop6, 16));
    uint8_t ll6[16] = { 0xfe, 0x80 };
    CHECK(bye_route_is_local(ll6, 16));
    uint8_t ula[16] = { 0xfd, 0x5e };
    CHECK(bye_route_is_local(ula, 16));
    uint8_t multi[16] = { 0xff, 0x02 };
    CHECK(bye_route_is_local(multi, 16));
    CHECK(!bye_route_is_local(site6, 16));
    CHECK(bye_route_is_local(site6, 7));
}

int main(void) {
    test_tunnel_names();
    test_ranges();
    test_hosts();
    test_gateways();
    test_route();
    if (!failed) puts("test_tg ok");
    return failed;
}

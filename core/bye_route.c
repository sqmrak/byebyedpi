#include "bye_route.h"

#include <arpa/inet.h>
#include <string.h>

#include "bye_tg.h"

int bye_route_is_local(const uint8_t *a, size_t len) {
    if (!a) return 1;
    if (len == 4) {
        return a[0] == 0 || a[0] == 10 || a[0] == 127 ||
               (a[0] == 169 && a[1] == 254) ||
               (a[0] == 172 && (a[1] & 0xF0) == 16) ||
               (a[0] == 192 && a[1] == 168) ||
               a[0] >= 224;
    }
    if (len == 16) {
        int zeros = 1;
        for (size_t i = 0; i < 15; ++i)
            if (a[i]) zeros = 0;
        if (zeros && (a[15] == 0 || a[15] == 1)) return 1;
        return (a[0] == 0xFE && (a[1] & 0xC0) == 0x80) || (a[0] & 0xFE) == 0xFC ||
               a[0] == 0xFF;
    }
    return 1;
}

bye_path_t bye_route_tcp(const bye_route_policy_t *policy, const uint8_t *addr,
                         size_t addr_len, uint16_t port) {
    if (!policy || bye_route_is_local(addr, addr_len)) return BYE_PATH_DIRECT;
    /* the clients use these three ports for the datacenters */
    if (policy->telegram && (port == 443 || port == 80 || port == 5222) &&
        bye_tg_is_address(addr, addr_len))
        return BYE_PATH_TELEGRAM;
    if (port == 443 || port == 80) return BYE_PATH_DESYNC;
    return BYE_PATH_DIRECT;
}

int bye_route_is_tunnel_ifname(const char *ifname) {
    static const char *const prefixes[] = { "utun", "ipsec", "ppp", "tun" };
    if (!ifname) return 0;
    for (size_t i = 0; i < sizeof prefixes / sizeof prefixes[0]; ++i)
        if (strncmp(ifname, prefixes[i], strlen(prefixes[i])) == 0) return 1;
    return 0;
}

int bye_route_brighton_link_matches(const char *ifname, const uint8_t *gateway4,
                                    const char *service_ifname, const char *service_router) {
    uint8_t router[4];
    if (!ifname || !gateway4 || !service_ifname || !service_router ||
        !ifname[0] || strlen(ifname) >= 16 || strcmp(ifname, service_ifname) != 0 ||
        inet_pton(AF_INET, service_router, router) != 1) return 0;
    return memcmp(gateway4, router, sizeof router) == 0;
}

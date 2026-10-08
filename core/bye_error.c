#include "bye_error.h"

#include <stddef.h>

static unsigned char ascii_lower(unsigned char ch) {
    return ch >= 'A' && ch <= 'Z' ? ch + ('a' - 'A') : ch;
}

static int contains(const char *text, const char *needle) {
    for (; *text; ++text) {
        size_t i = 0;
        while (needle[i] && text[i] && ascii_lower((unsigned char)text[i]) == (unsigned char)needle[i]) ++i;
        if (!needle[i]) return 1;
    }
    return 0;
}

const char *bye_start_hint(const char *detail) {
    static const struct { const char *needle; const char *text; } table[] = {
        { "another interface", "Another VPN or tunnel is using the same addresses. Turn the other one off, then try again." },
        { "another tunnel", "Another VPN or tunnel carries the default route. Turn it off, then try again." },
        { "different physical interfaces", "Wi-Fi and mobile data are both in use. Turn one of them off, then try again." },
        { "cannot open a utun device", "The system could not open a tunnel interface. See the system log for the cause." },
        { "ipv6 only", "The network gives only an IPv6 DNS server. Enter an IPv4 DNS address in Settings." },
        { "system resolver", "The device has no DNS server yet. Connect to a network, or enter a DNS address in Settings." },
        { "unreachable", "There is no network. Connect to Wi-Fi or mobile data, then try again." },
        { "no route", "There is no network. Connect to Wi-Fi or mobile data, then try again." },
        { "route", "The routes could not be set. Another VPN may be running: turn it off, then try again." },
        { "hosts list", "The site list cannot be used. Fix it in Lists, or choose no list." },
        { "network interface went away", "The network changed and the tunnel could not follow. Start it again." },
    };
    if (!detail) return NULL;
    for (size_t i = 0; i < sizeof table / sizeof table[0]; ++i)
        if (contains(detail, table[i].needle)) return table[i].text;
    return NULL;
}

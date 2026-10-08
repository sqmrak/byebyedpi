#include "bye_iface.h"
#include "bye_route.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioccom.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <unistd.h>

/* the ios sdk marks the exported configd calls __IPHONE_NA */
typedef const struct __SCDynamicStore *SCDynamicStoreRef;
extern SCDynamicStoreRef SCDynamicStoreCreate(CFAllocatorRef allocator, CFStringRef name,
                                              void *callout, void *context);
extern CFPropertyListRef SCDynamicStoreCopyValue(SCDynamicStoreRef store, CFStringRef key);

int bye_iface_brighton_link(const char *ifname, const uint8_t *gateway4) {
    if (!ifname || !gateway4) return 0;
    SCDynamicStoreRef store = SCDynamicStoreCreate(kCFAllocatorDefault, CFSTR("byedpid-uplink"),
                                                   NULL, NULL);
    if (!store) return 0;
    CFPropertyListRef value = SCDynamicStoreCopyValue(store,
        CFSTR("State:/Network/Service/dev.brighton.netd/IPv4"));
    int matches = 0;
    if (value && CFGetTypeID(value) == CFDictionaryGetTypeID()) {
        CFTypeRef name = CFDictionaryGetValue((CFDictionaryRef)value, CFSTR("InterfaceName"));
        CFTypeRef router = CFDictionaryGetValue((CFDictionaryRef)value, CFSTR("Router"));
        char name_text[16], router_text[INET_ADDRSTRLEN];
        if (name && router && CFGetTypeID(name) == CFStringGetTypeID() &&
            CFGetTypeID(router) == CFStringGetTypeID() &&
            CFStringGetCString((CFStringRef)name, name_text, sizeof name_text, kCFStringEncodingUTF8) &&
            CFStringGetCString((CFStringRef)router, router_text, sizeof router_text, kCFStringEncodingUTF8))
            matches = bye_route_brighton_link_matches(ifname, gateway4, name_text, router_text);
    }
    if (value) CFRelease(value);
    CFRelease((CFTypeRef)store);
    return matches;
}

/* the sdk headers keep the ipv6 alias request private */
struct bye_in6_addrlifetime {
    uint32_t expire;
    uint32_t preferred;
    uint32_t valid_lifetime;
    uint32_t preferred_lifetime;
};

struct bye_in6_aliasreq {
    char ifra_name[IFNAMSIZ];
    struct sockaddr_in6 ifra_addr;
    struct sockaddr_in6 ifra_dstaddr;
    struct sockaddr_in6 ifra_prefixmask;
    int ifra_flags;
    struct bye_in6_addrlifetime ifra_lifetime;
};

#define BYE_SIOCAIFADDR_IN6 _IOW('i', 26, struct bye_in6_aliasreq)

static int set_address4(int fd, const char *ifname, const char *ip, unsigned long request) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", ifname);
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_len = sizeof *sin;
    sin->sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &sin->sin_addr) != 1) {
        errno = EINVAL;
        return -1;
    }
    return ioctl(fd, request, &ifr);
}

static int set_address6(const char *ifname, const char *ip) {
    struct bye_in6_aliasreq request;
    memset(&request, 0, sizeof request);
    snprintf(request.ifra_name, sizeof request.ifra_name, "%s", ifname);
    request.ifra_addr.sin6_len = sizeof request.ifra_addr;
    request.ifra_addr.sin6_family = AF_INET6;
    request.ifra_prefixmask.sin6_len = sizeof request.ifra_prefixmask;
    request.ifra_prefixmask.sin6_family = AF_INET6;
    memset(request.ifra_prefixmask.sin6_addr.s6_addr, 0xff,
           sizeof request.ifra_prefixmask.sin6_addr.s6_addr);
    request.ifra_lifetime.valid_lifetime = UINT32_MAX;
    request.ifra_lifetime.preferred_lifetime = UINT32_MAX;
    if (inet_pton(AF_INET6, ip, &request.ifra_addr.sin6_addr) != 1) {
        errno = EINVAL;
        return -1;
    }
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int rc = ioctl(fd, BYE_SIOCAIFADDR_IN6, &request);
    int saved = errno;
    close(fd);
    errno = saved;
    return rc;
}

int bye_iface_up(const bye_iface_t *iface) {
    if (!iface || !iface->ifname[0] || !iface->local4[0] || !iface->peer4[0] || !iface->mtu) {
        errno = EINVAL;
        return -1;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int ok = set_address4(fd, iface->ifname, iface->local4, SIOCSIFADDR) == 0 &&
             set_address4(fd, iface->ifname, iface->peer4, SIOCSIFDSTADDR) == 0;
    if (ok) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof ifr);
        snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", iface->ifname);
        struct sockaddr_in *mask = (struct sockaddr_in *)&ifr.ifr_addr;
        mask->sin_len = sizeof *mask;
        mask->sin_family = AF_INET;
        mask->sin_addr.s_addr = htonl(0xffffffffU);
        ok = ioctl(fd, SIOCSIFNETMASK, &ifr) == 0;
        if (ok && ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
            ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
            ok = ioctl(fd, SIOCSIFFLAGS, &ifr) == 0;
        }
        if (ok) {
            memset(&ifr, 0, sizeof ifr);
            snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", iface->ifname);
            ifr.ifr_mtu = iface->mtu;
            ok = ioctl(fd, SIOCSIFMTU, &ifr) == 0;
        }
    }
    int saved = errno;
    close(fd);
    errno = saved;
    if (ok && iface->local6[0]) ok = set_address6(iface->ifname, iface->local6) == 0;
    return ok ? 0 : -1;
}

#else

int bye_iface_brighton_link(const char *ifname, const uint8_t *gateway4) {
    (void)ifname;
    (void)gateway4;
    return 0;
}

int bye_iface_up(const bye_iface_t *iface) {
    (void)iface;
    errno = ENOTSUP;
    return -1;
}

#endif

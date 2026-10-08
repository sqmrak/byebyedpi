#include "bye_resolver.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(__APPLE__)

#include <CoreFoundation/CoreFoundation.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* SystemConfiguration exports these on every ios release, but the ios sdk
   headers mark them __IPHONE_NA and the compiler refuses the calls */
typedef const struct __SCDynamicStore *SCDynamicStoreRef;
extern SCDynamicStoreRef SCDynamicStoreCreate(CFAllocatorRef allocator, CFStringRef name,
                                              void *callout, void *context);
extern CFPropertyListRef SCDynamicStoreCopyValue(SCDynamicStoreRef store, CFStringRef key);
extern CFArrayRef SCDynamicStoreCopyKeyList(SCDynamicStoreRef store, CFStringRef pattern);

/* the leading fields of configd's dnsinfo.h, which the sdk does not ship.
   libSystem exports the calls on ios 5.1.1 and in the 16.5 sdk. pack(4) and
   64 bit pointer slots give 32 and 64 bit processes one layout */
#define BYE_DNS_PTR(type, name) union { type ptr; uint64_t slot; } name
#pragma pack(4)
typedef struct {
    BYE_DNS_PTR(char *, domain);
    int32_t n_nameserver;
    BYE_DNS_PTR(struct sockaddr **, nameserver);
} bye_dns_resolver_t;
typedef struct {
    int32_t n_resolver;
    BYE_DNS_PTR(bye_dns_resolver_t **, resolver);
    int32_t n_scoped_resolver;
    BYE_DNS_PTR(bye_dns_resolver_t **, scoped_resolver);
} bye_dns_config_t;
#pragma pack()
/* weak so a firmware without the export still starts the daemon */
extern bye_dns_config_t *dns_configuration_copy(void) __attribute__((weak_import));
extern void dns_configuration_free(bye_dns_config_t *config) __attribute__((weak_import));

typedef struct {
    char  *out;
    size_t cap;
    int    found;
    int    saw_ipv6;
} pick_t;

static void pick_text(pick_t *pick, const char *text) {
    struct in_addr v4;
    struct in6_addr v6;
    if (pick->found) return;
    if (inet_pton(AF_INET, text, &v4) == 1) {
        /* a resolver on this device is the tunnel's own entry */
        if ((ntohl(v4.s_addr) >> 24) == 127) return;
        if (strlen(text) < pick->cap) {
            memcpy(pick->out, text, strlen(text) + 1);
            pick->found = 1;
        }
    } else if (inet_pton(AF_INET6, text, &v6) == 1) {
        pick->saw_ipv6 = 1;
    }
}

static void pick_from_dict(pick_t *pick, CFTypeRef value) {
    if (!value || CFGetTypeID(value) != CFDictionaryGetTypeID()) return;
    CFStringRef list_key = CFStringCreateWithCString(kCFAllocatorDefault, "ServerAddresses",
                                                     kCFStringEncodingUTF8);
    CFTypeRef list = list_key ? CFDictionaryGetValue((CFDictionaryRef)value, list_key) : NULL;
    if (list_key) CFRelease(list_key);
    if (!list || CFGetTypeID(list) != CFArrayGetTypeID()) return;
    for (CFIndex i = 0; i < CFArrayGetCount((CFArrayRef)list) && !pick->found; ++i) {
        CFTypeRef item = CFArrayGetValueAtIndex((CFArrayRef)list, i);
        char text[INET6_ADDRSTRLEN];
        if (item && CFGetTypeID(item) == CFStringGetTypeID() &&
            CFStringGetCString((CFStringRef)item, text, sizeof text, kCFStringEncodingUTF8))
            pick_text(pick, text);
    }
}

static void pick_from_key(pick_t *pick, SCDynamicStoreRef store, const char *key_text) {
    CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault, key_text,
                                                kCFStringEncodingUTF8);
    CFPropertyListRef value = key ? SCDynamicStoreCopyValue(store, key) : NULL;
    if (key) CFRelease(key);
    pick_from_dict(pick, value);
    if (value) CFRelease(value);
}

/* the global entry is what configd merges from the services, and it can be
   missing while a single service still holds the dhcp servers */
static void pick_from_services(pick_t *pick, SCDynamicStoreRef store, const char *pattern) {
    CFStringRef regex = CFStringCreateWithCString(kCFAllocatorDefault, pattern,
                                                  kCFStringEncodingUTF8);
    CFArrayRef keys = regex ? SCDynamicStoreCopyKeyList(store, regex) : NULL;
    if (regex) CFRelease(regex);
    if (!keys) return;
    for (CFIndex i = 0; i < CFArrayGetCount(keys) && !pick->found; ++i) {
        CFTypeRef item = CFArrayGetValueAtIndex(keys, i);
        char key[256];
        /* the tunnel's own entry from an earlier run must not feed itself */
        if (item && CFGetTypeID(item) == CFStringGetTypeID() &&
            CFStringGetCString((CFStringRef)item, key, sizeof key, kCFStringEncodingUTF8) &&
            !strstr(key, "com.byebyedpi.utun"))
            pick_from_key(pick, store, key);
    }
    CFRelease(keys);
}

static void pick_from_configd(pick_t *pick) {
    CFStringRef name = CFStringCreateWithCString(kCFAllocatorDefault, "byedpid-resolver",
                                                 kCFStringEncodingUTF8);
    SCDynamicStoreRef store = name ? SCDynamicStoreCreate(kCFAllocatorDefault, name, NULL, NULL)
                                   : NULL;
    if (name) CFRelease(name);
    if (!store) return;
    pick_from_key(pick, store, "State:/Network/Global/DNS");
    if (!pick->found) pick_from_services(pick, store, "State:/Network/Service/[^/]+/DNS");
    if (!pick->found) pick_from_services(pick, store, "Setup:/Network/Service/[^/]+/DNS");
    CFRelease((CFTypeRef)store);
}

/* resolvers bound to a domain (local, a vpn's search domain) are not the
   system's default and are skipped */
static void pick_from_resolvers(pick_t *pick, bye_dns_resolver_t **list, int32_t count) {
    if (!list || count <= 0) return;
    for (int32_t i = 0; i < count && !pick->found; ++i) {
        bye_dns_resolver_t *resolver = list[i];
        if (!resolver || (resolver->domain.ptr && resolver->domain.ptr[0])) continue;
        if (!resolver->nameserver.ptr || resolver->n_nameserver <= 0) continue;
        for (int32_t j = 0; j < resolver->n_nameserver && !pick->found; ++j) {
            const struct sockaddr *address = resolver->nameserver.ptr[j];
            char text[INET6_ADDRSTRLEN];
            if (!address) continue;
            if (address->sa_family == AF_INET &&
                inet_ntop(AF_INET, &((const struct sockaddr_in *)address)->sin_addr,
                          text, sizeof text))
                pick_text(pick, text);
            else if (address->sa_family == AF_INET6)
                pick->saw_ipv6 = 1;
        }
    }
}

bye_resolver_status_t bye_resolver_system(char *out, size_t cap) {
    if (!out || !cap) return BYE_RESOLVER_NONE;
    out[0] = '\0';
    pick_t pick = { out, cap, 0, 0 };
    pick_from_configd(&pick);
    /* an iphone 4s on ios 9.3.6 joined to wifi got no ipv4 server from
       State:/Network/Global/DNS. dnsinfo is the list libinfo itself resolves
       with, read over its own configd channel */
    if (!pick.found && dns_configuration_copy && dns_configuration_free) {
        bye_dns_config_t *config = dns_configuration_copy();
        if (config) {
            pick_from_resolvers(&pick, config->resolver.ptr, config->n_resolver);
            pick_from_resolvers(&pick, config->scoped_resolver.ptr, config->n_scoped_resolver);
            dns_configuration_free(config);
        }
    }
    if (pick.found) return BYE_RESOLVER_FOUND;
    return pick.saw_ipv6 ? BYE_RESOLVER_IPV6_ONLY : BYE_RESOLVER_NONE;
}

#else

bye_resolver_status_t bye_resolver_system(char *out, size_t cap) {
    if (out && cap) out[0] = '\0';
    return BYE_RESOLVER_NONE;
}

#endif

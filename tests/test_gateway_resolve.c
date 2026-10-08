#define _DEFAULT_SOURCE

#include "bye_backend.h"

#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static unsigned seen;
static int fail_all;
static int hold_dns;
static unsigned held;

/* deterministic dns answers keep the lookup test off the public network */
int getaddrinfo(const char *host, const char *service, const struct addrinfo *hints,
                struct addrinfo **out) {
    assert(!strcmp(service, "443") && hints->ai_family == AF_INET);
    *out = NULL;
    int dc = 0, media = strstr(host, "-1.web.telegram.org") != NULL;
    assert(sscanf(host, "kws%d", &dc) == 1 && dc >= 1 && dc <= BYE_TG_WS_DCS);
    char expected[BYE_TG_WS_HOST_MAX];
    assert(bye_tg_ws_host(dc, media, 0, expected, sizeof expected) == 0);
    assert(!strcmp(host, expected));
    pthread_mutex_lock(&lock);
    seen |= 1u << ((dc - 1) * 2 + media);
    if (hold_dns) {
        ++held;
        pthread_cond_broadcast(&changed);
        while (hold_dns) pthread_cond_wait(&changed, &lock);
    }
    int reject = fail_all || dc == 3;
    pthread_mutex_unlock(&lock);
    if (reject) return EAI_NONAME;
    struct addrinfo *entry = calloc(1, sizeof *entry);
    struct sockaddr_in *address = calloc(1, sizeof *address);
    assert(entry && address);
    address->sin_family = AF_INET;
    address->sin_addr.s_addr = htonl(0x7f000000u | (unsigned)(dc * 2 + media));
    entry->ai_family = AF_INET;
    entry->ai_addrlen = sizeof *address;
    entry->ai_addr = (struct sockaddr *)address;
    *out = entry;
    return 0;
}

void freeaddrinfo(struct addrinfo *entry) {
    assert(entry && !entry->ai_next);
    free(entry->ai_addr);
    free(entry);
}

static void *resolve(void *out) {
    bye_resolve_gateways(out);
    return NULL;
}

static void wait_held(unsigned count) {
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 3;
    pthread_mutex_lock(&lock);
    while (held < count) assert(pthread_cond_timedwait(&changed, &lock, &deadline) == 0);
    pthread_mutex_unlock(&lock);
}

static void test_bound(void) {
    bye_tg_ws_addresses_t first, second, third, empty;
    memset(&empty, 0, sizeof empty);
    pthread_mutex_lock(&lock);
    hold_dns = 1;
    held = 0;
    pthread_mutex_unlock(&lock);
    pthread_t a, b;
    assert(pthread_create(&a, NULL, resolve, &first) == 0);
    wait_held(10);
    assert(pthread_create(&b, NULL, resolve, &second) == 0);
    wait_held(14);
    /* saturated lookups leave the caller with pinned gateways, without new workers */
    bye_resolve_gateways(&third);
    assert(!memcmp(&third, &empty, sizeof empty));
    pthread_mutex_lock(&lock);
    assert(held == 14);
    hold_dns = 0;
    pthread_cond_broadcast(&changed);
    pthread_mutex_unlock(&lock);
    assert(pthread_join(a, NULL) == 0);
    assert(pthread_join(b, NULL) == 0);
}

int main(void) {
    bye_tg_ws_addresses_t addresses;
    memset(&addresses, 0xff, sizeof addresses);
    bye_resolve_gateways(&addresses);
    assert(seen == (1u << 10) - 1);
    for (int dc = 1; dc <= BYE_TG_WS_DCS; ++dc) {
        for (unsigned media = 0; media < 2; ++media) {
            const bye_tg_ws_address_t *entry = &addresses.dc[dc - 1][media];
            assert(entry->valid == (dc != 3));
            if (entry->valid) {
                assert(entry->address[0] == 127 && entry->address[3] == dc * 2 + media);
            } else {
                assert(!memcmp(entry->address, (const uint8_t[]){0, 0, 0, 0}, 4));
            }
        }
    }
    pthread_mutex_lock(&lock);
    fail_all = 1;
    seen = 0;
    pthread_mutex_unlock(&lock);
    bye_resolve_gateways(&addresses);
    assert(seen == (1u << 10) - 1);
    bye_tg_ws_addresses_t empty;
    memset(&empty, 0, sizeof empty);
    assert(!memcmp(&addresses, &empty, sizeof empty));
    bye_resolve_gateways(NULL);
    test_bound();
    puts("test_gateway_resolve ok");
    return 0;
}

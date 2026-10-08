#define _DEFAULT_SOURCE
#include "bye_altaddr.h"

#include "bye_route.h"

#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#define ENTRIES_MAX 16
#define THREADS_MAX 2
#define FRESH_S 600

typedef enum { E_FREE = 0, E_RUNNING, E_DONE } entry_state_t;

typedef struct {
    entry_state_t state;
    char          name[BYE_ALT_NAME_MAX];
    uint8_t       addrs[BYE_ALT_ADDRS_MAX][4];
    size_t        count;
    time_t        asked;
} entry_t;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static entry_t entries[ENTRIES_MAX];
static unsigned threads_running;
static unsigned next_slot;
static bye_altaddr_resolver_fn resolver;

void bye_altaddr_set_resolver(bye_altaddr_resolver_fn fn) {
    pthread_mutex_lock(&lock);
    resolver = fn;
    memset(entries, 0, sizeof entries);
    pthread_mutex_unlock(&lock);
}

static size_t system_lookup(const char *name, uint8_t out[][4], size_t max) {
    struct addrinfo hints, *found = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(name, NULL, &hints, &found) != 0 || !found) return 0;
    size_t count = 0;
    for (struct addrinfo *item = found; item && count < max; item = item->ai_next) {
        if (item->ai_family != AF_INET) continue;
        const uint8_t *addr = (const uint8_t *)&((struct sockaddr_in *)item->ai_addr)->sin_addr;
        /* a poisoned answer must not point a flow at the device or its network */
        if (bye_route_is_local(addr, 4)) continue;
        memcpy(out[count++], addr, 4);
    }
    freeaddrinfo(found);
    return count;
}

/* the name without its first label, or NULL when fewer than two labels would stay */
static const char *parent_of(const char *name) {
    const char *dot = strchr(name, '.');
    if (!dot || !strchr(dot + 1, '.')) return NULL;
    return dot + 1;
}

static void add_unique(uint8_t out[][4], size_t *count, size_t max, const uint8_t *addr) {
    for (size_t i = 0; i < *count; ++i)
        if (memcmp(out[i], addr, 4) == 0) return;
    if (*count < max) memcpy(out[(*count)++], addr, 4);
}

static void *lookup_thread(void *arg) {
    char name[BYE_ALT_NAME_MAX];
    memcpy(name, arg, sizeof name);
    free(arg);
    pthread_mutex_lock(&lock);
    bye_altaddr_resolver_fn fn = resolver ? resolver : system_lookup;
    pthread_mutex_unlock(&lock);

    uint8_t found[BYE_ALT_ADDRS_MAX][4];
    uint8_t part[BYE_ALT_ADDRS_MAX][4];
    size_t count = 0;
    size_t got = fn(name, part, BYE_ALT_ADDRS_MAX);
    for (size_t i = 0; i < got; ++i) add_unique(found, &count, BYE_ALT_ADDRS_MAX, part[i]);
    const char *parent = parent_of(name);
    if (parent) {
        got = fn(parent, part, BYE_ALT_ADDRS_MAX);
        for (size_t i = 0; i < got; ++i) add_unique(found, &count, BYE_ALT_ADDRS_MAX, part[i]);
    }

    pthread_mutex_lock(&lock);
    for (size_t i = 0; i < ENTRIES_MAX; ++i) {
        if (entries[i].state != E_RUNNING || strcmp(entries[i].name, name) != 0) continue;
        memcpy(entries[i].addrs, found, sizeof found);
        entries[i].count = count;
        entries[i].state = E_DONE;
        break;
    }
    --threads_running;
    pthread_mutex_unlock(&lock);
    return NULL;
}

void bye_altaddr_request(const char *name) {
    if (!name || !name[0] || strlen(name) >= BYE_ALT_NAME_MAX) return;
    time_t now = time(NULL);
    pthread_mutex_lock(&lock);
    entry_t *slot = NULL;
    for (size_t i = 0; i < ENTRIES_MAX; ++i) {
        if (entries[i].state != E_FREE && strcmp(entries[i].name, name) == 0) {
            int fresh = entries[i].state == E_RUNNING || now - entries[i].asked < FRESH_S;
            if (fresh) {
                pthread_mutex_unlock(&lock);
                return;
            }
            slot = &entries[i];
            break;
        }
    }
    if (!slot && threads_running >= THREADS_MAX) {
        pthread_mutex_unlock(&lock);
        return;
    }
    if (!slot) {
        /* a finished entry is the one replaced, oldest slot first */
        for (size_t tries = 0; tries < ENTRIES_MAX && !slot; ++tries) {
            entry_t *candidate = &entries[(next_slot + tries) % ENTRIES_MAX];
            if (candidate->state != E_RUNNING) slot = candidate;
        }
        if (!slot) {
            pthread_mutex_unlock(&lock);
            return;
        }
        next_slot = (unsigned)((slot - entries) + 1) % ENTRIES_MAX;
    }
    memset(slot, 0, sizeof *slot);
    snprintf(slot->name, sizeof slot->name, "%s", name);
    slot->state = E_RUNNING;
    slot->asked = now;
    ++threads_running;
    /* the thread owns this copy and frees it, the slot may be replaced meanwhile */
    char *arg = malloc(BYE_ALT_NAME_MAX);
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (!arg || (memcpy(arg, slot->name, BYE_ALT_NAME_MAX), pthread_create(&thread, &attr, lookup_thread, arg)) != 0) {
        free(arg);
        --threads_running;
        memset(slot, 0, sizeof *slot);
    }
    pthread_attr_destroy(&attr);
    pthread_mutex_unlock(&lock);
}

int bye_altaddr_get(const char *name, uint8_t out[][4], size_t max, size_t *count) {
    if (count) *count = 0;
    if (!name || !out || !count) return 0;
    int done = 0;
    pthread_mutex_lock(&lock);
    for (size_t i = 0; i < ENTRIES_MAX; ++i) {
        if (entries[i].state != E_DONE || strcmp(entries[i].name, name) != 0) continue;
        size_t n = entries[i].count < max ? entries[i].count : max;
        memcpy(out, entries[i].addrs, n * 4);
        *count = n;
        done = 1;
        break;
    }
    pthread_mutex_unlock(&lock);
    return done;
}

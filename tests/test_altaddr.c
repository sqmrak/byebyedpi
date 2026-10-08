#define _DEFAULT_SOURCE
#include "bye_altaddr.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "check.h"

static int lookups;
static pthread_mutex_t lookup_lock = PTHREAD_MUTEX_INITIALIZER;

static size_t fake(const char *name, uint8_t out[][4], size_t max) {
    pthread_mutex_lock(&lookup_lock);
    ++lookups;
    pthread_mutex_unlock(&lookup_lock);
    size_t n = 0;
    if (strcmp(name, "www.alt.test") == 0) {
        static const uint8_t own[2][4] = { { 10, 0, 0, 1 }, { 10, 0, 0, 2 } };
        for (; n < 2 && n < max; ++n) memcpy(out[n], own[n], 4);
    } else if (strcmp(name, "alt.test") == 0) {
        static const uint8_t parent[2][4] = { { 10, 0, 0, 2 }, { 10, 0, 0, 3 } };
        for (; n < 2 && n < max; ++n) memcpy(out[n], parent[n], 4);
    }
    return n;
}

static int wait_for(const char *name, uint8_t out[][4], size_t max, size_t *count) {
    for (int waited = 0; waited < 3000; waited += 10) {
        if (bye_altaddr_get(name, out, max, count)) return 1;
        usleep(10 * 1000);
    }
    return 0;
}

int main(void) {
    uint8_t out[BYE_ALT_ADDRS_MAX][4];
    size_t count = 99;

    bye_altaddr_set_resolver(fake);
    CHECK(!bye_altaddr_get("www.alt.test", out, BYE_ALT_ADDRS_MAX, &count) && count == 0);

    /* the name's own addresses first, then the parent's, each once */
    bye_altaddr_request("www.alt.test");
    CHECK(wait_for("www.alt.test", out, BYE_ALT_ADDRS_MAX, &count));
    CHECK(count == 3);
    CHECK(out[0][3] == 1 && out[1][3] == 2 && out[2][3] == 3 && out[0][0] == 10);

    /* a name asked for again within ten minutes is not looked up again */
    int before;
    pthread_mutex_lock(&lookup_lock);
    before = lookups;
    pthread_mutex_unlock(&lookup_lock);
    bye_altaddr_request("www.alt.test");
    usleep(50 * 1000);
    pthread_mutex_lock(&lookup_lock);
    CHECK(lookups == before);
    pthread_mutex_unlock(&lookup_lock);

    /* a name with two labels has no parent, and one the lookup does not know ends with none */
    bye_altaddr_request("alt.test");
    CHECK(wait_for("alt.test", out, BYE_ALT_ADDRS_MAX, &count) && count == 2);
    bye_altaddr_request("nothing.invalid.test");
    CHECK(wait_for("nothing.invalid.test", out, BYE_ALT_ADDRS_MAX, &count) && count == 0);

    /* the caller's room is respected */
    CHECK(bye_altaddr_get("www.alt.test", out, 2, &count) && count == 2);

    /* names that cannot be looked up are ignored */
    bye_altaddr_request(NULL);
    bye_altaddr_request("");
    char longname[BYE_ALT_NAME_MAX + 8];
    memset(longname, 'a', sizeof longname - 1);
    longname[sizeof longname - 1] = '\0';
    bye_altaddr_request(longname);
    CHECK(!bye_altaddr_get(longname, out, BYE_ALT_ADDRS_MAX, &count));

    /* the system lookup never returns an address of the device itself */
    bye_altaddr_set_resolver(NULL);
    bye_altaddr_request("localhost");
    CHECK(wait_for("localhost", out, BYE_ALT_ADDRS_MAX, &count) && count == 0);

    puts("test_altaddr ok");
    return 0;
}

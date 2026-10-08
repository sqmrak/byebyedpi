#include "proc_detach.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef struct {
    int32_t active;
    uint32_t active_attr;
    int32_t inactive;
    uint32_t inactive_attr;
} memlimit_props_t;

static memlimit_props_t current;
static memlimit_props_t requested;
static int set_calls;

int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags,
                         void *buffer, size_t size) {
    (void)pid;
    assert(flags == 0 && size == sizeof current);
    if (command == 8) {
        *(memlimit_props_t *)buffer = current;
        return 0;
    }
    assert(command == 7);
    requested = *(const memlimit_props_t *)buffer;
    ++set_calls;
    return 0;
}

static void check(int active, int inactive, int want_active, int want_inactive,
                  int want_set) {
    current.active = active;
    current.active_attr = 2;
    current.inactive = inactive;
    current.inactive_attr = 2;
    set_calls = 0;
    senko_raise_memory_limit();
    assert(set_calls == want_set);
    if (!want_set) return;
    assert(requested.active == want_active);
    assert(requested.inactive == want_inactive);
    assert(requested.active_attr == (active > 0 && active < 64 ? 1U : 2U));
    assert(requested.inactive_attr == (inactive > 0 && inactive < 64 ? 1U : 2U));
}

int main(void) {
    check(18, 18, 64, 64, 1);
    check(18, -1, 64, -1, 1);
    check(128, 18, 128, 64, 1);
    check(-1, -1, -1, -1, 0);
    check(128, 128, 128, 128, 0);
    puts("proc detach memory limit checks passed");
    return 0;
}

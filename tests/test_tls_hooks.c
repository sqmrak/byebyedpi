#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "check.h"

static int engine_available, substrate_available, target_available, engine_failure;
static int install_count, open_count, log_count;
static int target, replacement, substrate;

static void install(void *symbol, void *hook, void **original) {
    CHECK(symbol == &target);
    CHECK(hook == &replacement);
    *original = engine_failure ? NULL : symbol;
    ++install_count;
}

static void *lookup(void *handle, const char *name) {
    if (!strcmp(name, "MSHookFunction"))
        return engine_available || (handle == &substrate && substrate_available)
            ? (void *)install : NULL;
    if (!strcmp(name, "SSLHandshake") && target_available) return &target;
    return NULL;
}

static void *open_substrate(const char *path, int flags) {
    CHECK(!strcmp(path, "/usr/lib/libsubstrate.dylib"));
    CHECK(flags == (RTLD_NOW | RTLD_LOCAL));
    ++open_count;
    return substrate_available ? &substrate : NULL;
}

void stl_log(const char *fmt, ...) {
    (void)fmt;
    ++log_count;
}

#define dlsym lookup
#define dlopen open_substrate
#include "../byebyetlsfix/stl_hooks.c"
#undef dlsym
#undef dlopen

static int gate_active, skip_process, shadow_result, trust_result;
static int shadow_calls, trust_calls;

int stl_gate_is_active(void) { return gate_active; }
int stl_gate_skip_process(void) { return skip_process; }
void stl_gate_disable(void) { gate_active = 0; }
int stl_shadow_install_hooks(void) { ++shadow_calls; return shadow_result; }
int stl_trust_install_hooks(void) { ++trust_calls; return trust_result; }

/* invoke the constructor directly to test partial hook failures in one process */
#define __attribute__(value)
#include "../byebyetlsfix/stl_init.c"
#undef __attribute__

static void test_init(void) {
    static const struct {
        int active, skip, shadow, trust, remains_active, shadow_count, trust_count;
    } cases[] = {
        { 1, 0,  0,  0, 1, 1, 1 },
        { 1, 0, -1,  0, 0, 1, 0 },
        { 1, 0,  0, -1, 0, 1, 1 },
        { 1, 1,  0,  0, 1, 0, 0 },
        { 0, 0,  0,  0, 0, 0, 0 },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        gate_active = cases[i].active;
        skip_process = cases[i].skip;
        shadow_result = cases[i].shadow;
        trust_result = cases[i].trust;
        shadow_calls = trust_calls = 0;
        stl_init();
        CHECK(gate_active == cases[i].remains_active);
        CHECK(shadow_calls == cases[i].shadow_count);
        CHECK(trust_calls == cases[i].trust_count);
    }
}

static void reset(void) {
    engine_available = target_available = 1;
    substrate_available = 0;
    engine_failure = 0;
    install_count = open_count = log_count = 0;
}

int main(void) {
    test_init();
    void *original = NULL, *optional = NULL;
    stl_hook_t hooks[] = {
        { "SSLHandshake", &replacement, &original, 1 },
        { "SSLCopyPeerTrust", &replacement, &optional, 0 },
    };
    reset();
    CHECK(stl_hooks_install(hooks, 2) == 1);
    CHECK(install_count == 1 && original == &target && optional == NULL);
    CHECK(open_count == 0 && log_count == 0);

    /* missing old-runtime getters must not prevent the handshake hook */
    reset(); engine_available = 0; substrate_available = 1;
    original = NULL;
    CHECK(stl_hooks_install(hooks, 2) == 1);
    CHECK(install_count == 1 && original == &target && open_count == 1);

    /* missing required symbols must leave every function untouched */
    reset(); hooks[1].required = 1; original = NULL;
    CHECK(stl_hooks_install(hooks, 2) == -1);
    CHECK(install_count == 0 && original == NULL && log_count == 1);
    hooks[1].required = 0;

    reset(); target_available = 0;
    CHECK(stl_hooks_install(hooks, 2) == -1);
    CHECK(install_count == 0 && log_count == 1);

    reset(); engine_available = 0;
    CHECK(stl_hooks_install(hooks, 2) == -1);
    CHECK(install_count == 0 && open_count == 1 && log_count == 1);

    reset();
    CHECK(stl_hooks_install(NULL, 1) == -1);
    CHECK(stl_hooks_install(hooks, 0) == -1);
    CHECK(stl_hooks_install(hooks, 25) == -1);
    hooks[1].original = NULL;
    CHECK(stl_hooks_install(hooks, 2) == -1);
    CHECK(install_count == 0);

    reset(); original = NULL;
    CHECK(stl_hooks_install_address("SSLContext finalize", &target, &replacement, &original) == 0);
    CHECK(install_count == 1 && original == &target);
    reset(); engine_available = 0;
    CHECK(stl_hooks_install_address("SSLContext finalize", &target, &replacement, &original) == -1);
    CHECK(install_count == 0 && log_count == 1);
    CHECK(stl_hooks_install_address("SSLContext finalize", NULL, &replacement, &original) == -1);
    CHECK(stl_hooks_install_address("SSLContext finalize", &target, &replacement, NULL) == -1);

    reset(); engine_failure = 1; original = NULL;
    CHECK(stl_hooks_install_address("SSLContext finalize", &target, &replacement, &original) == -1);
    CHECK(install_count == 1 && original == NULL && log_count == 1);

    if (failed) return 1;
    puts("test_tls_hooks ok");
    return 0;
}

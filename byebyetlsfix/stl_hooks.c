#include "stl_hooks.h"
#include "stl_log.h"

#include <dlfcn.h>

#define STL_HOOK_MAX 24

typedef void (*hook_function_t)(void *, void *, void **);

static hook_function_t stl_hook_engine(void) {
    hook_function_t hook_function = dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (!hook_function) {
        /* keep substrate loaded while its original-function trampolines are in use */
        void *substrate = dlopen("/usr/lib/libsubstrate.dylib", RTLD_NOW | RTLD_LOCAL);
        if (substrate) hook_function = dlsym(substrate, "MSHookFunction");
    }
    if (!hook_function) {
        stl_log("hooks: MSHookFunction unavailable");
        return NULL;
    }
    return hook_function;
}

static int stl_hook_one(hook_function_t engine, const char *name, void *symbol,
                        void *replacement, void **original) {
    engine(symbol, replacement, original);
    if (!*original) {
        stl_log("hooks: cannot hook %s", name);
        return -1;
    }
    return 0;
}

int stl_hooks_install_address(const char *name, void *symbol, void *replacement,
                              void **original) {
    if (!name || !symbol || !replacement || !original) return -1;
    hook_function_t engine = stl_hook_engine();
    if (!engine) return -1;
    return stl_hook_one(engine, name, symbol, replacement, original);
}

int stl_hooks_install(const stl_hook_t *hooks, size_t count) {
    void *symbols[STL_HOOK_MAX];
    if (!hooks || !count || count > STL_HOOK_MAX) return -1;
    hook_function_t engine = stl_hook_engine();
    if (!engine) return -1;

    /* ios 5 lacks some later getters, but the stream hooks must all be present */
    for (size_t i = 0; i < count; ++i) {
        if (!hooks[i].name || !hooks[i].replacement || !hooks[i].original) return -1;
        symbols[i] = dlsym(RTLD_DEFAULT, hooks[i].name);
        if (!symbols[i] && hooks[i].required) {
            stl_log("hooks: required symbol %s unavailable", hooks[i].name);
            return -1;
        }
    }

    int installed = 0;
    for (size_t i = 0; i < count; ++i) {
        if (!symbols[i]) continue;
        /* ios 9 shared-cache calls bypass the import pointers used by fishhook */
        if (stl_hook_one(engine, hooks[i].name, symbols[i], hooks[i].replacement,
                         hooks[i].original) != 0) return -1;
        ++installed;
    }
    return installed;
}

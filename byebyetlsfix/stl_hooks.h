#ifndef STL_HOOKS_H
#define STL_HOOKS_H

#include <stddef.h>

typedef struct {
    const char *name;
    void *replacement;
    void **original;
    int required;
} stl_hook_t;

int stl_hooks_install(const stl_hook_t *hooks, size_t count);
int stl_hooks_install_address(const char *name, void *symbol, void *replacement,
                              void **original);

#endif

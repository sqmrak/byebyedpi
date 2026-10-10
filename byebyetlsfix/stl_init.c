#define _DEFAULT_SOURCE

#include "stl_gate.h"
#include "stl_shadow.h"

int stl_trust_install_hooks(void);

__attribute__((constructor))
static void stl_init(void) {
    if (stl_gate_skip_process() || !stl_gate_is_active())
        return;
    if (stl_shadow_install_hooks() != 0 || stl_trust_install_hooks() != 0)
        stl_gate_disable();
}

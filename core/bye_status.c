#include "bye_status.h"

#include <stdio.h>
#include <string.h>

static int plain_name(const char *name) {
    size_t len = strlen(name);
    if (len > BYE_STATUS_IFNAME_MAX) return 0;
    for (size_t i = 0; i < len; ++i) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_')) return 0;
    }
    return 1;
}

size_t bye_status_format(char *out, size_t cap, int on, const char *ifname) {
    if (!out || cap == 0) return 0;
    out[0] = '\0';
    int written;
    if (!on) {
        written = snprintf(out, cap, "0\n");
    } else if (!ifname || !ifname[0]) {
        written = snprintf(out, cap, "1\n");
    } else {
        if (!plain_name(ifname)) return 0;
        written = snprintf(out, cap, "1 %s\n", ifname);
    }
    if (written < 0 || (size_t)written >= cap) {
        out[0] = '\0';
        return 0;
    }
    return (size_t)written;
}

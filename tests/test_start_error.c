#include "bye_error.h"
#include "check.h"

#include <string.h>

int main(void) {
    const struct { const char *reason; const char *hint; } cases[] = {
        { "another tunnel (utun0) already carries the default route, turn it off and start again",
          "Another VPN or tunnel carries the default route. Turn it off, then try again." },
        { "cannot open a utun device (errno 1 Operation not permitted)",
          "The system could not open a tunnel interface. See the system log for the cause." },
        { "cannot open a utun device (errno 16 Device or resource busy)",
          "The system could not open a tunnel interface. See the system log for the cause." },
        { "cannot open a utun device (errno 2 No such file or directory)",
          "The system could not open a tunnel interface. See the system log for the cause." },
        { "the tunnel address is already in use on another interface",
          "Another VPN or tunnel is using the same addresses. Turn the other one off, then try again." },
        { "route add link-local6 via utun0: network is unreachable",
          "There is no network. Connect to Wi-Fi or mobile data, then try again." },
        { "cannot give utun1 its address (errno 22 Invalid argument)", NULL },
        { "utun0 read failed", NULL },
        { "CANNOT OPEN A UTUN DEVICE", "The system could not open a tunnel interface. See the system log for the cause." },
        { "", NULL }, { NULL, NULL }, { "u", NULL },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        const char *hint = bye_start_hint(cases[i].reason);
        CHECK(cases[i].hint ? hint && strcmp(hint, cases[i].hint) == 0 : !hint);
        CHECK(!hint || !strstr(hint, "root"));
    }
    if (!failed) puts("test_start_error ok");
    return failed;
}

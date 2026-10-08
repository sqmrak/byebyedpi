#include "bye_backend.h"
#include "tun/utun_route.h"
#include "check.h"

#include <errno.h>
#include <string.h>

static int lookups;
static int lookup_failed;
static const char *route_name = "en5";

/* the kernel reply is supplied, no host route is read or changed */
int utun_route_system_path(const uint8_t *address, uint8_t len,
                           utun_route_path_t *out, utun_route_error_t *error) {
    ++lookups;
    CHECK(len == 4 && memcmp(address, (const uint8_t[]){1, 1, 1, 1}, 4) == 0);
    memset(out, 0, sizeof *out);
    memset(error, 0, sizeof *error);
    if (lookup_failed) {
        error->code = ENETUNREACH;
        strcpy(error->message, "no route to the public address");
        return -1;
    }
    strcpy(out->ifname, route_name);
    return 0;
}

int main(void) {
    bye_backend_t backend;
    memset(&backend, 0, sizeof backend);
    char name[16], error[128];
    backend.active = 1;
    strcpy(backend.direct.ifname, "pdp_ip2");
    CHECK(bye_backend_external_interface(&backend, name, sizeof name, error, sizeof error) == 0);
    CHECK(strcmp(name, "pdp_ip2") == 0 && lookups == 0 && !error[0]);
    backend.active = 0;
    CHECK(bye_backend_external_interface(&backend, name, sizeof name, error, sizeof error) == 0);
    CHECK(strcmp(name, "en5") == 0 && lookups == 1 && !error[0]);
    route_name = "ipsec4";
    CHECK(bye_backend_external_interface(&backend, name, sizeof name, error, sizeof error) == 0);
    CHECK(strcmp(name, "ipsec4") == 0 && lookups == 2);
    lookup_failed = 1;
    CHECK(bye_backend_external_interface(&backend, name, sizeof name, error, sizeof error) == -1);
    CHECK(!name[0] && strcmp(error, "no route to the public address") == 0);
    backend.active = 1;
    backend.direct.ifname[0] = '\0';
    CHECK(bye_backend_external_interface(&backend, name, sizeof name, error, sizeof error) == -1);
    CHECK(!name[0] && error[0] && lookups == 3);
    memset(backend.direct.ifname, 'x', sizeof backend.direct.ifname);
    CHECK(bye_backend_external_interface(&backend, name, sizeof name, error, sizeof error) == -1);
    CHECK(!name[0] && error[0]);
    strcpy(backend.direct.ifname, "pdp_ip2");
    CHECK(bye_backend_external_interface(&backend, name, 3, error, sizeof error) == -1);
    CHECK(!name[0] && error[0]);
    CHECK(bye_backend_external_interface(NULL, name, sizeof name, error, sizeof error) == -1);
    CHECK(!name[0] && error[0]);
    if (!failed) puts("test_external_interface ok");
    return failed;
}

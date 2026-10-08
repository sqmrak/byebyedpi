#include "bye_status.h"

#include <string.h>

#include "check.h"

int main(void) {
    char out[BYE_STATUS_LINE_MAX];
    CHECK(bye_status_format(out, sizeof out, 0, "en0") == 2 && !strcmp(out, "0\n"));
    CHECK(bye_status_format(out, sizeof out, 1, "en0") == 6 && !strcmp(out, "1 en0\n"));
    CHECK(bye_status_format(out, sizeof out, 1, "pdp_ip0") == 10 && !strcmp(out, "1 pdp_ip0\n"));
    CHECK(bye_status_format(out, sizeof out, 1, NULL) == 2 && !strcmp(out, "1\n"));
    CHECK(bye_status_format(out, sizeof out, 1, "") == 2 && !strcmp(out, "1\n"));

    /* the longest name that fits, then one byte more */
    CHECK(bye_status_format(out, sizeof out, 1, "abcdefghijklmno") == 18);
    CHECK(bye_status_format(out, sizeof out, 1, "abcdefghijklmnop") == 0 && out[0] == '\0');

    /* the hook reads the name as a token, so nothing else may reach the file */
    CHECK(bye_status_format(out, sizeof out, 1, "en 0") == 0);
    CHECK(bye_status_format(out, sizeof out, 1, "en0\n0") == 0);
    CHECK(bye_status_format(out, sizeof out, 1, "../x") == 0);

    /* a buffer too small is a failure, never a cut line */
    char small[7];
    CHECK(bye_status_format(small, 6, 1, "en0") == 0 && small[0] == '\0');
    CHECK(bye_status_format(small, sizeof small, 1, "en0") == 6);
    CHECK(bye_status_format(NULL, 8, 1, "en0") == 0);
    CHECK(bye_status_format(out, 0, 1, "en0") == 0);
    if (!failed) puts("test_status ok");
    return failed;
}

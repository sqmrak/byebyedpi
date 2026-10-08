#ifndef BYE_TEST_CHECK_H
#define BYE_TEST_CHECK_H

#include <stdio.h>

static int failed;

#define CHECK(cond) do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failed = 1; \
        } \
    } while (0)

#endif

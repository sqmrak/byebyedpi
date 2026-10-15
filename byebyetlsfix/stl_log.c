#define _DEFAULT_SOURCE

#include "stl_log.h"
#include "../daemon/bye_paths.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

void stl_log(const char *fmt, ...) {
    FILE *f = fopen(BYE_TLS_LOG, "a");
    if (!f) return;

    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    fprintf(f, "%04d-%02d-%02d %02d:%02d:%02d ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec);
    fprintf(f, "[pid %d] ", (int)getpid());

    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

#import "bye_trace.h"

#import <UIKit/UIKit.h>
#include <execinfo.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

#define BYE_TRACE_CAP (32 * 1024)

static int ByeTraceOpen(void) {
    struct stat st;
    int flags = O_WRONLY | O_CREAT | O_APPEND;
    /* a log that grew past the cap starts over, so it never fills a small device */
    if (stat(BYE_TRACE_PATH, &st) == 0 && st.st_size > BYE_TRACE_CAP) flags = O_WRONLY | O_CREAT | O_TRUNC;
    return open(BYE_TRACE_PATH, flags, 0644);
}

static void ByeTraceWrite(const char *text) {
    int fd = ByeTraceOpen();
    if (fd < 0) return;
    char stamp[32];
    time_t now = time(NULL);
    struct tm parts;
    localtime_r(&now, &parts);
    strftime(stamp, sizeof stamp, "%m-%d %H:%M:%S ", &parts);
    (void)write(fd, stamp, strlen(stamp));
    (void)write(fd, text, strlen(text));
    (void)write(fd, "\n", 1);
    close(fd);
}

void ByeTrace(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *text = [[[NSString alloc] initWithFormat:format arguments:args] autorelease];
    va_end(args);
    const char *utf8 = [text UTF8String];
    if (utf8) ByeTraceWrite(utf8);
}

NSString *ByeTraceTail(NSUInteger maxBytes) {
    int fd = open(BYE_TRACE_PATH, O_RDONLY);
    if (fd < 0) return @"";
    struct stat st;
    off_t size = fstat(fd, &st) == 0 ? st.st_size : 0;
    off_t from = size > (off_t)maxBytes ? size - (off_t)maxBytes : 0;
    char *buffer = malloc(maxBytes + 1);
    NSString *text = @"";
    if (buffer && lseek(fd, from, SEEK_SET) >= 0) {
        ssize_t got = read(fd, buffer, maxBytes);
        if (got > 0) {
            char *start = buffer;
            if (from > 0) {
                char *newline = memchr(buffer, '\n', (size_t)got);
                if (newline) start = newline + 1;
            }
            NSString *decoded = [[[NSString alloc] initWithBytes:start length:(NSUInteger)(buffer + got - start)
                                                        encoding:NSUTF8StringEncoding] autorelease];
            if (decoded) text = decoded;
        }
    }
    free(buffer);
    close(fd);
    return text;
}

static void ByeExceptionHandler(NSException *exception) {
    ByeTrace(@"uncaught exception %@: %@", [exception name], [exception reason]);
    for (NSString *line in [exception callStackSymbols]) ByeTrace(@"  %@", line);
}

/* restore the default signal handler so ios can still produce its own crash report */
static void ByeSignalHandler(int sig) {
    int fd = ByeTraceOpen();
    if (fd >= 0) {
        const char *name = sig == SIGSEGV ? "SIGSEGV" : sig == SIGBUS ? "SIGBUS" : sig == SIGABRT ? "SIGABRT"
                         : sig == SIGILL ? "SIGILL" : sig == SIGFPE ? "SIGFPE" : "signal";
        (void)write(fd, "fatal ", 6);
        (void)write(fd, name, strlen(name));
        (void)write(fd, "\n", 1);
        void *frames[32];
        int count = backtrace(frames, 32);
        backtrace_symbols_fd(frames, count, fd);
        close(fd);
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

void ByeTraceInstall(void) {
    char machine[64] = "?";
    size_t len = sizeof machine;
    if (sysctlbyname("hw.machine", machine, &len, NULL, 0) != 0) strcpy(machine, "?");
    machine[sizeof machine - 1] = '\0';
    NSString *version = [[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleShortVersionString"];
    ByeTrace(@"launch ByeByeDPI %@ on %s, ios %@, %.0fx%.0f at %.0fx", version ? version : @"?", machine,
             [[UIDevice currentDevice] systemVersion], [UIScreen mainScreen].bounds.size.width,
             [UIScreen mainScreen].bounds.size.height, [UIScreen mainScreen].scale);
    NSSetUncaughtExceptionHandler(&ByeExceptionHandler);
    static const int fatal[] = { SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGFPE };
    for (size_t i = 0; i < sizeof fatal / sizeof fatal[0]; ++i) signal(fatal[i], ByeSignalHandler);
}

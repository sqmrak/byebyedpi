#import "bye_daemon.h"
#import "bye_l10n.h"
#import "bye_trace.h"
#import "bye_vpn.h"

#include "bye_client.h"
#include "bye_paths.h"
#include "bye_reply.h"
#include "bye_error.h"

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

NSString * const ByeDaemonDidChangeNotification = @"ByeDaemonDidChangeNotification";

#define BYE_ANSWER_MAX 16384
#define BYE_POLL_SECONDS 1.0
#define BYE_STATUS_TIMEOUT 4.0
#define BYE_START_TIMEOUT 40.0

#pragma mark - reply

@implementation ByeReply

@synthesize ok = _ok;
@synthesize detail = _detail;
@synthesize error = _error;
@synthesize values = _values;
@synthesize pairs = _pairs;
@synthesize failureKind = _failureKind;

- (id)initOK:(BOOL)ok detail:(NSString *)detail error:(NSString *)error
      values:(NSDictionary *)values pairs:(NSArray *)pairs {
    self = [super init];
    if (!self) return nil;
    _ok = ok;
    _detail = [detail copy];
    _error = [error copy];
    _values = [values retain];
    _pairs = [pairs retain];
    return self;
}

- (void)dealloc {
    [_detail release];
    [_error release];
    [_values release];
    [_pairs release];
    [super dealloc];
}

+ (ByeReply *)failure:(NSString *)error kind:(int)kind {
    ByeReply *reply = [[[ByeReply alloc] initOK:NO detail:@"" error:error values:nil pairs:nil] autorelease];
    reply->_failureKind = kind;
    return reply;
}

+ (ByeReply *)failure:(NSString *)error {
    return [ByeReply failure:error kind:BYE_CLIENT_IO];
}

+ (ByeReply *)replyFromText:(NSString *)text {
    const char *utf8 = [text UTF8String];
    bye_reply_t parsed;
    if (!utf8 || bye_reply_parse(utf8, strlen(utf8), &parsed) != 0)
        return [ByeReply failure:@"the daemon's answer is not understood"];
    NSMutableDictionary *values = [NSMutableDictionary dictionary];
    NSMutableArray *pairs = [NSMutableArray array];
    size_t cursor = 0;
    char key[96], value[1024];
    while (bye_reply_next(&parsed, &cursor, key, sizeof key, value, sizeof value)) {
        NSString *k = [NSString stringWithUTF8String:key];
        NSString *v = [NSString stringWithUTF8String:value];
        if (!k || !v) continue;
        /* the first line with a key answers for it, like bye_reply_value */
        if (![values objectForKey:k]) [values setObject:v forKey:k];
        [pairs addObject:[NSArray arrayWithObjects:k, v, nil]];
    }
    NSString *detail = [NSString stringWithUTF8String:parsed.detail];
    return [[[ByeReply alloc] initOK:parsed.ok != 0 detail:detail ? detail : @"" error:nil
                              values:values pairs:pairs] autorelease];
}

- (NSString *)valueForKey:(NSString *)key {
    return [_values objectForKey:key];
}

@end

#pragma mark - daemon

static NSString *ByeExplainTransport(int kind, NSString *raw) {
    switch (kind) {
    case BYE_CLIENT_NO_SOCKET:
        return ByeL(@"The daemon is not running: its control socket is missing. Install the package again, or load the launchd job com.byebyedpi.byedpid.");
    case BYE_CLIENT_REFUSED:
        return ByeL(@"The daemon has stopped: its control socket is there, but nothing answers on it. Look at /var/log/byebyedpi-system.log.");
    case BYE_CLIENT_DENIED:
        return ByeL(@"The app is not allowed to use the daemon's control socket.");
    case BYE_CLIENT_NO_TOKEN:
        return ByeL(@"The daemon has not written its token yet. Wait a moment, or restart the daemon.");
    case BYE_CLIENT_TOKEN_DENIED:
        return ByeL(@"The app cannot read the daemon's token file.");
    case BYE_CLIENT_TOKEN_BAD:
        return ByeL(@"The daemon's token file is damaged. Restart the daemon.");
    case BYE_CLIENT_TOKEN_REFUSED:
        return ByeL(@"The daemon does not accept the app's token. Restart the daemon.");
    case BYE_CLIENT_TIMEOUT:
        return ByeL(@"The daemon is busy and did not answer in time.");
    case BYE_CLIENT_CLOSED:
        return ByeL(@"The daemon ended the connection.");
    default:
        return raw;
    }
}

static NSString *ByeExplainStart(NSString *detail) {
    const char *hint = bye_start_hint([detail UTF8String]);
    return hint ? ByeL([NSString stringWithUTF8String:hint]) : detail;
}

@interface ByeDaemon ()
- (void)post;
- (void)applyStatus:(ByeReply *)reply;
@end

@implementation ByeDaemon

@synthesize state = _state;
@synthesize status = _status;
@synthesize config = _config;
@synthesize busy = _busy;
@synthesize restartPending = _restartPending;

+ (ByeDaemon *)shared {
    static ByeDaemon *shared;
    if (!shared) shared = [[ByeDaemon alloc] init];
    return shared;
}

- (id)init {
    self = [super init];
    if (!self) return nil;
    _queue = dispatch_queue_create("com.byebyedpi.daemon", DISPATCH_QUEUE_SERIAL);
    return self;
}

- (void)dealloc {
    [_timer invalidate];
    dispatch_release(_queue);
    [_status release];
    [_config release];
    [_transportError release];
    [_failure release];
    [super dealloc];
}

- (void)post {
    [[NSNotificationCenter defaultCenter] postNotificationName:ByeDaemonDidChangeNotification object:self];
}

- (NSString *)rawErrorText {
    if (_failure.length) return _failure;
    if (_state == ByeDaemonUnreachable) return _transportError ? _transportError : @"";
    NSString *error = [_status objectForKey:@"error"];
    /* a running tunnel's last error is history */
    return (_state == ByeDaemonStopped && error.length) ? error : @"";
}

- (NSString *)errorText {
    NSString *raw = [self rawErrorText];
    if (!raw.length) return @"";
    if (_failure.length) return ByeExplainStart(raw);
    if (_state == ByeDaemonUnreachable) return ByeExplainTransport(_transportKind, raw);
    return ByeExplainStart(raw);
}

#pragma mark commands

- (void)command:(NSString *)command timeout:(NSTimeInterval)timeout completion:(void (^)(ByeReply *reply))done {
    NSString *line = [[command copy] autorelease];
    void (^finish)(ByeReply *) = done ? [[done copy] autorelease] : nil;
    dispatch_async(_queue, ^{
        ByeReply *reply = nil;
        /* a queue block has no pool of its own on ios 5, and the reply must outlive the pool */
        @autoreleasepool {
            char error[BYE_CLIENT_ERROR_MAX] = "";
            bye_client_t client;
            if (bye_client_open(&client, BYE_CTL_SOCKET, 1, (uint32_t)(timeout * 1000.0), error, sizeof error) != 0) {
                reply = [[ByeReply failure:[NSString stringWithUTF8String:error] kind:client.failure] retain];
            } else {
                char *answer = malloc(BYE_ANSWER_MAX);
                long got = answer ? bye_client_call(&client, [line UTF8String], answer, BYE_ANSWER_MAX,
                                                    error, sizeof error) : -1;
                bye_client_close(&client);
                if (got < 0) {
                    reply = [[ByeReply failure:answer ? [NSString stringWithUTF8String:error]
                                                      : @"not enough memory" kind:client.failure] retain];
                } else {
                    NSString *text = [[[NSString alloc] initWithBytes:answer length:(NSUInteger)got
                                                             encoding:NSUTF8StringEncoding] autorelease];
                    reply = [[ByeReply replyFromText:text ? text : @""] retain];
                }
                free(answer);
            }
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            if (finish) finish(reply);
            [reply release];
        });
    });
}

- (void)applyStatus:(ByeReply *)reply {
    ByeDaemonState before = _state;
    if (reply.error) {
        [_transportError release];
        _transportError = [reply.error copy];
        _transportKind = reply.failureKind;
        _state = ByeDaemonUnreachable;
        [_status release];
        _status = nil;
    } else {
        [_transportError release];
        _transportError = nil;
        [_status release];
        _status = [reply.values retain];
        _state = [[reply.values objectForKey:@"running"] isEqualToString:@"1"] ? ByeDaemonRunning : ByeDaemonStopped;
    }
    if (_state != before || !_traced) {
        _traced = YES;
        ByeTrace(@"daemon %@%@", _state == ByeDaemonRunning ? @"running" : _state == ByeDaemonStopped ? @"stopped" : @"unreachable",
                 _state == ByeDaemonUnreachable ? [NSString stringWithFormat:@": %@", _transportError] : @"");
    }
    if (_state != ByeDaemonUnreachable) [[ByeVPN shared] followDaemonRunning:_state == ByeDaemonRunning];
    [self post];
}

- (void)refresh {
    if (_refreshing) return;
    _refreshing = YES;
    [self command:@"status" timeout:BYE_STATUS_TIMEOUT completion:^(ByeReply *reply) {
        _refreshing = NO;
        [self applyStatus:reply];
    }];
}

- (void)reloadConfig {
    [self command:@"config" timeout:BYE_STATUS_TIMEOUT completion:^(ByeReply *reply) {
        if (reply.error || !reply.ok) return;
        [_config release];
        _config = [reply.values retain];
        [self post];
    }];
}

- (void)pollTick {
    [self refresh];
}

- (void)startPolling {
    if (_timer) return;
    _timer = [NSTimer scheduledTimerWithTimeInterval:BYE_POLL_SECONDS target:self selector:@selector(pollTick)
                                            userInfo:nil repeats:YES];
    [self refresh];
    [self reloadConfig];
}

- (void)stopPolling {
    [_timer invalidate];
    _timer = nil;
}

/* tunnel commands block the control socket until completion, so refresh status afterward */
- (void)runTunnelCommand:(NSString *)command {
    if (_busy) return;
    _busy = YES;
    [_failure release];
    _failure = nil;
    [self post];
    [self command:command timeout:BYE_START_TIMEOUT completion:^(ByeReply *reply) {
        _busy = NO;
        ByeTrace(@"%@: %@", command, reply.error ? reply.error : (reply.ok ? @"ok" : reply.detail));
        if (reply.error) {
            [_failure release];
            _failure = [reply.error copy];
        } else if (!reply.ok) {
            [_failure release];
            _failure = [reply.detail copy];
        } else {
            _restartPending = NO;
        }
        _refreshing = NO;
        [self refresh];
        [self post];
    }];
}

- (void)startTunnel {
    [self runTunnelCommand:@"start"];
}

- (void)stopTunnel {
    [self runTunnelCommand:@"stop"];
}

- (void)restartTunnel {
    [self runTunnelCommand:@"restart"];
}

- (void)applyPendingSettings {
    if (_restartPending && _state == ByeDaemonRunning) [self restartTunnel];
}

- (void)setConfigValue:(NSString *)value forKey:(NSString *)key completion:(void (^)(NSString *error))done {
    void (^finish)(NSString *) = done ? [[done copy] autorelease] : nil;
    NSString *line = [NSString stringWithFormat:@"set %@ %@", key, value];
    // proxy settings wait for client teardown and bounded dns lookups
    NSTimeInterval timeout = ([key hasPrefix:@"proxy."] || [key isEqualToString:@"proxy"] ||
                              [key isEqualToString:@"relay"]) ? BYE_START_TIMEOUT : BYE_STATUS_TIMEOUT;
    [self command:line timeout:timeout completion:^(ByeReply *reply) {
        NSString *problem = nil;
        if (reply.error) problem = reply.error;
        else if (!reply.ok) problem = reply.detail.length ? reply.detail : @"the daemon refused the setting";
        else {
            if ([reply.detail rangeOfString:@"restart to apply"].location != NSNotFound) _restartPending = YES;
            NSMutableDictionary *next = [NSMutableDictionary dictionaryWithDictionary:_config];
            [next setObject:value forKey:key];
            [_config release];
            _config = [next retain];
        }
        [self post];
        if (finish) finish(problem);
    }];
}

+ (NSString *)logTail:(NSUInteger)maxBytes {
    return [self tailOfFile:BYE_SYSTEM_LOG maxBytes:maxBytes];
}

+ (NSString *)hookLogTail:(NSUInteger)maxBytes {
    return [self tailOfFile:BYE_STATUS_LOG maxBytes:maxBytes];
}

+ (NSString *)tailOfFile:(const char *)path maxBytes:(NSUInteger)maxBytes {
    int fd = open(path, O_RDONLY);
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
            /* a cut in the middle of a line starts at the next one */
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

@end

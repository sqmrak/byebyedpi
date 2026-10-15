#import "logs_vc.h"

#include <sys/sysctl.h>
#include "bye_paths.h"

#import "bye_chrome.h"
#import "bye_daemon.h"
#import "bye_l10n.h"
#import "bye_theme.h"
#import "bye_trace.h"

#define BYE_LOG_BYTES 6000

static NSString *ByeModel(void) {
    char machine[64];
    size_t len = sizeof machine;
    if (sysctlbyname("hw.machine", machine, &len, NULL, 0) != 0 || len == 0 || len > sizeof machine)
        return [[UIDevice currentDevice] model];
    machine[sizeof machine - 1] = '\0';
    NSString *code = [NSString stringWithUTF8String:machine];
    return code.length ? code : [[UIDevice currentDevice] model];
}

static NSArray *ByeGroups(void) {
    return [NSArray arrayWithObjects:
        [NSArray arrayWithObjects:@"State", @"running", @"wanted", @"interface", @"external_interface", @"external_interface.error", @"seconds", @"attempts", @"error", @"ended",
                                  @"warning", @"config_error", @"dns", @"strategy", nil],
        [NSArray arrayWithObjects:@"Flows", @"tcp.requested", @"tcp.direct", @"tcp.desync", @"tcp.desync_passed",
                                  @"tcp.hosts_skipped", @"tcp.refused", @"tcp.aborted", @"tcp.up", @"tcp.down",
                                  @"tcp.last_error", nil],
        [NSArray arrayWithObjects:@"Strategies", @"tcp.auto_retried", @"tcp.auto_learned", @"tcp.auto_exhausted",
                                  @"tcp.addr_retried", nil],
        [NSArray arrayWithObjects:@"Telegram", @"tcp.telegram", @"tcp.telegram_fallback", @"tcp.pool_hits",
                                  @"tcp.pool_misses", @"tcp.pool_ready", nil],
        [NSArray arrayWithObjects:@"Telegram proxy", @"proxy", @"proxy.error", @"proxy.clients", @"proxy.active",
                                  @"proxy.gateway_ok", @"proxy.gateway_fail", @"proxy.bad_init", @"proxy.up",
                                  @"proxy.down", @"proxy.last_error", nil],
        [NSArray arrayWithObjects:@"UDP", @"udp.received", @"udp.sent", @"udp.quic_dropped", @"udp.last_error", nil],
        nil];
}

static ByeRow *ByeCheck(NSString *title, NSString *detail, UIColor *color) {
    ByeRow *row = [ByeRow rowWithKind:detail.length > 26 ? ByeRowStacked : ByeRowValue title:title detail:detail ident:nil];
    row.detailColor = color;
    return row;
}

static UIColor *ByeGood(void) { return ByeColorGood(); }
static UIColor *ByeBad(void) { return ByeColorBad(); }
static UIColor *ByeWarn(void) { return ByeColorWarn(); }

static NSArray *ByeChecks(void) {
    ByeDaemon *daemon = [ByeDaemon shared];
    NSDictionary *config = daemon.config;
    NSMutableArray *rows = [NSMutableArray array];

    BOOL reachable = daemon.state != ByeDaemonUnreachable;
    [rows addObject:ByeCheck(ByeL(@"Daemon"), reachable ? ByeL(@"answers") : ByeL(@"does not answer"), reachable ? ByeGood() : ByeBad())];
    if (!reachable) {
        ByeRow *why = [ByeRow rowWithKind:ByeRowStacked title:ByeL(@"What is wrong") detail:[daemon errorText] ident:nil];
        why.detailColor = ByeBad();
        [rows addObject:why];
        return rows;
    }
    NSString *tlsError = [daemon.status objectForKey:@"tls.error"];
    if (tlsError.length)
        [rows addObject:ByeCheck(@"TLS", tlsError, ByeBad())];
    NSString *interface = [daemon.status objectForKey:@"interface"];
    if (daemon.state == ByeDaemonRunning) {
        [rows addObject:ByeCheck(ByeL(@"Tunnel"), ByeLF(@"up on %@", interface.length ? interface : @"utun"), ByeGood())];
        NSString *dns = [daemon.status objectForKey:@"dns"];
        [rows addObject:ByeCheck(@"DNS", [dns hasPrefix:@"system dns"] ? ByeL(@"in order") : (dns.length ? dns : @"-"),
                                 [dns hasPrefix:@"system dns"] ? ByeGood() : ByeWarn())];
        NSString *warning = [daemon.status objectForKey:@"warning"];
        if (warning.length) {
            ByeRow *row = ByeCheck(ByeL(@"Warning"), warning, ByeWarn());
            [rows addObject:row];
        }
    } else {
        NSString *error = [daemon errorText];
        [rows addObject:ByeCheck(ByeL(@"Tunnel"), ByeL(@"down"), error.length ? ByeBad() : ByeColorTextSecondary())];
        if (error.length) {
            ByeRow *why = [ByeRow rowWithKind:ByeRowStacked title:ByeL(@"What is wrong") detail:error ident:nil];
            why.detailColor = ByeBad();
            [rows addObject:why];
        }
    }
    NSString *external = [daemon.status objectForKey:@"external_interface"];
    NSString *externalError = [daemon.status objectForKey:@"external_interface.error"];
    if (external.length || externalError.length)
        [rows addObject:ByeCheck(ByeL(@"External interface"), external.length ? external : externalError,
                                 external.length ? ByeGood() : ByeWarn())];
    if (config) {
        NSString *running = [daemon.status objectForKey:@"strategy"];
        NSString *spec = daemon.state == ByeDaemonRunning && running.length ? running : [config objectForKey:@"desync.spec"];
        if (spec.length) {
            ByeRow *strategy = [ByeRow rowWithKind:ByeRowStacked title:ByeL(@"Strategy") detail:spec ident:nil];
            strategy.monospace = YES;
            [rows addObject:strategy];
        }
        NSString *hosts = [config objectForKey:@"hosts"];
        if (!hosts.length || [hosts isEqualToString:@"none"]) {
            [rows addObject:ByeCheck(ByeL(@"Site list"), ByeL(@"none, every site"), ByeGood())];
        } else {
            NSString *path = [[NSString stringWithUTF8String:BYE_HOSTS_DIR] stringByAppendingPathComponent:hosts];
            BOOL there = [[NSFileManager defaultManager] fileExistsAtPath:path];
            BOOL only = ![[config objectForKey:@"hosts.mode"] isEqualToString:@"except"];
            [rows addObject:ByeCheck(ByeL(@"Site list"), there ? [NSString stringWithFormat:@"%@, %@", hosts,
                                     only ? ByeL(@"only listed sites") : ByeL(@"all sites except listed")]
                                                               : ByeLF(@"%@ is missing", hosts),
                                     there ? ByeGood() : ByeBad())];
        }
        BOOL telegram = [[config objectForKey:@"telegram"] isEqualToString:@"on"];
        [rows addObject:ByeCheck(ByeL(@"Telegram gateway"), telegram ? ByeL(@"on") : ByeL(@"off"), ByeColorTextSecondary())];
        NSString *proxyError = [daemon.status objectForKey:@"proxy.error"];
        BOOL proxyUp = [[daemon.status objectForKey:@"proxy"] intValue] == 1;
        if (proxyError.length) {
            [rows addObject:ByeCheck(ByeL(@"Telegram proxy"), proxyError, ByeBad())];
        } else if (proxyUp) {
            [rows addObject:ByeCheck(ByeL(@"Telegram proxy"),
                                     [NSString stringWithFormat:@"127.0.0.1:%@", [config objectForKey:@"proxy.port"]], ByeGood())];
        } else {
            [rows addObject:ByeCheck(ByeL(@"Telegram proxy"), ByeL(@"off"), ByeColorTextSecondary())];
        }
    }
    return rows;
}

static NSString *ByeVersion(void) {
    NSString *version = [[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleShortVersionString"];
    return version ? version : @"?";
}

static NSString *ByeReportText(ByeReply *probe) {
    ByeDaemon *daemon = [ByeDaemon shared];
    NSMutableString *text = [NSMutableString string];
    [text appendFormat:@"ByeByeDPI %@, %@, iOS %@\n\n", ByeVersion(), ByeModel(), [[UIDevice currentDevice] systemVersion]];
    [text appendString:@"[status]\n"];
    NSDictionary *status = daemon.status;
    for (NSString *key in [[status allKeys] sortedArrayUsingSelector:@selector(compare:)])
        [text appendFormat:@"%@=%@\n", key, [status objectForKey:key]];
    if (!status) [text appendFormat:@"unreachable: %@\n", [daemon errorText]];
    /* read the daemon report because the app may have closed since the check */
    if (probe.ok && ![[probe valueForKey:@"state"] isEqualToString:@"idle"]) {
        [text appendString:@"\n[probe]\n"];
        for (NSArray *pair in probe.pairs)
            [text appendFormat:@"%@=%@\n", [pair objectAtIndex:0], [pair objectAtIndex:1]];
    }
    [text appendString:@"\n[config]\n"];
    NSDictionary *config = daemon.config;
    for (NSString *key in [[config allKeys] sortedArrayUsingSelector:@selector(compare:)]) {
        /* the report is pasted into chats, and the secret lets anyone on the device use the proxy */
        BOOL secret = [key isEqualToString:@"proxy.secret"] && [[config objectForKey:key] length] > 0 &&
                      ![[config objectForKey:key] isEqualToString:@"auto"];
        [text appendFormat:@"%@ = %@\n", key, secret ? @"(hidden)" : [config objectForKey:key]];
    }
    [text appendString:@"\n[log]\n"];
    [text appendString:[ByeDaemon logTail:BYE_LOG_BYTES]];
    [text appendString:@"\n[tls log]\n"];
    [text appendString:[ByeDaemon tailOfFile:BYE_TLS_LOG maxBytes:3000]];
    [text appendString:@"\n[status hook]\n"];
    [text appendString:[ByeDaemon hookLogTail:2000]];
    [text appendString:@"\n[app log]\n"];
    [text appendString:ByeTraceTail(3000)];
    return text;
}

/* retain the share controller while its menu is open */
static UIDocumentInteractionController *ByeShareMenu;

static NSString *ByeReportFileName(void) {
    NSDateFormatter *format = [[[NSDateFormatter alloc] init] autorelease];
    format.dateFormat = @"yyyyMMdd-HHmmss";
    return [NSString stringWithFormat:@"ByeByeDPI-%@.txt", [format stringFromDate:[NSDate date]]];
}

static void ByeRemoveOldReports(void) {
    NSString *directory = NSTemporaryDirectory();
    for (NSString *name in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:directory error:NULL]) {
        if ([name hasPrefix:@"ByeByeDPI-"] && [name hasSuffix:@".txt"])
            [[NSFileManager defaultManager] removeItemAtPath:[directory stringByAppendingPathComponent:name] error:NULL];
    }
}

@implementation LogsVC

+ (void)shareReportFrom:(UIViewController *)host {
    [[ByeDaemon shared] command:@"probe" timeout:3.0 completion:^(ByeReply *probe) {
        NSString *text = ByeReportText(probe);
        ByeRemoveOldReports();
        NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:ByeReportFileName()];
        NSError *error = nil;
        if (![text writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&error]) {
            ByeAlert(ByeL(@"The report was not saved"), error.localizedDescription ? error.localizedDescription : @"");
            return;
        }
        [ByeShareMenu release];
        ByeShareMenu = [[UIDocumentInteractionController interactionControllerWithURL:[NSURL fileURLWithPath:path]] retain];
        ByeShareMenu.UTI = @"public.plain-text";
        UIBarButtonItem *anchor = host.navigationItem.rightBarButtonItem;
        BOOL shown;
        if (anchor) {
            shown = [ByeShareMenu presentOptionsMenuFromBarButtonItem:anchor animated:YES];
        } else {
            CGRect bounds = host.view.bounds;
            shown = [ByeShareMenu presentOptionsMenuFromRect:CGRectMake(CGRectGetMidX(bounds), CGRectGetMidY(bounds), 1.0f, 1.0f)
                                                      inView:host.view animated:YES];
        }
        if (!shown) {
            [UIPasteboard generalPasteboard].string = text;
            ByeAlert(ByeL(@"No app takes the file"),
                     ByeL(@"The report is on the pasteboard instead. Paste it into a message to send it."));
        }
    }];
}

+ (void)copyReportAndTell {
    [[ByeDaemon shared] command:@"probe" timeout:3.0 completion:^(ByeReply *probe) {
        [UIPasteboard generalPasteboard].string = ByeReportText(probe);
        ByeAlert(ByeL(@"Copied"), ByeL(@"The report is on the pasteboard. Paste it into a message to send it."));
    }];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = ByeL(@"Diagnostics");
    self.navigationItem.rightBarButtonItem = ByeBarItem(nil, ByeIcon(@"copy", 20.0f, [UIColor whiteColor]), NO,
                                                        self, @selector(copyPressed));
    self.navigationItem.rightBarButtonItem.accessibilityLabel = ByeL(@"Share as a .txt file");
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(daemonChanged:)
                                                 name:ByeDaemonDidChangeNotification object:nil];
    [[ByeDaemon shared] reloadConfig];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [super dealloc];
}

- (void)copyPressed {
    ByeChoose(self, nil, [NSArray arrayWithObjects:ByeL(@"Share as a .txt file"), ByeL(@"Copy logs"), nil], ^(NSInteger index) {
        if (index == 0) [LogsVC shareReportFrom:self];
        else if (index == 1) [LogsVC copyReportAndTell];
    });
}

- (void)daemonChanged:(NSNotification *)note {
    (void)note;
    [self reloadForm];
}

- (NSArray *)buildSections {
    ByeDaemon *daemon = [ByeDaemon shared];
    NSDictionary *status = daemon.status;
    NSMutableArray *sections = [NSMutableArray array];

    [sections addObject:[ByeSection sectionWithTitle:ByeL(@"Checks") footer:nil rows:ByeChecks()]];

    NSString *state = daemon.state == ByeDaemonRunning ? ByeL(@"Connected")
                    : daemon.state == ByeDaemonStopped ? ByeL(@"Disconnected") : ByeL(@"Daemon unavailable");
    NSMutableArray *head = [NSMutableArray array];
    [head addObject:[ByeRow rowWithKind:ByeRowValue title:ByeL(@"Tunnel") detail:state ident:nil]];
    [head addObject:[ByeRow rowWithKind:ByeRowValue title:ByeL(@"App") detail:ByeVersion() ident:nil]];
    [head addObject:[ByeRow rowWithKind:ByeRowValue title:@"iOS"
                                 detail:[NSString stringWithFormat:@"%@ · %@", [[UIDevice currentDevice] systemVersion], ByeModel()]
                                  ident:nil]];
    NSString *raw = [daemon rawErrorText];
    if (raw.length) {
        ByeRow *row = [ByeRow rowWithKind:ByeRowStacked title:ByeL(@"Error as the daemon said it") detail:raw ident:nil];
        row.detailColor = ByeColorBad();
        row.monospace = YES;
        [head addObject:row];
    }
    [sections addObject:[ByeSection sectionWithTitle:ByeL(@"About this device") footer:nil rows:head]];

    for (NSArray *group in ByeGroups()) {
        NSMutableArray *rows = [NSMutableArray array];
        for (NSUInteger i = 1; i < group.count; ++i) {
            NSString *key = [group objectAtIndex:i];
            NSString *value = [status objectForKey:key];
            if (!value || [key isEqualToString:@"error"]) continue;
            if (!value.length && ([key hasSuffix:@"error"] || [key isEqualToString:@"ended"] || [key isEqualToString:@"warning"])) continue;
            ByeRow *row = [ByeRow rowWithKind:value.length > 28 ? ByeRowStacked : ByeRowValue title:key detail:value.length ? value : @"-" ident:nil];
            [rows addObject:row];
        }
        if (rows.count) [sections addObject:[ByeSection sectionWithTitle:ByeL([group objectAtIndex:0]) footer:nil rows:rows]];
    }

    NSString *tail = [ByeDaemon logTail:BYE_LOG_BYTES];
    ByeRow *log = [ByeRow rowWithKind:ByeRowStacked title:@"/var/log/byebyedpi-system.log"
                               detail:tail.length ? tail : ByeL(@"The log is empty.") ident:nil];
    log.monospace = YES;
    [sections addObject:[ByeSection sectionWithTitle:ByeL(@"Daemon log") footer:nil rows:[NSArray arrayWithObject:log]]];
    NSString *tlsTail = [ByeDaemon tailOfFile:BYE_TLS_LOG maxBytes:3000];
    ByeRow *tls = [ByeRow rowWithKind:ByeRowStacked title:@BYE_TLS_LOG
                               detail:tlsTail.length ? tlsTail : ByeL(@"The log is empty.") ident:nil];
    tls.monospace = YES;
    [sections addObject:[ByeSection sectionWithTitle:ByeL(@"TLS log") footer:nil rows:[NSArray arrayWithObject:tls]]];
    NSString *trace = ByeTraceTail(3000);
    ByeRow *app = [ByeRow rowWithKind:ByeRowStacked title:@"com.byebyedpi.app.log"
                               detail:trace.length ? trace : ByeL(@"The log is empty.") ident:nil];
    app.monospace = YES;
    [sections addObject:[ByeSection sectionWithTitle:ByeL(@"App log") footer:nil rows:[NSArray arrayWithObject:app]]];
    return sections;
}

@end

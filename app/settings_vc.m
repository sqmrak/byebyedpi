#import "settings_vc.h"

#import "bye_daemon.h"
#import "bye_l10n.h"
#import "bye_lists.h"
#import "bye_strategies.h"
#import "bye_theme.h"
#import "about_vc.h"
#import "editor_vc.h"
#import "lists_vc.h"
#import "probe_vc.h"

static NSString * const ByeConnectOnOpenKey = @"ByeConnectOnOpen";

@implementation SettingsVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = ByeL(@"Settings");
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(daemonChanged:)
                                                 name:ByeDaemonDidChangeNotification object:nil];
    [[ByeDaemon shared] reloadConfig];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [super dealloc];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    if (self.navigationController.topViewController != self) {
        /* a screen pushed from here keeps the restart for later; leaving settings applies it */
        if (self.isMovingFromParentViewController) [[ByeDaemon shared] applyPendingSettings];
    } else {
        [[ByeDaemon shared] applyPendingSettings];
    }
}

- (void)daemonChanged:(NSNotification *)note {
    (void)note;
    [self reloadForm];
}

- (NSString *)configValue:(NSString *)key {
    return [[[ByeDaemon shared] config] objectForKey:key];
}

- (BOOL)configOn:(NSString *)key {
    return [[self configValue:key] isEqualToString:@"on"];
}

- (NSString *)languageName {
    switch (ByeLanguageSetting()) {
    case ByeLanguageEnglish: return @"English";
    case ByeLanguageRussian: return @"Русский";
    default: return ByeL(@"Automatic");
    }
}

- (NSArray *)buildSections {
    ByeDaemon *daemon = [ByeDaemon shared];
    NSString *poolText = [self configValue:@"telegram.pool"];
    NSString *dns = [self configValue:@"dns"];
    NSString *relay = [self configValue:@"relay"];
    BOOL only = ![[self configValue:@"hosts.mode"] isEqualToString:@"except"];
    BOOL quicBlock = [[self configValue:@"quic"] isEqualToString:@"block"];

    ByeRow *language = [ByeRow rowWithKind:ByeRowValue title:ByeL(@"Language") detail:[self languageName] ident:@"language"];
    language.accessory = ByeAccessoryDisclosure;
    ByeRow *connect = [ByeRow rowWithKind:ByeRowSwitch title:ByeL(@"Connect when the app opens") detail:nil ident:@"connect"];
    connect.on = [[NSUserDefaults standardUserDefaults] boolForKey:ByeConnectOnOpenKey];
    ByeRow *autostart = [ByeRow rowWithKind:ByeRowSwitch title:ByeL(@"Connect when the device starts") detail:nil ident:@"autostart"];
    autostart.on = [self configOn:@"autostart"];

    ByeRow *strategies = [ByeRow rowWithKind:ByeRowValue title:ByeL(@"Strategy")
                                      detail:[ByeStrategies display:[self configValue:@"desync.spec"]] ident:@"strategies"];
    strategies.monospace = ![[self configValue:@"desync.spec"] isEqualToString:@"auto"];
    strategies.accessory = ByeAccessoryDisclosure;
    ByeRow *probe = [ByeRow rowWithKind:ByeRowValue title:ByeL(@"Find a working strategy") detail:nil ident:@"probe"];
    probe.accessory = ByeAccessoryDisclosure;
    ByeRow *lists = [ByeRow rowWithKind:ByeRowValue title:ByeL(@"Site lists") detail:nil ident:@"lists"];
    lists.accessory = ByeAccessoryDisclosure;
    ByeRow *mode = [ByeRow rowWithKind:ByeRowValue title:ByeL(@"Apply to")
                                detail:only ? ByeL(@"only listed sites") : ByeL(@"all sites except listed") ident:@"mode"];
    mode.accessory = ByeAccessoryDisclosure;

    ByeRow *quic = [ByeRow rowWithKind:ByeRowSwitch title:ByeL(@"Block QUIC (use TCP)") detail:nil ident:@"quic"];
    quic.on = quicBlock;
    ByeRow *dnsRow = [ByeRow rowWithKind:ByeRowValue title:@"DNS"
                                  detail:(dns.length && ![dns isEqualToString:@"system"]) ? dns : ByeL(@"system") ident:@"dns"];
    dnsRow.accessory = ByeAccessoryDisclosure;

    NSString *secret = [self configValue:@"proxy.secret"];
    BOOL haveSecret = secret.length == 32;
    NSString *port = [self configValue:@"proxy.port"];
    ByeRow *proxy = [ByeRow rowWithKind:ByeRowSwitch title:ByeL(@"Proxy for Telegram") detail:nil ident:@"proxy"];
    proxy.on = [self configOn:@"proxy"];
    NSMutableArray *proxyRows = [NSMutableArray arrayWithObject:proxy];
    if (proxy.on) {
        ByeRow *server = [ByeRow rowWithKind:ByeRowValue title:ByeL(@"Server") detail:@"127.0.0.1" ident:@"proxyserver"];
        ByeRow *portRow = [ByeRow rowWithKind:ByeRowValue title:ByeL(@"Port") detail:port.length ? port : @"1082" ident:@"proxyport"];
        portRow.accessory = ByeAccessoryDisclosure;
        [proxyRows addObject:server];
        [proxyRows addObject:portRow];
        if (haveSecret) {
            ByeRow *secretRow = [ByeRow rowWithKind:ByeRowStacked title:ByeL(@"Secret")
                                             detail:[@"dd" stringByAppendingString:secret] ident:@"proxysecret"];
            secretRow.monospace = YES;
            secretRow.selectable = YES;
            secretRow.accessory = ByeAccessoryDisclosure;
            [proxyRows addObject:secretRow];
            [proxyRows addObject:[ByeRow rowWithKind:ByeRowButton title:ByeL(@"Add the proxy to Telegram") detail:nil ident:@"proxyadd"]];
            [proxyRows addObject:[ByeRow rowWithKind:ByeRowButton title:ByeL(@"Copy the proxy link") detail:nil ident:@"proxycopy"]];
        }
    }
    NSString *proxyError = [daemon.status objectForKey:@"proxy.error"];
    NSString *proxyFooter = proxyError.length ? proxyError
        : ByeL(@"A local MTProto proxy. In Telegram it is a proxy of type MTProto on this device. It works with the tunnel on or off, and needs no strategy.");

    ByeRow *telegram = [ByeRow rowWithKind:ByeRowSwitch title:ByeL(@"Telegram through the tunnel") detail:nil ident:@"telegram"];
    telegram.on = [self configOn:@"telegram"];
    ByeRow *pool = [ByeRow rowWithKind:ByeRowValue title:ByeL(@"Telegram: connections kept ready") detail:poolText.length ? poolText : @"1" ident:@"pool"];
    pool.accessory = ByeAccessoryDisclosure;
    ByeRow *relayRow = [ByeRow rowWithKind:ByeRowValue title:ByeL(@"Telegram relay domains")
                                    detail:(relay.length && ![relay isEqualToString:@"none"]) ? relay : ByeL(@"none") ident:@"relay"];
    relayRow.accessory = ByeAccessoryDisclosure;

    ByeRow *restart = [ByeRow rowWithKind:ByeRowButton title:ByeL(@"Restart the tunnel") detail:nil ident:@"restart"];
    restart.selectable = daemon.state == ByeDaemonRunning && !daemon.busy;

    NSString *pending = daemon.restartPending && daemon.state == ByeDaemonRunning
        ? ByeL(@"The tunnel restarts when you leave this screen.") : nil;

    ByeRow *about = [ByeRow rowWithKind:ByeRowValue title:ByeL(@"About") detail:nil ident:@"about"];
    about.accessory = ByeAccessoryDisclosure;

    return [NSArray arrayWithObjects:
        [ByeSection sectionWithTitle:ByeL(@"General") footer:nil rows:[NSArray arrayWithObjects:language, connect, nil]],
        [ByeSection sectionWithTitle:ByeL(@"Automation") footer:nil rows:[NSArray arrayWithObject:autostart]],
        [ByeSection sectionWithTitle:@"ByeDPI" footer:ByeL(@"The lists decide which sites the bypass applies to: only the listed ones, or all the others.")
                                rows:[NSArray arrayWithObjects:strategies, probe, lists, mode, nil]],
        [ByeSection sectionWithTitle:ByeL(@"Network") footer:ByeL(@"Apps that try QUIC fall back to tcp at once when it is refused.")
                                rows:[NSArray arrayWithObjects:quic, dnsRow, nil]],
        [ByeSection sectionWithTitle:@"Telegram" footer:proxyFooter rows:proxyRows],
        [ByeSection sectionWithTitle:ByeL(@"Telegram through the tunnel")
                              footer:ByeL(@"Carries Telegram of every app on the device while the tunnel is on, with no proxy setting. Ready connections wait for the next flow of each datacenter in use. A relay is a cloudflare domain that carries the gateway, for the proxy as well, when the network blocks telegram's addresses.")
                                rows:[NSArray arrayWithObjects:telegram, pool, relayRow, nil]],
        [ByeSection sectionWithTitle:nil footer:pending rows:[NSArray arrayWithObject:restart]],
        [ByeSection sectionWithTitle:nil footer:nil rows:[NSArray arrayWithObject:about]],
        nil];
}

- (void)setKey:(NSString *)key value:(NSString *)value {
    [[ByeDaemon shared] setConfigValue:value forKey:key completion:^(NSString *error) {
        if (error) ByeAlert(ByeL(@"The setting was not saved"), error);
        /* the daemon draws the proxy secret itself, so the app asks for it */
        if ([key hasPrefix:@"proxy"]) [[ByeDaemon shared] reloadConfig];
        [self reloadForm];
    }];
}

- (NSString *)proxyQuery {
    return [NSString stringWithFormat:@"server=127.0.0.1&port=%@&secret=dd%@",
            [self configValue:@"proxy.port"], [self configValue:@"proxy.secret"]];
}

- (void)formSwitchChanged:(ByeRow *)row on:(BOOL)on {
    NSString *ident = row.ident;
    if ([ident isEqualToString:@"connect"]) {
        [[NSUserDefaults standardUserDefaults] setBool:on forKey:ByeConnectOnOpenKey];
        [[NSUserDefaults standardUserDefaults] synchronize];
    } else if ([ident isEqualToString:@"autostart"]) {
        [self setKey:@"autostart" value:on ? @"on" : @"off"];
    } else if ([ident isEqualToString:@"quic"]) {
        [self setKey:@"quic" value:on ? @"block" : @"pass"];
    } else if ([ident isEqualToString:@"telegram"]) {
        [self setKey:@"telegram" value:on ? @"on" : @"off"];
    } else if ([ident isEqualToString:@"proxy"]) {
        [self setKey:@"proxy" value:on ? @"on" : @"off"];
    }
}

- (void)formRowTapped:(ByeRow *)row {
    NSString *ident = row.ident;
    if ([ident isEqualToString:@"language"]) {
        ByeChoose(self, ByeL(@"Language"), [NSArray arrayWithObjects:ByeL(@"Automatic"), @"English",
                  @"Русский", nil], ^(NSInteger index) {
            if (index < 0) return;
            ByeSetLanguageSetting((ByeLanguage)index);
            self.title = ByeL(@"Settings");
            [self reloadForm];
        });
    } else if ([ident isEqualToString:@"strategies"]) {
        [self.navigationController pushViewController:[[[EditorVC alloc] init] autorelease] animated:YES];
    } else if ([ident isEqualToString:@"probe"]) {
        [self.navigationController pushViewController:[[[ProbeVC alloc] init] autorelease] animated:YES];
    } else if ([ident isEqualToString:@"lists"]) {
        [self.navigationController pushViewController:[[[ListsVC alloc] initForPurpose:ByeListsForHosts] autorelease] animated:YES];
    } else if ([ident isEqualToString:@"mode"]) {
        ByeChoose(self, ByeL(@"Apply to"), [NSArray arrayWithObjects:ByeL(@"only listed sites"), ByeL(@"all sites except listed"), nil],
                  ^(NSInteger index) {
            if (index < 0) return;
            [self setKey:@"hosts.mode" value:index == 0 ? @"only" : @"except"];
        });
    } else if ([ident isEqualToString:@"dns"]) {
        NSString *dns = [self configValue:@"dns"];
        ByePromptText(@"DNS", ByeL(@"An IPv4 address, or \"system\""), [dns isEqualToString:@"system"] ? @"" : dns, @"1.1.1.1", YES,
                      ^(NSString *text) {
            if (!text) return;
            NSString *value = [text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            [self setKey:@"dns" value:value.length ? value : @"system"];
        });
    } else if ([ident isEqualToString:@"pool"]) {
        ByeChoose(self, ByeL(@"Telegram: connections kept ready"), [NSArray arrayWithObjects:@"0", @"1", @"2", nil], ^(NSInteger index) {
            if (index < 0) return;
            [self setKey:@"telegram.pool" value:[NSString stringWithFormat:@"%ld", (long)index]];
        });
    } else if ([ident isEqualToString:@"relay"]) {
        NSString *relay = [self configValue:@"relay"];
        ByePromptText(ByeL(@"Telegram relay domains"), ByeL(@"Up to four domains split by commas, or \"none\""),
                      [relay isEqualToString:@"none"] ? @"" : relay, @"example.co.uk", NO, ^(NSString *text) {
            if (!text) return;
            NSString *value = [text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            [self setKey:@"relay" value:value.length ? value : @"none"];
        });
    } else if ([ident isEqualToString:@"proxyport"]) {
        ByePromptText(ByeL(@"Port"), ByeL(@"A number from 1 to 65535. Telegram has to be given the same one."),
                      [self configValue:@"proxy.port"], @"1082", YES, ^(NSString *text) {
            if (!text) return;
            [self setKey:@"proxy.port" value:[text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]];
        });
    } else if ([ident isEqualToString:@"proxysecret"]) {
        NSString *secret = row.detail;
        ByeChoose(self, nil, [NSArray arrayWithObjects:ByeL(@"Copy"), ByeL(@"New secret"), nil], ^(NSInteger index) {
            if (index == 0) {
                [UIPasteboard generalPasteboard].string = secret;
                ByeAlert(ByeL(@"Copied"), secret);
            } else if (index == 1) {
                [self setKey:@"proxy.secret" value:@"auto"];
            }
        });
    } else if ([ident isEqualToString:@"proxyadd"]) {
        /* the official client and its forks register tg:// */
        NSURL *url = [NSURL URLWithString:[@"tg://proxy?" stringByAppendingString:[self proxyQuery]]];
        if (![[UIApplication sharedApplication] openURL:url])
            ByeAlert(ByeL(@"Telegram did not open"),
                     ByeL(@"No app takes tg:// links. Install Telegram, or copy the link and open it in the client you use."));
    } else if ([ident isEqualToString:@"proxycopy"]) {
        NSString *link = [@"https://t.me/proxy?" stringByAppendingString:[self proxyQuery]];
        [UIPasteboard generalPasteboard].string = link;
        ByeAlert(ByeL(@"Copied"), link);
    } else if ([ident isEqualToString:@"about"]) {
        [self.navigationController pushViewController:[[[AboutVC alloc] init] autorelease] animated:YES];
    } else if ([ident isEqualToString:@"restart"]) {
        [[ByeDaemon shared] restartTunnel];
    }
}

@end

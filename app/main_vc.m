#import "main_vc.h"

#import <QuartzCore/QuartzCore.h>

#import "bye_boykisser.h"
#import "bye_chrome.h"
#import "bye_daemon.h"
#import "bye_l10n.h"
#import "bye_strategies.h"
#import "bye_theme.h"
#import "editor_vc.h"
#import "lists_vc.h"
#import "logs_vc.h"
#import "probe_vc.h"
#import "settings_vc.h"

static NSString * const ByeConnectOnOpenKey = @"ByeConnectOnOpen";
static const CGFloat ByeTitleInset = 14.0f;

@interface MainVC () {
    ByePowerButton *_power;
    UILabel *_status;
    UILabel *_detail;
    ByeChip *_chip;
    ByeTileButton *_editor, *_settings, *_probe, *_lists;
    ByeBoykisserField *_field;
    UIView *_titleLabel;
    UILabel *_titleText;
    BOOL _starting;          /* the busy state is a start, not a stop */
    BOOL _autoStartDone;
}
- (void)refreshUI;
@end

@implementation MainVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"ByeByeDPI";
    /* ios centres a title; a label as wide as the bar, aligned left, puts it at the edge */
    _titleLabel = [[UIView alloc] initWithFrame:CGRectMake(0.0f, 0.0f, 200.0f, 44.0f)];
    _titleLabel.backgroundColor = [UIColor clearColor];
    _titleText = [[UILabel alloc] initWithFrame:CGRectMake(ByeTitleInset, 0.0f, 180.0f, 44.0f)];
    _titleText.backgroundColor = [UIColor clearColor];
    _titleText.text = @"ByeByeDPI";
    _titleText.textAlignment = NSTextAlignmentLeft;
    _titleText.font = ByeFont(20.0f, YES);
    _titleText.textColor = ByeColorBarText();
    _titleText.shadowColor = ByeThemeModern() ? [UIColor clearColor] : [UIColor colorWithWhite:0.0f alpha:0.5f];
    _titleText.shadowOffset = CGSizeMake(0.0f, -1.0f);
    [_titleLabel addSubview:_titleText];
    _titleLabel.userInteractionEnabled = NO;
    self.navigationItem.titleView = _titleLabel;

    if (ByeThemeBoykisser()) {
        _field = [[ByeBoykisserField alloc] initWithFrame:self.view.bounds];
        _field.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        [self.view addSubview:_field];
        [_field start];
    }

    _power = [[ByePowerButton alloc] initWithFrame:CGRectMake(0.0f, 0.0f, 200.0f, 200.0f)];
    [_power addTarget:self action:@selector(powerPressed) forControlEvents:UIControlEventTouchUpInside];
    _power.accessibilityLabel = ByeL(@"Power");
    [self.view addSubview:_power];

    _status = [[UILabel alloc] initWithFrame:CGRectZero];
    _status.backgroundColor = [UIColor clearColor];
    _status.textAlignment = NSTextAlignmentCenter;
    _status.font = ByeFont(19.0f, YES);
    _status.textColor = ByeColorText();
    _status.shadowColor = ByeTextShadowColor();
    _status.shadowOffset = CGSizeMake(0.0f, -1.0f);
    _status.adjustsFontSizeToFitWidth = YES;
    _status.lineBreakMode = NSLineBreakByClipping;
    [self.view addSubview:_status];

    _detail = [[UILabel alloc] initWithFrame:CGRectZero];
    _detail.backgroundColor = [UIColor clearColor];
    _detail.textAlignment = NSTextAlignmentCenter;
    _detail.font = ByeFont(12.0f, NO);
    _detail.textColor = ByeColorTextSecondary();
    _detail.shadowColor = ByeTextShadowColor();
    _detail.shadowOffset = CGSizeMake(0.0f, -1.0f);
    _detail.numberOfLines = 3;
    _detail.lineBreakMode = NSLineBreakByWordWrapping;
    [self.view addSubview:_detail];
    [_detail addGestureRecognizer:[[[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(openDiagnostics)] autorelease]];

    _chip = [[ByeChip alloc] initWithFrame:CGRectZero];
    [self.view addSubview:_chip];
    [_chip addGestureRecognizer:[[[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(openEditor)] autorelease]];

    _editor = [[ByeTileButton alloc] initWithTitle:ByeL(@"Strategies") glyph:@"tune"];
    _settings = [[ByeTileButton alloc] initWithTitle:ByeL(@"Settings") glyph:@"settings"];
    _probe = [[ByeTileButton alloc] initWithTitle:ByeL(@"Probe") glyph:@"speed"];
    _lists = [[ByeTileButton alloc] initWithTitle:ByeL(@"Lists") glyph:@"lists"];
    [_editor addTarget:self action:@selector(openEditor) forControlEvents:UIControlEventTouchUpInside];
    [_settings addTarget:self action:@selector(openSettings) forControlEvents:UIControlEventTouchUpInside];
    [_probe addTarget:self action:@selector(openProbe) forControlEvents:UIControlEventTouchUpInside];
    [_lists addTarget:self action:@selector(openLists) forControlEvents:UIControlEventTouchUpInside];
    for (UIView *tile in [NSArray arrayWithObjects:_editor, _settings, _probe, _lists, nil]) [self.view addSubview:tile];

    self.navigationItem.rightBarButtonItem = ByeBarItem(nil, ByeIcon(@"more", 20.0f, [UIColor whiteColor]), NO,
                                                        self, @selector(menuPressed));
    self.navigationItem.rightBarButtonItem.accessibilityLabel = ByeL(@"Menu");

    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(daemonChanged:)
                                                 name:ByeDaemonDidChangeNotification object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(languageChanged:)
                                                 name:ByeLanguageDidChangeNotification object:nil];
    [self refreshUI];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [_power release];
    [_status release];
    [_detail release];
    [_chip release];
    [_editor release];
    [_settings release];
    [_probe release];
    [_lists release];
    [_field stop];
    [_field release];
    [_titleLabel release];
    [_titleText release];
    [super dealloc];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [_field setPaused:NO];
    [self refreshUI];
    [[ByeDaemon shared] reloadConfig];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    [_field setPaused:YES];
}

- (void)languageChanged:(NSNotification *)note {
    (void)note;
    [_editor setTitle:ByeL(@"Strategies")];
    [_settings setTitle:ByeL(@"Settings")];
    [_probe setTitle:ByeL(@"Probe")];
    [_lists setTitle:ByeL(@"Lists")];
    _power.accessibilityLabel = ByeL(@"Power");
    [self refreshUI];
}

#pragma mark state

static NSString *ByeDuration(long seconds) {
    if (seconds < 0) seconds = 0;
    return [NSString stringWithFormat:@"%02ld:%02ld:%02ld", seconds / 3600, (seconds / 60) % 60, seconds % 60];
}

/* saved settings may differ from the strategy the running tunnel uses */
- (NSString *)strategySummary {
    ByeDaemon *daemon = [ByeDaemon shared];
    NSDictionary *config = [daemon config];
    if (!config) return @"";
    NSString *running = [daemon.status objectForKey:@"strategy"];
    NSString *spec = daemon.state == ByeDaemonRunning && running.length ? running : [config objectForKey:@"desync.spec"];
    return [ByeStrategies display:spec];
}

- (void)refreshUI {
    ByeDaemon *daemon = [ByeDaemon shared];
    NSString *error = [daemon errorText];
    ByePowerState power = ByePowerOff;
    NSString *status = ByeL(@"Disconnected");
    NSString *detail = @"";
    UIColor *detailColor = ByeColorTextSecondary();
    NSDictionary *info = daemon.status;

    if (daemon.busy) {
        power = ByePowerBusy;
        status = _starting ? ByeL(@"Connecting...") : ByeL(@"Disconnecting...");
    } else if (daemon.state == ByeDaemonRunning) {
        power = ByePowerOn;
        status = ByeL(@"Connected");
        long seconds = [[info objectForKey:@"seconds"] longLongValue];
        detail = [NSString stringWithFormat:@"%@ \u00b7 %@", [info objectForKey:@"interface"], ByeDuration(seconds)];
        NSString *warning = [info objectForKey:@"warning"];
        if (warning.length) {
            detail = [detail stringByAppendingFormat:@"\n%@", warning];
            detailColor = ByeColorWarn();
        }
    } else if (daemon.state == ByeDaemonUnreachable) {
        power = ByePowerError;
        status = ByeL(@"Daemon unavailable");
        detail = error.length ? error : ByeL(@"The daemon does not answer.");
        detailColor = ByeColorBad();
    } else if (error.length) {
        power = ByePowerError;
        status = ByeL(@"Could not connect");
        detail = error;
        detailColor = ByeColorBad();
    } else {
        detail = ByeL(@"Tap the button to start");
    }
    /* the proxy does not depend on the tunnel, so it is said in every state it is up */
    if ([[info objectForKey:@"proxy"] intValue] == 1 && power != ByePowerError)
        detail = [detail stringByAppendingFormat:@"\n%@", [NSString stringWithFormat:ByeL(@"Telegram proxy: 127.0.0.1:%@"),
                                                           [[daemon config] objectForKey:@"proxy.port"]]];
    if (power == ByePowerError) detail = [detail stringByAppendingFormat:@"\n%@", ByeL(@"Tap here for diagnostics.")];
    _detail.userInteractionEnabled = power == ByePowerError;
    _power.powerState = power;
    _power.enabled = !daemon.busy && daemon.state != ByeDaemonUnreachable;
    _status.text = status;
    _detail.text = detail;
    _detail.textColor = detailColor;
    _chip.text = [self strategySummary];
    [self.view setNeedsLayout];
}

- (void)daemonChanged:(NSNotification *)note {
    (void)note;
    [self refreshUI];
    ByeDaemon *daemon = [ByeDaemon shared];
    /* "connect when the app opens": once, when the daemon first answers with the tunnel down */
    if (!_autoStartDone && daemon.state != ByeDaemonUnreachable && daemon.config) {
        _autoStartDone = YES;
        if ([[NSUserDefaults standardUserDefaults] boolForKey:ByeConnectOnOpenKey] &&
            daemon.state == ByeDaemonStopped && !daemon.busy) {
            _starting = YES;
            [daemon startTunnel];
        }
    }
}

#pragma mark actions

- (void)powerPressed {
    ByeDaemon *daemon = [ByeDaemon shared];
    if (daemon.busy || daemon.state == ByeDaemonUnreachable) return;
    if (daemon.state == ByeDaemonRunning) {
        _starting = NO;
        [daemon stopTunnel];
    } else {
        _starting = YES;
        [daemon startTunnel];
    }
}

- (void)openDiagnostics { [self.navigationController pushViewController:[[[LogsVC alloc] init] autorelease] animated:YES]; }
- (void)openEditor { [self.navigationController pushViewController:[[[EditorVC alloc] init] autorelease] animated:YES]; }
- (void)openSettings { [self.navigationController pushViewController:[[[SettingsVC alloc] init] autorelease] animated:YES]; }
- (void)openProbe { [self.navigationController pushViewController:[[[ProbeVC alloc] init] autorelease] animated:YES]; }
- (void)openLists {
    [self.navigationController pushViewController:[[[ListsVC alloc] initForPurpose:ByeListsForHosts] autorelease]
                                         animated:YES];
}

- (void)menuPressed {
    ByeDaemon *daemon = [ByeDaemon shared];
    NSMutableArray *items = [NSMutableArray arrayWithObjects:ByeL(@"Diagnostics"), ByeL(@"Share as a .txt file"), ByeL(@"Copy logs"), nil];
    BOOL running = daemon.state == ByeDaemonRunning && !daemon.busy;
    if (running) [items addObject:ByeL(@"Stop")];
    ByeChoose(self, nil, items, ^(NSInteger index) {
        if (index == 0) {
            [self.navigationController pushViewController:[[[LogsVC alloc] init] autorelease] animated:YES];
        } else if (index == 1) {
            [LogsVC shareReportFrom:self];
        } else if (index == 2) {
            [LogsVC copyReportAndTell];
        } else if (index == 3) {
            _starting = NO;
            [[ByeDaemon shared] stopTunnel];
        }
    });
}

#pragma mark layout

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    /* the bar centres its title view, so the label is as wide as the bar less a margin each side */
    CGFloat barWidth = self.navigationController.navigationBar.bounds.size.width;
    CGFloat titleWidth = MAX(120.0f, barWidth - 24.0f);
    if (barWidth > 0.0f && fabsf((float)(_titleLabel.frame.size.width - titleWidth)) > 0.5f) {
        _titleLabel.frame = CGRectMake(0.0f, 0.0f, titleWidth, 44.0f);
        _titleText.frame = CGRectMake(ByeTitleInset, 0.0f, titleWidth - ByeTitleInset, 44.0f);
        self.navigationItem.titleView = _titleLabel;
    }

    CGRect b = self.view.bounds;
    CGFloat safeBottom = ByeBottomSafeInset();
    BOOL wide = b.size.width > b.size.height * 1.15f;
    BOOL pad = ByeIsPad();
    CGFloat margin = pad ? 24.0f : 14.0f;
    CGFloat gap = pad ? 16.0f : 10.0f;
    if (!wide && b.size.height < 600.0f) {
        margin = 10.0f;
        gap = 6.0f;
    }

    /* a short screen needs one row of tiles to leave room for the connection controls */
    CGRect tiles;
    CGRect upper;
    CGFloat tileWidth, tileHeight;
    BOOL compact = !wide && b.size.height < 600.0f;
    if (wide) {
        CGFloat columns = MIN(b.size.width * 0.44f, pad ? 460.0f : 320.0f);
        tileWidth = floorf((float)(columns - gap) * 0.5f);
        tileHeight = MIN(floorf((float)(b.size.height - margin * 2.0f - gap - safeBottom) * 0.5f), pad ? 130.0f : 84.0f);
        tiles = CGRectMake(b.size.width - margin - columns, floorf((float)(b.size.height - safeBottom - tileHeight * 2.0f - gap) * 0.5f),
                           columns, tileHeight * 2.0f + gap);
        upper = CGRectMake(0.0f, 0.0f, b.size.width - columns - margin * 2.0f, b.size.height - safeBottom);
    } else if (compact) {
        CGFloat side = MIN(b.size.width - margin * 2.0f, 520.0f);
        tileWidth = floorf((float)(side - gap * 3.0f) * 0.25f);
        tileHeight = floorf((float)tileWidth * 1.1f);
        tiles = CGRectMake(floorf((float)(b.size.width - side) * 0.5f), b.size.height - safeBottom - margin - tileHeight,
                           side, tileHeight);
        upper = CGRectMake(0.0f, 0.0f, b.size.width, tiles.origin.y - 4.0f);
    } else {
        CGFloat side = MIN(b.size.width - margin * 2.0f, pad ? 600.0f : 420.0f);
        tileWidth = floorf((float)(side - gap) * 0.5f);
        tileHeight = pad ? 132.0f : 88.0f;
        tiles = CGRectMake(floorf((float)(b.size.width - side) * 0.5f),
                           b.size.height - safeBottom - margin - tileHeight * 2.0f - gap, side, tileHeight * 2.0f + gap);
        upper = CGRectMake(0.0f, 0.0f, b.size.width, tiles.origin.y - 4.0f);
    }
    NSArray *order = [NSArray arrayWithObjects:_editor, _settings, _probe, _lists, nil];
    for (NSUInteger i = 0; i < order.count; ++i) {
        NSUInteger column = compact ? i : i % 2, row = compact ? 0 : i / 2;
        CGRect frame = CGRectMake(tiles.origin.x + (tileWidth + gap) * column, tiles.origin.y + (tileHeight + gap) * row,
                                  tileWidth, tileHeight);
        [[order objectAtIndex:i] setFrame:frame];
    }
    CGFloat common = 15.0f;
    for (ByeTileButton *tile in order) common = MIN(common, [tile fitSizeForTileWidth:tileWidth]);
    for (ByeTileButton *tile in order) [tile setTitleSize:ByeThemeModern() ? common : 0.0f];

    /* reserve the measured text height before sizing the button so long errors remain visible */
    CGFloat textWidth = MIN(upper.size.width - margin * 2.0f, pad ? 560.0f : 380.0f);
    _detail.font = ByeFitFont(_detail.text, 12.0f, 9.0f, NO, textWidth, 3);
    CGFloat statusHeight = ceilf((float)_status.font.lineHeight) + 4.0f;
    CGFloat detailHeight = ceilf((float)_detail.font.lineHeight * 3.0f) + 4.0f;
    CGFloat chipHeight = pad ? 30.0f : 24.0f;
    CGFloat textHeight = statusHeight + 4.0f + detailHeight + 4.0f + chipHeight;
    CGFloat diameter = MIN(MIN(upper.size.width * 0.80f, pad ? 460.0f : 300.0f), upper.size.height - textHeight - 12.0f);
    diameter = MAX(diameter, 110.0f);
    CGFloat block = diameter + 8.0f + textHeight;
    CGFloat top = upper.origin.y + MAX(2.0f, floorf((float)(upper.size.height - block) * 0.5f));
    CGFloat centerX = CGRectGetMidX(upper);
    _power.frame = CGRectMake(floorf((float)(centerX - diameter * 0.5f)) - 4.0f, top - 4.0f, diameter + 8.0f, diameter + 8.0f);
    CGFloat y = top + diameter + 6.0f;
    CGFloat textLeft = floorf((float)(centerX - textWidth * 0.5f));
    _status.frame = CGRectMake(textLeft, y, textWidth, statusHeight);
    _detail.frame = CGRectMake(textLeft, y + statusHeight + 4.0f, textWidth, detailHeight);
    UIFont *mono = [UIFont fontWithName:@"Courier" size:pad ? 14.0f : 12.0f];
    CGFloat chipWidth = MIN(textWidth, MAX(130.0f, ceilf((float)ByeTextSize(_chip.text, mono, 600.0f).width) + 36.0f));
    _chip.frame = CGRectMake(floorf((float)(centerX - chipWidth * 0.5f)), y + statusHeight + detailHeight + 8.0f, chipWidth, chipHeight);
    _chip.hidden = _chip.text.length == 0;
}

@end

#import "probe_vc.h"

#import "bye_l10n.h"
#import "bye_lists.h"
#import "bye_strategies.h"
#import "bye_theme.h"
#import "lists_vc.h"

#include "bye_reply.h"

static NSArray *probe_unresolved_names(ByeReply *report) {
    NSMutableArray *names = [NSMutableArray array];
    for (NSArray *pair in report.pairs)
        if ([[pair objectAtIndex:0] isEqualToString:@"unresolved"])
            [names addObject:[pair objectAtIndex:1]];
    return names;
}

static NSString *probe_resolution_error(ByeReply *report, NSString *name) {
    NSString *prefix = [name stringByAppendingString:@" "];
    for (NSArray *pair in report.pairs) {
        NSString *value = [pair objectAtIndex:1];
        if ([[pair objectAtIndex:0] isEqualToString:@"unresolved.error"] && [value hasPrefix:prefix])
            return [value substringFromIndex:prefix.length];
    }
    return ByeL(@"does not resolve");
}

@implementation ProbeVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = ByeL(@"Probe");
    self.navigationItem.rightBarButtonItem = ByeBarItem(nil, ByeIcon(@"settings", 20.0f, [UIColor whiteColor]), NO,
                                                        self, @selector(openLists));
    self.navigationItem.rightBarButtonItem.accessibilityLabel = ByeL(@"Test lists");

    _header = [[UIView alloc] initWithFrame:CGRectMake(0.0f, 0.0f, 320.0f, 124.0f)];
    _header.backgroundColor = [UIColor clearColor];
    _start = [[ByeGlossButton alloc] initWithTitle:ByeL(@"Start the check") kind:ByeGlossBlue];
    [_start addTarget:self action:@selector(startPressed) forControlEvents:UIControlEventTouchUpInside];
    [_header addSubview:_start];
    _bar = [[ByeProgressBar alloc] initWithFrame:CGRectZero];
    [_header addSubview:_bar];
    _state = [[UILabel alloc] initWithFrame:CGRectZero];
    _state.backgroundColor = [UIColor clearColor];
    _state.textAlignment = NSTextAlignmentCenter;
    _state.font = ByeFont(13.0f, NO);
    _state.numberOfLines = 2;
    _state.lineBreakMode = NSLineBreakByWordWrapping;
    _state.adjustsFontSizeToFitWidth = YES;
    _state.textColor = ByeGroupedCaptionColor();
    _state.shadowColor = [UIColor blackColor];
    _state.shadowOffset = CGSizeMake(0.0f, -1.0f);
    [_header addSubview:_state];
    self.table.tableHeaderView = _header;
    [self layoutHeader];
    [self askForReport];
}

- (void)dealloc {
    [_timer invalidate];
    [_start release];
    [_bar release];
    [_state release];
    [_header release];
    [_report release];
    [super dealloc];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    [_timer invalidate];
    _timer = nil;
    if (self.isMovingFromParentViewController) [[ByeDaemon shared] applyPendingSettings];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    if (_running && !_timer) [self startTimer];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    [self layoutHeader];
}

- (void)layoutHeader {
    CGFloat width = self.table.bounds.size.width;
    if (fabsf((float)(_header.frame.size.width - width)) > 0.5f) {
        _header.frame = CGRectMake(0.0f, 0.0f, width, 124.0f);
        self.table.tableHeaderView = _header;
    }
    CGFloat inner = MIN(width - 40.0f, 360.0f);
    CGFloat x = floorf((float)(width - inner) * 0.5f);
    _start.frame = CGRectMake(x, 14.0f, inner, 44.0f);
    _bar.frame = CGRectMake(x, 68.0f, inner, 14.0f);
    _state.frame = CGRectMake(x, 86.0f, inner, 34.0f);
}

- (void)openLists {
    [self.navigationController pushViewController:[[[ListsVC alloc] initForPurpose:ByeListsForProbe] autorelease] animated:YES];
}

#pragma mark running

- (void)startTimer {
    [_timer invalidate];
    _timer = [NSTimer scheduledTimerWithTimeInterval:1.0 target:self selector:@selector(askForReport) userInfo:nil repeats:YES];
}

- (void)startPressed {
    if (_running) {
        [[ByeDaemon shared] command:@"probe stop" timeout:5.0 completion:^(ByeReply *reply) { (void)reply; }];
        return;
    }
    NSArray *names = [ByeLists probeNames];
    NSString *command = [@"probe " stringByAppendingString:[names componentsJoinedByString:@" "]];
    _start.enabled = NO;
    [[ByeDaemon shared] command:command timeout:10.0 completion:^(ByeReply *reply) {
        _start.enabled = YES;
        if (reply.error || !reply.ok) {
            ByeAlert(ByeL(@"The check did not start"), reply.error ? reply.error : reply.detail);
            return;
        }
        _running = YES;
        [self startTimer];
        [self askForReport];
    }];
}

- (void)askForReport {
    if (_asking) return;
    _asking = YES;
    [[ByeDaemon shared] command:@"probe" timeout:5.0 completion:^(ByeReply *reply) {
        _asking = NO;
        if (reply.error || !reply.ok) return;
        [_report release];
        _report = [reply retain];
        NSString *state = [reply valueForKey:@"state"];
        BOOL running = [state isEqualToString:@"running"];
        if (_running && !running) {
            [_timer invalidate];
            _timer = nil;
        }
        if (running && !_timer && self.isViewLoaded) [self startTimer];
        _running = running;
        [self refreshHeader];
        [self reloadForm];
    }];
}

- (void)refreshHeader {
    NSString *progress = [_report valueForKey:@"progress"];
    NSArray *parts = [progress componentsSeparatedByString:@"/"];
    CGFloat done = parts.count == 2 ? [[parts objectAtIndex:0] floatValue] : 0.0f;
    CGFloat total = parts.count == 2 ? [[parts objectAtIndex:1] floatValue] : 0.0f;
    _bar.progress = total > 0.0f ? done / total : 0.0f;
    NSString *state = [_report valueForKey:@"state"];
    NSArray *unresolved = probe_unresolved_names(_report);
    _state.textColor = ByeGroupedCaptionColor();
    if (_running) _state.text = [NSString stringWithFormat:ByeL(@"Checking: %@"), progress ? progress : @"0/0"];
    else if ([state isEqualToString:@"done"] && unresolved.count) {
        _state.text = [NSString stringWithFormat:ByeL(@"DNS failed: %@"), [unresolved componentsJoinedByString:@", "]];
        _state.textColor = ByeRGB(0xf2a39c, 1.0f);
    }
    else if ([state isEqualToString:@"done"]) _state.text = ByeL(@"Done");
    else if ([state isEqualToString:@"stopped"]) _state.text = ByeL(@"Stopped");
    else _state.text = [NSString stringWithFormat:ByeL(@"Names: %@"), [[ByeLists probeNames] componentsJoinedByString:@", "]];
    [_start setTitle:_running ? ByeL(@"Stop the check") : ByeL(@"Start the check") forState:UIControlStateNormal];
    [_start setKind:_running ? ByeGlossRed : ByeGlossBlue];
}

#pragma mark rows

- (NSArray *)buildSections {
    NSMutableArray *sections = [NSMutableArray array];
    NSArray *unresolved = probe_unresolved_names(_report);
    if (unresolved.count) {
        NSString *warning = [NSString stringWithFormat:ByeL(@"DNS lookup failed for %@. The results below cover only the resolved names."),
                            [unresolved componentsJoinedByString:@", "]];
        [sections addObject:[ByeSection sectionWithTitle:ByeL(@"Partial check") footer:warning rows:[NSArray array]]];
    }
    NSInteger configured = [[_report valueForKey:@"configured"] integerValue];
    NSMutableArray *results = [NSMutableArray array];
    NSMutableArray *addresses = [NSMutableArray array];
    for (NSArray *pair in _report.pairs) {
        NSString *key = [pair objectAtIndex:0], *value = [pair objectAtIndex:1];
        if ([key hasPrefix:@"candidate."]) {
            bye_reply_candidate_t c;
            if (!bye_reply_candidate([value UTF8String], &c)) continue;
            NSInteger index = [[key substringFromIndex:10] integerValue];
            NSString *summary;
            UIColor *color;
            if (c.tried == 0) {
                summary = ByeL(@"waiting");
                color = ByeGroupedCaptionColor();
            } else if (c.ok == c.tried) {
                summary = [NSString stringWithFormat:ByeL(@"works %u of %u, %u ms"), c.ok, c.tried, c.ms];
                color = ByeRGB(0x7fe08a, 1.0f);
            } else if (c.ok > 0) {
                summary = [NSString stringWithFormat:ByeL(@"works %u of %u, %u ms"), c.ok, c.tried, c.ms];
                color = ByeRGB(0xf2c879, 1.0f);
            } else {
                summary = [NSString stringWithFormat:ByeL(@"fails %u of %u"), c.tried, c.tried];
                color = ByeRGB(0xf2a39c, 1.0f);
            }
            if (index < configured) summary = [summary stringByAppendingString:ByeL(@" (in your list)")];
            ByeRow *row = [ByeRow rowWithKind:ByeRowStacked title:summary
                                       detail:[NSString stringWithUTF8String:c.spec] ident:key];
            row.monospace = YES;
            row.titleColor = color;
            row.selectable = YES;
            row.accessory = [self isInUse:row.detail] ? ByeAccessoryCheck : ByeAccessoryDisclosure;
            [results addObject:row];
        } else if ([key hasPrefix:@"address."]) {
            NSRange space = [value rangeOfString:@" "];
            if (space.location == NSNotFound) continue;
            [addresses addObject:[ByeRow rowWithKind:ByeRowValue title:[value substringToIndex:space.location]
                                              detail:[value substringFromIndex:space.location + 1] ident:key]];
        } else if ([key isEqualToString:@"unresolved"]) {
            ByeRow *row = [ByeRow rowWithKind:ByeRowStacked title:value
                                       detail:probe_resolution_error(_report, value) ident:key];
            row.detailColor = ByeRGB(0xf2a39c, 1.0f);
            [addresses addObject:row];
        }
    }
    NSString *suggest = [_report valueForKey:@"suggest"];
    if (suggest.length && !_running) {
        NSMutableArray *rows = [NSMutableArray array];
        for (NSString *part in [suggest componentsSeparatedByString:@"|"]) {
            NSString *text = [ByeStrategies clean:part];
            if (!text.length) continue;
            ByeRow *row = [ByeRow rowWithKind:ByeRowStacked
                                        title:[NSString stringWithFormat:@"%lu", (unsigned long)(rows.count + 1)]
                                       detail:text ident:[NSString stringWithFormat:@"suggest.%lu", (unsigned long)rows.count]];
            row.monospace = YES;
            row.selectable = YES;
            row.accessory = [self isInUse:text] ? ByeAccessoryCheck : ByeAccessoryDisclosure;
            [rows addObject:row];
        }
        [sections addObject:[ByeSection sectionWithTitle:ByeL(@"Suggestion")
                                                  footer:ByeL(@"The ones that got through, best first. Tap one to use it, copy it or keep it in the history. The one you pick replaces automatic mode and is used as it is.")
                                                    rows:rows]];
    } else if ([[_report valueForKey:@"state"] isEqualToString:@"done"] && !suggest.length) {
        [sections addObject:[ByeSection sectionWithTitle:ByeL(@"Suggestion")
                                                  footer:ByeL(@"None of the strategies got through. The names may be blocked by address, or the network is down.")
                                                    rows:[NSArray array]]];
    }
    if (results.count) [sections addObject:[ByeSection sectionWithTitle:ByeL(@"Strategies") footer:nil rows:results]];
    if (addresses.count)
        [sections addObject:[ByeSection sectionWithTitle:ByeL(@"Names")
                                                  footer:ByeL(@"The addresses are the ones this device resolves.") rows:addresses]];
    if (!sections.count)
        [sections addObject:[ByeSection sectionWithTitle:nil
                                                  footer:ByeL(@"The check opens a real tls connection to each name once per strategy and waits for the server's answer. It takes a minute or more. The names come from the test lists, see the gear.")
                                                    rows:[NSArray array]]];
    return sections;
}

- (BOOL)isInUse:(NSString *)text {
    NSString *saved = [[[ByeDaemon shared] config] objectForKey:@"desync.spec"];
    return saved.length && [[ByeStrategies clean:saved] isEqualToString:[ByeStrategies clean:text]];
}

- (void)formRowTapped:(ByeRow *)row {
    if (![row.ident hasPrefix:@"suggest."] && ![row.ident hasPrefix:@"candidate."]) return;
    [ByeStrategies offerText:row.detail from:self remembered:NO completion:^{
        [self reloadForm];
    }];
}

@end

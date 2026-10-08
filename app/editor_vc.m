#import "editor_vc.h"

#import "bye_chrome.h"
#import "bye_daemon.h"
#import "bye_l10n.h"
#import "bye_strategies.h"
#import "bye_theme.h"
#import "probe_vc.h"

#include "bye_desync.h"

@implementation EditorVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = ByeL(@"Strategy");
    self.navigationItem.rightBarButtonItem = ByeBarItem(ByeL(@"Edit"), nil, NO, self, @selector(toggleEditing));
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(daemonChanged:)
                                                 name:ByeDaemonDidChangeNotification object:nil];
    [[ByeDaemon shared] reloadConfig];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [_history release];
    [super dealloc];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    if (self.isMovingFromParentViewController || self.navigationController.topViewController != self)
        [[ByeDaemon shared] applyPendingSettings];
}

- (void)daemonChanged:(NSNotification *)note {
    (void)note;
    if (!self.table.isEditing) [self reloadForm];
}

- (void)toggleEditing {
    BOOL editing = !self.table.isEditing;
    [self.table setEditing:editing animated:YES];
    self.navigationItem.rightBarButtonItem = ByeBarItem(editing ? ByeL(@"Done") : ByeL(@"Edit"), nil, NO, self,
                                                        @selector(toggleEditing));
    if (!editing) [self reloadForm];
}

- (NSString *)savedSpec {
    NSString *spec = [[[ByeDaemon shared] config] objectForKey:@"desync.spec"];
    return spec.length ? [ByeStrategies clean:spec] : @"";
}

- (NSString *)notesFooter:(NSString *)spec {
    NSString *footer = ByeL(@"tlsrec=P cuts the tls record, split=P,P cuts segments, oob=P sends one urgent byte, none sends the bytes as they are. Positions: N, name, name+N, mid, end. Clauses are joined with \";\". The options of the original ByeDPI work too, for example -d1 -s5+s -r1+s.");
    if (![spec hasPrefix:@"-"]) return footer;
    bye_strategies_t parsed;
    char error[160] = "";
    if (bye_strategies_parse([spec UTF8String], &parsed, error, sizeof error) != BYE_DESYNC_OK)
        return [NSString stringWithUTF8String:error];
    footer = [NSString stringWithFormat:ByeL(@"The options of the original ByeDPI. Every -A starts a group that is tried after a failure it names. Groups: %lu."),
              (unsigned long)parsed.count];
    if (parsed.notes[0])
        footer = [NSString stringWithFormat:@"%@\n%@\n%s", footer, ByeL(@"Left out on this device:"), parsed.notes];
    return footer;
}

- (NSArray *)buildSections {
    ByeDaemon *daemon = [ByeDaemon shared];
    NSString *saved = [self savedSpec];
    NSString *running = [[daemon.status objectForKey:@"strategy"] length] ? [daemon.status objectForKey:@"strategy"] : @"";
    BOOL up = daemon.state == ByeDaemonRunning;
    [_history release];
    _history = [[ByeStrategies history] retain];

    /* the saved strategy may differ from the one the running tunnel uses */
    NSString *shownTitle = up ? ByeL(@"Running with") : ByeL(@"Starts with");
    NSString *shownText = [ByeStrategies display:up ? running : saved];
    NSString *explain = ByeL(@"Automatic mode cuts the first bytes of a connection and, when a site does not answer, tries the next cut by itself. It remembers what worked for each address. A text you write is used as it is.");
    NSString *inUseFooter = explain;
    if (up && saved.length && ![running isEqualToString:saved])
        inUseFooter = [explain stringByAppendingFormat:@"\n%@",
                       ByeL(@"The saved text below is not running yet. It applies after a restart of the tunnel.")];
    ByeRow *inUse = [ByeRow rowWithKind:ByeRowStacked title:shownTitle detail:shownText.length ? shownText : @"-" ident:@"inuse"];
    inUse.monospace = ![shownText isEqualToString:ByeL(@"Automatic")];
    inUse.selectable = shownText.length > 0;
    NSMutableArray *useRows = [NSMutableArray arrayWithObject:inUse];

    ByeRow *edit = [ByeRow rowWithKind:ByeRowStacked title:ByeL(@"Strategy text") detail:saved.length ? [ByeStrategies display:saved] : @"-" ident:@"edit"];
    edit.monospace = ![saved isEqualToString:@"auto"];
    edit.selectable = YES;
    edit.accessory = ByeAccessoryDisclosure;
    ByeRow *paste = [ByeRow rowWithKind:ByeRowButton title:ByeL(@"Paste from the clipboard") detail:nil ident:@"paste"];
    ByeRow *restore = [ByeRow rowWithKind:ByeRowButton title:ByeL(@"Use automatic mode") detail:nil ident:@"default"];

    NSMutableArray *historyRows = [NSMutableArray array];
    for (NSUInteger i = 0; i < _history.count; ++i) {
        ByeRow *row = [ByeRow rowWithKind:ByeRowStacked title:[NSString stringWithFormat:@"%lu", (unsigned long)(i + 1)]
                                    detail:[ByeStrategies display:[_history objectAtIndex:i]]
                                    ident:[NSString stringWithFormat:@"h%lu", (unsigned long)i]];
        row.monospace = YES;
        row.selectable = YES;
        [historyRows addObject:row];
    }

    ByeRow *probe = [ByeRow rowWithKind:ByeRowStacked title:ByeL(@"Find strategies that work here")
                                 detail:ByeL(@"Tries strategies on real sites over your network. Nothing is changed until you pick one.")
                                  ident:@"probe"];
    probe.glyph = @"speed";
    probe.accessory = ByeAccessoryDisclosure;
    probe.selectable = YES;

    NSMutableArray *sections = [NSMutableArray array];
    [sections addObject:[ByeSection sectionWithTitle:ByeL(@"In use now") footer:inUseFooter rows:useRows]];
    [sections addObject:[ByeSection sectionWithTitle:ByeL(@"Change it") footer:[self notesFooter:saved]
                                                rows:[NSArray arrayWithObjects:edit, paste, restore, nil]]];
    if (historyRows.count)
        [sections addObject:[ByeSection sectionWithTitle:ByeL(@"History")
                                                  footer:ByeL(@"The strategies you replaced. Tap one to put it back, copy it or delete it.")
                                                    rows:historyRows]];
    [sections addObject:[ByeSection sectionWithTitle:nil footer:nil rows:[NSArray arrayWithObject:probe]]];
    return sections;
}

- (void)useText:(NSString *)text {
    [ByeStrategies use:text completion:^(NSString *error) {
        if (error) ByeAlert(ByeL(@"The strategy was not saved"), error);
        [self reloadForm];
    }];
}

- (NSInteger)historyIndexOfRow:(ByeRow *)row {
    if (![row.ident hasPrefix:@"h"] || row.ident.length < 2) return -1;
    NSInteger index = [[row.ident substringFromIndex:1] integerValue];
    return index >= 0 && (NSUInteger)index < _history.count ? index : -1;
}

- (void)formRowTapped:(ByeRow *)row {
    NSString *ident = row.ident;
    if ([ident isEqualToString:@"inuse"]) {
        NSString *running = [[[ByeDaemon shared] status] objectForKey:@"strategy"];
        NSString *text = [ByeDaemon shared].state == ByeDaemonRunning && running.length ? running : [self savedSpec];
        ByeChoose(self, nil, [NSArray arrayWithObjects:ByeL(@"Copy"), ByeL(@"Keep in the history"), nil], ^(NSInteger index) {
            if (index == 0) {
                [UIPasteboard generalPasteboard].string = text;
                ByeAlert(ByeL(@"Copied"), text);
            } else if (index == 1) {
                [ByeStrategies remember:text];
                [self reloadForm];
            }
        });
    } else if ([ident isEqualToString:@"edit"]) {
        ByePromptText(ByeL(@"Strategy text"), ByeL(@"A native strategy like tlsrec=mid;split=1,mid, or ByeDPI options like -d1 -s5+s"),
                      [self savedSpec], @"", NO, ^(NSString *text) {
            if (text) [self useText:text];
        });
    } else if ([ident isEqualToString:@"paste"]) {
        NSString *text = [UIPasteboard generalPasteboard].string;
        if (![ByeStrategies clean:text].length) {
            ByeAlert(ByeL(@"Nothing to paste"), ByeL(@"The clipboard has no text. Copy a strategy first."));
            return;
        }
        [self useText:text];
    } else if ([ident isEqualToString:@"default"]) {
        [self useText:[NSString stringWithUTF8String:BYE_STRATEGIES_DEFAULT]];
    } else if ([ident isEqualToString:@"probe"]) {
        [self.navigationController pushViewController:[[[ProbeVC alloc] init] autorelease] animated:YES];
    } else {
        NSInteger index = [self historyIndexOfRow:row];
        if (index < 0) return;
        [ByeStrategies offerText:[_history objectAtIndex:(NSUInteger)index] from:self remembered:YES completion:^{
            [self reloadForm];
        }];
    }
}

- (BOOL)formCanDeleteRow:(ByeRow *)row {
    return [self historyIndexOfRow:row] >= 0;
}

- (void)formDeleteRow:(ByeRow *)row {
    NSInteger index = [self historyIndexOfRow:row];
    if (index < 0) return;
    [ByeStrategies forget:[_history objectAtIndex:(NSUInteger)index]];
    [self reloadForm];
}

@end

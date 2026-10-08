#import "lists_vc.h"

#import <QuartzCore/QuartzCore.h>

#import "bye_chrome.h"
#import "bye_daemon.h"
#import "bye_l10n.h"
#import "bye_theme.h"

@implementation ListsVC

- (id)initForPurpose:(ByeListsPurpose)purpose {
    self = [super initWithNibName:nil bundle:nil];
    if (!self) return nil;
    _purpose = purpose;
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = _purpose == ByeListsForHosts ? ByeL(@"Site lists") : ByeL(@"Test lists");
    self.navigationItem.rightBarButtonItem = ByeBarItem(ByeL(@"Edit"), nil, NO, self, @selector(toggleEditing));
    [[ByeDaemon shared] reloadConfig];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    if (_purpose == ByeListsForHosts && self.isMovingFromParentViewController)
        [[ByeDaemon shared] applyPendingSettings];
}

- (void)toggleEditing {
    BOOL editing = !self.table.isEditing;
    [self.table setEditing:editing animated:YES];
    self.navigationItem.rightBarButtonItem = ByeBarItem(editing ? ByeL(@"Done") : ByeL(@"Edit"), nil, NO, self,
                                                        @selector(toggleEditing));
}

static NSString *ByeDomainPreview(NSArray *domains) {
    NSUInteger shown = MIN((NSUInteger)4, domains.count);
    NSString *head = [[domains subarrayWithRange:NSMakeRange(0, shown)] componentsJoinedByString:@"\n"];
    return domains.count > shown ? [head stringByAppendingFormat:@"\n... (%lu)", (unsigned long)domains.count] : head;
}

- (NSArray *)buildSections {
    NSMutableArray *sections = [NSMutableArray array];
    BOOL hosts = _purpose == ByeListsForHosts;
    if (hosts) {
        BOOL only = ![[[[ByeDaemon shared] config] objectForKey:@"hosts.mode"] isEqualToString:@"except"];
        ByeRow *mode = [ByeRow rowWithKind:ByeRowValue title:ByeL(@"Apply to")
                                    detail:only ? ByeL(@"only listed sites") : ByeL(@"all sites except listed") ident:@"mode"];
        mode.accessory = ByeAccessoryDisclosure;
        [sections addObject:[ByeSection sectionWithTitle:nil
                                                  footer:ByeL(@"With no list chosen the bypass applies to every site.")
                                                    rows:[NSArray arrayWithObject:mode]]];
    }
    NSMutableArray *rows = [NSMutableArray array];
    for (ByeList *list in [ByeLists all]) {
        ByeRow *row = [ByeRow rowWithKind:ByeRowStacked title:list.title detail:ByeDomainPreview(list.domains) ident:list.ident];
        row.selectable = YES;
        row.monospace = YES;
        row.accessory = [ByeLists isSelected:list for:_purpose] ? ByeAccessoryCheck : ByeAccessoryNone;
        [rows addObject:row];
    }
    [sections addObject:[ByeSection sectionWithTitle:ByeL(@"Lists")
                                              footer:hosts ? nil : ByeL(@"The probe tries the first name of each chosen list.")
                                                rows:rows]];
    [sections addObject:[ByeSection sectionWithTitle:nil footer:nil
                                                rows:[NSArray arrayWithObject:[ByeRow rowWithKind:ByeRowButton title:ByeL(@"Add a list")
                                                                                           detail:nil ident:@"add"]]]];
    return sections;
}

- (ByeList *)listForIdent:(NSString *)ident {
    for (ByeList *list in [ByeLists all]) if ([list.ident isEqualToString:ident]) return list;
    return nil;
}

- (void)syncHosts {
    if (_purpose != ByeListsForHosts) return;
    [ByeLists syncHostsWithDaemon:^(NSString *error) {
        if (error) ByeAlert(ByeL(@"The lists were not saved"), error);
    }];
}

- (void)formRowTapped:(ByeRow *)row {
    if ([row.ident isEqualToString:@"mode"]) {
        ByeChoose(self, ByeL(@"Apply to"), [NSArray arrayWithObjects:ByeL(@"only listed sites"), ByeL(@"all sites except listed"), nil],
                  ^(NSInteger index) {
            if (index < 0) return;
            [[ByeDaemon shared] setConfigValue:index == 0 ? @"only" : @"except" forKey:@"hosts.mode" completion:^(NSString *error) {
                if (error) ByeAlert(ByeL(@"The setting was not saved"), error);
                [self reloadForm];
            }];
        });
        return;
    }
    if ([row.ident isEqualToString:@"add"]) {
        ListEditVC *editor = [[[ListEditVC alloc] initWithSaved:^(ByeList *list) {
            [ByeLists setSelected:YES list:list for:_purpose];
            [self syncHosts];
        }] autorelease];
        [self.navigationController pushViewController:editor animated:YES];
        return;
    }
    ByeList *list = [self listForIdent:row.ident];
    if (!list) return;
    [ByeLists setSelected:![ByeLists isSelected:list for:_purpose] list:list for:_purpose];
    [self syncHosts];
    [self reloadForm];
}

- (BOOL)formCanDeleteRow:(ByeRow *)row {
    return [[self listForIdent:row.ident] custom];
}

- (void)formDeleteRow:(ByeRow *)row {
    ByeList *list = [self listForIdent:row.ident];
    if (!list.custom) return;
    [ByeLists removeCustomList:list];
    [self syncHosts];
    [self reloadForm];
}

@end

#pragma mark - edit

@implementation ListEditVC

- (id)initWithSaved:(void (^)(ByeList *list))saved {
    self = [super initWithNibName:nil bundle:nil];
    if (!self) return nil;
    _saved = [saved copy];
    return self;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    _text.delegate = nil;
    _name.delegate = nil;
    [_name release];
    [_text release];
    [_saved release];
    [super dealloc];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = ByeL(@"New list");
    self.navigationItem.rightBarButtonItem = ByeBarItem(ByeL(@"Save"), nil, NO, self, @selector(savePressed));

    _name = [[UITextField alloc] initWithFrame:CGRectZero];
    _name.borderStyle = UITextBorderStyleRoundedRect;
    _name.placeholder = ByeL(@"Name of the list");
    _name.font = ByeFont(17.0f, NO);
    _name.autocorrectionType = UITextAutocorrectionTypeNo;
    _name.returnKeyType = UIReturnKeyNext;
    _name.delegate = self;
    [self.view addSubview:_name];

    _text = [[UITextView alloc] initWithFrame:CGRectZero];
    _text.font = [UIFont fontWithName:@"Courier" size:13.0f];
    _text.autocapitalizationType = UITextAutocapitalizationTypeNone;
    _text.autocorrectionType = UITextAutocorrectionTypeNo;
    _text.keyboardType = UIKeyboardTypeURL;
    _text.layer.cornerRadius = 8.0f;
    _text.layer.borderColor = [UIColor colorWithWhite:0.0f alpha:0.55f].CGColor;
    _text.layer.borderWidth = 1.0f;
    [self.view addSubview:_text];

    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(keyboardChanged:)
                                                 name:UIKeyboardWillChangeFrameNotification object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(keyboardChanged:)
                                                 name:UIKeyboardWillHideNotification object:nil];
}

- (BOOL)textFieldShouldReturn:(UITextField *)field {
    [_text becomeFirstResponder];
    return NO;
}

- (void)keyboardChanged:(NSNotification *)note {
    CGRect end = [[[note userInfo] objectForKey:UIKeyboardFrameEndUserInfoKey] CGRectValue];
    CGRect local = [self.view convertRect:[self.view.window convertRect:end fromWindow:nil] fromView:nil];
    CGFloat covered = [note.name isEqualToString:UIKeyboardWillHideNotification] ? 0.0f
                    : MAX(0.0f, CGRectGetMaxY(self.view.bounds) - local.origin.y);
    _keyboard = covered;
    [self.view setNeedsLayout];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    CGRect b = self.view.bounds;
    CGFloat margin = 12.0f;
    CGFloat width = MIN(b.size.width - margin * 2.0f, 600.0f);
    CGFloat x = floorf((float)(b.size.width - width) * 0.5f);
    _name.frame = CGRectMake(x, margin, width, 36.0f);
    CGFloat bottom = MAX(_keyboard, ByeBottomSafeInset()) + margin;
    _text.frame = CGRectMake(x, margin * 2.0f + 36.0f, width, MAX(80.0f, b.size.height - margin * 2.0f - 36.0f - bottom));
}

- (void)savePressed {
    NSString *error = nil;
    ByeList *list = [ByeLists addCustomListTitled:_name.text text:_text.text error:&error];
    if (!list) {
        ByeAlert(ByeL(@"The list was not saved"), error);
        return;
    }
    if (_saved) _saved(list);
    [self.navigationController popViewControllerAnimated:YES];
}

@end

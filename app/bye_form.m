#import "bye_form.h"

#import <QuartzCore/QuartzCore.h>
#include <objc/message.h>

#import "bye_chrome.h"
#import "bye_l10n.h"
#import "bye_theme.h"
#import "bye_trace.h"

#pragma mark - screen

@implementation ByeScreen

- (void)loadView {
    UIView *view = [[[UIView alloc] initWithFrame:[[UIScreen mainScreen] bounds]] autorelease];
    view.backgroundColor = ByeBackgroundColor();
    view.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.view = view;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    /* from ios 7 the content runs under a bar by default; the root controller already
       sits below the status bar, and a bar here is opaque */
    if ([self respondsToSelector:@selector(setEdgesForExtendedLayout:)])
        ((void (*)(id, SEL, NSUInteger))objc_msgSend)(self, @selector(setEdgesForExtendedLayout:), 0);
    if ([self respondsToSelector:@selector(setAutomaticallyAdjustsScrollViewInsets:)])
        ((void (*)(id, SEL, BOOL))objc_msgSend)(self, @selector(setAutomaticallyAdjustsScrollViewInsets:), NO);
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    ByeTrace(@"screen %@", NSStringFromClass([self class]));
    ByeStyleNavigationBar(self.navigationController.navigationBar);
}

@end

#pragma mark - model

@implementation ByeRow

@synthesize kind = _kind;
@synthesize accessory = _accessory;
@synthesize title = _title;
@synthesize detail = _detail;
@synthesize glyph = _glyph;
@synthesize image = _image;
@synthesize ident = _ident;
@synthesize on = _on;
@synthesize selectable = _selectable;
@synthesize monospace = _monospace;
@synthesize detailColor = _detailColor;
@synthesize titleColor = _titleColor;

+ (ByeRow *)rowWithKind:(ByeRowKind)kind title:(NSString *)title detail:(NSString *)detail ident:(NSString *)ident {
    ByeRow *row = [[[ByeRow alloc] init] autorelease];
    row.kind = kind;
    row.title = title;
    row.detail = detail;
    row.ident = ident;
    row.selectable = kind == ByeRowButton;
    return row;
}

- (void)dealloc {
    [_title release];
    [_detail release];
    [_glyph release];
    [_image release];
    [_ident release];
    [_detailColor release];
    [_titleColor release];
    [super dealloc];
}

@end

@implementation ByeSection

@synthesize title = _title;
@synthesize footer = _footer;
@synthesize rows = _rows;

+ (ByeSection *)sectionWithTitle:(NSString *)title footer:(NSString *)footer rows:(NSArray *)rows {
    ByeSection *section = [[[ByeSection alloc] init] autorelease];
    section.title = title;
    section.footer = footer;
    section.rows = rows;
    return section;
}

- (void)dealloc {
    [_title release];
    [_footer release];
    [_rows release];
    [super dealloc];
}

@end

#pragma mark - cell

/* share geometry between measurement and layout so wrapped text fits its row */
typedef struct {
    CGRect glyph;
    CGRect title;
    CGRect detail;
    CGFloat height;
} ByeRowGeometry;

static ByeRowGeometry ByeRowGeometryFor(ByeRowKind kind, CGFloat glyphSize, NSString *title, UIFont *titleFont,
                                        NSString *detail, UIFont *detailFont, CGFloat contentWidth) {
    ByeRowGeometry g;
    memset(&g, 0, sizeof g);
    CGFloat x = glyphSize > 0.0f ? 14.0f + glyphSize + 12.0f : 14.0f;
    CGFloat avail = MAX(40.0f, contentWidth - x - 12.0f);
    CGFloat minimum = ByeIsPad() ? 50.0f : 44.0f;
    switch (kind) {
    case ByeRowStacked: {
        CGFloat titleHeight = MAX(titleFont.lineHeight, ByeTextSize(title, titleFont, avail).height);
        CGFloat detailHeight = detail.length ? ByeTextSize(detail, detailFont, avail).height : 0.0f;
        g.title = CGRectMake(x, 11.0f, avail, titleHeight);
        g.detail = CGRectMake(x, 11.0f + titleHeight + 3.0f, avail, detailHeight);
        g.height = MAX(minimum, 11.0f + titleHeight + (detail.length ? 3.0f + detailHeight : 0.0f) + 12.0f);
        if (glyphSize > 0.0f) g.glyph = CGRectMake(14.0f, 11.0f + (glyphSize > 30.0f ? 0.0f : 2.0f), glyphSize, glyphSize);
        break;
    }
    case ByeRowValue: {
        CGFloat valueWidth = detail.length ? MIN(ceilf((float)ByeTextSize(detail, detailFont, avail).width), avail * 0.5f) : 0.0f;
        CGFloat titleWidth = avail - valueWidth - (valueWidth > 0.0f ? 10.0f : 0.0f);
        CGFloat titleHeight = MAX(titleFont.lineHeight, ByeTextSize(title, titleFont, titleWidth).height);
        CGFloat detailHeight = detail.length ? MAX(detailFont.lineHeight, ByeTextSize(detail, detailFont, valueWidth).height) : 0.0f;
        g.height = MAX(minimum, MAX(titleHeight, detailHeight) + 22.0f);
        g.title = CGRectMake(x, floorf((float)(g.height - titleHeight) * 0.5f), titleWidth, titleHeight);
        g.detail = CGRectMake(contentWidth - 12.0f - valueWidth, floorf((float)(g.height - detailHeight) * 0.5f), valueWidth, detailHeight);
        if (glyphSize > 0.0f) g.glyph = CGRectMake(14.0f, floorf((float)(g.height - glyphSize) * 0.5f), glyphSize, glyphSize);
        break;
    }
    case ByeRowSwitch:
    case ByeRowButton: {
        CGFloat titleHeight = MAX(titleFont.lineHeight, ByeTextSize(title, titleFont, avail).height);
        g.height = MAX(minimum, titleHeight + 22.0f);
        g.title = CGRectMake(x, floorf((float)(g.height - titleHeight) * 0.5f), avail, titleHeight);
        if (glyphSize > 0.0f) g.glyph = CGRectMake(14.0f, floorf((float)(g.height - glyphSize) * 0.5f), glyphSize, glyphSize);
        break;
    }
    }
    return g;
}

@interface ByeFormCell : UITableViewCell {
@public
    UIImageView *glyphView;
    UILabel     *detailLabel;
    UILabel     *titleLabel;
    ByeRowKind   kind;
    CGFloat      glyphSize;
}
@end

@implementation ByeFormCell

- (id)initWithReuseIdentifier:(NSString *)reuse {
    self = [super initWithStyle:UITableViewCellStyleDefault reuseIdentifier:reuse];
    if (!self) return nil;
    glyphView = [[UIImageView alloc] initWithFrame:CGRectZero];
    glyphView.contentMode = UIViewContentModeScaleAspectFit;
    [self.contentView addSubview:glyphView];
    titleLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    titleLabel.backgroundColor = [UIColor clearColor];
    titleLabel.numberOfLines = 0;
    titleLabel.lineBreakMode = NSLineBreakByWordWrapping;
    [self.contentView addSubview:titleLabel];
    detailLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    detailLabel.backgroundColor = [UIColor clearColor];
    detailLabel.numberOfLines = 0;
    detailLabel.lineBreakMode = NSLineBreakByWordWrapping;
    [self.contentView addSubview:detailLabel];
    self.textLabel.text = @"";
    return self;
}

- (void)dealloc {
    [glyphView release];
    [detailLabel release];
    [titleLabel release];
    [super dealloc];
}

- (void)layoutSubviews {
    [super layoutSubviews];
    ByeRowGeometry g = ByeRowGeometryFor(kind, glyphView.image ? glyphSize : 0.0f, titleLabel.text, titleLabel.font,
                                         detailLabel.text, detailLabel.font, self.contentView.bounds.size.width);
    glyphView.frame = glyphView.image ? g.glyph : CGRectZero;
    titleLabel.frame = g.title;
    detailLabel.frame = g.detail;
}

@end

#pragma mark - controller

@interface ByeFormController () <UIAlertViewDelegate>
@end

@implementation ByeFormController

@synthesize table = _table;
@synthesize sections = _sections;

- (void)dealloc {
    _table.delegate = nil;
    _table.dataSource = nil;
    [_table release];
    [_sections release];
    [super dealloc];
}

- (NSArray *)buildSections {
    return [NSArray array];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    _table = [[UITableView alloc] initWithFrame:self.view.bounds style:UITableViewStyleGrouped];
    _table.dataSource = self;
    _table.delegate = self;
    ByeStyleTable(_table);
    _table.showsVerticalScrollIndicator = YES;
    [self.view addSubview:_table];
    [self reloadForm];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self reloadForm];
}

/* ios 7 no longer insets grouped rows; cap the table width so ipad rows remain readable */
- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    CGRect bounds = self.view.bounds;
    CGFloat column = ByeIsPad() ? MIN(bounds.size.width, 720.0f) : bounds.size.width;
    CGFloat side = ByeGroupedMargin();
    CGRect frame = CGRectMake(floorf((float)(bounds.size.width - column) * 0.5f) + side, 0.0f,
                              column - side * 2.0f, bounds.size.height);
    if (!CGRectEqualToRect(_table.frame, frame)) _table.frame = frame;
    CGFloat bottom = ByeBottomSafeInset();
    UIEdgeInsets inset = UIEdgeInsetsMake(0.0f, 0.0f, bottom + 8.0f, 0.0f);
    if (!UIEdgeInsetsEqualToEdgeInsets(_table.contentInset, inset) && !_table.isEditing) {
        _table.contentInset = inset;
        _table.scrollIndicatorInsets = inset;
    }
}

- (void)reloadForm {
    if (!_table) return;
    [_sections release];
    _sections = [[self buildSections] retain];
    [_table reloadData];
}

- (ByeRow *)rowAtIndexPath:(NSIndexPath *)indexPath {
    if ((NSUInteger)indexPath.section >= _sections.count) return nil;
    NSArray *rows = [[_sections objectAtIndex:(NSUInteger)indexPath.section] rows];
    return (NSUInteger)indexPath.row < rows.count ? [rows objectAtIndex:(NSUInteger)indexPath.row] : nil;
}

- (NSIndexPath *)indexPathOfRowWithIdent:(NSString *)ident {
    for (NSUInteger s = 0; s < _sections.count; ++s) {
        NSArray *rows = [[_sections objectAtIndex:s] rows];
        for (NSUInteger r = 0; r < rows.count; ++r)
            if ([[[rows objectAtIndex:r] ident] isEqualToString:ident])
                return [NSIndexPath indexPathForRow:(NSInteger)r inSection:(NSInteger)s];
    }
    return nil;
}

- (void)formRowTapped:(ByeRow *)row {
    (void)row;
}

- (void)formSwitchChanged:(ByeRow *)row on:(BOOL)on {
    (void)row;
    (void)on;
}

- (BOOL)formCanDeleteRow:(ByeRow *)row { (void)row; return NO; }
- (void)formDeleteRow:(ByeRow *)row { (void)row; }
- (BOOL)formCanMoveRow:(ByeRow *)row { (void)row; return NO; }
- (void)formMoveRowFrom:(NSIndexPath *)from to:(NSIndexPath *)to { (void)from; (void)to; }

#pragma mark table

- (NSInteger)numberOfSectionsInTableView:(UITableView *)table {
    (void)table;
    return (NSInteger)_sections.count;
}

- (NSInteger)tableView:(UITableView *)table numberOfRowsInSection:(NSInteger)section {
    (void)table;
    return (NSInteger)[[[_sections objectAtIndex:(NSUInteger)section] rows] count];
}

- (UIFont *)titleFontForRow:(ByeRow *)row {
    return ByeFont(row.kind == ByeRowStacked ? 14.0f : 15.0f, YES);
}

- (UIFont *)detailFontForRow:(ByeRow *)row {
    if (row.monospace) {
        UIFont *font = [UIFont fontWithName:@"Courier" size:ByeIsPad() ? 14.0f : 12.0f];
        if (font) return font;
    }
    return ByeFont(row.kind == ByeRowStacked ? 12.0f : 15.0f, NO);
}

/* include accessory spacing when measuring text so the row is not too short */
- (CGFloat)contentWidthForRow:(ByeRow *)row {
    CGFloat cell = _table.bounds.size.width - ByeCellSideInset() * 2.0f;
    CGFloat accessory = 0.0f;
    if (row.kind == ByeRowSwitch) accessory = 79.0f + 30.0f;
    else if (row.accessory == ByeAccessoryDisclosure) accessory = 11.0f + 30.0f;
    else if (row.accessory == ByeAccessoryCheck) accessory = 16.0f + 30.0f;
    return MAX(80.0f, cell - accessory);
}

- (CGFloat)tableView:(UITableView *)table heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    (void)table;
    ByeRow *row = [self rowAtIndexPath:indexPath];
    if (!row) return 44.0f;
    CGFloat glyph = row.image ? 36.0f : (row.glyph ? 24.0f : 0.0f);
    return ByeRowGeometryFor(row.kind, glyph, row.title, [self titleFontForRow:row], row.detail,
                             [self detailFontForRow:row], [self contentWidthForRow:row]).height;
}

- (CGFloat)tableView:(UITableView *)table heightForHeaderInSection:(NSInteger)section {
    (void)table;
    return [[[_sections objectAtIndex:(NSUInteger)section] title] length] ? 44.0f : 14.0f;
}

- (CGFloat)tableView:(UITableView *)table heightForFooterInSection:(NSInteger)section {
    ByeSection *model = [_sections objectAtIndex:(NSUInteger)section];
    return ByeGroupedFooterHeight(model.footer, table.bounds.size.width);
}

- (UIView *)tableView:(UITableView *)table viewForHeaderInSection:(NSInteger)section {
    return ByeGroupedHeader([[_sections objectAtIndex:(NSUInteger)section] title], table.bounds.size.width);
}

- (UIView *)tableView:(UITableView *)table viewForFooterInSection:(NSInteger)section {
    return ByeGroupedFooter([[_sections objectAtIndex:(NSUInteger)section] footer], table.bounds.size.width);
}

- (void)switchFlipped:(ByeSwitch *)toggle {
    NSIndexPath *path = [NSIndexPath indexPathForRow:toggle.tag % 1000 inSection:toggle.tag / 1000];
    ByeRow *row = [self rowAtIndexPath:path];
    if (!row) return;
    row.on = toggle.on;
    [self formSwitchChanged:row on:toggle.on];
}

- (UITableViewCell *)tableView:(UITableView *)table cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *reuse = @"form";
    ByeFormCell *cell = (ByeFormCell *)[table dequeueReusableCellWithIdentifier:reuse];
    if (!cell) cell = [[[ByeFormCell alloc] initWithReuseIdentifier:reuse] autorelease];
    ByeRow *row = [self rowAtIndexPath:indexPath];
    NSInteger count = [self tableView:table numberOfRowsInSection:indexPath.section];
    BOOL first = indexPath.row == 0, last = indexPath.row == count - 1;
    ByeStyleGroupedCell(cell, first, last);
    cell.textLabel.text = nil;
    cell->kind = row.kind;
    cell->titleLabel.text = row.title;
    cell->titleLabel.textAlignment = row.kind == ByeRowButton ? NSTextAlignmentCenter : NSTextAlignmentLeft;
    cell->titleLabel.font = [self titleFontForRow:row];
    cell->titleLabel.textColor = row.titleColor ? row.titleColor
                               : (row.kind == ByeRowButton ? ByeColorValue() : ByeGroupedTextColor());
    cell->titleLabel.highlightedTextColor = [UIColor whiteColor];
    cell->detailLabel.text = row.detail;
    cell->detailLabel.font = [self detailFontForRow:row];
    cell->detailLabel.textAlignment = row.kind == ByeRowValue ? NSTextAlignmentRight : NSTextAlignmentLeft;
    cell->detailLabel.textColor = row.detailColor ? row.detailColor
                                : (row.kind == ByeRowStacked ? ByeGroupedCaptionColor() : ByeGroupedValueColor());
    cell->detailLabel.highlightedTextColor = [UIColor whiteColor];
    UIImage *glyph = row.image ? row.image : (row.glyph ? ByeIcon(row.glyph, 22.0f, ByeRGB(0xd6e3f5, 1.0f)) : nil);
    cell->glyphView.image = glyph;
    BOOL face = row.image != nil;
    cell->glyphSize = face ? 36.0f : 24.0f;
    cell->glyphView.layer.cornerRadius = face ? 12.0f : 0.0f;
    cell->glyphView.layer.masksToBounds = face;

    cell.accessoryView = nil;
    if (row.kind == ByeRowSwitch) {
        ByeSwitch *toggle = [[[ByeSwitch alloc] initWithFrame:CGRectZero] autorelease];
        toggle.on = row.on;
        toggle.tag = indexPath.section * 1000 + indexPath.row;
        [toggle addTarget:self action:@selector(switchFlipped:) forControlEvents:UIControlEventValueChanged];
        cell.accessoryView = toggle;
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
    } else if (row.accessory == ByeAccessoryDisclosure) {
        cell.accessoryView = ByeDisclosure();
    } else if (row.accessory == ByeAccessoryCheck) {
        cell.accessoryView = ByeCheckmark();
    }
    if (row.kind != ByeRowSwitch)
        cell.selectionStyle = (row.selectable || row.accessory == ByeAccessoryDisclosure)
            ? UITableViewCellSelectionStyleBlue : UITableViewCellSelectionStyleNone;
    cell.accessibilityLabel = row.title;
    [cell setNeedsLayout];
    return cell;
}

- (void)tableView:(UITableView *)table didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [table deselectRowAtIndexPath:indexPath animated:YES];
    ByeRow *row = [self rowAtIndexPath:indexPath];
    if (row && (row.selectable || row.accessory != ByeAccessoryNone)) [self formRowTapped:row];
}

- (UITableViewCellEditingStyle)tableView:(UITableView *)table editingStyleForRowAtIndexPath:(NSIndexPath *)indexPath {
    (void)table;
    ByeRow *row = [self rowAtIndexPath:indexPath];
    return row && [self formCanDeleteRow:row] ? UITableViewCellEditingStyleDelete : UITableViewCellEditingStyleNone;
}

- (BOOL)tableView:(UITableView *)table canEditRowAtIndexPath:(NSIndexPath *)indexPath {
    (void)table;
    ByeRow *row = [self rowAtIndexPath:indexPath];
    return row && ([self formCanDeleteRow:row] || [self formCanMoveRow:row]);
}

- (BOOL)tableView:(UITableView *)table shouldIndentWhileEditingRowAtIndexPath:(NSIndexPath *)indexPath {
    (void)table; (void)indexPath;
    return YES;
}

- (void)tableView:(UITableView *)table commitEditingStyle:(UITableViewCellEditingStyle)style
forRowAtIndexPath:(NSIndexPath *)indexPath {
    (void)table;
    if (style != UITableViewCellEditingStyleDelete) return;
    ByeRow *row = [self rowAtIndexPath:indexPath];
    if (row && [self formCanDeleteRow:row]) [self formDeleteRow:row];
}

- (BOOL)tableView:(UITableView *)table canMoveRowAtIndexPath:(NSIndexPath *)indexPath {
    (void)table;
    ByeRow *row = [self rowAtIndexPath:indexPath];
    return row && [self formCanMoveRow:row];
}

- (NSIndexPath *)tableView:(UITableView *)table targetIndexPathForMoveFromRowAtIndexPath:(NSIndexPath *)from
       toProposedIndexPath:(NSIndexPath *)proposed {
    (void)table;
    if (from.section != proposed.section) return from;
    ByeRow *target = [self rowAtIndexPath:proposed];
    return target && [self formCanMoveRow:target] ? proposed : from;
}

- (void)tableView:(UITableView *)table moveRowAtIndexPath:(NSIndexPath *)from toIndexPath:(NSIndexPath *)to {
    (void)table;
    [self formMoveRowFrom:from to:to];
}

@end

#pragma mark - prompts

@interface ByePrompt : NSObject <UIAlertViewDelegate> {
    void (^_done)(NSString *);
    BOOL _numbers;
}
@end

@implementation ByePrompt

- (id)initWithDone:(void (^)(NSString *))done {
    self = [super init];
    if (!self) return nil;
    _done = [done copy];
    return self;
}

- (void)dealloc {
    [_done release];
    [super dealloc];
}

- (void)alertView:(UIAlertView *)alert clickedButtonAtIndex:(NSInteger)index {
    NSString *text = nil;
    if (index != alert.cancelButtonIndex && [alert alertViewStyle] == UIAlertViewStylePlainTextInput)
        text = [[alert textFieldAtIndex:0] text];
    if (_done) _done(text ? text : nil);
}

/* the alert holds its delegate weakly, and nothing else holds this one */
- (void)alertView:(UIAlertView *)alert didDismissWithButtonIndex:(NSInteger)index {
    (void)alert;
    (void)index;
    [self autorelease];
}

@end

void ByePromptText(NSString *title, NSString *message, NSString *text, NSString *placeholder,
                   BOOL numbers, void (^done)(NSString *text)) {
    ByePrompt *prompt = [[ByePrompt alloc] initWithDone:done];
    UIAlertView *alert = [[[UIAlertView alloc] initWithTitle:title message:message delegate:prompt
                                           cancelButtonTitle:ByeL(@"Cancel") otherButtonTitles:ByeL(@"OK"), nil] autorelease];
    alert.alertViewStyle = UIAlertViewStylePlainTextInput;
    UITextField *field = [alert textFieldAtIndex:0];
    field.text = text;
    field.placeholder = placeholder;
    field.autocapitalizationType = UITextAutocapitalizationTypeNone;
    field.autocorrectionType = UITextAutocorrectionTypeNo;
    field.keyboardType = numbers ? UIKeyboardTypeNumbersAndPunctuation : UIKeyboardTypeASCIICapable;
    [alert show];
}

void ByeAlert(NSString *title, NSString *message) {
    UIAlertView *alert = [[[UIAlertView alloc] initWithTitle:title message:message delegate:nil
                                           cancelButtonTitle:ByeL(@"OK") otherButtonTitles:nil] autorelease];
    [alert show];
}

@interface ByeChoice : NSObject <UIActionSheetDelegate> {
    void (^_done)(NSInteger);
    NSInteger _count;
}
@end

@implementation ByeChoice

- (id)initWithCount:(NSInteger)count done:(void (^)(NSInteger))done {
    self = [super init];
    if (!self) return nil;
    _count = count;
    _done = [done copy];
    return self;
}

- (void)dealloc {
    [_done release];
    [super dealloc];
}

- (void)actionSheet:(UIActionSheet *)sheet clickedButtonAtIndex:(NSInteger)index {
    (void)sheet;
    if (_done) _done(index >= 0 && index < _count ? index : -1);
}

- (void)actionSheet:(UIActionSheet *)sheet didDismissWithButtonIndex:(NSInteger)index {
    (void)sheet;
    (void)index;
    [self autorelease];
}

@end

void ByeChoose(UIViewController *host, NSString *title, NSArray *choices, void (^done)(NSInteger index)) {
    ByeChoice *choice = [[ByeChoice alloc] initWithCount:(NSInteger)choices.count done:done];
    UIActionSheet *sheet = [[[UIActionSheet alloc] initWithTitle:title delegate:choice
                                               cancelButtonTitle:nil destructiveButtonTitle:nil
                                               otherButtonTitles:nil] autorelease];
    for (NSString *item in choices) [sheet addButtonWithTitle:item];
    sheet.cancelButtonIndex = [sheet addButtonWithTitle:ByeL(@"Cancel")];
    sheet.actionSheetStyle = UIActionSheetStyleBlackOpaque;
    UIView *view = host.view;
    [sheet showInView:view];
}

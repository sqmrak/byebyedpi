#ifndef BYE_FORM_H
#define BYE_FORM_H

#import <UIKit/UIKit.h>

@interface ByeScreen : UIViewController
@end

typedef enum {
    ByeRowValue = 0,  /* a title on the left, a value on the right */
    ByeRowStacked,    /* a title over a text that wraps, with an optional glyph */
    ByeRowSwitch,     /* a title and an on/off switch */
    ByeRowButton      /* a centred title that acts */
} ByeRowKind;

typedef enum {
    ByeAccessoryNone = 0,
    ByeAccessoryDisclosure,
    ByeAccessoryCheck
} ByeAccessory;

@interface ByeRow : NSObject {
    ByeRowKind _kind;
    ByeAccessory _accessory;
    NSString *_title;
    NSString *_detail;
    NSString *_glyph;
    UIImage *_image;
    NSString *_ident;
    BOOL _on;
    BOOL _selectable;
    BOOL _monospace;
    UIColor *_detailColor;
    UIColor *_titleColor;
}
@property(nonatomic) ByeRowKind kind;
@property(nonatomic) ByeAccessory accessory;
@property(nonatomic, copy) NSString *title;
@property(nonatomic, copy) NSString *detail;
@property(nonatomic, copy) NSString *glyph;      /* a name of an ic-*.png mask */
@property(nonatomic, retain) UIImage *image;     /* drawn as it is, rounded */
@property(nonatomic, copy) NSString *ident;      /* what the subclass knows the row by */
@property(nonatomic) BOOL on;
@property(nonatomic) BOOL selectable;
@property(nonatomic) BOOL monospace;
@property(nonatomic, retain) UIColor *detailColor;
@property(nonatomic, retain) UIColor *titleColor;
+ (ByeRow *)rowWithKind:(ByeRowKind)kind title:(NSString *)title detail:(NSString *)detail ident:(NSString *)ident;
@end

@interface ByeSection : NSObject {
    NSString *_title;
    NSString *_footer;
    NSArray *_rows;
}
@property(nonatomic, copy) NSString *title;
@property(nonatomic, copy) NSString *footer;
@property(nonatomic, retain) NSArray *rows;
+ (ByeSection *)sectionWithTitle:(NSString *)title footer:(NSString *)footer rows:(NSArray *)rows;
@end

/* keep measurement and drawing in one controller so screens use the same row geometry */
@interface ByeFormController : ByeScreen <UITableViewDataSource, UITableViewDelegate> {
    UITableView *_table;
    NSArray *_sections;
}
@property(nonatomic, readonly) UITableView *table;
@property(nonatomic, readonly) NSArray *sections;

/* the sections of the screen now; called again on every -reloadForm */
- (NSArray *)buildSections;
- (void)reloadForm;
- (ByeRow *)rowAtIndexPath:(NSIndexPath *)indexPath;
- (NSIndexPath *)indexPathOfRowWithIdent:(NSString *)ident;

- (void)formRowTapped:(ByeRow *)row;
- (void)formSwitchChanged:(ByeRow *)row on:(BOOL)on;

- (BOOL)formCanDeleteRow:(ByeRow *)row;
- (void)formDeleteRow:(ByeRow *)row;
- (BOOL)formCanMoveRow:(ByeRow *)row;
- (void)formMoveRowFrom:(NSIndexPath *)from to:(NSIndexPath *)to;
@end

/* the alert owns the callback until dismissal; cancellation passes nil */
void ByePromptText(NSString *title, NSString *message, NSString *text, NSString *placeholder,
                   BOOL numbers, void (^done)(NSString *text));

void ByeAlert(NSString *title, NSString *message);

/* a sheet of choices; done gets the index of the choice, or -1 when cancelled */
void ByeChoose(UIViewController *host, NSString *title, NSArray *choices, void (^done)(NSInteger index));

#endif

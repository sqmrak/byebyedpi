#ifndef BYE_CHROME_H
#define BYE_CHROME_H

#import <UIKit/UIKit.h>

/* custom drawing keeps the ios 5 appearance when newer uikit uses flat controls */

/* the glossy bar behind titles, sized for a bar of that height */
UIImage *ByeBarImage(CGFloat height);
void ByeStyleNavigationBar(UINavigationBar *bar);

/* a bordered bar button, or the arrow shaped back button, with a title or a glyph */
UIBarButtonItem *ByeBarItem(NSString *title, UIImage *glyph, BOOL back, id target, SEL action);

/* the grey chevron of a row and its blue check mark, as accessory views */
UIView *ByeDisclosure(void);
UIView *ByeCheckmark(void);

/* rows and separators that run to the edge on every ios, as ios 5 lays them out */
void ByeStyleTable(UITableView *table);

UIColor *ByeGroupedTextColor(void);
UIColor *ByeGroupedValueColor(void);
UIColor *ByeGroupedCaptionColor(void);
/* how far a grouped table sits in from each side: ios 5 and 6 inset the rows
   themselves (0 here), ios 7 and later run them edge to edge */
CGFloat ByeGroupedMargin(void);
void ByeStyleGroupedCell(UITableViewCell *cell, BOOL first, BOOL last);
/* how far a grouped cell is inset from its table's edge: ios 5 and 6 do it themselves, later ios do not */
CGFloat ByeCellSideInset(void);
/* where text lines up with the group's edge, measured from the table's own edge */
CGFloat ByeGroupedSideInset(void);
/* section titles above and notes below a group; width is the table's */
UIView *ByeGroupedHeader(NSString *title, CGFloat width);
UIView *ByeGroupedFooter(NSString *text, CGFloat width);
CGFloat ByeGroupedFooterHeight(NSString *text, CGFloat width);

/* the ios 5 on/off switch; it answers -isOn and -setOn:animated: like UISwitch */
@interface ByeSwitch : UIControl {
    BOOL _on;
    CGFloat _knob;
    CGFloat _dragStart;
    BOOL _dragged;
}
@property(nonatomic, getter=isOn) BOOL on;
- (void)setOn:(BOOL)on animated:(BOOL)animated;
@end

/* pushes put a drawn back button on screens that have no left item of their own */
@interface ByeNavigationController : UINavigationController
@end

typedef enum {
    ByeGlossBlue = 0,
    ByeGlossGrey,
    ByeGlossRed
} ByeGlossKind;

@interface ByeGlossButton : UIButton {
    ByeGlossKind _kind;
}
- (id)initWithTitle:(NSString *)title kind:(ByeGlossKind)kind;
- (void)setKind:(ByeGlossKind)kind;
@end

typedef enum {
    ByePowerOff = 0,  /* the tunnel is down: blue glass */
    ByePowerBusy,     /* a start or a stop is on its way: amber */
    ByePowerOn,       /* it carries traffic: green */
    ByePowerError     /* it ended with an error: red */
} ByePowerState;

@interface ByePowerButton : UIControl {
    ByePowerState _powerState;
}
@property(nonatomic) ByePowerState powerState;
@end

/* a glossy square button with a glyph over a title, like an ios 5 home screen icon */
@interface ByeTileButton : UIControl {
    NSString *_title;
    NSString *_glyph;
}
- (id)initWithTitle:(NSString *)title glyph:(NSString *)glyph;
- (void)setTitle:(NSString *)title;
@end

@interface ByeChip : UIView {
    NSString *_text;
}
@property(nonatomic, copy) NSString *text;
@end

/* a glossy bar that fills from the left */
@interface ByeProgressBar : UIView {
    CGFloat _progress;
}
@property(nonatomic) CGFloat progress;
@end

#endif

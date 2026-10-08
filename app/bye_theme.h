#ifndef BYE_THEME_H
#define BYE_THEME_H

#import <UIKit/UIKit.h>

/* ios 7 changed the standard controls, so draw the ios 5 appearance here */

BOOL ByeIsPad(void);

/* ios 7 and later draw the status bar over the app, ios 11 notched phones have
   a taller one; before ios 7 the bar takes its own strip and this is zero */
CGFloat ByeStatusBarInset(void);
CGFloat ByeBottomSafeInset(void);

/* ios 9 changed the system font, so keep helvetica for the ios 5 appearance */
UIFont *ByeFont(CGFloat size, BOOL bold);

/* shrink text to fit fixed bounds; minSize limits how small it can become */
UIFont *ByeFitFont(NSString *text, CGFloat size, CGFloat minSize, BOOL bold, CGFloat width, NSUInteger maxLines);

/* ios 15 text drawing can crash with an unbounded height, so measure with a label */
CGSize ByeTextSize(NSString *text, UIFont *font, CGFloat width);

UIColor *ByeRGB(unsigned rgb, CGFloat alpha);
UIColor *ByeColorText(void);
UIColor *ByeColorTextSecondary(void);
UIColor *ByeColorTextTertiary(void);
UIColor *ByeColorValue(void);   /* the pale blue of a row's value */
UIColor *ByeColorAccent(void);

UIColor *ByeBackgroundColor(void);

/* a glyph from the bundle's ic-NAME.png masks, tinted and scaled, cached */
UIImage *ByeIcon(NSString *name, CGFloat points, UIColor *color);

/* one gradient between colors, top to bottom, with optional stops */
void ByeGradient(CGContextRef ctx, CGRect rect, const CGFloat *components,
                 const CGFloat *locations, size_t count);

/* a plain rect from a block of flat color, for a one pixel rule */
void ByeFillRule(CGRect rect, UIColor *color);

#endif

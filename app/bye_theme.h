#ifndef BYE_THEME_H
#define BYE_THEME_H

#import <UIKit/UIKit.h>

/* ios 7 changed the standard controls, so draw the ios 5 appearance here.
   there are two themes. classic is that appearance and has one set of colours. modern is
   flat, the way the android app draws it: a solid background, rounded cards, one accent
   colour. boykisser is drawn like modern with the pink palette of senko and falling sprites.
   modern and boykisser have an appearance, light or dark */

typedef enum {
    ByeThemeStyleClassic = 0,
    ByeThemeStyleModern,
    ByeThemeStyleBoykisser
} ByeThemeStyle;

typedef enum {
    ByeAppearanceLight = 0,
    ByeAppearanceDark
} ByeAppearance;

/* what the screens draw with: the classic theme, or a flat one in one of its two appearances */
typedef enum {
    ByeThemeClassic = 0,
    ByeThemeLight,
    ByeThemeDark,
    ByeThemeBoyLight,
    ByeThemeBoyDark
} ByeThemeKind;

extern NSString * const ByeThemeDidChangeNotification;

ByeThemeStyle ByeThemeGetStyle(void);
ByeAppearance ByeAppearanceGet(void);
/* each saves the choice and tells the app to build its screens again */
void ByeThemeSetStyle(ByeThemeStyle style);
void ByeAppearanceSet(ByeAppearance appearance);
/* the theme in use, after the appearance is resolved */
ByeThemeKind ByeTheme(void);
/* true for every flat theme, boykisser included */
BOOL ByeThemeModern(void);
BOOL ByeThemeBoykisser(void);
/* the light appearance of either flat theme */
BOOL ByeThemeIsLight(void);
/* grows with every change, so a cached image knows it was drawn for another theme */
NSUInteger ByeThemeGeneration(void);
/* what overrideUserInterfaceStyle takes on ios 13 and later: system controls follow the theme */
NSInteger ByeThemeInterfaceStyle(void);

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

UIColor *ByeColorSurface(void);        /* a card, a row, a tile */
UIColor *ByeColorSurfacePressed(void);
UIColor *ByeColorSeparator(void);
UIColor *ByeColorBar(void);
UIColor *ByeColorBarText(void);
UIColor *ByeColorGood(void);
UIColor *ByeColorWarn(void);
UIColor *ByeColorBad(void);
UIColor *ByeColorIcon(void);           /* a glyph in a row */
UIColor *ByeColorOnSelected(void);     /* text over a pressed row */
UIColor *ByeTextShadowColor(void);     /* the classic emboss, clear in the flat themes */

UIColor *ByeBackgroundColor(void);

/* a glyph from the bundle's ic-NAME.png masks, tinted and scaled, cached */
UIImage *ByeIcon(NSString *name, CGFloat points, UIColor *color);

/* one gradient between colors, top to bottom, with optional stops */
void ByeGradient(CGContextRef ctx, CGRect rect, const CGFloat *components,
                 const CGFloat *locations, size_t count);

/* a plain rect from a block of flat color, for a one pixel rule */
void ByeFillRule(CGRect rect, UIColor *color);

#endif

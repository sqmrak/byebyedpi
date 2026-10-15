#import "bye_theme.h"

#import <QuartzCore/QuartzCore.h>
#include <stdlib.h>

NSString * const ByeThemeDidChangeNotification = @"ByeThemeDidChange";

static NSString * const ByeThemeKey = @"ByeThemeStyle";
static NSString * const ByeAppearanceKey = @"ByeAppearance";
/* the first build kept both in one setting: classic, light, dark or system */
static NSString * const ByeOldThemeKey = @"ByeTheme";

static ByeThemeKind gKind = ByeThemeDark;
static BOOL gResolved;
static NSUInteger gGeneration = 1;

ByeThemeStyle ByeThemeGetStyle(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *saved = [defaults stringForKey:ByeThemeKey];
    if (!saved) saved = [[defaults stringForKey:ByeOldThemeKey] isEqualToString:@"classic"] ? @"classic" : @"modern";
    if ([saved isEqualToString:@"boykisser"]) return ByeThemeStyleBoykisser;
    return [saved isEqualToString:@"classic"] ? ByeThemeStyleClassic : ByeThemeStyleModern;
}

ByeAppearance ByeAppearanceGet(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *saved = [defaults stringForKey:ByeAppearanceKey];
    if (!saved) saved = [defaults stringForKey:ByeOldThemeKey];
    /* an old "system" has no counterpart: the dark one is what it was before ios 13 */
    return [saved isEqualToString:@"light"] ? ByeAppearanceLight : ByeAppearanceDark;
}

static ByeThemeKind ByeResolve(void) {
    ByeThemeStyle style = ByeThemeGetStyle();
    if (style == ByeThemeStyleClassic) return ByeThemeClassic;
    BOOL light = ByeAppearanceGet() == ByeAppearanceLight;
    if (style == ByeThemeStyleBoykisser) return light ? ByeThemeBoyLight : ByeThemeBoyDark;
    return light ? ByeThemeLight : ByeThemeDark;
}

ByeThemeKind ByeTheme(void) {
    if (!gResolved) {
        gKind = ByeResolve();
        gResolved = YES;
    }
    return gKind;
}

BOOL ByeThemeModern(void) {
    return ByeTheme() != ByeThemeClassic;
}

BOOL ByeThemeBoykisser(void) {
    return ByeTheme() == ByeThemeBoyLight || ByeTheme() == ByeThemeBoyDark;
}

BOOL ByeThemeIsLight(void) {
    return ByeTheme() == ByeThemeLight || ByeTheme() == ByeThemeBoyLight;
}

NSUInteger ByeThemeGeneration(void) {
    return gGeneration;
}

NSInteger ByeThemeInterfaceStyle(void) {
    return ByeThemeIsLight() ? 1 : 2;
}

static void ByeThemeChanged(void) {
    [[NSUserDefaults standardUserDefaults] synchronize];
    gKind = ByeResolve();
    gResolved = YES;
    ++gGeneration;
    [[NSNotificationCenter defaultCenter] postNotificationName:ByeThemeDidChangeNotification object:nil];
}

void ByeThemeSetStyle(ByeThemeStyle style) {
    static NSString * const names[] = { @"classic", @"modern", @"boykisser" };
    [[NSUserDefaults standardUserDefaults] setObject:names[style] forKey:ByeThemeKey];
    ByeThemeChanged();
}

void ByeAppearanceSet(ByeAppearance appearance) {
    static NSString * const names[] = { @"light", @"dark" };
    [[NSUserDefaults standardUserDefaults] setObject:names[appearance] forKey:ByeAppearanceKey];
    ByeThemeChanged();
}

/* one colour for each theme: classic, light, dark, and the two pink ones of boykisser */
static UIColor *ByePick5(unsigned classic, unsigned light, unsigned dark, unsigned boyLight, unsigned boyDark) {
    switch (ByeTheme()) {
    case ByeThemeLight: return ByeRGB(light, 1.0f);
    case ByeThemeDark: return ByeRGB(dark, 1.0f);
    case ByeThemeBoyLight: return ByeRGB(boyLight, 1.0f);
    case ByeThemeBoyDark: return ByeRGB(boyDark, 1.0f);
    default: return ByeRGB(classic, 1.0f);
    }
}

/* the colours that mean the same thing in boykisser as in modern */
static UIColor *ByePick(unsigned classic, unsigned light, unsigned dark) {
    return ByePick5(classic, light, dark, light, dark);
}

BOOL ByeIsPad(void) {
    return [[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPad;
}

/* -safeAreaInsets does not exist before ios 11, so it is reached by name */
static UIEdgeInsets ByeSafeAreaInsets(void) {
    UIEdgeInsets zero = UIEdgeInsetsZero;
    UIWindow *window = [UIApplication sharedApplication].keyWindow;
    SEL sel = NSSelectorFromString(@"safeAreaInsets");
    if (!window || ![window respondsToSelector:sel]) return zero;
    UIEdgeInsets (*call)(id, SEL) = (UIEdgeInsets (*)(id, SEL))[window methodForSelector:sel];
    UIEdgeInsets insets = call(window, sel);
    if (insets.top < 0.0f || insets.left < 0.0f || insets.bottom < 0.0f || insets.right < 0.0f)
        return zero;
    return insets;
}

CGFloat ByeStatusBarInset(void) {
#if __IPHONE_OS_VERSION_MAX_ALLOWED < 70000
    /* the armv7 slice is linked before ios 7: ios 7 to 10 still lay it out below the bar, and
       adding the inset again left a second black strip on ios 10 */
    return 0.0f;
#else
    UIEdgeInsets safe = ByeSafeAreaInsets();
    if (safe.top > 0.0f) return safe.top;
    /* ios 7 added this selector, and with it the bar over the app */
    if (![UIViewController instancesRespondToSelector:@selector(setNeedsStatusBarAppearanceUpdate)])
        return 0.0f;
    CGRect bar = [UIApplication sharedApplication].statusBarFrame;
    /* the shorter edge stays the bar's thickness after a landscape swap */
    CGFloat edge = bar.size.height;
    if (bar.size.width > 0.0f && bar.size.width < edge) edge = bar.size.width;
    return edge >= 1.0f ? edge : 20.0f;
#endif
}

CGFloat ByeBottomSafeInset(void) {
    return ByeSafeAreaInsets().bottom;
}

UIFont *ByeFont(CGFloat size, BOOL bold) {
    if (ByeIsPad()) size = roundf((float)(size * 1.15f));
    /* the flat themes take the system face: helvetica neue on ios 7 and 8, the newer one from ios 9 */
    if (ByeThemeModern()) return bold ? [UIFont boldSystemFontOfSize:size] : [UIFont systemFontOfSize:size];
    UIFont *font = [UIFont fontWithName:bold ? @"Helvetica-Bold" : @"Helvetica" size:size];
    if (font) return font;
    return bold ? [UIFont boldSystemFontOfSize:size] : [UIFont systemFontOfSize:size];
}

CGSize ByeTextSize(NSString *text, UIFont *font, CGFloat width) {
    static UILabel *gauge = nil;
    if (!text.length || !font || width < 1.0f) return CGSizeZero;
    if (!gauge) {
        gauge = [[UILabel alloc] initWithFrame:CGRectZero];
        gauge.numberOfLines = 0;
        gauge.lineBreakMode = NSLineBreakByWordWrapping;
        gauge.backgroundColor = [UIColor clearColor];
    }
    gauge.font = font;
    gauge.text = text;
    CGSize fit = [gauge sizeThatFits:CGSizeMake(width, 100000.0f)];
    if (fit.width > width) fit.width = width;
    return CGSizeMake(ceilf((float)fit.width), ceilf((float)fit.height));
}

UIFont *ByeFitFont(NSString *text, CGFloat size, CGFloat minSize, BOOL bold, CGFloat width, NSUInteger maxLines) {
    UIFont *font = ByeFont(size, bold);
    for (CGFloat step = size; step >= minSize; step -= 0.5f) {
        font = ByeFont(step, bold);
        if (ByeTextSize(text, font, width).height <= font.lineHeight * (CGFloat)maxLines + 1.0f) return font;
    }
    return font;
}

UIColor *ByeRGB(unsigned rgb, CGFloat alpha) {
    return [UIColor colorWithRed:((rgb >> 16) & 0xFF) / 255.0f
                           green:((rgb >> 8) & 0xFF) / 255.0f
                            blue:(rgb & 0xFF) / 255.0f
                           alpha:alpha];
}

UIColor *ByeColorText(void) { return ByePick5(0xffffff, 0x1c1c1e, 0xffffff, 0x472438, 0xffedf3); }
UIColor *ByeColorTextSecondary(void) { return ByePick5(0xa9b8cd, 0x5f6368, 0xa9abb5, 0x9e6b85, 0xc7a1b3); }
UIColor *ByeColorTextTertiary(void) { return ByePick5(0x72849e, 0x8a8d94, 0x7b7e8a, 0xb88fa5, 0x94738a); }
UIColor *ByeColorValue(void) { return ByePick5(0x8fb0dc, 0x3c52a3, 0x7ba3ff, 0xe6408f, 0xff75b8); }
UIColor *ByeColorAccent(void) { return ByePick5(0x3b82d6, 0x5976df, 0x3a7bff, 0xff61ad, 0xff75b8); }
UIColor *ByeColorSurface(void) { return ByePick5(0x1f2937, 0xffffff, 0x1a1d26, 0xfffafc, 0x22141d); }
UIColor *ByeColorSurfacePressed(void) { return ByePick5(0x2f3f55, 0xe4e7f0, 0x2a2f3d, 0xffe0ec, 0x332029); }
UIColor *ByeColorSeparator(void) { return ByePick5(0x4d6385, 0xe3e5ec, 0x2b2f3b, 0xffd3e4, 0x3a2530); }
UIColor *ByeColorBar(void) { return ByePick5(0x1b3a66, 0x5976df, 0x2c2c30, 0xf25a9e, 0xde428f); }
UIColor *ByeColorBarText(void) { return [UIColor whiteColor]; }
UIColor *ByeColorGood(void) { return ByePick(0x7fe08a, 0x2e7d32, 0x66c26a); }
UIColor *ByeColorWarn(void) { return ByePick(0xf2c879, 0xb26a00, 0xffb74d); }
UIColor *ByeColorBad(void) { return ByePick(0xf2a39c, 0xc62828, 0xff7b72); }
UIColor *ByeColorIcon(void) { return ByePick5(0xd6e3f5, 0x5976df, 0x7ba3ff, 0xe6408f, 0xff75b8); }
UIColor *ByeColorOnSelected(void) { return ByeThemeModern() ? ByeColorText() : [UIColor whiteColor]; }
UIColor *ByeTextShadowColor(void) { return ByeThemeModern() ? [UIColor clearColor] : [UIColor blackColor]; }

UIColor *ByeBackgroundColor(void) {
    static UIColor *leather;
    if (ByeThemeModern()) return ByePick5(0, 0xf2f3f7, 0x000000, 0xfff0f5, 0x1d1218);
    if (leather) return leather;
    CGFloat side = 64.0f;
    UIGraphicsBeginImageContextWithOptions(CGSizeMake(side, side), YES, 0.0f);
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    [ByeRGB(0x0e1b2d, 1.0f) setFill];
    CGContextFillRect(ctx, CGRectMake(0.0f, 0.0f, side, side));
    /* a fixed seed, so the grain is the same on every launch and every redraw */
    srand(20241004);
    CGFloat scale = [UIScreen mainScreen].scale;
    int specks = (int)(side * side * 0.35f);
    for (int i = 0; i < specks; ++i) {
        CGFloat x = (CGFloat)(rand() % (int)(side * scale)) / scale;
        CGFloat y = (CGFloat)(rand() % (int)(side * scale)) / scale;
        BOOL light = (rand() & 1) != 0;
        CGFloat alpha = 0.03f + (CGFloat)(rand() % 5) * 0.012f;
        [[UIColor colorWithWhite:light ? 1.0f : 0.0f alpha:alpha] setFill];
        CGContextFillRect(ctx, CGRectMake(x, y, 1.0f / scale, 1.0f / scale));
    }
    UIImage *tile = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    leather = [[UIColor colorWithPatternImage:tile] retain];
    return leather;
}

UIImage *ByeIcon(NSString *name, CGFloat points, UIColor *color) {
    static NSCache *cache;
    if (!cache) {
        cache = [[NSCache alloc] init];
        [cache setCountLimit:120];
    }
    if (!name.length || points <= 0.0f) return nil;
    CGFloat r = 1, g = 1, b = 1, a = 1;
    if (color && ![color getRed:&r green:&g blue:&b alpha:&a]) {
        CGFloat white = 1;
        if ([color getWhite:&white alpha:&a]) r = g = b = white;
    }
    NSString *key = [NSString stringWithFormat:@"%@|%.1f|%.3f,%.3f,%.3f,%.3f", name, points, r, g, b, a];
    UIImage *hit = [cache objectForKey:key];
    if (hit) return hit;
    NSString *path = [[NSBundle mainBundle] pathForResource:[@"ic-" stringByAppendingString:name] ofType:@"png"];
    UIImage *mask = path ? [UIImage imageWithContentsOfFile:path] : nil;
    if (!mask) return nil;
    CGRect rect = CGRectMake(0.0f, 0.0f, points, points);
    UIGraphicsBeginImageContextWithOptions(rect.size, NO, 0.0f);
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    CGContextSetInterpolationQuality(ctx, kCGInterpolationHigh);
    [mask drawInRect:rect];
    CGContextSetBlendMode(ctx, kCGBlendModeSourceIn);
    CGContextSetFillColorWithColor(ctx, (color ? color : [UIColor whiteColor]).CGColor);
    CGContextFillRect(ctx, rect);
    UIImage *image = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    if (image) [cache setObject:image forKey:key];
    return image;
}

void ByeGradient(CGContextRef ctx, CGRect rect, const CGFloat *components, const CGFloat *locations,
                 size_t count) {
    CGColorSpaceRef space = CGColorSpaceCreateDeviceRGB();
    CGGradientRef gradient = CGGradientCreateWithColorComponents(space, components, locations, count);
    if (gradient) {
        CGContextDrawLinearGradient(ctx, gradient, CGPointMake(0.0f, CGRectGetMinY(rect)),
                                    CGPointMake(0.0f, CGRectGetMaxY(rect)), 0);
        CGGradientRelease(gradient);
    }
    CGColorSpaceRelease(space);
}

void ByeFillRule(CGRect rect, UIColor *color) {
    [color setFill];
    UIRectFill(rect);
}

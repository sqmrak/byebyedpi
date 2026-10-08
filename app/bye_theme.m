#import "bye_theme.h"

#import <QuartzCore/QuartzCore.h>
#include <stdlib.h>

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

UIColor *ByeColorText(void) { return [UIColor whiteColor]; }
UIColor *ByeColorTextSecondary(void) { return ByeRGB(0xa9b8cd, 1.0f); }
UIColor *ByeColorTextTertiary(void) { return ByeRGB(0x72849e, 1.0f); }
UIColor *ByeColorValue(void) { return ByeRGB(0x8fb0dc, 1.0f); }
UIColor *ByeColorAccent(void) { return ByeRGB(0x3b82d6, 1.0f); }

UIColor *ByeBackgroundColor(void) {
    static UIColor *leather;
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

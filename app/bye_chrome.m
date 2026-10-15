#import "bye_chrome.h"

/* ios 5 needs the text drawing methods and title attribute names deprecated in ios 7 */
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import <QuartzCore/QuartzCore.h>
#include <objc/message.h>

#import "bye_theme.h"
#import "bye_l10n.h"

static const CGFloat ByeButtonHeight = 30.0f;

#pragma mark - bar

UIImage *ByeBarImage(CGFloat height) {
    static NSMutableDictionary *cache;
    static NSUInteger generation;
    if (generation != ByeThemeGeneration()) {
        [cache release];
        cache = nil;
        generation = ByeThemeGeneration();
    }
    if (!cache) cache = [[NSMutableDictionary alloc] init];
    NSNumber *key = [NSNumber numberWithFloat:(float)height];
    UIImage *hit = [cache objectForKey:key];
    if (hit) return hit;
    CGRect rect = CGRectMake(0.0f, 0.0f, 1.0f, height);
    UIGraphicsBeginImageContextWithOptions(rect.size, YES, 0.0f);
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    if (ByeThemeModern()) {
        /* a flat bar: one colour, and no rule under it, the bar's own shadow image is cleared */
        ByeFillRule(rect, ByeColorBar());
        UIImage *flat = [UIGraphicsGetImageFromCurrentImageContext() resizableImageWithCapInsets:UIEdgeInsetsZero];
        UIGraphicsEndImageContext();
        if (flat) [cache setObject:flat forKey:key];
        return flat;
    }
    const CGFloat colors[16] = { 0.46f, 0.62f, 0.82f, 1.0f,   0.27f, 0.43f, 0.67f, 1.0f,
                                 0.17f, 0.33f, 0.58f, 1.0f,   0.10f, 0.22f, 0.43f, 1.0f };
    const CGFloat stops[4] = { 0.0f, 0.5f, 0.5f, 1.0f };
    ByeGradient(ctx, rect, colors, stops, 4);
    ByeFillRule(CGRectMake(0.0f, 0.0f, 1.0f, 1.0f), [UIColor colorWithWhite:1.0f alpha:0.35f]);
    ByeFillRule(CGRectMake(0.0f, height - 1.0f, 1.0f, 1.0f), [UIColor colorWithWhite:0.0f alpha:0.6f]);
    UIImage *image = [UIGraphicsGetImageFromCurrentImageContext() resizableImageWithCapInsets:UIEdgeInsetsZero];
    UIGraphicsEndImageContext();
    if (image) [cache setObject:image forKey:key];
    return image;
}

/* ios 13 moved bar styling to UINavigationBarAppearance, and from ios 15 a bar
   scrolled to the top uses its scroll edge appearance, which is transparent unless set */
static void ByeStyleBarAppearance(UINavigationBar *bar, UIImage *portrait, UIImage *landscape) {
    [bar setBackgroundImage:portrait forBarMetrics:UIBarMetricsDefault];
    [bar setBackgroundImage:landscape forBarMetrics:UIBarMetricsLandscapePhone];
    Class appearanceClass = NSClassFromString(@"UINavigationBarAppearance");
    SEL standard = NSSelectorFromString(@"setStandardAppearance:");
    if (!appearanceClass || ![bar respondsToSelector:standard]) return;
    id appearance = [[[appearanceClass alloc] init] autorelease];
    [appearance performSelector:NSSelectorFromString(@"configureWithOpaqueBackground")];
    [appearance performSelector:NSSelectorFromString(@"setBackgroundColor:") withObject:ByeColorBar()];
    [appearance performSelector:NSSelectorFromString(@"setBackgroundImage:") withObject:portrait];
    [appearance performSelector:NSSelectorFromString(@"setShadowColor:") withObject:nil];
    NSDictionary *title;
    if (ByeThemeModern()) {
        title = [NSDictionary dictionaryWithObjectsAndKeys:
                 ByeColorBarText(), @"NSColor", ByeFont(19.0f, NO), @"NSFont", nil];
    } else {
        /* the appearance takes the current attribute names only; NSShadow exists from ios 6 */
        NSShadow *shadow = [[[NSClassFromString(@"NSShadow") alloc] init] autorelease];
        [shadow setShadowColor:[UIColor colorWithWhite:0.0f alpha:0.5f]];
        [shadow setShadowOffset:CGSizeMake(0.0f, -1.0f)];
        title = [NSDictionary dictionaryWithObjectsAndKeys:
                 [UIColor whiteColor], @"NSColor", ByeFont(18.0f, YES), @"NSFont",
                 shadow, @"NSShadow", nil];
    }
    [appearance performSelector:NSSelectorFromString(@"setTitleTextAttributes:") withObject:title];
    [bar performSelector:standard withObject:appearance];
    SEL edge = NSSelectorFromString(@"setScrollEdgeAppearance:");
    if ([bar respondsToSelector:edge]) [bar performSelector:edge withObject:appearance];
    SEL compact = NSSelectorFromString(@"setCompactAppearance:");
    if ([bar respondsToSelector:compact]) [bar performSelector:compact withObject:appearance];
    SEL compactEdge = NSSelectorFromString(@"setCompactScrollEdgeAppearance:");
    if ([bar respondsToSelector:compactEdge]) [bar performSelector:compactEdge withObject:appearance];
}

void ByeStyleNavigationBar(UINavigationBar *bar) {
    if (!bar) return;
    UIImage *portrait = ByeBarImage(44.0f);
    NSDictionary *title = ByeThemeModern()
        ? [NSDictionary dictionaryWithObjectsAndKeys:
           ByeColorBarText(), UITextAttributeTextColor,
           [UIColor clearColor], UITextAttributeTextShadowColor,
           [NSValue valueWithUIOffset:UIOffsetZero], UITextAttributeTextShadowOffset,
           ByeFont(19.0f, NO), UITextAttributeFont, nil]
        : [NSDictionary dictionaryWithObjectsAndKeys:
           [UIColor whiteColor], UITextAttributeTextColor,
           [UIColor colorWithWhite:0.0f alpha:0.5f], UITextAttributeTextShadowColor,
           [NSValue valueWithUIOffset:UIOffsetMake(0.0f, -1.0f)], UITextAttributeTextShadowOffset,
           ByeFont(18.0f, YES), UITextAttributeFont, nil];
    /* every screen restyles the bar as it appears, and ios 5 rebuilds the title on each
       assignment: doing it in the middle of a push drew the new title over the old one */
    if ([bar backgroundImageForBarMetrics:UIBarMetricsDefault] == portrait && [bar.titleTextAttributes isEqual:title])
        return;
    bar.barStyle = UIBarStyleDefault;
    bar.translucent = NO;
    bar.tintColor = ByeColorBar();
    ByeStyleBarAppearance(bar, portrait, ByeBarImage(32.0f));
    /* the bar image carries its own dark line; the hairline ios 6 adds would double it */
    if ([bar respondsToSelector:@selector(setShadowImage:)])
        [bar setShadowImage:[[[UIImage alloc] init] autorelease]];
    bar.titleTextAttributes = title;
}

static UIBezierPath *ByeButtonPath(CGRect rect, BOOL back) {
    CGFloat radius = 5.0f;
    if (!back) return [UIBezierPath bezierPathWithRoundedRect:rect cornerRadius:radius];
    CGFloat minX = CGRectGetMinX(rect), maxX = CGRectGetMaxX(rect);
    CGFloat minY = CGRectGetMinY(rect), maxY = CGRectGetMaxY(rect), midY = CGRectGetMidY(rect);
    CGFloat tip = 11.0f;
    UIBezierPath *path = [UIBezierPath bezierPath];
    [path moveToPoint:CGPointMake(minX + tip, minY)];
    [path addLineToPoint:CGPointMake(maxX - radius, minY)];
    [path addArcWithCenter:CGPointMake(maxX - radius, minY + radius) radius:radius startAngle:(CGFloat)(-M_PI_2)
                  endAngle:0.0f clockwise:YES];
    [path addLineToPoint:CGPointMake(maxX, maxY - radius)];
    [path addArcWithCenter:CGPointMake(maxX - radius, maxY - radius) radius:radius startAngle:0.0f
                  endAngle:(CGFloat)M_PI_2 clockwise:YES];
    [path addLineToPoint:CGPointMake(minX + tip, maxY)];
    [path addLineToPoint:CGPointMake(minX + 1.0f, midY + 1.0f)];
    [path addQuadCurveToPoint:CGPointMake(minX + 1.0f, midY - 1.0f) controlPoint:CGPointMake(minX, midY)];
    [path closePath];
    path.lineJoinStyle = kCGLineJoinRound;
    return path;
}

static UIImage *ByeButtonImage(BOOL back, BOOL pressed) {
    static UIImage *images[4];
    UIImage **slot = &images[(back ? 2 : 0) + (pressed ? 1 : 0)];
    if (*slot) return *slot;
    CGFloat left = back ? 14.0f : 6.0f, right = 6.0f;
    CGSize size = CGSizeMake(left + right + 1.0f, ByeButtonHeight);
    UIGraphicsBeginImageContextWithOptions(size, NO, 0.0f);
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    CGRect body = CGRectMake(0.5f, 0.5f, size.width - 1.0f, size.height - 2.0f);
    [[UIColor colorWithWhite:1.0f alpha:0.22f] setStroke];
    [ByeButtonPath(CGRectOffset(body, 0.0f, 1.0f), back) stroke];
    UIBezierPath *shape = ByeButtonPath(body, back);
    CGContextSaveGState(ctx);
    [shape addClip];
    CGFloat dim = pressed ? 0.62f : 1.0f;
    const CGFloat colors[16] = { 0.34f * dim, 0.50f * dim, 0.74f * dim, 1.0f,  0.20f * dim, 0.35f * dim, 0.60f * dim, 1.0f,
                                 0.13f * dim, 0.27f * dim, 0.50f * dim, 1.0f,  0.09f * dim, 0.21f * dim, 0.42f * dim, 1.0f };
    const CGFloat stops[4] = { 0.0f, 0.5f, 0.5f, 1.0f };
    ByeGradient(ctx, body, colors, stops, 4);
    CGContextRestoreGState(ctx);
    [[UIColor colorWithRed:0.02f green:0.07f blue:0.16f alpha:0.85f] setStroke];
    shape.lineWidth = 1.0f;
    [shape stroke];
    UIImage *image = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    *slot = [[image resizableImageWithCapInsets:UIEdgeInsetsMake(0.0f, left, 0.0f, right)] retain];
    return *slot;
}

/* the flat themes draw no bezel: a glyph or a word, and a chevron for the way back */
static UIImage *ByeBackChevron(void) {
    static UIImage *chevron;
    if (chevron) return chevron;
    UIGraphicsBeginImageContextWithOptions(CGSizeMake(12.0f, 20.0f), NO, 0.0f);
    UIBezierPath *path = [UIBezierPath bezierPath];
    [path moveToPoint:CGPointMake(10.0f, 2.0f)];
    [path addLineToPoint:CGPointMake(2.5f, 10.0f)];
    [path addLineToPoint:CGPointMake(10.0f, 18.0f)];
    path.lineWidth = 2.4f;
    path.lineCapStyle = kCGLineCapRound;
    path.lineJoinStyle = kCGLineJoinRound;
    [[UIColor whiteColor] setStroke];
    [path stroke];
    chevron = [UIGraphicsGetImageFromCurrentImageContext() retain];
    UIGraphicsEndImageContext();
    return chevron;
}

static UIBarButtonItem *ByeFlatBarItem(NSString *title, UIImage *glyph, BOOL back, id target, SEL action) {
    UIButton *button = [UIButton buttonWithType:UIButtonTypeCustom];
    UIFont *font = ByeFont(16.0f, NO);
    CGFloat width;
    if (glyph) {
        [button setImage:glyph forState:UIControlStateNormal];
        width = MAX(44.0f, glyph.size.width + 20.0f);
    } else {
        button.titleLabel.font = font;
        button.titleLabel.lineBreakMode = NSLineBreakByClipping;
        [button setTitle:title forState:UIControlStateNormal];
        [button setTitleColor:ByeColorBarText() forState:UIControlStateNormal];
        [button setTitleColor:[UIColor colorWithWhite:1.0f alpha:0.5f] forState:UIControlStateHighlighted];
        CGFloat text = ceilf((float)ByeTextSize(title, font, 400.0f).width);
        if (back) {
            [button setImage:ByeBackChevron() forState:UIControlStateNormal];
            button.imageEdgeInsets = UIEdgeInsetsMake(0.0f, -4.0f, 0.0f, 4.0f);
            button.titleEdgeInsets = UIEdgeInsetsMake(0.0f, 2.0f, 0.0f, -2.0f);
            width = MAX(44.0f, text + 12.0f + 14.0f);
        } else {
            width = MAX(44.0f, text + 16.0f);
        }
    }
    button.adjustsImageWhenHighlighted = YES;
    button.showsTouchWhenHighlighted = NO;
    button.frame = CGRectMake(0.0f, 0.0f, width, 36.0f);
    if (title.length) button.accessibilityLabel = title;
    [button addTarget:target action:action forControlEvents:UIControlEventTouchUpInside];
    return [[[UIBarButtonItem alloc] initWithCustomView:button] autorelease];
}

UIBarButtonItem *ByeBarItem(NSString *title, UIImage *glyph, BOOL back, id target, SEL action) {
    if (ByeThemeModern()) return ByeFlatBarItem(title, glyph, back, target, action);
    UIButton *button = [UIButton buttonWithType:UIButtonTypeCustom];
    UIFont *font = ByeFont(12.0f, YES);
    CGFloat leftPad = back ? 15.0f : 10.0f, rightPad = 10.0f;
    CGFloat width;
    if (glyph) {
        [button setImage:glyph forState:UIControlStateNormal];
        width = MAX(40.0f, glyph.size.width + leftPad + rightPad);
    } else {
        button.titleLabel.font = font;
        button.titleLabel.shadowOffset = CGSizeMake(0.0f, -1.0f);
        button.titleLabel.lineBreakMode = NSLineBreakByClipping;
        [button setTitle:title forState:UIControlStateNormal];
        [button setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [button setTitleShadowColor:[UIColor colorWithWhite:0.0f alpha:0.5f] forState:UIControlStateNormal];
        width = MAX(50.0f, ceilf((float)ByeTextSize(title, font, 400.0f).width) + leftPad + rightPad);
    }
    button.contentEdgeInsets = UIEdgeInsetsMake(0.0f, leftPad, 0.0f, rightPad);
    button.adjustsImageWhenHighlighted = NO;
    [button setBackgroundImage:ByeButtonImage(back, NO) forState:UIControlStateNormal];
    [button setBackgroundImage:ByeButtonImage(back, YES) forState:UIControlStateHighlighted];
    button.frame = CGRectMake(0.0f, 0.0f, width, ByeButtonHeight);
    if (title.length) button.accessibilityLabel = title;
    [button addTarget:target action:action forControlEvents:UIControlEventTouchUpInside];
    return [[[UIBarButtonItem alloc] initWithCustomView:button] autorelease];
}

UIView *ByeDisclosure(void) {
    static UIImage *chevron;
    static NSUInteger generation;
    if (generation != ByeThemeGeneration()) {
        [chevron release];
        chevron = nil;
        generation = ByeThemeGeneration();
    }
    if (!chevron) {
        UIGraphicsBeginImageContextWithOptions(CGSizeMake(11.0f, 15.0f), NO, 0.0f);
        UIBezierPath *path = [UIBezierPath bezierPath];
        [path moveToPoint:CGPointMake(2.0f, 2.0f)];
        [path addLineToPoint:CGPointMake(8.0f, 7.5f)];
        [path addLineToPoint:CGPointMake(2.0f, 13.0f)];
        path.lineWidth = ByeThemeModern() ? 2.0f : 3.0f;
        path.lineCapStyle = ByeThemeModern() ? kCGLineCapRound : kCGLineCapSquare;
        path.lineJoinStyle = ByeThemeModern() ? kCGLineJoinRound : kCGLineJoinMiter;
        [(ByeThemeModern() ? ByeColorTextTertiary() : [UIColor colorWithRed:0.55f green:0.64f blue:0.78f alpha:1.0f]) setStroke];
        [path stroke];
        chevron = [UIGraphicsGetImageFromCurrentImageContext() retain];
        UIGraphicsEndImageContext();
    }
    return [[[UIImageView alloc] initWithImage:chevron] autorelease];
}

UIView *ByeCheckmark(void) {
    static UIImage *check;
    static NSUInteger generation;
    if (generation != ByeThemeGeneration()) {
        [check release];
        check = nil;
        generation = ByeThemeGeneration();
    }
    if (!check) {
        UIGraphicsBeginImageContextWithOptions(CGSizeMake(16.0f, 14.0f), NO, 0.0f);
        UIBezierPath *path = [UIBezierPath bezierPath];
        [path moveToPoint:CGPointMake(2.0f, 7.5f)];
        [path addLineToPoint:CGPointMake(6.0f, 11.5f)];
        [path addLineToPoint:CGPointMake(14.0f, 2.0f)];
        path.lineWidth = 3.0f;
        path.lineCapStyle = kCGLineCapRound;
        path.lineJoinStyle = kCGLineJoinRound;
        [(ByeThemeModern() ? ByeColorAccent() : [UIColor colorWithRed:0.42f green:0.74f blue:1.0f alpha:1.0f]) setStroke];
        [path stroke];
        check = [UIGraphicsGetImageFromCurrentImageContext() retain];
        UIGraphicsEndImageContext();
    }
    return [[[UIImageView alloc] initWithImage:check] autorelease];
}

/* ios 7 indents separators, ios 8 adds layout margins and ios 9 narrows ipad rows to a reading width;
   ios 5 has none of these, so each is reset where the running uikit has it */
static void ByeZeroInsets(id view, NSString *selector) {
    SEL sel = NSSelectorFromString(selector);
    if (![view respondsToSelector:sel]) return;
    ((void (*)(id, SEL, UIEdgeInsets))objc_msgSend)(view, sel, UIEdgeInsetsZero);
}

static void ByeSetFlag(id view, NSString *selector, BOOL value) {
    SEL sel = NSSelectorFromString(selector);
    if (![view respondsToSelector:sel]) return;
    ((void (*)(id, SEL, BOOL))objc_msgSend)(view, sel, value);
}

void ByeStyleTable(UITableView *table) {
    ByeZeroInsets(table, @"setSeparatorInset:");
    ByeZeroInsets(table, @"setLayoutMargins:");
    ByeSetFlag(table, @"setCellLayoutMarginsFollowReadableWidth:", NO);
    table.separatorStyle = UITableViewCellSeparatorStyleNone;
    table.backgroundView = nil;
    table.backgroundColor = [UIColor clearColor];
}

#pragma mark - grouped tables

UIColor *ByeGroupedTextColor(void) { return ByeThemeModern() ? ByeColorText() : [UIColor whiteColor]; }
UIColor *ByeGroupedValueColor(void) { return ByeColorValue(); }
UIColor *ByeGroupedCaptionColor(void) { return ByeThemeModern() ? ByeColorTextSecondary() : ByeRGB(0x9db0ca, 1.0f); }

static BOOL ByeSystemInsetsGroups(void) {
    return ![UITableView instancesRespondToSelector:@selector(setSeparatorInset:)];
}

CGFloat ByeGroupedMargin(void) {
    if (ByeSystemInsetsGroups()) return 0.0f;
    return ByeIsPad() ? 45.0f : 10.0f;
}

/* a flat card: rounded where the group starts and ends, a hairline between rows */
static void ByeDrawFlatSegment(CGRect bounds, BOOL first, BOOL last, BOOL selected) {
    CGFloat radius = 14.0f;
    UIRectCorner corners = (first ? UIRectCornerTopLeft | UIRectCornerTopRight : 0) |
                           (last ? UIRectCornerBottomLeft | UIRectCornerBottomRight : 0);
    UIBezierPath *shape = [UIBezierPath bezierPathWithRoundedRect:bounds byRoundingCorners:corners
                                                      cornerRadii:CGSizeMake(radius, radius)];
    [(selected ? ByeColorSurfacePressed() : ByeColorSurface()) setFill];
    [shape fill];
    if (!last) {
        CGFloat rule = 1.0f / [UIScreen mainScreen].scale;
        ByeFillRule(CGRectMake(16.0f, CGRectGetMaxY(bounds) - rule, bounds.size.width - 16.0f, rule), ByeColorSeparator());
    }
}

static void ByeDrawGroupedSegment(CGRect bounds, BOOL first, BOOL last, BOOL selected) {
    if (ByeThemeModern()) {
        ByeDrawFlatSegment(bounds, first, last, selected);
        return;
    }
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    CGFloat radius = 10.0f;
    /* a row below another lets its top rim fall outside, so the row above's bottom rim is the one separator */
    CGRect body = bounds;
    if (!first) {
        body.origin.y -= 1.0f;
        body.size.height += 1.0f;
    }
    body = CGRectInset(body, 0.5f, 0.5f);
    UIRectCorner corners = (first ? UIRectCornerTopLeft | UIRectCornerTopRight : 0) |
                           (last ? UIRectCornerBottomLeft | UIRectCornerBottomRight : 0);
    UIBezierPath *shape = [UIBezierPath bezierPathWithRoundedRect:body byRoundingCorners:corners
                                                      cornerRadii:CGSizeMake(radius, radius)];
    CGContextSaveGState(ctx);
    [shape addClip];
    if (selected) {
        const CGFloat colors[8] = { 0.02f, 0.55f, 0.96f, 1.0f,  0.00f, 0.37f, 0.90f, 1.0f };
        ByeGradient(ctx, body, colors, NULL, 2);
    } else {
        const CGFloat colors[8] = { 0.18f, 0.24f, 0.33f, 1.0f,  0.13f, 0.18f, 0.26f, 1.0f };
        ByeGradient(ctx, body, colors, NULL, 2);
    }
    CGContextRestoreGState(ctx);
    [[UIColor colorWithRed:0.30f green:0.39f blue:0.52f alpha:1.0f] setStroke];
    shape.lineWidth = 1.0f;
    [shape stroke];
}

@interface ByeSegmentView : UIView {
    BOOL _first, _last, _selected;
}
- (id)initWithFirst:(BOOL)first last:(BOOL)last selected:(BOOL)selected;
@end

@implementation ByeSegmentView

- (id)initWithFirst:(BOOL)first last:(BOOL)last selected:(BOOL)selected {
    self = [super initWithFrame:CGRectZero];
    if (!self) return nil;
    _first = first;
    _last = last;
    _selected = selected;
    self.opaque = NO;
    self.backgroundColor = [UIColor clearColor];
    self.contentMode = UIViewContentModeRedraw;
    return self;
}

- (void)drawRect:(CGRect)rect {
    (void)rect;
    ByeDrawGroupedSegment(self.bounds, _first, _last, _selected);
}

@end

void ByeStyleGroupedCell(UITableViewCell *cell, BOOL first, BOOL last) {
    cell.backgroundColor = [UIColor clearColor];
    cell.backgroundView = [[[ByeSegmentView alloc] initWithFirst:first last:last selected:NO] autorelease];
    cell.selectedBackgroundView = [[[ByeSegmentView alloc] initWithFirst:first last:last selected:YES] autorelease];
    cell.textLabel.backgroundColor = [UIColor clearColor];
    cell.textLabel.textColor = ByeGroupedTextColor();
    cell.textLabel.highlightedTextColor = ByeColorOnSelected();
    cell.textLabel.font = ByeFont(15.0f, !ByeThemeModern());
    cell.detailTextLabel.backgroundColor = [UIColor clearColor];
    cell.detailTextLabel.textColor = ByeGroupedValueColor();
    cell.detailTextLabel.highlightedTextColor = ByeColorOnSelected();
    cell.detailTextLabel.font = ByeFont(15.0f, NO);
    cell.selectionStyle = UITableViewCellSelectionStyleBlue;
}

CGFloat ByeCellSideInset(void) {
    return ByeSystemInsetsGroups() ? (ByeIsPad() ? 45.0f : 10.0f) : 0.0f;
}

static CGFloat ByeGroupedTextInset(void) {
    return ByeCellSideInset() + 10.0f;
}

CGFloat ByeGroupedSideInset(void) {
    return ByeGroupedTextInset();
}

static UILabel *ByeEmbossedLabel(CGFloat size, BOOL bold) {
    UILabel *label = [[[UILabel alloc] initWithFrame:CGRectZero] autorelease];
    label.backgroundColor = [UIColor clearColor];
    label.textColor = ByeGroupedCaptionColor();
    label.shadowColor = ByeTextShadowColor();
    label.shadowOffset = ByeThemeModern() ? CGSizeZero : CGSizeMake(0.0f, -1.0f);
    label.font = ByeFont(size, bold);
    return label;
}

UIView *ByeGroupedHeader(NSString *title, CGFloat width) {
    UIView *header = [[[UIView alloc] initWithFrame:CGRectMake(0.0f, 0.0f, width, 44.0f)] autorelease];
    header.backgroundColor = [UIColor clearColor];
    if (!title.length) return header;
    CGFloat inset = ByeGroupedTextInset();
    UILabel *label = ByeEmbossedLabel(ByeThemeModern() ? 14.0f : 15.0f, YES);
    /* the flat themes colour the title like the android app's section headers */
    if (ByeThemeModern()) label.textColor = ByeColorValue();
    label.frame = CGRectMake(inset, 16.0f, MAX(0.0f, width - inset * 2.0f), 22.0f);
    label.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    label.text = title;
    [header addSubview:label];
    return header;
}

CGFloat ByeGroupedFooterHeight(NSString *text, CGFloat width) {
    if (!text.length) return 10.0f;
    CGFloat inset = ByeGroupedTextInset();
    return ceilf((float)ByeTextSize(text, ByeFont(12.0f, NO), MAX(40.0f, width - inset * 2.0f)).height) + 16.0f;
}

UIView *ByeGroupedFooter(NSString *text, CGFloat width) {
    CGFloat height = ByeGroupedFooterHeight(text, width);
    UIView *footer = [[[UIView alloc] initWithFrame:CGRectMake(0.0f, 0.0f, width, height)] autorelease];
    footer.backgroundColor = [UIColor clearColor];
    if (!text.length) return footer;
    CGFloat inset = ByeGroupedTextInset();
    UILabel *label = ByeEmbossedLabel(12.0f, NO);
    label.numberOfLines = 0;
    label.textAlignment = NSTextAlignmentCenter;
    label.frame = CGRectMake(inset, 6.0f, MAX(0.0f, width - inset * 2.0f), height - 10.0f);
    label.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    label.text = text;
    [footer addSubview:label];
    return footer;
}

#pragma mark - switch

/* the flat switch is the size of the system one of ios 7 and later */
static CGFloat ByeSwitchWidthNow(void) { return ByeThemeModern() ? 51.0f : 79.0f; }
static CGFloat ByeSwitchHeightNow(void) { return ByeThemeModern() ? 31.0f : 27.0f; }
#define ByeSwitchWidth ByeSwitchWidthNow()
#define ByeSwitchHeight ByeSwitchHeightNow()

@interface ByeSwitch ()
- (UIView *)strip;
- (void)placeKnob:(CGFloat)position;
@end

@implementation ByeSwitch

@synthesize on = _on;

static UIImage *ByeSwitchStrip(void) {
    static UIImage *strip;
    static BOOL russian;
    static NSUInteger generation;
    if (strip && russian == ByeLanguageIsRussian() && generation == ByeThemeGeneration()) return strip;
    [strip release];
    russian = ByeLanguageIsRussian();
    generation = ByeThemeGeneration();
    CGFloat w = ByeSwitchWidth, h = ByeSwitchHeight, d = h, side = w - d * 0.5f;
    CGSize size = CGSizeMake(side * 2.0f, h);
    UIGraphicsBeginImageContextWithOptions(size, YES, 0.0f);
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    if (ByeThemeModern()) {
        /* the left half shows when the switch is on, the right one when it is off */
        ByeFillRule(CGRectMake(0.0f, 0.0f, side, h), ByeColorAccent());
        ByeFillRule(CGRectMake(side, 0.0f, side, h),
                    ByeThemeBoykisser() ? (ByeThemeIsLight() ? ByeRGB(0xd1b8c7, 1.0f) : ByeRGB(0x6e4f61, 1.0f))
                                        : (ByeThemeIsLight() ? ByeRGB(0xc9ccd6, 1.0f) : ByeRGB(0x3a3f4d, 1.0f)));
        strip = [UIGraphicsGetImageFromCurrentImageContext() retain];
        UIGraphicsEndImageContext();
        return strip;
    }
    const CGFloat blue[12] = { 0.16f, 0.45f, 0.90f, 1.0f,  0.25f, 0.56f, 0.97f, 1.0f,  0.42f, 0.70f, 1.0f, 1.0f };
    const CGFloat grey[12] = { 0.80f, 0.80f, 0.80f, 1.0f,  0.93f, 0.93f, 0.93f, 1.0f,  0.99f, 0.99f, 0.99f, 1.0f };
    CGContextSaveGState(ctx);
    CGContextClipToRect(ctx, CGRectMake(0.0f, 0.0f, side, h));
    ByeGradient(ctx, CGRectMake(0.0f, 0.0f, side, h), blue, NULL, 3);
    CGContextRestoreGState(ctx);
    CGContextSaveGState(ctx);
    CGContextClipToRect(ctx, CGRectMake(side, 0.0f, side, h));
    ByeGradient(ctx, CGRectMake(side, 0.0f, side, h), grey, NULL, 3);
    CGContextRestoreGState(ctx);
    /* russian ios 5 marks the halves with I and O instead of words */
    NSString *onText = russian ? @"I" : @"ON", *offText = russian ? @"O" : @"OFF";
    UIFont *font = ByeFont(16.0f, YES);
    CGFloat textY = floorf((float)(h - font.lineHeight) * 0.5f);
    CGFloat textWidth = w - d;
    CGContextSetShadowWithColor(ctx, CGSizeMake(0.0f, -1.0f), 0.0f, [UIColor colorWithWhite:0.0f alpha:0.4f].CGColor);
    [[UIColor whiteColor] set];
    [onText drawInRect:CGRectMake(0.0f, textY, textWidth, font.lineHeight) withFont:font
         lineBreakMode:NSLineBreakByClipping alignment:NSTextAlignmentCenter];
    CGContextSetShadowWithColor(ctx, CGSizeZero, 0.0f, NULL);
    [[UIColor colorWithWhite:0.45f alpha:1.0f] set];
    [offText drawInRect:CGRectMake(side * 2.0f - textWidth, textY, textWidth, font.lineHeight) withFont:font
          lineBreakMode:NSLineBreakByClipping alignment:NSTextAlignmentCenter];
    strip = [UIGraphicsGetImageFromCurrentImageContext() retain];
    UIGraphicsEndImageContext();
    return strip;
}

static UIImage *ByeSwitchKnob(void) {
    static UIImage *knob;
    static NSUInteger generation;
    if (knob && generation == ByeThemeGeneration()) return knob;
    [knob release];
    generation = ByeThemeGeneration();
    CGFloat d = ByeSwitchHeight;
    UIGraphicsBeginImageContextWithOptions(CGSizeMake(d, d), NO, 0.0f);
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    if (ByeThemeModern()) {
        CGRect disc = CGRectInset(CGRectMake(0.0f, 0.0f, d, d), 2.5f, 2.5f);
        CGContextSetShadowWithColor(ctx, CGSizeMake(0.0f, 1.0f), 2.0f, [UIColor colorWithWhite:0.0f alpha:0.35f].CGColor);
        [[UIColor whiteColor] setFill];
        CGContextFillEllipseInRect(ctx, disc);
        knob = [UIGraphicsGetImageFromCurrentImageContext() retain];
        UIGraphicsEndImageContext();
        return knob;
    }
    CGRect disc = CGRectMake(0.5f, 0.5f, d - 1.0f, d - 1.0f);
    CGContextSaveGState(ctx);
    CGContextAddEllipseInRect(ctx, disc);
    CGContextClip(ctx);
    const CGFloat colors[8] = { 0.99f, 0.99f, 0.99f, 1.0f,  0.80f, 0.80f, 0.81f, 1.0f };
    ByeGradient(ctx, disc, colors, NULL, 2);
    CGContextRestoreGState(ctx);
    [[UIColor colorWithWhite:0.0f alpha:0.45f] setStroke];
    CGContextSetLineWidth(ctx, 1.0f);
    CGContextStrokeEllipseInRect(ctx, disc);
    knob = [UIGraphicsGetImageFromCurrentImageContext() retain];
    UIGraphicsEndImageContext();
    return knob;
}

static UIImage *ByeSwitchFrame(void) {
    static UIImage *frame;
    if (frame) return frame;
    CGFloat w = ByeSwitchWidth, h = ByeSwitchHeight;
    UIGraphicsBeginImageContextWithOptions(CGSizeMake(w, h), NO, 0.0f);
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    CGRect body = CGRectMake(0.5f, 0.5f, w - 1.0f, h - 1.0f);
    UIBezierPath *shape = [UIBezierPath bezierPathWithRoundedRect:body cornerRadius:h * 0.5f];
    CGContextSaveGState(ctx);
    [shape addClip];
    UIBezierPath *shade = [UIBezierPath bezierPathWithRoundedRect:CGRectOffset(body, 0.0f, 1.5f) cornerRadius:h * 0.5f];
    shade.lineWidth = 2.0f;
    [[UIColor colorWithWhite:0.0f alpha:0.3f] setStroke];
    [shade stroke];
    CGContextRestoreGState(ctx);
    [[UIColor colorWithWhite:0.0f alpha:0.5f] setStroke];
    [shape stroke];
    frame = [UIGraphicsGetImageFromCurrentImageContext() retain];
    UIGraphicsEndImageContext();
    return frame;
}

- (id)initWithFrame:(CGRect)frame {
    frame.size = CGSizeMake(ByeSwitchWidth, ByeSwitchHeight);
    self = [super initWithFrame:frame];
    if (!self) return nil;
    self.backgroundColor = [UIColor clearColor];
    UIView *window = [[[UIView alloc] initWithFrame:self.bounds] autorelease];
    window.userInteractionEnabled = NO;
    window.layer.cornerRadius = ByeSwitchHeight * 0.5f;
    window.layer.masksToBounds = YES;
    window.tag = 1;
    UIImageView *strip = [[[UIImageView alloc] initWithImage:ByeSwitchStrip()] autorelease];
    strip.tag = 2;
    [window addSubview:strip];
    UIImageView *knob = [[[UIImageView alloc] initWithImage:ByeSwitchKnob()] autorelease];
    knob.tag = 3;
    [window addSubview:knob];
    [self addSubview:window];
    if (!ByeThemeModern()) {
        UIImageView *rim = [[[UIImageView alloc] initWithImage:ByeSwitchFrame()] autorelease];
        rim.userInteractionEnabled = NO;
        [self addSubview:rim];
    }
    [self placeKnob:0.0f];
    self.isAccessibilityElement = YES;
    return self;
}

- (UIView *)strip {
    return [[self viewWithTag:1] viewWithTag:2];
}

- (void)placeKnob:(CGFloat)position {
    CGFloat travel = ByeSwitchWidth - ByeSwitchHeight;
    position = MAX(0.0f, MIN(1.0f, position));
    _knob = position;
    UIView *strip = [self strip];
    CGRect frame = strip.frame;
    frame.origin.x = -(1.0f - position) * travel;
    strip.frame = frame;
    UIView *knob = [[self viewWithTag:1] viewWithTag:3];
    knob.frame = CGRectMake(position * travel, 0.0f, ByeSwitchHeight, ByeSwitchHeight);
}

- (void)setOn:(BOOL)on {
    [self setOn:on animated:NO];
}

- (void)setOn:(BOOL)on animated:(BOOL)animated {
    _on = on;
    if (!animated) {
        [self placeKnob:on ? 1.0f : 0.0f];
        return;
    }
    [UIView animateWithDuration:0.2 animations:^{ [self placeKnob:on ? 1.0f : 0.0f]; }];
}

- (CGSize)sizeThatFits:(CGSize)size {
    (void)size;
    return CGSizeMake(ByeSwitchWidth, ByeSwitchHeight);
}

- (BOOL)beginTrackingWithTouch:(UITouch *)touch withEvent:(UIEvent *)event {
    (void)event;
    _dragStart = [touch locationInView:self].x;
    _dragged = NO;
    return YES;
}

- (BOOL)continueTrackingWithTouch:(UITouch *)touch withEvent:(UIEvent *)event {
    (void)event;
    CGFloat x = [touch locationInView:self].x;
    CGFloat travel = ByeSwitchWidth - ByeSwitchHeight;
    if (!_dragged && fabsf((float)(x - _dragStart)) < 4.0f) return YES;
    _dragged = YES;
    [self placeKnob:(_on ? 1.0f : 0.0f) + (x - _dragStart) / travel];
    return YES;
}

- (void)endTrackingWithTouch:(UITouch *)touch withEvent:(UIEvent *)event {
    (void)touch;
    (void)event;
    BOOL next = _dragged ? _knob >= 0.5f : !_on;
    BOOL changed = next != _on;
    [self setOn:next animated:YES];
    if (changed) [self sendActionsForControlEvents:UIControlEventValueChanged];
}

- (void)cancelTrackingWithEvent:(UIEvent *)event {
    (void)event;
    [self setOn:_on animated:YES];
}

@end

#pragma mark - navigation

@implementation ByeNavigationController

- (void)chromeBackPressed {
    [self popViewControllerAnimated:YES];
}

- (void)pushViewController:(UIViewController *)controller animated:(BOOL)animated {
    UIViewController *top = self.topViewController;
    UINavigationItem *item = controller.navigationItem;
    if (top && !item.leftBarButtonItem && !item.hidesBackButton) {
        NSString *title = top.navigationItem.title.length ? top.navigationItem.title : top.title;
        /* a long title squeezes the new screen's own title, so ios 5 falls back to "back" */
        if (!title.length || title.length > 12) title = ByeL(@"Back");
        item.leftBarButtonItem = ByeBarItem(title, nil, YES, self, @selector(chromeBackPressed));
    }
    [super pushViewController:controller animated:animated];
}

@end

#pragma mark - glossy button

/* a flat button: one colour and rounded ends, darker while it is pressed */
static UIImage *ByeFlatButtonImage(ByeGlossKind kind, BOOL pressed) {
    static UIImage *images[6];
    static NSUInteger generation;
    if (generation != ByeThemeGeneration()) {
        for (int i = 0; i < 6; ++i) {
            [images[i] release];
            images[i] = nil;
        }
        generation = ByeThemeGeneration();
    }
    UIImage **slot = &images[(int)kind * 2 + (pressed ? 1 : 0)];
    if (*slot) return *slot;
    CGFloat radius = 12.0f, height = 44.0f;
    CGSize size = CGSizeMake(radius * 2.0f + 1.0f, height);
    UIGraphicsBeginImageContextWithOptions(size, NO, 0.0f);
    UIColor *fill = kind == ByeGlossBlue ? ByeColorAccent()
                  : kind == ByeGlossRed ? ByeRGB(0xd32f2f, 1.0f) : ByeColorSurfacePressed();
    [fill setFill];
    [[UIBezierPath bezierPathWithRoundedRect:CGRectMake(0.0f, 0.0f, size.width, size.height) cornerRadius:radius] fill];
    if (pressed) {
        [[UIColor colorWithWhite:0.0f alpha:0.25f] setFill];
        [[UIBezierPath bezierPathWithRoundedRect:CGRectMake(0.0f, 0.0f, size.width, size.height) cornerRadius:radius] fill];
    }
    UIImage *image = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    *slot = [[image resizableImageWithCapInsets:UIEdgeInsetsMake(0.0f, radius, 0.0f, radius)] retain];
    return *slot;
}

static UIImage *ByeGlossImage(ByeGlossKind kind, BOOL pressed) {
    if (ByeThemeModern()) return ByeFlatButtonImage(kind, pressed);
    static UIImage *images[6];
    UIImage **slot = &images[(int)kind * 2 + (pressed ? 1 : 0)];
    if (*slot) return *slot;
    CGFloat radius = 15.0f, height = 44.0f;
    CGSize size = CGSizeMake(radius * 2.0f + 1.0f, height);
    UIGraphicsBeginImageContextWithOptions(size, NO, 0.0f);
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    CGRect body = CGRectMake(0.5f, 0.5f, size.width - 1.0f, height - 2.0f);
    [[UIColor colorWithWhite:1.0f alpha:0.18f] setStroke];
    [[UIBezierPath bezierPathWithRoundedRect:CGRectOffset(body, 0.0f, 1.0f) cornerRadius:radius] stroke];
    UIBezierPath *shape = [UIBezierPath bezierPathWithRoundedRect:body cornerRadius:radius];
    CGContextSaveGState(ctx);
    [shape addClip];
    CGFloat dim = pressed ? 0.66f : 1.0f;
    CGFloat c[16];
    static const CGFloat palette[3][16] = {
        { 0.50f, 0.72f, 1.00f, 1.0f,  0.18f, 0.45f, 0.90f, 1.0f,  0.08f, 0.33f, 0.80f, 1.0f,  0.10f, 0.40f, 0.88f, 1.0f },
        { 0.62f, 0.66f, 0.72f, 1.0f,  0.38f, 0.42f, 0.50f, 1.0f,  0.27f, 0.31f, 0.39f, 1.0f,  0.31f, 0.35f, 0.43f, 1.0f },
        { 0.98f, 0.52f, 0.46f, 1.0f,  0.82f, 0.20f, 0.16f, 1.0f,  0.66f, 0.10f, 0.08f, 1.0f,  0.74f, 0.16f, 0.12f, 1.0f }
    };
    for (int i = 0; i < 16; ++i) c[i] = (i % 4 == 3) ? 1.0f : palette[(int)kind][i] * dim;
    const CGFloat stops[4] = { 0.0f, 0.5f, 0.5f, 1.0f };
    ByeGradient(ctx, body, c, stops, 4);
    CGContextRestoreGState(ctx);
    [[UIColor colorWithWhite:0.0f alpha:0.6f] setStroke];
    shape.lineWidth = 1.0f;
    [shape stroke];
    UIImage *image = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    *slot = [[image resizableImageWithCapInsets:UIEdgeInsetsMake(0.0f, radius, 0.0f, radius)] retain];
    return *slot;
}

@implementation ByeGlossButton

- (id)initWithTitle:(NSString *)title kind:(ByeGlossKind)kind {
    self = [super initWithFrame:CGRectMake(0.0f, 0.0f, 200.0f, 44.0f)];
    if (!self) return nil;
    self.adjustsImageWhenHighlighted = NO;
    self.titleLabel.font = ByeFont(16.0f, YES);
    self.titleLabel.shadowOffset = ByeThemeModern() ? CGSizeZero : CGSizeMake(0.0f, -1.0f);
    self.titleLabel.lineBreakMode = NSLineBreakByClipping;
    self.titleLabel.adjustsFontSizeToFitWidth = YES;
    [self setTitle:title forState:UIControlStateNormal];
    [self setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [self setTitleShadowColor:ByeThemeModern() ? [UIColor clearColor] : [UIColor colorWithWhite:0.0f alpha:0.55f]
                     forState:UIControlStateNormal];
    [self setTitleColor:[UIColor colorWithWhite:1.0f alpha:0.45f] forState:UIControlStateDisabled];
    [self setBackgroundImage:ByeGlossImage(ByeGlossGrey, NO) forState:UIControlStateDisabled];
    [self setKind:kind];
    return self;
}

- (void)setKind:(ByeGlossKind)kind {
    _kind = kind;
    /* a grey button of the light theme is pale, so its words are dark */
    [self setTitleColor:(ByeThemeModern() && kind == ByeGlossGrey) ? ByeColorText() : [UIColor whiteColor]
               forState:UIControlStateNormal];
    [self setBackgroundImage:ByeGlossImage(kind, NO) forState:UIControlStateNormal];
    [self setBackgroundImage:ByeGlossImage(kind, YES) forState:UIControlStateHighlighted];
}

@end

#pragma mark - power button

@implementation ByePowerButton

@synthesize powerState = _powerState;

- (id)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (!self) return nil;
    self.opaque = NO;
    self.backgroundColor = [UIColor clearColor];
    self.contentMode = UIViewContentModeRedraw;
    return self;
}

- (void)setPowerState:(ByePowerState)state {
    if (state == _powerState) return;
    _powerState = state;
    [self setNeedsDisplay];
}

- (void)setHighlighted:(BOOL)highlighted {
    if (highlighted == self.highlighted) return;
    [super setHighlighted:highlighted];
    [self setNeedsDisplay];
}

- (void)setEnabled:(BOOL)enabled {
    [super setEnabled:enabled];
    [self setNeedsDisplay];
}

- (void)drawRect:(CGRect)dirty {
    (void)dirty;
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    CGRect b = self.bounds;
    CGFloat d = MIN(b.size.width, b.size.height) - 8.0f;
    if (d < 40.0f) return;
    CGRect sq = CGRectMake(floorf((float)(CGRectGetMidX(b) - d * 0.5f)), floorf((float)(CGRectGetMidY(b) - d * 0.5f)), d, d);
    BOOL pressed = self.highlighted;

    if (ByeThemeModern()) {
        /* a flat disc in the colour of the state, with a soft shadow under it */
        static const unsigned states[4] = { 0, 0xffa726, 0x4caf50, 0xe53935 };
        UIColor *fill = _powerState == ByePowerOff ? ByeColorAccent() : ByeRGB(states[_powerState], 1.0f);
        if (ByeThemeBoykisser()) {
            /* pink means connected, as in senko, so the idle disc is grey and only a failure stays red */
            if (_powerState == ByePowerOff) fill = ByeRGB(ByeThemeIsLight() ? 0xd1b8c7 : 0x6e4f61, 1.0f);
            else if (_powerState == ByePowerBusy) fill = ByeRGB(0xff9acb, 1.0f);
            else if (_powerState == ByePowerOn) fill = ByeColorAccent();
        }
        CGRect disc = CGRectInset(sq, d * 0.04f, d * 0.04f);
        if (pressed) disc = CGRectInset(disc, d * 0.012f, d * 0.012f);
        CGContextSaveGState(ctx);
        CGContextSetShadowWithColor(ctx, CGSizeMake(0.0f, 3.0f), 8.0f,
                                    [UIColor colorWithWhite:0.0f alpha:ByeThemeIsLight() ? 0.28f : 0.6f].CGColor);
        [fill setFill];
        CGContextFillEllipseInRect(ctx, disc);
        CGContextRestoreGState(ctx);
        if (pressed) {
            [[UIColor colorWithWhite:0.0f alpha:0.2f] setFill];
            CGContextFillEllipseInRect(ctx, disc);
        }
        CGFloat glyphSize = floorf((float)(disc.size.width * 0.38f));
        UIImage *glyph = ByeIcon(@"power", glyphSize, [UIColor whiteColor]);
        CGContextSetAlpha(ctx, self.enabled ? 1.0f : 0.5f);
        [glyph drawInRect:CGRectMake(CGRectGetMidX(disc) - glyphSize * 0.5f, CGRectGetMidY(disc) - glyphSize * 0.5f,
                                     glyphSize, glyphSize)];
        return;
    }

    CGContextSaveGState(ctx);
    CGContextSetShadowWithColor(ctx, CGSizeMake(0.0f, 4.0f), 10.0f, [UIColor colorWithWhite:0.0f alpha:0.75f].CGColor);
    [[UIColor blackColor] setFill];
    CGContextFillEllipseInRect(ctx, CGRectInset(sq, d * 0.02f, d * 0.02f));
    CGContextRestoreGState(ctx);

    CGRect bezel = CGRectInset(sq, d * 0.02f, d * 0.02f);
    CGContextSaveGState(ctx);
    CGContextAddEllipseInRect(ctx, bezel);
    CGContextClip(ctx);
    const CGFloat metal[20] = { 0.97f, 0.98f, 1.0f, 1.0f,  0.70f, 0.74f, 0.80f, 1.0f,  0.34f, 0.38f, 0.45f, 1.0f,
                                0.58f, 0.63f, 0.71f, 1.0f,  0.88f, 0.91f, 0.96f, 1.0f };
    const CGFloat metalStops[5] = { 0.0f, 0.28f, 0.55f, 0.82f, 1.0f };
    ByeGradient(ctx, bezel, metal, metalStops, 5);
    CGContextRestoreGState(ctx);
    [[UIColor colorWithWhite:0.0f alpha:0.7f] setStroke];
    CGContextSetLineWidth(ctx, 1.0f);
    CGContextStrokeEllipseInRect(ctx, CGRectInset(bezel, 0.5f, 0.5f));

    CGRect well = CGRectInset(sq, d * 0.085f, d * 0.085f);
    CGContextSaveGState(ctx);
    CGContextAddEllipseInRect(ctx, well);
    CGContextClip(ctx);
    const CGFloat wellColors[8] = { 0.01f, 0.03f, 0.06f, 1.0f,  0.10f, 0.15f, 0.23f, 1.0f };
    ByeGradient(ctx, well, wellColors, NULL, 2);
    CGContextRestoreGState(ctx);
    [[UIColor colorWithWhite:1.0f alpha:0.25f] setStroke];
    CGContextStrokeEllipseInRect(ctx, CGRectInset(well, 0.5f, 0.5f));

    CGRect cap = CGRectInset(sq, d * 0.125f, d * 0.125f);
    if (pressed) cap = CGRectOffset(cap, 0.0f, 1.5f);
    CGFloat dim = pressed ? 0.72f : 1.0f;
    if (!self.enabled) dim *= 0.6f;
    static const CGFloat glass[4][16] = {
        { 0.52f, 0.76f, 1.00f, 1.0f,  0.20f, 0.50f, 0.95f, 1.0f,  0.08f, 0.34f, 0.82f, 1.0f,  0.12f, 0.45f, 0.92f, 1.0f },
        { 1.00f, 0.88f, 0.52f, 1.0f,  0.96f, 0.68f, 0.18f, 1.0f,  0.82f, 0.48f, 0.05f, 1.0f,  0.90f, 0.58f, 0.10f, 1.0f },
        { 0.58f, 0.92f, 0.62f, 1.0f,  0.22f, 0.72f, 0.32f, 1.0f,  0.08f, 0.52f, 0.20f, 1.0f,  0.14f, 0.64f, 0.28f, 1.0f },
        { 1.00f, 0.56f, 0.50f, 1.0f,  0.88f, 0.22f, 0.18f, 1.0f,  0.70f, 0.10f, 0.08f, 1.0f,  0.80f, 0.16f, 0.13f, 1.0f }
    };
    CGFloat c[16];
    for (int i = 0; i < 16; ++i) c[i] = (i % 4 == 3) ? 1.0f : glass[_powerState][i] * dim;
    CGContextSaveGState(ctx);
    CGContextAddEllipseInRect(ctx, cap);
    CGContextClip(ctx);
    ByeGradient(ctx, cap, c, NULL, 4);
    CGRect glow = CGRectMake(cap.origin.x + cap.size.width * 0.12f, cap.origin.y + cap.size.height * 0.62f,
                             cap.size.width * 0.76f, cap.size.height * 0.5f);
    CGContextSaveGState(ctx);
    CGContextAddEllipseInRect(ctx, glow);
    CGContextClip(ctx);
    const CGFloat lower[8] = { 1.0f, 1.0f, 1.0f, 0.0f,  1.0f, 1.0f, 1.0f, 0.28f };
    ByeGradient(ctx, glow, lower, NULL, 2);
    CGContextRestoreGState(ctx);
    CGRect sheet = CGRectMake(cap.origin.x + cap.size.width * 0.07f, cap.origin.y + cap.size.height * 0.035f,
                              cap.size.width * 0.86f, cap.size.height * 0.52f);
    CGContextSaveGState(ctx);
    CGContextAddEllipseInRect(ctx, sheet);
    CGContextClip(ctx);
    const CGFloat gloss[8] = { 1.0f, 1.0f, 1.0f, pressed ? 0.45f : 0.72f,  1.0f, 1.0f, 1.0f, 0.06f };
    ByeGradient(ctx, sheet, gloss, NULL, 2);
    CGContextRestoreGState(ctx);
    CGContextRestoreGState(ctx);
    [[UIColor colorWithWhite:0.0f alpha:0.55f] setStroke];
    CGContextStrokeEllipseInRect(ctx, CGRectInset(cap, 0.5f, 0.5f));

    CGFloat glyphSize = floorf((float)(cap.size.width * 0.44f));
    UIImage *glyph = ByeIcon(@"power", glyphSize, [UIColor whiteColor]);
    CGRect glyphRect = CGRectMake(CGRectGetMidX(cap) - glyphSize * 0.5f, CGRectGetMidY(cap) - glyphSize * 0.5f + 1.0f,
                                  glyphSize, glyphSize);
    CGContextSaveGState(ctx);
    CGContextSetShadowWithColor(ctx, CGSizeMake(0.0f, -1.0f), 1.0f, [UIColor colorWithWhite:0.0f alpha:0.55f].CGColor);
    CGContextSetAlpha(ctx, self.enabled ? 1.0f : 0.5f);
    [glyph drawInRect:glyphRect];
    CGContextRestoreGState(ctx);
}

@end

#pragma mark - tile

@implementation ByeTileButton

- (id)initWithTitle:(NSString *)title glyph:(NSString *)glyph {
    self = [super initWithFrame:CGRectMake(0.0f, 0.0f, 140.0f, 100.0f)];
    if (!self) return nil;
    _title = [title copy];
    _glyph = [glyph copy];
    self.opaque = NO;
    self.backgroundColor = [UIColor clearColor];
    self.contentMode = UIViewContentModeRedraw;
    self.accessibilityLabel = title;
    return self;
}

- (void)dealloc {
    [_title release];
    [_glyph release];
    [super dealloc];
}

- (void)setTitle:(NSString *)title {
    if ([title isEqualToString:_title]) return;
    [_title release];
    _title = [title copy];
    self.accessibilityLabel = title;
    [self setNeedsDisplay];
}

- (CGFloat)fitSizeForTileWidth:(CGFloat)width {
    CGFloat room = width - 4.0f - 8.0f - 2.0f;
    for (CGFloat size = 15.0f; size > 9.0f; size -= 0.5f) {
        UIFont *font = ByeFont(size, NO);
        if (ByeTextSize(_title, font, 4000.0f).width <= room) return size;
    }
    return 9.0f;
}

- (void)setTitleSize:(CGFloat)size {
    if (size == _titleSize) return;
    _titleSize = size;
    [self setNeedsDisplay];
}

- (void)setHighlighted:(BOOL)highlighted {
    if (highlighted == self.highlighted) return;
    [super setHighlighted:highlighted];
    [self setNeedsDisplay];
}

- (void)drawRect:(CGRect)dirty {
    (void)dirty;
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    CGRect b = CGRectInset(self.bounds, 2.0f, 2.0f);
    BOOL pressed = self.highlighted;
    CGFloat radius = 16.0f;

    if (ByeThemeModern()) {
        /* a card with the accent glyph over the title, like the tiles of the android app */
        [(pressed ? ByeColorSurfacePressed() : ByeColorSurface()) setFill];
        [[UIBezierPath bezierPathWithRoundedRect:b cornerRadius:radius] fill];
        CGFloat flatGlyph = MIN(40.0f, floorf((float)(b.size.height * 0.36f)));
        UIImage *flat = ByeIcon(_glyph, flatGlyph, ByeColorAccent());
        [flat drawInRect:CGRectMake(CGRectGetMidX(b) - flatGlyph * 0.5f, b.origin.y + b.size.height * 0.17f,
                                    flatGlyph, flatGlyph)];
        CGRect box = CGRectMake(b.origin.x + 4.0f, b.origin.y + b.size.height - 32.0f, b.size.width - 8.0f, 22.0f);
        UIFont *face = _titleSize > 0.0f ? ByeFont(_titleSize, NO) : ByeFitFont(_title, 15.0f, 9.0f, NO, box.size.width - 2.0f, 1);
        [ByeColorText() set];
        [_title drawInRect:box withFont:face lineBreakMode:NSLineBreakByTruncatingTail alignment:NSTextAlignmentCenter];
        return;
    }

    CGContextSaveGState(ctx);
    CGContextSetShadowWithColor(ctx, CGSizeMake(0.0f, 2.0f), 5.0f, [UIColor colorWithWhite:0.0f alpha:0.7f].CGColor);
    [[UIColor blackColor] setFill];
    [[UIBezierPath bezierPathWithRoundedRect:b cornerRadius:radius] fill];
    CGContextRestoreGState(ctx);

    UIBezierPath *shape = [UIBezierPath bezierPathWithRoundedRect:b cornerRadius:radius];
    CGContextSaveGState(ctx);
    [shape addClip];
    CGFloat dim = pressed ? 0.7f : 1.0f;
    const CGFloat colors[16] = { 0.40f * dim, 0.53f * dim, 0.72f * dim, 1.0f,  0.20f * dim, 0.32f * dim, 0.52f * dim, 1.0f,
                                 0.11f * dim, 0.21f * dim, 0.40f * dim, 1.0f,  0.08f * dim, 0.16f * dim, 0.32f * dim, 1.0f };
    const CGFloat stops[4] = { 0.0f, 0.5f, 0.5f, 1.0f };
    ByeGradient(ctx, b, colors, stops, 4);
    [[UIColor colorWithWhite:1.0f alpha:pressed ? 0.12f : 0.45f] setFill];
    UIRectFill(CGRectMake(b.origin.x, b.origin.y, b.size.width, 1.0f));
    CGContextRestoreGState(ctx);
    [[UIColor colorWithRed:0.01f green:0.05f blue:0.12f alpha:0.9f] setStroke];
    shape.lineWidth = 1.0f;
    [shape stroke];

    CGFloat glyphSize = MIN(44.0f, floorf((float)(b.size.height * 0.40f)));
    UIImage *glyph = ByeIcon(_glyph, glyphSize, [UIColor whiteColor]);
    CGFloat top = b.origin.y + b.size.height * 0.16f + (pressed ? 1.0f : 0.0f);
    CGContextSaveGState(ctx);
    CGContextSetShadowWithColor(ctx, CGSizeMake(0.0f, -1.0f), 1.0f, [UIColor colorWithWhite:0.0f alpha:0.55f].CGColor);
    [glyph drawInRect:CGRectMake(CGRectGetMidX(b) - glyphSize * 0.5f, top, glyphSize, glyphSize)];
    CGContextRestoreGState(ctx);

    /* use the drawing width when fitting the font so the title is not clipped */
    CGRect titleBox = CGRectMake(b.origin.x + 2.0f, b.origin.y + b.size.height - 28.0f + (pressed ? 1.0f : 0.0f),
                                 b.size.width - 4.0f, 20.0f);
    UIFont *font = ByeFitFont(_title, 12.0f, 7.5f, YES, titleBox.size.width - 2.0f, 1);
    CGContextSetShadowWithColor(ctx, CGSizeMake(0.0f, -1.0f), 0.0f, [UIColor colorWithWhite:0.0f alpha:0.6f].CGColor);
    [[UIColor whiteColor] set];
    [_title drawInRect:titleBox withFont:font lineBreakMode:NSLineBreakByTruncatingTail alignment:NSTextAlignmentCenter];
}

@end

#pragma mark - chip

@implementation ByeChip

@synthesize text = _text;

- (id)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (!self) return nil;
    self.opaque = NO;
    self.backgroundColor = [UIColor clearColor];
    self.contentMode = UIViewContentModeRedraw;
    return self;
}

- (void)dealloc {
    [_text release];
    [super dealloc];
}

- (void)setText:(NSString *)text {
    if ((text == _text) || [text isEqualToString:_text]) return;
    [_text release];
    _text = [text copy];
    [self setNeedsDisplay];
}

- (void)drawRect:(CGRect)dirty {
    (void)dirty;
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    CGRect b = CGRectInset(self.bounds, 0.5f, 0.5f);
    CGFloat radius = b.size.height * 0.5f;
    if (ByeThemeModern()) {
        [ByeColorSurface() setFill];
        [[UIBezierPath bezierPathWithRoundedRect:b cornerRadius:radius] fill];
        if (!_text.length) return;
        UIFont *mono = [UIFont fontWithName:@"Courier" size:ByeIsPad() ? 14.0f : 12.0f];
        if (!mono) mono = ByeFont(12.0f, NO);
        [ByeColorText() set];
        CGFloat line = floorf((float)(CGRectGetMidY(b) - mono.lineHeight * 0.5f));
        [_text drawInRect:CGRectMake(b.origin.x + radius, line, b.size.width - radius * 2.0f, mono.lineHeight)
                 withFont:mono lineBreakMode:NSLineBreakByTruncatingTail alignment:NSTextAlignmentCenter];
        return;
    }
    UIBezierPath *shape = [UIBezierPath bezierPathWithRoundedRect:b cornerRadius:radius];
    [[UIColor colorWithWhite:1.0f alpha:0.16f] setStroke];
    [[UIBezierPath bezierPathWithRoundedRect:CGRectOffset(b, 0.0f, 1.0f) cornerRadius:radius] stroke];
    CGContextSaveGState(ctx);
    [shape addClip];
    const CGFloat colors[8] = { 0.03f, 0.07f, 0.13f, 1.0f,  0.09f, 0.15f, 0.25f, 1.0f };
    ByeGradient(ctx, b, colors, NULL, 2);
    UIBezierPath *shade = [UIBezierPath bezierPathWithRoundedRect:CGRectOffset(b, 0.0f, 1.5f) cornerRadius:radius];
    shade.lineWidth = 2.0f;
    [[UIColor colorWithWhite:0.0f alpha:0.45f] setStroke];
    [shade stroke];
    CGContextRestoreGState(ctx);
    [[UIColor colorWithWhite:0.0f alpha:0.7f] setStroke];
    [shape stroke];
    if (!_text.length) return;
    UIFont *font = [UIFont fontWithName:@"Courier" size:ByeIsPad() ? 14.0f : 12.0f];
    if (!font) font = ByeFont(12.0f, NO);
    [ByeRGB(0xb9d3f5, 1.0f) set];
    CGFloat y = floorf((float)(CGRectGetMidY(b) - font.lineHeight * 0.5f));
    [_text drawInRect:CGRectMake(b.origin.x + radius, y, b.size.width - radius * 2.0f, font.lineHeight)
             withFont:font lineBreakMode:NSLineBreakByTruncatingTail alignment:NSTextAlignmentCenter];
}

@end

#pragma mark - progress bar

@implementation ByeProgressBar

@synthesize progress = _progress;

- (id)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (!self) return nil;
    self.opaque = NO;
    self.backgroundColor = [UIColor clearColor];
    self.contentMode = UIViewContentModeRedraw;
    return self;
}

- (void)setProgress:(CGFloat)progress {
    progress = MAX(0.0f, MIN(1.0f, progress));
    if (fabsf((float)(progress - _progress)) < 0.001f) return;
    _progress = progress;
    [self setNeedsDisplay];
}

- (void)drawRect:(CGRect)dirty {
    (void)dirty;
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    CGRect b = CGRectInset(self.bounds, 0.5f, 0.5f);
    CGFloat radius = b.size.height * 0.5f;
    if (ByeThemeModern()) {
        [ByeColorSurfacePressed() setFill];
        [[UIBezierPath bezierPathWithRoundedRect:b cornerRadius:radius] fill];
        if (_progress > 0.0f) {
            CGRect fill = CGRectMake(b.origin.x, b.origin.y, MAX(b.size.height, b.size.width * _progress), b.size.height);
            [ByeColorAccent() setFill];
            [[UIBezierPath bezierPathWithRoundedRect:fill cornerRadius:radius] fill];
        }
        return;
    }
    UIBezierPath *track = [UIBezierPath bezierPathWithRoundedRect:b cornerRadius:radius];
    CGContextSaveGState(ctx);
    [track addClip];
    const CGFloat well[8] = { 0.02f, 0.05f, 0.10f, 1.0f,  0.10f, 0.16f, 0.26f, 1.0f };
    ByeGradient(ctx, b, well, NULL, 2);
    if (_progress > 0.0f) {
        CGRect fill = CGRectMake(b.origin.x, b.origin.y, MAX(b.size.height, b.size.width * _progress), b.size.height);
        UIBezierPath *bar = [UIBezierPath bezierPathWithRoundedRect:fill cornerRadius:radius];
        CGContextSaveGState(ctx);
        [bar addClip];
        const CGFloat blue[16] = { 0.55f, 0.78f, 1.00f, 1.0f,  0.22f, 0.52f, 0.95f, 1.0f,
                                   0.10f, 0.38f, 0.85f, 1.0f,  0.14f, 0.46f, 0.92f, 1.0f };
        const CGFloat stops[4] = { 0.0f, 0.5f, 0.5f, 1.0f };
        ByeGradient(ctx, fill, blue, stops, 4);
        CGContextRestoreGState(ctx);
    }
    CGContextRestoreGState(ctx);
    [[UIColor colorWithWhite:0.0f alpha:0.7f] setStroke];
    [track stroke];
}

@end

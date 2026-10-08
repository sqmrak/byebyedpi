#import "about_vc.h"

/* ios 5 needs the text drawing methods and title attribute names deprecated in ios 7 */
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import <QuartzCore/QuartzCore.h>
#include <sys/sysctl.h>

#import "bye_chrome.h"
#import "bye_daemon.h"
#import "bye_l10n.h"
#import "bye_theme.h"

static NSString * const ByeAboutThanks =
    @"@fly1ngangel, @inraxx, @anazerka, @Lineysom, @menstry, @CookieValerka, "
    @"@not_a_modder, @s3dativee, @Vladus324, @shizotoaster";

static NSString *ByeAboutModel(void) {
    char machine[64];
    size_t len = sizeof machine;
    if (sysctlbyname("hw.machine", machine, &len, NULL, 0) != 0 || len == 0 || len > sizeof machine)
        return [[UIDevice currentDevice] model];
    machine[sizeof machine - 1] = '\0';
    NSString *code = [NSString stringWithUTF8String:machine];
    return code.length ? code : [[UIDevice currentDevice] model];
}

static NSString *ByeAboutSlice(void) {
#if defined(__arm64__) || defined(__aarch64__)
    return @"arm64";
#else
    return @"armv7";
#endif
}

static NSString *ByeAboutVersion(void) {
    NSString *version = [[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleShortVersionString"];
    return version ? version : @"?";
}

@interface ByeAboutPlate : UIView {
@public
    NSString *caption;
    NSString *value;
}
@end

@implementation ByeAboutPlate

- (id)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (!self) return nil;
    self.opaque = NO;
    self.backgroundColor = [UIColor clearColor];
    self.contentMode = UIViewContentModeRedraw;
    return self;
}

- (void)dealloc {
    [caption release];
    [value release];
    [super dealloc];
}

- (void)drawRect:(CGRect)dirty {
    (void)dirty;
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    CGRect b = CGRectInset(self.bounds, 0.5f, 0.5f);
    UIBezierPath *shape = [UIBezierPath bezierPathWithRoundedRect:b cornerRadius:10.0f];
    [[UIColor colorWithWhite:1.0f alpha:0.14f] setStroke];
    [[UIBezierPath bezierPathWithRoundedRect:CGRectOffset(b, 0.0f, 1.0f) cornerRadius:10.0f] stroke];
    CGContextSaveGState(ctx);
    [shape addClip];
    const CGFloat colors[8] = { 0.18f, 0.24f, 0.33f, 1.0f,  0.12f, 0.17f, 0.25f, 1.0f };
    ByeGradient(ctx, b, colors, NULL, 2);
    [[UIColor colorWithWhite:1.0f alpha:0.12f] setFill];
    UIRectFill(CGRectMake(b.origin.x, b.origin.y, b.size.width, 1.0f));
    CGContextRestoreGState(ctx);
    [[UIColor colorWithRed:0.30f green:0.39f blue:0.52f alpha:1.0f] setStroke];
    [shape stroke];
    [ByeGroupedCaptionColor() set];
    [caption drawInRect:CGRectMake(8.0f, 9.0f, b.size.width - 16.0f, 16.0f) withFont:ByeFont(12.0f, NO)
          lineBreakMode:NSLineBreakByClipping alignment:NSTextAlignmentCenter];
    [[UIColor whiteColor] set];
    [value drawInRect:CGRectMake(8.0f, 28.0f, b.size.width - 16.0f, 24.0f) withFont:ByeFont(17.0f, YES)
        lineBreakMode:NSLineBreakByClipping alignment:NSTextAlignmentCenter];
}

@end

@interface ByeAboutHero : UIView {
    UIImageView *icon;
    UILabel *name;
    UILabel *tagline;
    ByeAboutPlate *versionPlate;
    ByeAboutPlate *systemPlate;
}
- (void)applyLanguage;
@end

enum { ByeAboutHeroHeight = 282 };

static UILabel *ByeHeroLabel(UIView *host, UIFont *font, UIColor *color) {
    UILabel *label = [[[UILabel alloc] initWithFrame:CGRectZero] autorelease];
    label.backgroundColor = [UIColor clearColor];
    label.font = font;
    label.textColor = color;
    label.textAlignment = NSTextAlignmentCenter;
    label.lineBreakMode = NSLineBreakByClipping;
    label.adjustsFontSizeToFitWidth = YES;
    label.shadowColor = [UIColor blackColor];
    label.shadowOffset = CGSizeMake(0.0f, -1.0f);
    [host addSubview:label];
    return label;
}

@implementation ByeAboutHero

- (id)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (!self) return nil;
    self.backgroundColor = [UIColor clearColor];
    NSString *path = [[NSBundle mainBundle] pathForResource:@"ByeIcon-60@3x" ofType:@"png"];
    icon = [[UIImageView alloc] initWithImage:path ? [UIImage imageWithContentsOfFile:path] : nil];
    icon.contentMode = UIViewContentModeScaleAspectFill;
    icon.layer.masksToBounds = YES;
    icon.layer.cornerRadius = 16.0f;
    /* a separate view keeps the shadow outside the clipped icon */
    UIView *shadow = [[[UIView alloc] initWithFrame:CGRectZero] autorelease];
    shadow.tag = 7;
    shadow.backgroundColor = ByeRGB(0x0e1b2d, 1.0f);
    shadow.layer.cornerRadius = 16.0f;
    shadow.layer.shadowColor = [UIColor blackColor].CGColor;
    shadow.layer.shadowOpacity = 0.7f;
    shadow.layer.shadowRadius = 6.0f;
    shadow.layer.shadowOffset = CGSizeMake(0.0f, 3.0f);
    [self addSubview:shadow];
    [self addSubview:icon];
    name = [ByeHeroLabel(self, ByeFont(30.0f, YES), [UIColor whiteColor]) retain];
    name.text = @"ByeByeDPI";
    tagline = [ByeHeroLabel(self, ByeFont(14.0f, NO), ByeGroupedCaptionColor()) retain];
    versionPlate = [[ByeAboutPlate alloc] initWithFrame:CGRectZero];
    systemPlate = [[ByeAboutPlate alloc] initWithFrame:CGRectZero];
    [self addSubview:versionPlate];
    [self addSubview:systemPlate];
    versionPlate->value = [ByeAboutVersion() copy];
    systemPlate->caption = [@"iOS" copy];
    systemPlate->value = [[NSString stringWithFormat:@"%@ · %@", [[UIDevice currentDevice] systemVersion], ByeAboutSlice()] copy];
    [self applyLanguage];
    return self;
}

- (void)dealloc {
    [icon release];
    [name release];
    [tagline release];
    [versionPlate release];
    [systemPlate release];
    [super dealloc];
}

- (void)applyLanguage {
    tagline.text = ByeL(@"DPI bypass and Telegram gateway");
    [versionPlate->caption release];
    versionPlate->caption = [ByeL(@"Version") copy];
    [versionPlate setNeedsDisplay];
    [systemPlate setNeedsDisplay];
}

- (void)layoutSubviews {
    [super layoutSubviews];
    CGFloat w = self.bounds.size.width;
    CGFloat side = ByeGroupedSideInset();
    icon.frame = CGRectMake(floorf((float)(w - 88.0f) * 0.5f), 22.0f, 88.0f, 88.0f);
    [self viewWithTag:7].frame = icon.frame;
    name.frame = CGRectMake(side, 120.0f, w - side * 2.0f, 36.0f);
    tagline.frame = CGRectMake(side, 166.0f, w - side * 2.0f, 18.0f);
    CGFloat gap = 10.0f;
    CGFloat inner = MIN(w - side * 2.0f, 560.0f);
    CGFloat plateWidth = floorf((float)(inner - gap) * 0.5f);
    CGFloat left = floorf((float)(w - inner) * 0.5f);
    versionPlate.frame = CGRectMake(left, 204.0f, plateWidth, 62.0f);
    systemPlate.frame = CGRectMake(left + plateWidth + gap, 204.0f, plateWidth, 62.0f);
}

@end

@implementation AboutVC {
    ByeAboutHero *_hero;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = ByeL(@"About");
    _hero = [[ByeAboutHero alloc] initWithFrame:CGRectMake(0.0f, 0.0f, self.view.bounds.size.width, ByeAboutHeroHeight)];
    self.table.tableHeaderView = _hero;
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(languageChanged:)
                                                 name:ByeLanguageDidChangeNotification object:nil];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [_hero release];
    [super dealloc];
}

- (void)languageChanged:(NSNotification *)note {
    (void)note;
    self.title = ByeL(@"About");
    [_hero applyLanguage];
    [self reloadForm];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    CGFloat width = self.table.bounds.size.width;
    /* a table reads its header's height again only when the header is set again */
    if (fabsf((float)(_hero.frame.size.width - width)) > 0.5f) {
        _hero.frame = CGRectMake(0.0f, 0.0f, width, ByeAboutHeroHeight);
        self.table.tableHeaderView = _hero;
    }
}

static ByeRow *ByeAboutRow(NSString *title, NSString *detail, NSString *glyph, NSString *ident) {
    ByeRow *row = [ByeRow rowWithKind:ByeRowStacked title:title detail:detail ident:ident];
    row.glyph = glyph;
    if (ident) {
        row.selectable = YES;
        row.accessory = ByeAccessoryDisclosure;
    }
    return row;
}

- (NSArray *)buildSections {
    NSString *state = [ByeDaemon shared].state == ByeDaemonRunning ? ByeL(@"Connected")
                    : [ByeDaemon shared].state == ByeDaemonStopped ? ByeL(@"Disconnected") : ByeL(@"Daemon unavailable");
    ByeSection *device = [ByeSection sectionWithTitle:ByeL(@"Device") footer:nil rows:[NSArray arrayWithObjects:
        ByeAboutRow(ByeL(@"Model"), ByeAboutModel(), @"info", nil),
        ByeAboutRow(ByeL(@"iOS version"), [[UIDevice currentDevice] systemVersion], @"settings", nil),
        ByeAboutRow(ByeL(@"Architecture"), ByeAboutSlice(), @"hash", nil),
        ByeAboutRow(ByeL(@"Tunnel"), state, @"shield", nil),
        nil]];

    ByeSection *app = [ByeSection sectionWithTitle:@"ByeByeDPI" footer:nil rows:[NSArray arrayWithObjects:
        ByeAboutRow(ByeL(@"How it works"),
                    ByeL(@"The daemon opens a utun tunnel and takes the device's tcp and udp traffic. The first bytes of a tls hello are cut so a filter that matches the server name misses it. Telegram goes over websocket gateways. Routing needs root, and a jailbreak already provides it."),
                    @"globe", nil),
        ByeAboutRow(ByeL(@"Features"),
                    ByeL(@"Strategy list with automatic retry\nName lists\nTelegram gateway with relays\nQUIC refusal\nStrategy probe"),
                    @"split", nil),
        ByeAboutRow(ByeL(@"Compatibility"), @"iOS 5-16 · armv7 + arm64", @"repeat", nil),
        ByeAboutRow(ByeL(@"Security"),
                    ByeL(@"Token-authenticated control socket · certificate-checked gateway, no way around it · list files read as plain files only."),
                    @"shield", nil),
        ByeAboutRow(ByeL(@"System log"), @"/var/log/byebyedpi-system.log", @"logs", nil),
        nil]];

    ByeSection *links = [ByeSection sectionWithTitle:ByeL(@"Links") footer:nil rows:[NSArray arrayWithObjects:
        ByeAboutRow(@"GitHub", @"github.com/sqmrak/byebyedpi", @"code", @"github"),
        ByeAboutRow(@"Telegram", @"t.me/sqmrakdev", @"globe", @"telegram"),
        nil]];

    ByeRow *developer = ByeAboutRow(ByeL(@"Developer"), @"sqmrak", nil, nil);
    NSString *avatar = [[NSBundle mainBundle] pathForResource:@"sqmrak" ofType:@"jpg"];
    UIImage *face = avatar ? [UIImage imageWithContentsOfFile:avatar] : nil;
    if (face) developer.image = face;
    ByeSection *credits = [ByeSection sectionWithTitle:ByeL(@"Credits") footer:nil rows:[NSArray arrayWithObjects:
        developer,
        ByeAboutRow(ByeL(@"Special thanks"), ByeAboutThanks, @"bolt", nil),
        ByeAboutRow(ByeL(@"Built on"),
                    @"ByeDPI by hufrea\nByeByeDPI for Android by romanvht\nByeByeDPI x TG by EwenLoy\ntg-ws-proxy by Flowseal",
                    @"bolt", nil),
        ByeAboutRow(ByeL(@"Libraries"), @"lwIP · OpenSSL", @"rocket", nil),
        ByeAboutRow(ByeL(@"Glyphs"), ByeL(@"Material Symbols (Apache 2.0) and drawings made for this app"), @"palette", nil),
        nil]];
    return [NSArray arrayWithObjects:device, app, links, credits, nil];
}

- (void)formRowTapped:(ByeRow *)row {
    NSString *address = [row.ident isEqualToString:@"github"] ? @"https://github.com/sqmrak/byebyedpi"
                      : [row.ident isEqualToString:@"telegram"] ? @"https://t.me/sqmrakdev" : nil;
    NSURL *url = address ? [NSURL URLWithString:address] : nil;
    if (url) [[UIApplication sharedApplication] openURL:url];
}

@end

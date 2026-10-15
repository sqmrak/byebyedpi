#import "bye_boykisser.h"

#import <QuartzCore/QuartzCore.h>

#include <stdlib.h>
#include <string.h>

#import "bye_theme.h"

enum { ByeFlakesPhone = 10, ByeFlakesPad = 16, ByeFlakesMax = 16 };

typedef struct {
    CGFloat x, y, vx, vy, rot, vrot, h;
    CALayer *layer;
} ByeFlake;

/* one scaled copy per idiom, so a flake never decodes the png */
static UIImage *ByeBoySprite(BOOL pad) {
    static UIImage *cache[2];
    UIImage *hit = cache[pad ? 1 : 0];
    if (hit) return hit;
    NSString *path = [[NSBundle mainBundle] pathForResource:@"boykisser" ofType:@"png"];
    UIImage *src = path ? [UIImage imageWithContentsOfFile:path] : nil;
    if (!src || src.size.width < 1.0f || src.size.height < 1.0f) return nil;
    CGFloat side = pad ? 180.0f : 112.0f;
    CGFloat scale = side / MAX(src.size.width, src.size.height);
    CGSize size = CGSizeMake(src.size.width * scale + 10.0f, src.size.height * scale + 10.0f);
    UIGraphicsBeginImageContextWithOptions(size, NO, 1.0f);
    CGContextSetShadowWithColor(UIGraphicsGetCurrentContext(), CGSizeMake(0.0f, 1.5f), pad ? 3.0f : 2.0f,
                                [UIColor colorWithRed:0.55f green:0.12f blue:0.35f alpha:0.35f].CGColor);
    [src drawInRect:CGRectMake(5.0f, 5.0f, src.size.width * scale, src.size.height * scale)];
    UIImage *out = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    cache[pad ? 1 : 0] = [out retain];
    return out;
}

static CGFloat ByeRandom(CGFloat low, CGFloat high) {
    return low + ((CGFloat)(arc4random() % 10000) / 10000.0f) * (high - low);
}

@implementation ByeBoykisserField {
    ByeFlake _flakes[ByeFlakesMax];
    int _count;
    CADisplayLink *_link;
    BOOL _paused;
    BOOL _pad;
    UIImage *_sprite;
    CGSize _laidSize;
    CFTimeInterval _lastTime;
    CGFloat _baseHeight;
}

- (id)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (!self) return nil;
    self.userInteractionEnabled = NO;
    self.backgroundColor = [UIColor clearColor];
    self.clipsToBounds = YES;
    _pad = ByeIsPad();
    _count = _pad ? ByeFlakesPad : ByeFlakesPhone;
    _baseHeight = _pad ? 110.0f : 70.0f;
    _sprite = [ByeBoySprite(_pad) retain];
    memset(_flakes, 0, sizeof _flakes);
    for (int i = 0; i < _count; ++i) {
        CALayer *layer = [CALayer layer];
        layer.contents = (id)_sprite.CGImage;
        layer.contentsGravity = kCAGravityResizeAspect;
        layer.contentsScale = 1.0f;
        /* a moving layer would animate every property change implicitly */
        layer.actions = [NSDictionary dictionaryWithObjectsAndKeys:
                         [NSNull null], @"position", [NSNull null], @"transform",
                         [NSNull null], @"bounds", [NSNull null], @"opacity", nil];
        [self.layer addSublayer:layer];
        _flakes[i].layer = layer;
        [self resetFlake:&_flakes[i] scatter:YES];
    }
    return self;
}

- (void)dealloc {
    [self stop];
    for (int i = 0; i < _count; ++i) [_flakes[i].layer removeFromSuperlayer];
    [_sprite release];
    [super dealloc];
}

- (void)resetFlake:(ByeFlake *)f scatter:(BOOL)scatter {
    CGFloat width = self.bounds.size.width > 1.0f ? self.bounds.size.width : 320.0f;
    CGFloat height = self.bounds.size.height > 1.0f ? self.bounds.size.height : 480.0f;
    CGFloat scale = _pad ? ByeRandom(0.85f, 1.45f) : ByeRandom(0.70f, 1.20f);
    f->vy = _pad ? ByeRandom(52.0f, 78.0f) : ByeRandom(44.0f, 64.0f);
    f->vx = _pad ? ByeRandom(-10.0f, 10.0f) : ByeRandom(-6.0f, 6.0f);
    f->x = ByeRandom(24.0f, width - 24.0f);
    f->y = scatter ? ByeRandom(-40.0f, height) : ByeRandom(-(_baseHeight + 40.0f), -36.0f);
    f->rot = ByeRandom(-0.18f, 0.18f);
    f->vrot = ByeRandom(-0.28f, 0.28f);
    f->h = _baseHeight * scale;
    CGFloat w = f->h * (_sprite.size.height > 1.0f ? _sprite.size.width / _sprite.size.height : 1.0f);
    f->layer.bounds = CGRectMake(0.0f, 0.0f, w, f->h);
    f->layer.opacity = _pad ? ByeRandom(0.92f, 1.0f) : ByeRandom(0.84f, 1.0f);
    f->layer.position = CGPointMake(f->x, f->y);
    f->layer.affineTransform = CGAffineTransformMakeRotation(f->rot);
}

- (void)layoutSubviews {
    [super layoutSubviews];
    CGSize size = self.bounds.size;
    if (CGSizeEqualToSize(_laidSize, size) || size.width <= 1.0f || size.height <= 1.0f) return;
    _laidSize = size;
    for (int i = 0; i < _count; ++i) [self resetFlake:&_flakes[i] scatter:YES];
}

- (void)tick:(CADisplayLink *)link {
    CFTimeInterval now = link.timestamp;
    CGFloat dt = _lastTime > 0.0 ? (CGFloat)(now - _lastTime) : 1.0f / 30.0f;
    _lastTime = now;
    /* a long gap after a pause would throw every flake off the screen at once */
    if (dt > 1.0f / 20.0f) dt = 1.0f / 30.0f;
    CGSize size = self.bounds.size;
    for (int i = 0; i < _count; ++i) {
        ByeFlake *f = &_flakes[i];
        f->y += f->vy * dt;
        f->x += f->vx * dt;
        f->rot += f->vrot * dt;
        if (f->y > size.height + f->h || f->x < -f->h || f->x > size.width + f->h) {
            [self resetFlake:f scatter:NO];
            continue;
        }
        f->layer.position = CGPointMake(f->x, f->y);
        f->layer.affineTransform = CGAffineTransformMakeRotation(f->rot);
    }
}

- (void)start {
    if (_link || !_sprite) return;
    _lastTime = 0.0;
    _link = [[CADisplayLink displayLinkWithTarget:self selector:@selector(tick:)] retain];
    /* frameInterval 2 is 30 fps, enough for slow falling and half the cpu of the old phones */
    _link.frameInterval = 2;
    _link.paused = _paused;
    [_link addToRunLoop:[NSRunLoop mainRunLoop] forMode:NSRunLoopCommonModes];
}

- (void)stop {
    [_link invalidate];
    [_link release];
    _link = nil;
}

- (void)setPaused:(BOOL)paused {
    _paused = paused;
    _lastTime = 0.0;
    _link.paused = paused;
}

@end

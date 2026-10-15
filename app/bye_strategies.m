#import "bye_strategies.h"

#import <UIKit/UIKit.h>

#import "bye_daemon.h"
#import "bye_form.h"
#import "bye_l10n.h"
#import "bye_theme.h"

#include "bye_desync.h"

static NSString * const ByeHistoryKey = @"ByeStrategyHistory";
static const NSUInteger ByeHistoryMax = 20;

@implementation ByeStrategies

+ (NSString *)clean:(NSString *)text {
    NSString *flat = [[text stringByReplacingOccurrencesOfString:@"\n" withString:@" "]
                      stringByReplacingOccurrencesOfString:@"\r" withString:@" "];
    return [flat stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

+ (NSString *)display:(NSString *)text {
    NSString *clean = [self clean:text];
    return [clean isEqualToString:@"auto"] ? ByeL(@"Automatic") : clean;
}

+ (NSArray *)history {
    id stored = [[NSUserDefaults standardUserDefaults] objectForKey:ByeHistoryKey];
    if (![stored isKindOfClass:[NSArray class]]) return [NSArray array];
    NSMutableArray *items = [NSMutableArray array];
    for (id item in stored)
        if ([item isKindOfClass:[NSString class]] && [item length]) [items addObject:item];
    return items;
}

+ (void)saveHistory:(NSArray *)items {
    [[NSUserDefaults standardUserDefaults] setObject:items forKey:ByeHistoryKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

+ (void)forgetAll {
    [self saveHistory:[NSArray array]];
}

+ (void)remember:(NSString *)text {
    NSString *clean = [self clean:text];
    if (!clean.length) return;
    NSMutableArray *items = [NSMutableArray arrayWithArray:[self history]];
    [items removeObject:clean];
    [items insertObject:clean atIndex:0];
    while (items.count > ByeHistoryMax) [items removeLastObject];
    [self saveHistory:items];
}

+ (void)forget:(NSString *)text {
    NSMutableArray *items = [NSMutableArray arrayWithArray:[self history]];
    [items removeObject:[self clean:text]];
    [self saveHistory:items];
}

+ (NSString *)problemWith:(NSString *)text {
    NSString *clean = [self clean:text];
    if (!clean.length) return ByeL(@"A strategy is empty.");
    if ([clean rangeOfString:@"|"].location != NSNotFound) return ByeL(@"A strategy has no \"|\" in it.");
    bye_strategies_t parsed;
    char error[160] = "";
    if (bye_strategies_parse([clean UTF8String], &parsed, error, sizeof error) != BYE_DESYNC_OK)
        return [NSString stringWithUTF8String:error];
    return nil;
}

+ (void)use:(NSString *)text completion:(void (^)(NSString *error))done {
    NSString *clean = [self clean:text];
    NSString *problem = [self problemWith:clean];
    void (^finish)(NSString *) = done ? [[done copy] autorelease] : nil;
    if (problem) {
        if (finish) finish(problem);
        return;
    }
    NSString *previous = [[[ByeDaemon shared] config] objectForKey:@"desync.spec"];
    [[ByeDaemon shared] setConfigValue:clean forKey:@"desync.spec" completion:^(NSString *error) {
        if (!error) {
            if (previous.length && ![previous isEqualToString:clean]) [self remember:previous];
            /* the one in use is not in the history, it is on top of the screen */
            [self forget:clean];
            [[ByeDaemon shared] applyPendingSettings];
        }
        if (finish) finish(error);
    }];
}

+ (void)offerText:(NSString *)text from:(UIViewController *)host remembered:(BOOL)remembered
       completion:(void (^)(void))done {
    NSString *clean = [self clean:text];
    void (^finish)(void) = done ? [[done copy] autorelease] : nil;
    NSMutableArray *items = [NSMutableArray arrayWithObjects:ByeL(@"Use"), ByeL(@"Copy"), nil];
    if (!remembered) [items addObject:ByeL(@"Keep in the history")];
    else [items addObject:ByeL(@"Delete")];
    ByeChoose(host, nil, items, ^(NSInteger index) {
        if (index == 0) {
            [self use:clean completion:^(NSString *error) {
                if (error) ByeAlert(ByeL(@"The strategy was not saved"), error);
                if (finish) finish();
            }];
        } else if (index == 1) {
            [UIPasteboard generalPasteboard].string = clean;
            ByeAlert(ByeL(@"Copied"), clean);
        } else if (index == 2) {
            if (remembered) [self forget:clean];
            else [self remember:clean];
            if (finish) finish();
        }
    });
}

@end

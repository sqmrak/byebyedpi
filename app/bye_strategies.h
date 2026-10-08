#ifndef BYE_STRATEGIES_H
#define BYE_STRATEGIES_H

#import <UIKit/UIKit.h>

/* the daemon owns automatic retries; the app keeps replaced strategies for manual reuse */

@interface ByeStrategies : NSObject

/* the replaced strategies, newest first */
+ (NSArray *)history;
+ (void)remember:(NSString *)text;
+ (void)forget:(NSString *)text;

/* the text trimmed, one line */
+ (NSString *)clean:(NSString *)text;

/* show a translated label because auto names the built-in strategy list */
+ (NSString *)display:(NSString *)text;

/* nil when the daemon will take the text, else the reason in plain words */
+ (NSString *)problemWith:(NSString *)text;

/* restart a running tunnel because it keeps the strategy it started with
   keep the replaced strategy in history; done receives nil or an error */
+ (void)use:(NSString *)text completion:(void (^)(NSString *error))done;

/* a sheet for a strategy that is on screen: use it, copy it, keep it in the history */
+ (void)offerText:(NSString *)text from:(UIViewController *)host remembered:(BOOL)remembered
       completion:(void (^)(void))done;

@end

#endif

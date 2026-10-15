#ifndef BYE_BOYKISSER_H
#define BYE_BOYKISSER_H

#import <UIKit/UIKit.h>

/* boykisser.png falling behind the main screen of the boykisser theme */
@interface ByeBoykisserField : UIView
/* the display link retains the field, so stop it before the owner lets go */
- (void)start;
- (void)stop;
/* keeps the flakes still while another screen covers this one */
- (void)setPaused:(BOOL)paused;
@end

#endif

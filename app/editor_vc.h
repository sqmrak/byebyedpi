#ifndef BYE_EDITOR_VC_H
#define BYE_EDITOR_VC_H

#import "bye_form.h"

/* the strategy screen: the one text the daemon uses, what runs now, and the
   history of the texts it replaced */
@interface EditorVC : ByeFormController {
    NSArray *_history;
}
@end

#endif

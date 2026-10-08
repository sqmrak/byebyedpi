#ifndef BYE_LISTS_VC_H
#define BYE_LISTS_VC_H

#import "bye_form.h"
#import "bye_lists.h"

/* the lists of domain names, with a check mark on the chosen ones */
@interface ListsVC : ByeFormController {
    ByeListsPurpose _purpose;
}
- (id)initForPurpose:(ByeListsPurpose)purpose;
@end

/* a list of the user's own: a name and one domain per line */
@interface ListEditVC : ByeScreen <UITextFieldDelegate, UITextViewDelegate> {
    UITextField *_name;
    UITextView *_text;
    void (^_saved)(ByeList *list);
    CGFloat _keyboard;
}
- (id)initWithSaved:(void (^)(ByeList *list))saved;
@end

#endif

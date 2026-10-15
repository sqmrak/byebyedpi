#ifndef BYE_SETTINGS_VC_H
#define BYE_SETTINGS_VC_H

#import "bye_form.h"

/* the app's saved choices of an older build are dropped once, the way the daemon drops its config */
void ByeResetSavedSettings(void);

@interface SettingsVC : ByeFormController
@end

#endif

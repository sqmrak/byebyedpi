#ifndef BYE_LOGS_VC_H
#define BYE_LOGS_VC_H

#import "bye_form.h"

/* what the daemon reports and the end of its log */
@interface LogsVC : ByeFormController
/* copies the report to the pasteboard and says so */
+ (void)copyReportAndTell;
/* writes the report to a .txt file in the temporary directory and opens the system
   menu for it (mail, messages, other apps). with no app to take it, the text is
   copied instead and the alert says so */
+ (void)shareReportFrom:(UIViewController *)host;
@end

#endif

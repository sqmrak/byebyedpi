#ifndef BYE_PROBE_VC_H
#define BYE_PROBE_VC_H

#import "bye_form.h"
#import "bye_chrome.h"
#import "bye_daemon.h"

/* which strategies get a tls hello through on this network: the daemon tries
   each one on real sites, and the screen shows how it goes */
@interface ProbeVC : ByeFormController {
    ByeGlossButton *_start;
    ByeProgressBar *_bar;
    UILabel *_state;
    UIView *_header;
    NSTimer *_timer;
    ByeReply *_report;
    BOOL _running;
    BOOL _asking;
}
@end

#endif

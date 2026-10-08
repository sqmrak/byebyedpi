#ifndef BYE_TRACE_H
#define BYE_TRACE_H

#import <Foundation/Foundation.h>

/* keep launch and crash details readable over ssh when the app cannot show diagnostics
   reset the file above 32 KB so it cannot fill a small device */

#define BYE_TRACE_PATH "/var/mobile/Library/Preferences/com.byebyedpi.app.log"

void ByeTraceInstall(void);
void ByeTrace(NSString *format, ...) NS_FORMAT_FUNCTION(1, 2);

/* the end of the file, for the diagnostics screen */
NSString *ByeTraceTail(NSUInteger maxBytes);

#endif

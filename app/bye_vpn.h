#ifndef BYE_VPN_H
#define BYE_VPN_H

#import <Foundation/Foundation.h>

/* the vpn badge marker for ios 12 and later: a NetworkExtension tunnel that
   carries nothing and is up exactly while byedpid's tunnel is. older systems
   get the badge from the springboard hook and are left alone here */
@interface ByeVPN : NSObject
+ (ByeVPN *)shared;
/* called with every daemon state. only a change of the answer does anything,
   so a tunnel the user turned off in Settings stays off until the next change */
- (void)followDaemonRunning:(BOOL)running;
@end

#endif

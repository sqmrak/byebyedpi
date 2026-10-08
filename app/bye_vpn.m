#import "bye_vpn.h"

#import <UIKit/UIKit.h>
#import <objc/message.h>
#include <dlfcn.h>

#import "bye_trace.h"

static NSString * const ByeTunnelProviderID = @"com.byebyedpi.app.tunnel";

/* NEVPNStatus */
enum { ByeVPNStatusConnecting = 2, ByeVPNStatusConnected = 3 };

static BOOL ByeVPNAvailable(void) {
    /* before ios 12 the springboard hook draws the badge */
    NSArray *parts = [[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."];
    NSInteger major = parts.count ? [[parts objectAtIndex:0] integerValue] : 0;
    if (major < 12) return NO;
    /* not linked: the armv7 slice is built against an sdk without the framework, and
       the classes only exist once it is loaded */
    dlopen("/System/Library/Frameworks/NetworkExtension.framework/NetworkExtension", RTLD_LAZY);
    return NSClassFromString(@"NETunnelProviderManager") && NSClassFromString(@"NETunnelProviderProtocol");
}

static id ByeVPNFind(NSArray *managers) {
    for (id manager in managers) {
        id protocol = ((id (*)(id, SEL))objc_msgSend)(manager, @selector(protocolConfiguration));
        id identifier = protocol ? ((id (*)(id, SEL))objc_msgSend)(protocol, @selector(providerBundleIdentifier)) : nil;
        if ([identifier isEqual:ByeTunnelProviderID]) return manager;
    }
    return nil;
}

static void ByeVPNStart(id manager) {
    id protocol = [[NSClassFromString(@"NETunnelProviderProtocol") alloc] init];
    ((void (*)(id, SEL, id))objc_msgSend)(protocol, @selector(setProviderBundleIdentifier:), ByeTunnelProviderID);
    ((void (*)(id, SEL, id))objc_msgSend)(protocol, @selector(setServerAddress:), @"198.18.255.2");
    ((void (*)(id, SEL, id))objc_msgSend)(manager, @selector(setProtocolConfiguration:), protocol);
    ((void (*)(id, SEL, id))objc_msgSend)(manager, @selector(setLocalizedDescription:), @"ByeByeDPI");
    ((void (*)(id, SEL, BOOL))objc_msgSend)(manager, @selector(setEnabled:), YES);
    [protocol release];
    [manager retain];
    ((void (*)(id, SEL, void (^)(NSError *)))objc_msgSend)(manager, @selector(saveToPreferencesWithCompletionHandler:), ^(NSError *error) {
        if (error) {
            ByeTrace(@"vpn badge: cannot save the tunnel: %@", error);
            [manager release];
            return;
        }
        id connection = ((id (*)(id, SEL))objc_msgSend)(manager, @selector(connection));
        NSError *startError = nil;
        BOOL started = ((BOOL (*)(id, SEL, NSError **))objc_msgSend)(connection, @selector(startVPNTunnelAndReturnError:), &startError);
        ByeTrace(@"vpn badge: %@", started ? @"tunnel started" : [NSString stringWithFormat:@"cannot start: %@", startError]);
        [manager release];
    });
}

@implementation ByeVPN {
    int _wanted; /* -1 nothing decided yet */
}

+ (ByeVPN *)shared {
    static ByeVPN *shared;
    if (!shared) {
        shared = [[ByeVPN alloc] init];
        shared->_wanted = -1;
    }
    return shared;
}

- (void)followDaemonRunning:(BOOL)running {
    if (!ByeVPNAvailable() || _wanted == (running ? 1 : 0)) return;
    _wanted = running ? 1 : 0;
    ((void (*)(id, SEL, void (^)(NSArray *, NSError *)))objc_msgSend)(NSClassFromString(@"NETunnelProviderManager"),
        @selector(loadAllFromPreferencesWithCompletionHandler:), ^(NSArray *managers, NSError *error) {
        if (error) {
            ByeTrace(@"vpn badge: cannot read the tunnels: %@", error);
            return;
        }
        id manager = ByeVPNFind(managers);
        id connection = manager ? ((id (*)(id, SEL))objc_msgSend)(manager, @selector(connection)) : nil;
        NSInteger status = connection ? ((NSInteger (*)(id, SEL))objc_msgSend)(connection, @selector(status)) : 0;
        if (running) {
            if (status == ByeVPNStatusConnected || status == ByeVPNStatusConnecting) return;
            if (!manager) manager = [[[NSClassFromString(@"NETunnelProviderManager") alloc] init] autorelease];
            ByeVPNStart(manager);
        } else if (connection) {
            ((void (*)(id, SEL))objc_msgSend)(connection, @selector(stopVPNTunnel));
            ByeTrace(@"vpn badge: tunnel stopped");
        }
    });
}

@end

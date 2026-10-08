#import <NetworkExtension/NetworkExtension.h>
#import <Foundation/Foundation.h>

/* ios 12 and later draw the vpn badge only for a NetworkExtension tunnel that is
   connected, never for the utun that byedpid opens itself. this provider carries
   no traffic: it holds a tunnel up, with a route for its own subnet only, while
   byedpid keeps relaying through its own utun */
@interface ByeTunnelProvider : NEPacketTunnelProvider
@end

@implementation ByeTunnelProvider

- (void)startTunnelWithOptions:(NSDictionary *)options
              completionHandler:(void (^)(NSError *error))completionHandler {
    (void)options;
    NEPacketTunnelNetworkSettings *network =
        [[[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:@"198.18.255.2"] autorelease];
    NEIPv4Settings *ipv4 =
        [[[NEIPv4Settings alloc] initWithAddresses:[NSArray arrayWithObject:@"198.18.255.1"]
                                       subnetMasks:[NSArray arrayWithObject:@"255.255.255.0"]] autorelease];
    /* an empty list could be read as "no routes" or as the default route, so the
       one route is spelled out, and it is not the one byedpid's tunnel owns */
    ipv4.includedRoutes = [NSArray arrayWithObject:
        [[[NEIPv4Route alloc] initWithDestinationAddress:@"198.18.255.0"
                                              subnetMask:@"255.255.255.0"] autorelease]];
    network.IPv4Settings = ipv4;
    [self setTunnelNetworkSettings:network completionHandler:^(NSError *error) {
        if (completionHandler) completionHandler(error);
    }];
}

- (void)stopTunnelWithReason:(NEProviderStopReason)reason
            completionHandler:(void (^)(void))completionHandler {
    (void)reason;
    if (completionHandler) completionHandler();
}

@end

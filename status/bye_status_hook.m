#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#include <dispatch/dispatch.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* springboard tweak for ios 5 to 11: shows the vpn badge while the daemon's
   tunnel runs and keeps the wifi glyph. the daemon writes "1 en0" or "0" to the
   state file and posts the notification, see daemon/bye_badge.c */

static const char kStatePath[] = "/var/mobile/Library/Preferences/com.byebyedpi.status.state";
static const char kLogPath[] = "/var/mobile/Library/Preferences/com.byebyedpi.status.log";
static const CFStringRef kNotify = CFSTR("com.byebyedpi.status.changed");
#define LOG_CAP (32 * 1024)
#define APPLY_RETRIES 30

static BOOL gReady = NO;
static BOOL gQueued = NO;
static BOOL gDidApply = NO;
static BOOL gLastState = NO;
static unsigned gRetries = 0;
static BOOL gHookFailureLogged = NO;
static BOOL gVPNForced = NO;

static BOOL (*gOrigUsingVPN)(id, SEL) = NULL;
static void (*gOrigUpdateVPNItem)(id, SEL) = NULL;
static void (*gOrigPrimaryChanged)(id, SEL, BOOL) = NULL;
static BOOL gWiFiHookTried = NO;

/* springboard cannot show its own log to anyone, and the glyph depends on
   firmware details, so every apply leaves a line here. the file restarts at
   the cap */
static void WriteLog(NSString *line) {
    const char *text = [[NSString stringWithFormat:@"%.0f %@",
        [[NSDate date] timeIntervalSince1970], line] UTF8String];
    if (!text) return;
    struct stat st;
    int flags = O_WRONLY | O_CREAT | O_APPEND;
    if (stat(kLogPath, &st) == 0 && st.st_size > LOG_CAP) flags = O_WRONLY | O_CREAT | O_TRUNC;
    int fd = open(kLogPath, flags, 0644);
    if (fd < 0) return;
    if (write(fd, text, strlen(text)) < 0 || write(fd, "\n", 1) < 0)
        NSLog(@"byedpid status: cannot write %s", kLogPath);
    close(fd);
    NSLog(@"byedpid status: %@", line);
}

/* "1 en0" while the tunnel runs; the interface is empty when the daemon could
   not name it */
static BOOL ReadState(char *ifname, size_t cap) {
    char buf[40];
    ifname[0] = '\0';
    int fd = open(kStatePath, O_RDONLY);
    if (fd < 0) return NO;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n < 1 || buf[0] != '1') return NO;
    buf[n] = '\0';
    if (n > 2 && buf[1] == ' ') {
        size_t len = strcspn(buf + 2, "\n");
        if (len < cap) {
            memcpy(ifname, buf + 2, len);
            ifname[len] = '\0';
        }
    }
    return YES;
}

static id SharedObject(NSString *className, SEL first, SEL second) {
    Class cls = NSClassFromString(className);
    if (!cls) return nil;
    SEL sel = [cls respondsToSelector:first] ? first : ([cls respondsToSelector:second] ? second : NULL);
    if (!sel) return nil;
    id (*call)(id, SEL) = (id (*)(id, SEL))[cls methodForSelector:sel];
    return call((id)cls, sel);
}

static BOOL CallVoid(id obj, SEL sel) {
    if (!obj || ![obj respondsToSelector:sel]) return NO;
    void (*call)(id, SEL) = (void (*)(id, SEL))[obj methodForSelector:sel];
    call(obj, sel);
    return YES;
}

static BOOL CallBool(id obj, SEL sel, BOOL *out) {
    if (!obj || ![obj respondsToSelector:sel]) return NO;
    BOOL (*call)(id, SEL) = (BOOL (*)(id, SEL))[obj methodForSelector:sel];
    *out = call(obj, sel);
    return YES;
}

/* one counter per thread: statuskit may recompute the vpn item off the main
   thread, and a process-wide flag would let the forced answer reach another
   thread's unrelated call to the same getter */
static pthread_key_t gDepthKey;
static pthread_once_t gDepthOnce = PTHREAD_ONCE_INIT;

static void DepthKeyInit(void) {
    pthread_key_create(&gDepthKey, free);
}

static long *DepthSlot(void) {
    pthread_once(&gDepthOnce, DepthKeyInit);
    long *slot = pthread_getspecific(gDepthKey);
    if (!slot) {
        slot = calloc(1, sizeof(long));
        if (slot) pthread_setspecific(gDepthKey, slot);
    }
    return slot;
}

/* answering yes to every caller makes ios 13 and later read the link as a vpn
   instead of wifi and drop the glyph, so the answer is scoped to the run of
   the method that paints the vpn item */
static BOOL UsingVPNConnection(id self, SEL _cmd) {
    BOOL original = gOrigUsingVPN ? gOrigUsingVPN(self, _cmd) : NO;
    if (!gVPNForced) return original;
    long *depth = DepthSlot();
    return (depth && *depth > 0) ? YES : original;
}

static void UpdateVPNItem(id self, SEL _cmd) {
    long *depth = DepthSlot();
    if (depth) (*depth)++;
    if (gOrigUpdateVPNItem) gOrigUpdateVPNItem(self, _cmd);
    if (depth) (*depth)--;
}

/* ios 6 and 7 keep the item on the data manager, later releases on an aggregator */
static NSString * const kItemOwners[] = {
    @"SBStatusBarStateAggregator", @"STStatusBarStateAggregator", @"SBStatusBarDataManager"
};

static BOOL InstallItemHook(void) {
    static const char *names[] = { "_updateVPNItem", "updateVPNItem", NULL };
    if (gOrigUpdateVPNItem) return YES;
    for (size_t i = 0; i < sizeof kItemOwners / sizeof kItemOwners[0]; ++i) {
        Class cls = NSClassFromString(kItemOwners[i]);
        if (!cls) continue;
        for (size_t n = 0; names[n]; ++n) {
            Method method = class_getInstanceMethod(cls, sel_registerName(names[n]));
            if (!method) continue;
            const char *types = method_getTypeEncoding(method);
            if (types && types[0] != 'v') continue;
            gOrigUpdateVPNItem = (void (*)(id, SEL))method_setImplementation(method, (IMP)UpdateVPNItem);
            WriteLog([NSString stringWithFormat:@"badge scoped to -[%@ %s]", kItemOwners[i], names[n]]);
            return YES;
        }
    }
    return NO;
}

static BOOL InstallVPNHook(void) {
    static const char *names[] = { "isUsingVPNConnection", "usingVPNConnection", "isVPNActive", NULL };
    /* the item hook goes in first: without it the forced answer would reach
       every caller of the getter, including the one the wifi glyph depends on */
    if (!InstallItemHook()) {
        if (!gHookFailureLogged) {
            gHookFailureLogged = YES;
            WriteLog(@"no vpn item update on this firmware, retrying while springboard starts");
        }
        return NO;
    }
    if (gOrigUsingVPN) return YES;
    Class cls = NSClassFromString(@"SBTelephonyManager");
    for (size_t i = 0; cls && names[i]; ++i) {
        Method method = class_getInstanceMethod(cls, sel_registerName(names[i]));
        if (!method) continue;
        const char *types = method_getTypeEncoding(method);
        /* both BOOL encodings return one byte; anything else is another method */
        if (types && types[0] != 'c' && types[0] != 'B') continue;
        gOrigUsingVPN = (BOOL (*)(id, SEL))method_setImplementation(method, (IMP)UsingVPNConnection);
        return YES;
    }
    if (!gHookFailureLogged) {
        gHookFailureLogged = YES;
        WriteLog(@"SBTelephonyManager has no vpn getter, retrying while springboard starts");
    }
    return NO;
}

static int DataConnectionType(void) {
    id telephony = SharedObject(@"SBTelephonyManager", @selector(sharedTelephonyManager),
                                @selector(sharedInstance));
    SEL sel = sel_registerName("dataConnectionType");
    if (!telephony || ![telephony respondsToSelector:sel]) return -1;
    int (*call)(id, SEL) = (int (*)(id, SEL))[telephony methodForSelector:sel];
    return call(telephony, sel);
}

/* what the status bar draws from, for the log: data type 8 is wifi on the ios
   5.1.1 and 6.1 springboards */
static NSString *NetworkFacts(void) {
    id wifi = SharedObject(@"SBWiFiManager", @selector(sharedInstance), @selector(sharedWiFiManager));
    BOOL primary = NO;
    BOOL have = CallBool(wifi, sel_registerName("isPrimaryInterface"), &primary);
    return [NSString stringWithFormat:@"data=%d wifi_primary=%d", DataConnectionType(),
            have ? (int)primary : -1];
}

/* springboard draws the wifi glyph only while configd's primary interface is
   the wifi one (SBWiFiManager -_primaryInterfaceChanged:, ios 6.1). the
   daemon's configd service puts the tunnel first on ios before 12, so while the
   tunnel leaves by wifi the flag is set again here */
static void PrimaryInterfaceChanged(id self, SEL _cmd, BOOL primary) {
    char ifname[16];
    if (!primary && ReadState(ifname, sizeof ifname) && strncmp(ifname, "en", 2) == 0) {
        gOrigPrimaryChanged(self, _cmd, YES);
        WriteLog([@"tunnel is primary, wifi glyph kept: " stringByAppendingString:NetworkFacts()]);
        return;
    }
    gOrigPrimaryChanged(self, _cmd, primary);
}

static void InstallWiFiHook(void) {
    if (gOrigPrimaryChanged || gWiFiHookTried) return;
    Class cls = NSClassFromString(@"SBWiFiManager");
    if (!cls) return;
    gWiFiHookTried = YES;
    Method method = class_getInstanceMethod(cls, sel_registerName("_primaryInterfaceChanged:"));
    char ret[4] = "", arg[4] = "";
    if (method) {
        method_getReturnType(method, ret, sizeof ret);
        if (method_getNumberOfArguments(method) == 3) method_getArgumentType(method, 2, arg, sizeof arg);
    }
    if (!method || ret[0] != 'v' || (arg[0] != 'c' && arg[0] != 'B')) {
        WriteLog(@"no -[SBWiFiManager _primaryInterfaceChanged:] here, the wifi glyph follows configd");
        return;
    }
    gOrigPrimaryChanged = (void (*)(id, SEL, BOOL))
        method_setImplementation(method, (IMP)PrimaryInterfaceChanged);
    WriteLog(@"wifi glyph kept while the tunnel leaves by wifi");
}

/* configd announced the tunnel before the state file was written, so the flag
   is set now instead of at the next network change */
static void RefreshWiFi(void) {
    char ifname[16];
    InstallWiFiHook();
    if (!gOrigPrimaryChanged || !ReadState(ifname, sizeof ifname) || strncmp(ifname, "en", 2) != 0) return;
    id wifi = SharedObject(@"SBWiFiManager", @selector(sharedInstance), @selector(sharedWiFiManager));
    if (wifi) PrimaryInterfaceChanged(wifi, sel_registerName("_primaryInterfaceChanged:"), YES);
}

static BOOL ApplyStatus(BOOL enabled) {
    if (!InstallVPNHook()) return NO;
    gVPNForced = enabled;

    /* only the vpn item is refreshed: rebuilding the data network item drops
       the wifi glyph on ios 6 until the next system update */
    BOOL refreshed = NO;
    NSString *via = @"none";
    for (size_t i = 0; i < sizeof kItemOwners / sizeof kItemOwners[0] && !refreshed; ++i) {
        id owner = [kItemOwners[i] isEqualToString:@"SBStatusBarDataManager"]
            ? SharedObject(kItemOwners[i], @selector(sharedDataManager), @selector(sharedInstance))
            : SharedObject(kItemOwners[i], @selector(sharedInstance), @selector(sharedAggregator));
        if (CallVoid(owner, NSSelectorFromString(@"_updateVPNItem")) ||
            CallVoid(owner, NSSelectorFromString(@"updateVPNItem"))) {
            refreshed = YES;
            via = kItemOwners[i];
        }
    }
    /* a status bar with no item refresh only repaints on the telephony
       republish, which on statuskit would rebuild the wifi item as well */
    BOOL modernStatusKit = NSClassFromString(@"SBStatusBarStateAggregator") != nil ||
                           NSClassFromString(@"STStatusBarStateAggregator") != nil;
    if (!refreshed && !modernStatusKit) {
        id telephony = SharedObject(@"SBTelephonyManager", @selector(sharedTelephonyManager),
                                    @selector(sharedInstance));
        refreshed = CallVoid(telephony, @selector(updateSpringBoard));
        if (refreshed) via = @"SBTelephonyManager.updateSpringBoard";
    }
    WriteLog([NSString stringWithFormat:@"apply enabled=%d via=%@ %@", enabled, via, NetworkFacts()]);
    return refreshed;
}

@interface ByeStatusBridge : NSObject
+ (void)markReady;
+ (void)poll;
+ (void)applyLater;
+ (void)applyNow;
@end

@implementation ByeStatusBridge

+ (void)markReady {
    if (gReady) return;
    gReady = YES;
    [self applyLater];
    /* the daemon's darwin notification does not reach springboard on ios 9, though the
       same post from a shell does, so a badge left on after the tunnel stopped stayed
       there. the state file is the source of truth and a read of it every second is cheap */
    [NSTimer scheduledTimerWithTimeInterval:1.0 target:self selector:@selector(poll) userInfo:nil repeats:YES];
}

+ (void)poll {
    char ifname[16];
    if (gDidApply && ReadState(ifname, sizeof ifname) != gLastState) [self applyLater];
}

+ (void)applyLater {
    if (gQueued) return;
    gQueued = YES;
    [self performSelector:@selector(applyNow) withObject:nil afterDelay:0.2];
}

+ (void)applyNow {
    gQueued = NO;
    if (!gReady) return;
    char ifname[16];
    BOOL enabled = ReadState(ifname, sizeof ifname);
    if (gDidApply && gLastState == enabled) {
        RefreshWiFi();
        return;
    }
    BOOL applied = ApplyStatus(enabled);
    /* ios 6 recalculates the wifi item while it publishes the vpn item */
    RefreshWiFi();
    if (applied) {
        gDidApply = YES;
        gLastState = enabled;
        gRetries = 0;
        return;
    }
    /* springboard publishes its status classes after the library loads */
    if (gRetries++ < APPLY_RETRIES)
        [self performSelector:@selector(applyLater) withObject:nil afterDelay:1.0];
    else
        WriteLog(@"giving up, the vpn badge stays off on this firmware");
}

@end

static void OnNotify(CFNotificationCenterRef center, void *observer, CFStringRef name,
                     const void *object, CFDictionaryRef userInfo) {
    (void)center; (void)observer; (void)name; (void)object; (void)userInfo;
    dispatch_async(dispatch_get_main_queue(), ^{ [ByeStatusBridge applyLater]; });
}

__attribute__((constructor))
static void ByeStatusInit(void) {
    @autoreleasepool {
        if (![[[NSBundle mainBundle] bundleIdentifier] isEqualToString:@"com.apple.springboard"]) return;
        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, OnNotify,
                                        kNotify, NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
        [[NSNotificationCenter defaultCenter] addObserver:[ByeStatusBridge class]
                                                 selector:@selector(markReady)
                                                     name:UIApplicationDidFinishLaunchingNotification
                                                   object:nil];
        [ByeStatusBridge performSelector:@selector(markReady) withObject:nil afterDelay:2.0];
    }
}

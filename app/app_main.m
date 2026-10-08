#import <UIKit/UIKit.h>
#include <signal.h>

#import "bye_chrome.h"
#import "bye_daemon.h"
#import "bye_trace.h"
#import "bye_theme.h"
#import "main_vc.h"

@interface UIViewController (ByeRotation)
@end

@implementation UIViewController (ByeRotation)

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)orientation {
    /* ios 5 and 6 never ask -supportedInterfaceOrientations, so the ipad's extra
       upside-down orientation has to be allowed here too */
    if (ByeIsPad()) return YES;
    return orientation != UIInterfaceOrientationPortraitUpsideDown;
}

- (BOOL)shouldAutorotate {
    return YES;
}

- (NSUInteger)supportedInterfaceOrientations {
    return ByeIsPad() ? UIInterfaceOrientationMaskAll : UIInterfaceOrientationMaskAllButUpsideDown;
}

@end

#if __IPHONE_OS_VERSION_MAX_ALLOWED >= 70000
/* holds the navigation stack below the status bar: from ios 7 the bar is drawn
   over the app, and black under it is the opaque bar of ios 5 */
@interface ByeRootController : UIViewController {
    UINavigationController *_navigation;
}
- (id)initWithNavigation:(UINavigationController *)navigation;
@end

@implementation ByeRootController

- (id)initWithNavigation:(UINavigationController *)navigation {
    self = [super initWithNibName:nil bundle:nil];
    if (!self) return nil;
    _navigation = [navigation retain];
    return self;
}

- (void)dealloc {
    [_navigation release];
    [super dealloc];
}

- (void)loadView {
    UIView *view = [[[UIView alloc] initWithFrame:[[UIScreen mainScreen] bounds]] autorelease];
    view.backgroundColor = [UIColor blackColor];
    view.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.view = view;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    [self addChildViewController:_navigation];
    [self.view addSubview:_navigation.view];
    [_navigation didMoveToParentViewController:self];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    CGRect b = self.view.bounds;
    CGFloat top = ByeStatusBarInset();
    _navigation.view.frame = CGRectMake(0.0f, top, b.size.width, b.size.height - top);
}

@end
#endif

@interface ByeAppDelegate : UIResponder <UIApplicationDelegate> {
    UIWindow *_window;
}
@end

@implementation ByeAppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    (void)application;
    (void)options;
    ByeTrace(@"did finish launching");
    /* a daemon that goes away must not take the app down with a write signal */
    signal(SIGPIPE, SIG_IGN);
    _window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    _window.backgroundColor = [UIColor blackColor];
    MainVC *main = [[[MainVC alloc] init] autorelease];
    ByeNavigationController *navigation = [[[ByeNavigationController alloc] initWithRootViewController:main] autorelease];
#if __IPHONE_OS_VERSION_MAX_ALLOWED >= 70000
    _window.rootViewController = [[[ByeRootController alloc] initWithNavigation:navigation] autorelease];
#else
    /* a binary linked before ios 7 keeps the status bar out of the layout on every ios, and
       a container root stops the ipad from turning the interface on ios 10 */
    _window.rootViewController = navigation;
#endif
    [_window makeKeyAndVisible];
    ByeTrace(@"window is up");
    [[ByeDaemon shared] startPolling];
    return YES;
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
    (void)application;
    [[ByeDaemon shared] startPolling];
}

- (void)applicationWillResignActive:(UIApplication *)application {
    (void)application;
    [[ByeDaemon shared] stopPolling];
}

- (void)dealloc {
    [_window release];
    [super dealloc];
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        ByeTraceInstall();
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([ByeAppDelegate class]));
    }
}

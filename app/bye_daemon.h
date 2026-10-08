#ifndef BYE_DAEMON_H
#define BYE_DAEMON_H

#import <Foundation/Foundation.h>

/* the app's view of byedpid, over its control socket. every call runs on a
   queue of its own and answers on the main thread, so no screen waits on the
   daemon. a screen listens for ByeDaemonDidChangeNotification and reads the
   state it needs */

extern NSString * const ByeDaemonDidChangeNotification;

typedef enum {
    ByeDaemonUnreachable = 0, /* nothing answers on the socket */
    ByeDaemonStopped,         /* the daemon is up, the tunnel is down */
    ByeDaemonRunning          /* the tunnel carries traffic */
} ByeDaemonState;

/* one answer: OK or ERR with its detail, and the key=value lines as a
   dictionary and in order. error is set instead when nothing answered */
@interface ByeReply : NSObject {
    BOOL _ok;
    NSString *_detail;
    NSString *_error;
    NSDictionary *_values;
    NSArray *_pairs;
    int _failureKind;
}
@property(nonatomic, readonly) BOOL ok;
@property(nonatomic, readonly, copy) NSString *detail;
@property(nonatomic, readonly, copy) NSString *error;
@property(nonatomic, readonly, retain) NSDictionary *values;
@property(nonatomic, readonly, retain) NSArray *pairs; /* arrays of key, value */
/* with an error: which kind, a bye_client_failure_t */
@property(nonatomic, readonly) int failureKind;
/* the text of an answer without its closing dot, for tests and for the logs screen */
+ (ByeReply *)replyFromText:(NSString *)text;
- (NSString *)valueForKey:(NSString *)key;
@end

@interface ByeDaemon : NSObject {
    dispatch_queue_t _queue;
    NSTimer *_timer;
    ByeDaemonState _state;
    NSDictionary *_status;
    NSDictionary *_config;
    NSString *_transportError;
    int _transportKind;
    NSString *_failure;
    BOOL _busy;
    BOOL _refreshing;
    BOOL _restartPending;
    BOOL _traced;
}
+ (ByeDaemon *)shared;

@property(nonatomic, readonly) ByeDaemonState state;
@property(nonatomic, readonly, retain) NSDictionary *status;
@property(nonatomic, readonly, retain) NSDictionary *config;
/* a start or a stop is on its way */
@property(nonatomic, readonly) BOOL busy;
/* a setting changed that the running tunnel does not have yet */
@property(nonatomic, readonly) BOOL restartPending;
/* why the tunnel is not up in plain words, with what to do about it; empty when nothing is wrong */
- (NSString *)errorText;
/* the same as the daemon or the socket said it, for the diagnostics */
- (NSString *)rawErrorText;

- (void)startPolling;
- (void)stopPolling;
- (void)refresh;
- (void)reloadConfig;

- (void)startTunnel;
- (void)stopTunnel;
- (void)restartTunnel;
/* restarts a running tunnel that has settings it does not have yet */
- (void)applyPendingSettings;

/* one command, answered on the main thread. timeout in seconds */
- (void)command:(NSString *)command timeout:(NSTimeInterval)timeout completion:(void (^)(ByeReply *reply))done;
- (void)setConfigValue:(NSString *)value forKey:(NSString *)key completion:(void (^)(NSString *error))done;

/* the last bytes of the daemon's log, empty when it cannot be read */
+ (NSString *)logTail:(NSUInteger)maxBytes;

/* the last bytes of what the springboard hook logged, empty when there is none */
+ (NSString *)hookLogTail:(NSUInteger)maxBytes;

/* the last bytes of a text file, from the start of a line */
+ (NSString *)tailOfFile:(const char *)path maxBytes:(NSUInteger)maxBytes;

@end

#endif

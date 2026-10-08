#ifndef BYE_LISTS_H
#define BYE_LISTS_H

#import <Foundation/Foundation.h>

/* the domain lists of the app: the ones that ship in the bundle and the ones
   the user wrote. two choices are kept over them: the lists whose names the
   desync is limited to (or spared), and the lists the strategy probe takes its
   names from */

typedef enum {
    ByeListsForHosts = 0,
    ByeListsForProbe
} ByeListsPurpose;

@interface ByeList : NSObject {
    NSString *_ident;
    NSString *_title;
    NSArray *_domains;
    BOOL _custom;
}
@property(nonatomic, readonly, copy) NSString *ident;
@property(nonatomic, readonly, copy) NSString *title;
@property(nonatomic, readonly, retain) NSArray *domains;
@property(nonatomic, readonly) BOOL custom;
@end

@interface ByeLists : NSObject

/* the bundled lists by title, then the user's in the order they were made */
+ (NSArray *)all;

+ (BOOL)isSelected:(ByeList *)list for:(ByeListsPurpose)purpose;
+ (void)setSelected:(BOOL)selected list:(ByeList *)list for:(ByeListsPurpose)purpose;

/* a list from text, one domain per line. nil with the reason in error when a
   line is not a domain name or nothing is left */
+ (ByeList *)addCustomListTitled:(NSString *)title text:(NSString *)text error:(NSString **)error;
+ (void)removeCustomList:(ByeList *)list;

/* the names of the selected lists for the hosts purpose, deduplicated, one per line */
+ (NSString *)hostsText;

/* writes hostsText to the file the daemon reads and points the daemon at it:
   "hosts = lists.txt", or "none" when no list is selected. completion gets the
   reason when something failed */
+ (void)syncHostsWithDaemon:(void (^)(NSString *error))completion;

/* up to four names for the probe, the first of each selected list, with the
   defaults when none is selected */
+ (NSArray *)probeNames;

/* the file name the daemon reads, in the hosts directory */
+ (NSString *)hostsFileName;

@end

#endif

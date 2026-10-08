#import "bye_lists.h"

#import "bye_daemon.h"
#import "bye_l10n.h"

#include "bye_hosts.h"
#include "bye_paths.h"

static NSString * const ByeHostsFile = @"lists.txt";
static NSString * const ByeCustomKey = @"ByeCustomLists";
static NSString * const ByeSelectedHostsKey = @"ByeSelectedHostLists";
static NSString * const ByeSelectedProbeKey = @"ByeSelectedProbeLists";

@interface ByeList ()
- (id)initWithIdent:(NSString *)ident title:(NSString *)title domains:(NSArray *)domains custom:(BOOL)custom;
@end

@implementation ByeList

@synthesize ident = _ident;
@synthesize title = _title;
@synthesize domains = _domains;
@synthesize custom = _custom;

- (id)initWithIdent:(NSString *)ident title:(NSString *)title domains:(NSArray *)domains custom:(BOOL)custom {
    self = [super init];
    if (!self) return nil;
    _ident = [ident copy];
    _title = [title copy];
    _domains = [domains retain];
    _custom = custom;
    return self;
}

- (void)dealloc {
    [_ident release];
    [_title release];
    [_domains release];
    [super dealloc];
}

@end

/* a name the daemon's list reader takes: the same rule decides here, so a list
   the app writes is never refused when the tunnel starts */
static BOOL ByeDomainOK(NSString *name) {
    NSData *data = [name dataUsingEncoding:NSUTF8StringEncoding];
    return data.length > 0 && bye_hosts_name_ok((const char *)[data bytes], data.length) != 0;
}

/* one domain per line, "#" comments, blanks and repeats dropped, names lowercased */
static NSArray *ByeParseDomains(NSString *text, NSString **badLine) {
    NSMutableArray *domains = [NSMutableArray array];
    NSMutableSet *seen = [NSMutableSet set];
    NSUInteger number = 0;
    for (NSString *raw in [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        ++number;
        NSString *line = raw;
        NSRange hash = [line rangeOfString:@"#"];
        if (hash.location != NSNotFound) line = [line substringToIndex:hash.location];
        line = [[line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]] lowercaseString];
        while ([line hasPrefix:@"*."] || [line hasPrefix:@"."]) line = [line substringFromIndex:[line hasPrefix:@"*."] ? 2 : 1];
        while ([line hasSuffix:@"."]) line = [line substringToIndex:line.length - 1];
        if (!line.length) continue;
        if (!ByeDomainOK(line)) {
            if (badLine) *badLine = [NSString stringWithFormat:@"%lu", (unsigned long)number];
            return nil;
        }
        if ([seen containsObject:line]) continue;
        [seen addObject:line];
        [domains addObject:line];
    }
    return domains;
}

static NSString *ByeBundledTitle(NSString *ident) {
    if ([ident isEqualToString:@"cloudflare"]) return @"Cloudflare";
    if ([ident isEqualToString:@"googlevideo"]) return @"Googlevideo";
    if ([ident isEqualToString:@"turkiye"]) return @"Türkiye";
    return [[[ident substringToIndex:1] uppercaseString] stringByAppendingString:[ident substringFromIndex:1]];
}

@implementation ByeLists

+ (NSArray *)bundled {
    static NSArray *bundled;
    if (bundled) return bundled;
    NSMutableArray *lists = [NSMutableArray array];
    NSArray *paths = [[NSBundle mainBundle] pathsForResourcesOfType:@"sites" inDirectory:nil];
    for (NSString *path in paths) {
        NSString *file = [[path lastPathComponent] stringByDeletingPathExtension];
        if (![file hasPrefix:@"list-"]) continue;
        NSString *ident = [file substringFromIndex:5];
        NSString *text = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL];
        NSArray *domains = text ? ByeParseDomains(text, NULL) : nil;
        if (!domains.count) continue;
        [lists addObject:[[[ByeList alloc] initWithIdent:ident title:ByeBundledTitle(ident)
                                                 domains:domains custom:NO] autorelease]];
    }
    [lists sortUsingComparator:^NSComparisonResult(ByeList *a, ByeList *b) {
        return [a.title caseInsensitiveCompare:b.title];
    }];
    bundled = [lists retain];
    return bundled;
}

+ (NSArray *)custom {
    NSMutableArray *lists = [NSMutableArray array];
    NSArray *stored = [[NSUserDefaults standardUserDefaults] arrayForKey:ByeCustomKey];
    for (NSDictionary *item in stored) {
        if (![item isKindOfClass:[NSDictionary class]]) continue;
        NSString *ident = [item objectForKey:@"id"], *title = [item objectForKey:@"title"];
        NSArray *domains = [item objectForKey:@"domains"];
        if (![ident isKindOfClass:[NSString class]] || ![title isKindOfClass:[NSString class]] ||
            ![domains isKindOfClass:[NSArray class]]) continue;
        [lists addObject:[[[ByeList alloc] initWithIdent:ident title:title domains:domains custom:YES] autorelease]];
    }
    return lists;
}

+ (NSArray *)all {
    NSMutableArray *all = [NSMutableArray arrayWithArray:[self bundled]];
    [all addObjectsFromArray:[self custom]];
    return all;
}

+ (NSString *)keyFor:(ByeListsPurpose)purpose {
    return purpose == ByeListsForHosts ? ByeSelectedHostsKey : ByeSelectedProbeKey;
}

+ (BOOL)isSelected:(ByeList *)list for:(ByeListsPurpose)purpose {
    NSArray *selected = [[NSUserDefaults standardUserDefaults] arrayForKey:[self keyFor:purpose]];
    return [selected containsObject:list.ident];
}

+ (void)setSelected:(BOOL)selected list:(ByeList *)list for:(ByeListsPurpose)purpose {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSMutableArray *next = [NSMutableArray arrayWithArray:[defaults arrayForKey:[self keyFor:purpose]]];
    [next removeObject:list.ident];
    if (selected) [next addObject:list.ident];
    [defaults setObject:next forKey:[self keyFor:purpose]];
    [defaults synchronize];
}

+ (ByeList *)addCustomListTitled:(NSString *)title text:(NSString *)text error:(NSString **)error {
    NSString *name = [title stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (!name.length) {
        if (error) *error = ByeL(@"Give the list a name.");
        return nil;
    }
    NSString *bad = nil;
    NSArray *domains = ByeParseDomains(text, &bad);
    if (!domains) {
        if (error) *error = ByeLF(@"Line %@ is not a domain name.", bad);
        return nil;
    }
    if (!domains.count) {
        if (error) *error = ByeL(@"The list has no domain names.");
        return nil;
    }
    NSString *ident = [NSString stringWithFormat:@"custom-%.0f", [[NSDate date] timeIntervalSince1970] * 1000.0];
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSMutableArray *stored = [NSMutableArray arrayWithArray:[defaults arrayForKey:ByeCustomKey]];
    [stored addObject:[NSDictionary dictionaryWithObjectsAndKeys:ident, @"id", name, @"title", domains, @"domains", nil]];
    [defaults setObject:stored forKey:ByeCustomKey];
    [defaults synchronize];
    return [[[ByeList alloc] initWithIdent:ident title:name domains:domains custom:YES] autorelease];
}

+ (void)removeCustomList:(ByeList *)list {
    if (!list.custom) return;
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSMutableArray *stored = [NSMutableArray array];
    for (NSDictionary *item in [defaults arrayForKey:ByeCustomKey])
        if (![[item objectForKey:@"id"] isEqualToString:list.ident]) [stored addObject:item];
    [defaults setObject:stored forKey:ByeCustomKey];
    for (NSString *key in [NSArray arrayWithObjects:ByeSelectedHostsKey, ByeSelectedProbeKey, nil]) {
        NSMutableArray *selected = [NSMutableArray arrayWithArray:[defaults arrayForKey:key]];
        [selected removeObject:list.ident];
        [defaults setObject:selected forKey:key];
    }
    [defaults synchronize];
}

+ (NSString *)hostsFileName {
    return ByeHostsFile;
}

+ (NSString *)hostsText {
    NSMutableString *text = [NSMutableString string];
    NSMutableSet *seen = [NSMutableSet set];
    for (ByeList *list in [self all]) {
        if (![self isSelected:list for:ByeListsForHosts]) continue;
        for (NSString *domain in list.domains) {
            if ([seen containsObject:domain]) continue;
            [seen addObject:domain];
            [text appendFormat:@"%@\n", domain];
        }
    }
    return text;
}

+ (void)syncHostsWithDaemon:(void (^)(NSString *))completion {
    void (^finish)(NSString *) = completion ? [[completion copy] autorelease] : nil;
    NSString *text = [self hostsText];
    if (!text.length) {
        [[ByeDaemon shared] setConfigValue:@"none" forKey:@"hosts" completion:finish];
        return;
    }
    NSString *dir = [NSString stringWithUTF8String:BYE_HOSTS_DIR];
    NSFileManager *files = [NSFileManager defaultManager];
    NSError *failure = nil;
    if (![files createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:&failure] ||
        ![text writeToFile:[dir stringByAppendingPathComponent:ByeHostsFile] atomically:YES
                  encoding:NSUTF8StringEncoding error:&failure]) {
        if (finish) finish(ByeLF(@"Cannot write the list: %@", [failure localizedDescription]));
        return;
    }
    [[ByeDaemon shared] setConfigValue:ByeHostsFile forKey:@"hosts" completion:finish];
}

+ (NSArray *)probeNames {
    NSMutableArray *names = [NSMutableArray array];
    for (ByeList *list in [self all]) {
        if (names.count == 4) break;
        if (![self isSelected:list for:ByeListsForProbe] || !list.domains.count) continue;
        [names addObject:[list.domains objectAtIndex:0]];
    }
    if (!names.count) return [NSArray arrayWithObjects:@"youtube.com", @"discord.com", nil];
    return names;
}

@end

#ifndef BYE_L10N_H
#define BYE_L10N_H

#import <Foundation/Foundation.h>

/* english text is the key, and russian is looked up for it; a text with no
   translation shows as it is. the language is the device's unless the user
   picked one */

extern NSString * const ByeLanguageDidChangeNotification;

typedef enum {
    ByeLanguageAuto = 0,
    ByeLanguageEnglish = 1,
    ByeLanguageRussian = 2
} ByeLanguage;

ByeLanguage ByeLanguageSetting(void);
void ByeSetLanguageSetting(ByeLanguage language);
BOOL ByeLanguageIsRussian(void);

NSString *ByeL(NSString *english);
/* a translated format filled with arguments */
NSString *ByeLF(NSString *english, ...) NS_FORMAT_FUNCTION(1, 2);

#endif

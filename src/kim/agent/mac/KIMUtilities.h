//
//  KIMUtilities.h
//  Kerberos5
//
//  Created by Justin Anderson on 9/28/08.
//  Copyright 2008 MIT. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <Kerberos/kim.h>

#define VALID_LIFETIME_INCREMENT (5 * 60)
#define RENEWABLE_LIFETIME_INCREMENT (15 * 60)

#define log_kim_error_to_console(err)\
{\
NSLog(@"%s got error %@", __FUNCTION__, [KIMUtilities stringForLastKIMError:err]);\
} while (0);

@interface KIMUtilities : NSObject

+ (NSString *) stringForLastKIMError: (kim_error) in_err;

+ (BOOL) validatePrincipalWithName: (NSString *) name
                             realm: (NSString *) realm;

+ (NSDictionary *) dictionaryForKimOptions: (kim_options) options;

+ (kim_options) kimOptionsForDictionary: (NSDictionary *) aDict;

+ (NSUInteger)minValidLifetime;
+ (NSUInteger)maxValidLifetime;
+ (NSUInteger)minRenewableLifetime;
+ (NSUInteger)maxRenewableLifetime;

@end

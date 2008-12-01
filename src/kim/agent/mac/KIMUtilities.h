/*
 * Copyright 2008 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */


#import <Cocoa/Cocoa.h>
#import <Kerberos/kim.h>

#define VALID_LIFETIME_INCREMENT (5 * 60)
#define RENEWABLE_LIFETIME_INCREMENT (15 * 60)

#define client_name_keypath          @"content.name"
#define client_path_keypath          @"content.path"

#define identity_string_keypath      @"content.identity_string"
#define favorite_strings_keypath     @"content.favorite_identity_strings"
#define title_keypath                @"content.title"
#define message_keypath              @"content.message"
#define description_keypath          @"content.description"

#define prompt_response_keypath      @"content.prompt_response"
#define allow_save_password_keypath  @"content.allow_save"
#define should_save_password_keypath @"content.save_response"

#define password_expired_keypath     @"content.expired"
#define old_password_keypath         @"content.old_password"
#define new_password_keypath         @"content.new_password"
#define verify_password_keypath      @"content.verify_password"

#define enable_identity_ok_keypath   @"content.isPrincipalValid"
#define enable_prompt_ok_keypath     @"content.isPromptValid"
#define change_password_ok_keypath   @"content.isChangePasswordValid"

#define options_keypath              @"content.options"

#define uses_default_options_keypath @"content.usesDefaultTicketOptions"
#define valid_lifetime_keypath       @"content.valid_lifetime"
#define renewal_lifetime_keypath     @"content.renewal_lifetime"
#define renewable_keypath            @"content.renewable"
#define addressless_keypath          @"content.addressless"
#define forwardable_keypath          @"content.forwardable"

#define min_valid_keypath            @"content.minValidLifetime"
#define max_valid_keypath            @"content.maxValidLifetime"
#define min_renewable_keypath        @"content.minRenewableLifetime"
#define max_renewable_keypath        @"content.maxRenewableLifetime"

#define wants_change_password_keypath @"content.wants_change_password"
#define accepting_input_keypath      @"content.acceptingInput"

#define ACKVOContext                 @"authenticationController"



#define log_kim_error_to_console(err)\
{\
NSLog(@"%s got error %@", __FUNCTION__, [KIMUtilities stringForLastKIMError:err]);\
} while (0);

@interface KIMUtilities : NSObject

+ (NSString *) stringForLastKIMError: (kim_error) in_err;

+ (BOOL) validatePrincipalWithName: (NSString *) name
                             realm: (NSString *) realm;

+ (BOOL) validateIdentity: (NSString *) identityString;

+ (NSString *) expandedIdentity: (NSString *) identityString;

+ (NSDictionary *) dictionaryForKimOptions: (kim_options) options;
+ (kim_options) kimOptionsForDictionary: (NSDictionary *) aDict;

+ (NSDictionary *) dictionaryForKimSelectionHints: (kim_selection_hints) hints;

+ (NSUInteger)minValidLifetime;
+ (NSUInteger)maxValidLifetime;
+ (NSUInteger)minRenewableLifetime;
+ (NSUInteger)maxRenewableLifetime;

@end

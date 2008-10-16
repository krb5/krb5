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

#import "KIMUtilities.h"

@implementation KIMUtilities

+ (NSString *) stringForLastKIMError: (kim_error) in_err
{
    kim_error err = KIM_NO_ERROR;
    kim_string string = NULL;
    NSString *result = nil;
    
    err = kim_string_create_for_last_error(&string, in_err);
    if (!err) {
        result = [NSString stringWithUTF8String:string];
    }
    kim_string_free(&string);
    
    return result;
}

+ (BOOL) validatePrincipalWithName: (NSString *) name
                             realm: (NSString *) realm
{
    kim_error err = KIM_NO_ERROR;
    NSString *identityString = nil;
    
    if (!name || !realm || [name length] == 0) {
        err = KIM_BAD_PRINCIPAL_STRING_ERR;
    }
    if (!err) {
        identityString = [[NSString alloc] initWithFormat:@"%@@%@", name, realm];
        err = [KIMUtilities validateIdentity:identityString];
        [identityString release];
    }
    
    return (err == KIM_NO_ERROR);
}

+ (BOOL) validateIdentity: (NSString *) identityString
{
    kim_error err = KIM_NO_ERROR;
    kim_identity identity = NULL;
    
    if (!identityString || [identityString length] <= 1) {
        err = KIM_BAD_PRINCIPAL_STRING_ERR;
    }
    if (!err) {
        err = kim_identity_create_from_string(&identity, [identityString UTF8String]);
    }
    if (!identity) {
        err = KIM_BAD_PRINCIPAL_STRING_ERR;
    }
    kim_identity_free(&identity);
    
    return (err == KIM_NO_ERROR);
}

+ (NSString *) expandedIdentity: (NSString *) identityString
{
    NSString *result = nil;
    kim_error err = KIM_NO_ERROR;
    kim_identity identity = NULL;
    kim_string validated_string = NULL;
    
    // convert to how it will actually be
    // e.g. foo becomes foo@ATHENA.MIT.EDU
    // for the purpose of matching to a favorite
    if (!identityString) {
        err = KIM_BAD_PRINCIPAL_STRING_ERR;
    }
    if (!err) {
        err = kim_identity_create_from_string(&identity, [identityString UTF8String]);
    }
    if (!err && identity) {
        err = kim_identity_get_display_string(identity, &validated_string);
    }
    if (!err && validated_string) {
        result = [NSString stringWithUTF8String:validated_string];
    }
    kim_identity_free(&identity);
    kim_string_free(&validated_string);
    
    return result;
}

+ (NSDictionary *) dictionaryForKimOptions: (kim_options) options
{
    kim_error err = KIM_NO_ERROR;
    kim_preferences prefs = NULL;
    NSMutableDictionary *newDict = [NSMutableDictionary dictionaryWithCapacity:8];
    kim_boolean addressless = FALSE;
    kim_boolean forwardable = FALSE;
    kim_boolean proxiable = FALSE;
    kim_boolean renewable = FALSE;
    kim_lifetime valid_lifetime = 0;
    kim_lifetime renewal_lifetime = 0;
    kim_string service_name = NULL;
    kim_time start_time = 0;
    
    if (options == KIM_OPTIONS_DEFAULT) {
        [newDict setObject:[NSNumber numberWithBool:YES]
                    forKey:@"usesDefaultTicketOptions"];
        err = kim_preferences_create(&prefs);
        if (!err) {
            err = kim_preferences_get_options(prefs, &options);
        }
    }
    
    if (!err) {
        err = kim_options_get_addressless(options, &addressless);
    }
    if (!err) {
        [newDict setValue:[NSNumber numberWithBool:addressless] 
                                            forKey:@"addressless"];
    }
    if (!err) {
        err = kim_options_get_forwardable(options, &forwardable);
    }
    if (!err) {
        [newDict setValue:[NSNumber numberWithBool:forwardable] 
                                            forKey:@"forwardable"];
    }
    if (!err) {
        err = kim_options_get_proxiable(options, &proxiable);
    }
    if (!err) {
        [newDict setValue:[NSNumber numberWithBool:proxiable] 
                                            forKey:@"proxiable"];
    }
    if (!err) {
        err = kim_options_get_renewable(options, &renewable);
    }
    if (!err) {
        [newDict setValue:[NSNumber numberWithBool:renewable] 
                                            forKey:@"renewable"];
    }
    if (!err) {
        err = kim_options_get_lifetime(options, &valid_lifetime);
    }
    if (!err) {
        [newDict setValue:[NSNumber numberWithInteger:valid_lifetime] 
                                               forKey:@"valid_lifetime"];
    }
    if (!err) {
        err = kim_options_get_renewal_lifetime(options, &renewal_lifetime);
    }
    if (!err) {
        [newDict setValue:[NSNumber numberWithInteger:renewal_lifetime] 
                                               forKey:@"renewal_lifetime"];
    }
    if (!err) {
        err = kim_options_get_service_name(options, &service_name);
    }
    if (!err) {
        [newDict setValue:(service_name) ? 
         [NSString stringWithUTF8String:service_name] : @""
                   forKey:@"service_name"];
    }
    if (!err) {
        err = kim_options_get_start_time(options, &start_time);
    }
    if (!err) {
        [newDict setValue:[NSNumber numberWithInteger:start_time] 
                   forKey:@"start_time"];
    }

    // only free options if it was allocated by this method
    if (prefs) {
        kim_options_free(&options);
        kim_preferences_free(&prefs);
    }

    return newDict;
}

+ (kim_options) kimOptionsForDictionary: (NSDictionary *) aDict
{
    kim_error err = KIM_NO_ERROR;
    kim_options options = NULL;
    kim_boolean addressless;
    kim_boolean forwardable;
    kim_boolean proxiable;
    kim_boolean renewable;
    kim_lifetime valid_lifetime;
    kim_lifetime renewal_lifetime;
    kim_string service_name;
    kim_time start_time;

    if (!aDict || [[aDict objectForKey:@"usesDefaultTicketOptions"] boolValue]) {
        return KIM_OPTIONS_DEFAULT;
    }
    
    addressless = [[aDict valueForKey:@"addressless"] boolValue];
    forwardable = [[aDict valueForKey:@"forwardable"] boolValue];
    proxiable = [[aDict valueForKey:@"proxiable"] boolValue];
    renewable = [[aDict valueForKey:@"renewable"] boolValue];
    valid_lifetime = [[aDict valueForKey:@"valid_lifetime"] integerValue];
    renewal_lifetime = [[aDict valueForKey:@"renewal_lifetime"] integerValue];
    service_name = ([[aDict valueForKey:@"service_name"] length] > 0) ?
    [[aDict valueForKey:@"service_name"] UTF8String] : NULL;
    start_time = [[aDict valueForKey:@"start_time"] integerValue];
    
    if (!err) {
        err = kim_options_create (&options);
    }
    if (!err) {
        err = kim_options_set_addressless(options, addressless);
    }
    if (!err) {
        err = kim_options_set_forwardable(options, forwardable);
    }
    if (!err) {
        err = kim_options_set_proxiable(options, proxiable);
    }
    if (!err) {
        err = kim_options_set_renewable(options, renewable);
    }
    if (!err) {
        err = kim_options_set_lifetime(options, valid_lifetime);
    }
    if (!err) {
        err = kim_options_set_renewal_lifetime(options, renewal_lifetime);
    }
    if (!err) {
        err = kim_options_set_service_name(options, service_name);
    }
    if (!err) {
        err = kim_options_set_start_time(options, start_time);
    }
    
    return options;
}

+ (NSDictionary *) dictionaryForKimSelectionHints: (kim_selection_hints) hints
{
    kim_error err = KIM_NO_ERROR;

    NSMutableDictionary *newDict = [NSMutableDictionary dictionaryWithCapacity:20];
    
    kim_string explanation             = NULL;
    kim_options options                = NULL;
    kim_string service_identity        = NULL;
    kim_string client_realm            = NULL;
    kim_string user                    = NULL;
    kim_string service_realm           = NULL;
    kim_string service                 = NULL;
    kim_string server                  = NULL;

    if (!err) {
        err = kim_selection_hints_get_explanation(hints, &explanation);
        [newDict setValue:(explanation) ? [NSString stringWithUTF8String:explanation] : @"" 
                   forKey:@"explanation"];
    }
    if (!err) {
        err = kim_selection_hints_get_options(hints, &options);
        [newDict setValue:[KIMUtilities dictionaryForKimOptions:options]
                   forKey:@"options"];
    }
    if (!err) {
        err = kim_selection_hints_get_hint(hints, kim_hint_key_client_realm, &client_realm);
        [newDict setValue:(client_realm) ? [NSString stringWithUTF8String:client_realm] : @"" 
                    forKey:@"client_realm"];
    }
    if (!err) {
        err = kim_selection_hints_get_hint(hints, kim_hint_key_user, &user);
        [newDict setValue:(user) ? [NSString stringWithUTF8String:user] : @"" 
                   forKey:@"user"];
    }
    if (!err) {
        err = kim_selection_hints_get_hint(hints, kim_hint_key_service_realm, &service_realm);
        [newDict setValue:(service_realm) ? [NSString stringWithUTF8String:service_realm] : @"" 
                   forKey:@"service_realm"];
    }
    if (!err) {
        err = kim_selection_hints_get_hint(hints, kim_hint_key_service, &service);
        [newDict setValue:(service) ? [NSString stringWithUTF8String:service] : @"" 
                   forKey:@"service"];
    }
    if (!err) {
        err = kim_selection_hints_get_hint(hints, kim_hint_key_server, &server);
        [newDict setValue:(server) ? [NSString stringWithUTF8String:server] : @"" 
                   forKey:@"server"];
    }
    if (!err) {
        err = kim_selection_hints_get_hint(hints, kim_hint_key_service_identity, &service_identity);
        [newDict setValue:(service_identity) ? [NSString stringWithUTF8String:service_identity] : @"" 
                   forKey:@"service_identity"];
    }
    
    return newDict;
}

+ (NSUInteger)minValidLifetime
{
    kim_error err = KIM_NO_ERROR;
    kim_preferences prefs = NULL;
    kim_lifetime value = 0;
    
    err = kim_preferences_create(&prefs);
    
    if (!err) {
        kim_preferences_get_minimum_lifetime(prefs, &value);
    }
    
    return (NSUInteger) value;
}

+ (NSUInteger)maxValidLifetime
{
    kim_error err = KIM_NO_ERROR;
    kim_preferences prefs = NULL;
    kim_lifetime value = 0;
    
    err = kim_preferences_create(&prefs);
    
    if (!err) {
        kim_preferences_get_maximum_lifetime(prefs, &value);
    }
    
    return (NSUInteger) value;
}

+ (NSUInteger)minRenewableLifetime
{
    kim_error err = KIM_NO_ERROR;
    kim_preferences prefs = NULL;
    kim_lifetime value = 0;
    
    err = kim_preferences_create(&prefs);
    
    if (!err) {
        kim_preferences_get_minimum_renewal_lifetime(prefs, &value);
    }
    
    return (NSUInteger) value;
}

+ (NSUInteger)maxRenewableLifetime
{
    kim_error err = KIM_NO_ERROR;
    kim_preferences prefs = NULL;
    kim_lifetime value = 0;
    
    err = kim_preferences_create(&prefs);
    
    if (!err) {
        kim_preferences_get_maximum_renewal_lifetime(prefs, &value);
    }
    
    return (NSUInteger) value;
}

@end

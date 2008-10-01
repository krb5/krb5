//
//  KIMUtilities.m
//  Kerberos5
//
//  Created by Justin Anderson on 9/28/08.
//  Copyright 2008 MIT. All rights reserved.
//

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
    kim_identity identity = NULL;
    NSString *principal = nil;
    
    if (!name || !realm || [name length] == 0) {
        err = KIM_BAD_PRINCIPAL_STRING_ERR;
    }
    if (!err) {
        principal = [[NSString alloc] initWithFormat:@"%@@%@", name, realm];
        err = kim_identity_create_from_string(&identity, [principal UTF8String]);
        [principal release];
    }
    if (!identity) {
        err = KIM_BAD_PRINCIPAL_STRING_ERR;
    }
    kim_identity_free(&identity);
    
    return (err == KIM_NO_ERROR);
}

+ (NSDictionary *) dictionaryForKimOptions: (kim_options) options
{
    kim_error err = KIM_NO_ERROR;
    NSMutableDictionary *newDict = [NSMutableDictionary dictionaryWithCapacity:8];
    kim_boolean addressless = FALSE;
    kim_boolean forwardable = FALSE;
    kim_boolean proxiable = FALSE;
    kim_boolean renewable = FALSE;
    kim_lifetime valid_lifetime = 0;
    kim_lifetime renewal_lifetime = 0;
    kim_string service_name = NULL;
    kim_time start_time = 0;
    
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

    return newDict;
}

+ (kim_options) kimOptionsForDictionary: (NSDictionary *) aDict
{
    kim_error err = KIM_NO_ERROR;
    kim_options options = NULL;
    kim_boolean addressless = [[aDict valueForKey:@"addressless"] boolValue];
    kim_boolean forwardable = [[aDict valueForKey:@"forwardable"] boolValue];
    kim_boolean proxiable = [[aDict valueForKey:@"proxiable"] boolValue];
    kim_boolean renewable = [[aDict valueForKey:@"renewable"] boolValue];
    kim_lifetime valid_lifetime = [[aDict valueForKey:@"valid_lifetime"] integerValue];
    kim_lifetime renewal_lifetime = [[aDict valueForKey:@"renewal_lifetime"] integerValue];
    kim_string service_name = ([[aDict valueForKey:@"service_name"] length] > 0) ?
                               [[aDict valueForKey:@"service_name"] UTF8String] : NULL;
    kim_time start_time = [[aDict valueForKey:@"start_time"] integerValue];
    
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

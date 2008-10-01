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

@end

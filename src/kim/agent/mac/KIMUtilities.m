//
//  KIMUtilities.m
//  Kerberos5
//
//  Created by Justin Anderson on 9/28/08.
//  Copyright 2008 MIT. All rights reserved.
//

#import "KIMUtilities.h"


@implementation NSString (KIMUtilities)

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

@end

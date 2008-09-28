//
//  KIMUtilities.h
//  Kerberos5
//
//  Created by Justin Anderson on 9/28/08.
//  Copyright 2008 MIT. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <Kerberos/kim.h>

@interface NSString (KIMUtilities)

+ (NSString *) stringForLastKIMError: (kim_error) in_err;

@end

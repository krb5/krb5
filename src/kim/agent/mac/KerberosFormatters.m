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

#import "KerberosFormatters.h"

#define EXPIRED_STRING @"Expired"

@implementation KerberosTimeFormatter

/*
 * For display of Kerberos expiration times.
 * Converts an NSDate into an NSString like "09:53" for 9 hours and 53 minutes
 * in the future. Returns @"Expired" if expiration date is before now.
 */
- (NSString *)stringForObjectValue:(id)anObject
{
    NSString *result = nil;
    if (anObject == nil || ![anObject respondsToSelector:@selector(timeIntervalSince1970)]) {
	result = [NSString stringWithFormat:@"%s given invalid object %@", 
                  _cmd, NSStringFromClass([anObject class])];
    }
    else {
	time_t lifetime = [(NSDate *)anObject timeIntervalSince1970] - time(NULL);
	
	if (lifetime > 0) {
	    time_t seconds  = (lifetime % 60);
	    time_t minutes  = (lifetime / 60 % 60);
	    time_t hours    = (lifetime / 3600 % 24);
	    time_t days     = (lifetime / 86400);
	    
	    if (seconds >  0) { seconds = 0; minutes++; }
	    if (minutes > 59) { minutes = 0; hours++; }
	    if (hours   > 23) { hours   = 0; days++; }
	    
	    result = [NSString stringWithFormat:@"%02ld:%02ld", hours, minutes];
	} else {
	    result = EXPIRED_STRING;
	}
    }
    
    return result;
}

/*
 * Converts NSStrings like @"09:53" into NSDate representation of that point 
 * in the future. If string is @"Expired", NSDate is set to 1970.
 */

- (BOOL)getObjectValue:(id *)anObject 
	     forString:(NSString *)string 
      errorDescription:(NSString **)error
{
    NSArray *tokens = [string componentsSeparatedByString:@":"];
    *anObject = nil;
    
    if ([tokens count] == 2) {
	NSInteger hours = [[tokens objectAtIndex:0] longValue];
	NSInteger minutes = [[tokens objectAtIndex:1] longValue];
	*anObject = [NSDate dateWithTimeIntervalSince1970:(hours * 60 * 60) + (minutes * 60)];
    } else if ([string isEqualToString:EXPIRED_STRING]) {
	*anObject = [NSDate dateWithTimeIntervalSince1970:0];
    }
    
    if (*anObject == nil) {
	return false;
    }
    return true;
}

- (NSAttributedString *)attributedStringForObjectValue:(id)anObject 
				 withDefaultAttributes:(NSDictionary *)attributes
{
    NSAttributedString *resultString = nil;
    NSString *plainString = [self stringForObjectValue:anObject];
    NSMutableDictionary *newAttributes = [attributes mutableCopy];
    
    if ([plainString isEqualToString:EXPIRED_STRING]) {
	[newAttributes setObject:[NSColor redColor] 
			  forKey:NSForegroundColorAttributeName];
	[newAttributes setObject: [NSNumber numberWithFloat: 0.3]
			  forKey: NSObliquenessAttributeName];
    }
    
    resultString = [[NSAttributedString alloc] initWithString:plainString attributes:newAttributes];
    [newAttributes release];
    
    return [resultString autorelease];
}
@end

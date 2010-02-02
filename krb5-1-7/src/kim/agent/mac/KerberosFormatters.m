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

@implementation KerberosTimeFormatter

@synthesize displaySeconds;
@synthesize displayShortFormat;

- (id) init
{
    self = [super init];
    if (self != nil) {
        // default to --:-- style
        self.displaySeconds = NO;
        self.displayShortFormat = YES;
    }
    return self;
}

/*
 * For display of Kerberos expiration times.
 * Converts an NSDate into an NSString like "09:53" for 9 hours and 53 minutes
 * in the future. Returns @"Expired" if expiration date is before now.
 */
- (NSString *)stringForObjectValue:(id)anObject
{
    NSString *result = nil;
    
    if (anObject) {
        if ([anObject respondsToSelector:@selector(timeIntervalSinceNow)]) {
            result = [self stringForLifetime:(time_t)[(NSDate *)anObject timeIntervalSinceNow]];
        }
        else if ([anObject respondsToSelector:@selector(unsignedIntegerValue)]) {
            result = [self stringForLifetime:(time_t)[(NSNumber *)anObject unsignedIntegerValue]];
        }
    }
    
    return result;
}

- (NSAttributedString *)attributedStringForObjectValue:(id)anObject 
				 withDefaultAttributes:(NSDictionary *)attributes
{
    return [[[NSAttributedString alloc] initWithString:[self stringForObjectValue:anObject] 
                                            attributes:attributes] autorelease];
}

- (NSString *) stringForLifetime: (time_t) lifetime
{
    NSMutableString *string = [NSMutableString string];
    NSString *separatorKey = (self.displayShortFormat) ? @"LifetimeStringSeparatorShortFormat" : 
    @"LifetimeStringSeparatorLongFormat";
    NSString *separator = NSLocalizedStringFromTable (separatorKey, @"KerberosFormatters", NULL);
    NSString *key = NULL;
    
    // Break the lifetime up into time units
    time_t days     = (lifetime / 86400);
    time_t hours    = (lifetime / 3600 % 24);
    time_t minutes  = (lifetime / 60 % 60);
    time_t seconds  = (lifetime % 60);
    
    if (lifetime > 0) {
        // If we aren't going to display seconds, round up
        if (!self.displaySeconds) {
            if (seconds >  0) { seconds = 0; minutes++; }
            if (minutes > 59) { minutes = 0; hours++; }
            if (hours   > 23) { hours   = 0; days++; }
        }
        
        if (days > 0 && !self.displayShortFormat) {
            if (self.displayShortFormat) { 
                key = (days > 1) ? @"LifetimeStringDaysShortFormat" : @"LifetimeStringDayShortFormat"; 
            } else { 
                key = (days > 1) ? @"LifetimeStringDaysLongFormat" : @"LifetimeStringDayLongFormat";
            }
            [string appendFormat: NSLocalizedStringFromTable (key, @"KerberosFormatters", NULL), days];
        }
        
        if ((hours > 0) || self.displayShortFormat) {
            if (self.displayShortFormat) { 
                key = (hours > 1) ? @"LifetimeStringHoursShortFormat" : @"LifetimeStringHourShortFormat"; 
                hours += days * 24;
                days = 0;
            } else { 
                key = (hours > 1) ? @"LifetimeStringHoursLongFormat" : @"LifetimeStringHourLongFormat";
            }
            if ([string length] > 0) { [string appendString: separator]; }
            [string appendFormat: NSLocalizedStringFromTable (key, @"KerberosFormatters", NULL), hours];
        }
        
        if ((minutes > 0) || self.displayShortFormat) {
            if (self.displayShortFormat) { 
                key = (minutes > 1) ? @"LifetimeStringMinutesShortFormat" : @"LifetimeStringMinuteShortFormat"; 
            } else { 
                key = (minutes > 1) ? @"LifetimeStringMinutesLongFormat" : @"LifetimeStringMinuteLongFormat";
            }
            if ([string length] > 0) { [string appendString: separator]; }
            [string appendFormat: NSLocalizedStringFromTable (key, @"KerberosFormatters", NULL), minutes];
        }
        
        if (self.displaySeconds && ((seconds > 0) || self.displayShortFormat)) {
            if (self.displayShortFormat) { 
                key = (seconds > 1) ? @"LifetimeStringSecondsShortFormat" : @"LifetimeStringSecondShortFormat"; 
            } else { 
                key = (seconds > 1) ? @"LifetimeStringSecondsLongFormat" : @"LifetimeStringSecondLongFormat";
            }
            if ([string length] > 0) { [string appendString: separator]; }
            [string appendFormat: NSLocalizedStringFromTable (key, @"KerberosFormatters", NULL), seconds];
        }
    } else {
        key = @"LifetimeStringExpired";
        [string appendString: NSLocalizedStringFromTable (key, @"KerberosFormatters", NULL)];
    }
    
    // Return an NSString (non-mutable) from our mutable temporary
    return [NSString stringWithString: string];
}

@end

@implementation KerberosFavoriteFormatter

/*
 * For displaying favorite status of KIM identities.
 * Converts an NSNumber containing a boolean value into an NSString.
 * If true, returns a heart character, /u2665.
 * If false, returns empty string @"".
 */
- (NSString *)stringForObjectValue:(id)anObject
{
    NSString *key = nil;
    if (anObject == nil || 
        ![anObject respondsToSelector:@selector(boolValue)] ||
        ([(NSNumber *)anObject boolValue] == FALSE)) {
        key = @"FavoriteStringNotFavorite";
    }
    else {
        key = @"FavoriteStringIsFavorite";
    }
    
    return NSLocalizedStringFromTable (key, @"KerberosFormatters", NULL);
}

- (NSAttributedString *)attributedStringForObjectValue:(id)anObject 
				 withDefaultAttributes:(NSDictionary *)attributes
{
    return [[[NSAttributedString alloc] initWithString:[self stringForObjectValue:anObject] 
                                            attributes:attributes] autorelease];
}

@end

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

#import "Identities.h"
#import <Kerberos/Kerberos.h>

#define VALID_LIFETIME_INCREMENT (5 * 60)
#define RENEWABLE_LIFETIME_INCREMENT (15 * 60)

@interface Identity ()

- (NSString *)stringForLifetime:(NSUInteger)lifetime;

@end


@implementation Identity

@synthesize state;
@synthesize expiration_time;
@synthesize favorite;

#pragma mark Initialization & Comparison

// ---------------------------------------------------------------------------

+ (NSSet *)keyPathsForValuesAffectingValueForKey:(NSString *)key
{
    NSMutableSet *result = [[super keyPathsForValuesAffectingValueForKey:key] mutableCopy];
    NSSet *otherKeys = nil;
    
    if ([key isEqualToString:@"principalString"]) {
        otherKeys = [NSSet setWithObjects:@"kimIdentity", nil];
    } 
    else if ([key isEqualToString:@"expirationDate"]) {
        otherKeys = [NSSet setWithObjects:@"kimOptions", @"state", @"expirationTime", nil];
    } 
    else if ([key isEqualToString:@"expirationString"]) {
        otherKeys = [NSSet setWithObjects:@"kimOptions", @"state", @"expirationTime", nil];
    }
    else if ([key isEqualToString:@"isProxiable"]) {
        otherKeys = [NSSet setWithObjects:@"kimOptions", nil];
    }
    else if ([key isEqualToString:@"isForwardable"]) {
        otherKeys = [NSSet setWithObjects:@"kimOptions", nil];
    }
    else if ([key isEqualToString:@"isAddressless"]) {
        otherKeys = [NSSet setWithObjects:@"kimOptions", nil];
    }
    else if ([key isEqualToString:@"isRenewable"]) {
        otherKeys = [NSSet setWithObjects:@"kimOptions", nil];
    }
    else if ([key isEqualToString:@"validLifetime"]) {
        otherKeys = [NSSet setWithObjects:@"kimOptions", nil];
    }
    else if ([key isEqualToString:@"renewableLifetime"]) {
        otherKeys = [NSSet setWithObjects:@"kimOptions", nil];
    }
    else if ([key isEqualToString:@"validLifetimeString"]) {
        otherKeys = [NSSet setWithObjects:@"kimOptions", @"validLifetime", nil];
    }
    else if ([key isEqualToString:@"renewableLifetimeString"]) {
        otherKeys = [NSSet setWithObjects:@"kimOptions", @"renewableLifetime", nil];
    }
    
    [result unionSet:otherKeys];
    
    return [result autorelease];
}

// ---------------------------------------------------------------------------

- (id) init
{
    return [self initWithIdentity: NULL options: NULL];
}

// ---------------------------------------------------------------------------

- (id) initWithIdentity: (kim_identity) identity options: (kim_options) options
{
    if ((self = [super init])) {
        self.kimIdentity = identity;
        self.kimOptions = options;
        self.state = kim_credentials_state_not_yet_valid;
        self.expiration_time = 0;
        self.favorite = FALSE;
    }
    
    return self;
}

// ---------------------------------------------------------------------------

- (id) initWithFavoriteIdentity: (kim_identity) identity options: (kim_options) options
{
    if ((self = [self initWithIdentity: identity options: options])) {
        self.favorite = TRUE;
    }
    
    return self;
}

// ---------------------------------------------------------------------------

- (BOOL) isEqualToKIMIdentity: (kim_identity) identity
{
    kim_error err = KIM_NO_ERROR;
    kim_comparison comparison;
    
    err = kim_identity_compare (kimIdentity, identity, &comparison);
    
    return (!err && kim_comparison_is_equal_to (comparison));
}

// ---------------------------------------------------------------------------

- (BOOL) isEqual: (Identity *)otherIdentity
{
    return ([self isEqualToKIMIdentity:otherIdentity.kimIdentity]);
}

// ---------------------------------------------------------------------------

- (NSUInteger)hash
{
    return [self.principalString hash];
}

// ---------------------------------------------------------------------------

- (NSComparisonResult) compare: (Identity *)otherIdentity
{
    return ([self.principalString compare:otherIdentity.principalString]);
}

#pragma mark Actions

// ---------------------------------------------------------------------------

- (void) resetOptions
{
    // property setter converts NULL into actual kim_options with default settings
    self.kimOptions = NULL;
}

// ---------------------------------------------------------------------------

- (void) toggleFavorite
{
    if (self.favorite) {
	[self removeFromFavorites];
    } else {
	[self addToFavorites];
    }
}

// ---------------------------------------------------------------------------

- (BOOL) addToFavorites
{
    kim_error err = KIM_NO_ERROR;
    kim_preferences preferences = NULL;
    kim_options options = NULL;
    kim_string error_string = NULL;
    err = kim_preferences_create(&preferences);
    
    if (!err) {
	err = kim_options_create(&options);
    }
    
    if (!err) {
	err = kim_preferences_add_favorite_identity(preferences, self.kimIdentity, options);
    }
    if (!err) {
	err = kim_preferences_synchronize(preferences);
    }
    if (options) {
	kim_options_free(&options);
    }
    kim_preferences_free(&preferences);
    if (!err) {
	self.favorite = true;
    } else {
	kim_string_create_for_last_error(&error_string, err);
	NSLog(@"%s failed with %s", _cmd, error_string);
    }
    return (err != KIM_NO_ERROR);
}

// ---------------------------------------------------------------------------

- (BOOL) removeFromFavorites
{
    kim_error err = KIM_NO_ERROR;
    kim_preferences preferences = NULL;
    kim_options options = NULL;
    kim_string error_string = NULL;
    err = kim_preferences_create(&preferences);
    
    if (!err) {
	err = kim_options_create(&options);
    }
    
    if (!err) {
	err = kim_preferences_remove_favorite_identity(preferences, self.kimIdentity);
    }
    if (!err) {
	err = kim_preferences_synchronize(preferences);
    }
    if (options) {
	kim_options_free(&options);
    }
    kim_preferences_free(&preferences);
    if (!err) {
	self.favorite = false;
    } else {
	kim_string_create_for_last_error(&error_string, err);
	NSLog(@"%s failed with %s", _cmd, error_string);
    }
    return (err != KIM_NO_ERROR);
}

#pragma mark Accessors

// ---------------------------------------------------------------------------

- (NSDate *) expirationDate
{
    return [NSDate dateWithTimeIntervalSince1970:expiration_time];
}

// ---------------------------------------------------------------------------

- (BOOL) hasCCache
{
    kim_error err = KIM_NO_ERROR;
    kim_ccache ccache = NULL;
    
    err = kim_ccache_create_from_client_identity(&ccache, self.kimIdentity);
    
    if (!err && ccache) {
        return TRUE;
    }
    
    return FALSE;
}


// ---------------------------------------------------------------------------

- (kim_identity) kimIdentity
{
    return kimIdentity;
}

// ---------------------------------------------------------------------------

- (void) setKimIdentity:(kim_identity)newKimIdentity
{
    kim_error err = KIM_NO_ERROR;
    kim_string string = NULL;

    if (!kimIdentity || kimIdentity != newKimIdentity) {
        [self willChangeValueForKey:@"kimOptions"];

        kim_identity_free(&kimIdentity);
        kimIdentity = NULL;
        if (newKimIdentity != NULL) {
            kim_identity_get_display_string(newKimIdentity, &string);
            err = kim_identity_copy(&kimIdentity, newKimIdentity);
        }
        
        [self didChangeValueForKey:@"kimOptions"];
    }
    
    if (err) {
        NSLog(@"%s got error %s", _cmd, error_message(err));
    }
}

// ---------------------------------------------------------------------------

- (kim_options) kimOptions
{
    return kimOptions;
}

// ---------------------------------------------------------------------------

- (void) setKimOptions:(kim_options)newKimOptions
{
    // Passing NULL resets to default options
    kim_error err = KIM_NO_ERROR;
    
    if (!kimOptions || kimOptions != newKimOptions) {
        [self willChangeValueForKey:@"kimOptions"];
        
        kim_options_free(&kimOptions);
        kimOptions = NULL;

        if (newKimOptions == NULL) {
            err = kim_options_create(&kimOptions);
        } else {
            err = kim_options_copy(&kimOptions, newKimOptions);
        }

        [self didChangeValueForKey:@"kimOptions"];
    }
}

// ---------------------------------------------------------------------------

- (BOOL) isRenewable
{
    kim_error err = KIM_NO_ERROR;
    kim_boolean result = FALSE;
    kim_options options = self.kimOptions;
    
    err = kim_options_get_renewable(options, &result);
    
    return (result != 0);
}

// ---------------------------------------------------------------------------

- (void) setIsRenewable: (BOOL) value
{
    kim_error err = KIM_NO_ERROR;
    kim_options options = self.kimOptions;
    
    err = kim_options_set_renewable(options, value);
}

// ---------------------------------------------------------------------------

- (BOOL) isForwardable
{
    kim_error err = KIM_NO_ERROR;
    kim_boolean result = FALSE;
    kim_options options = self.kimOptions;
    
    err = kim_options_get_forwardable(options, &result);
    
    return (result != 0);
}

// ---------------------------------------------------------------------------

- (void) setIsForwardable: (BOOL) value
{
    kim_error err = KIM_NO_ERROR;
    kim_options options = self.kimOptions;
    
    err = kim_options_set_forwardable(options, value);
}

// ---------------------------------------------------------------------------

- (BOOL) isAddressless
{
    kim_error err = KIM_NO_ERROR;
    kim_boolean result = FALSE;
    kim_options options = self.kimOptions;
    
    err = kim_options_get_addressless(options, &result);
    
    return (result != 0);
}

// ---------------------------------------------------------------------------

- (void) setIsAddressless: (BOOL) value
{
    kim_error err = KIM_NO_ERROR;
    kim_options options = self.kimOptions;
    
    err = kim_options_set_addressless(options, value);
}

// ---------------------------------------------------------------------------

- (BOOL) isProxiable
{
    kim_error err = KIM_NO_ERROR;
    kim_boolean result = FALSE;
    kim_options options = self.kimOptions;
    
    err = kim_options_get_proxiable(options, &result);
    
    return (result != 0);
}

// ---------------------------------------------------------------------------

- (void) setIsProxiable: (BOOL) value
{
    kim_error err = KIM_NO_ERROR;
    kim_options options = self.kimOptions;
    
    err = kim_options_set_proxiable(options, value);
}

// ---------------------------------------------------------------------------

- (NSUInteger) validLifetime
{
    kim_error err = KIM_NO_ERROR;
    kim_lifetime value = 0;
    kim_options options = self.kimOptions;

    err = kim_options_get_lifetime(options, &value);
    
    return (NSUInteger) value;
}

// ---------------------------------------------------------------------------

- (void) setValidLifetime: (NSUInteger) newLifetime
{
    kim_error err = KIM_NO_ERROR;
    kim_options options = self.kimOptions;
    
    // round to nearest five minutes
    newLifetime = (newLifetime / VALID_LIFETIME_INCREMENT) * VALID_LIFETIME_INCREMENT;
    
    err = kim_options_set_lifetime(options, (kim_lifetime) newLifetime);
}

// ---------------------------------------------------------------------------

- (NSUInteger) renewableLifetime
{
    kim_error err = KIM_NO_ERROR;
    kim_lifetime value = 0;
    kim_options options = self.kimOptions;
    
    err = kim_options_get_renewal_lifetime(options, &value);

    return (NSUInteger) value;
}

// ---------------------------------------------------------------------------

- (void) setRenewableLifetime: (NSUInteger) newLifetime
{
    kim_error err = KIM_NO_ERROR;
    kim_options options = self.kimOptions;

    // round to nearest five minutes
    newLifetime = (newLifetime / RENEWABLE_LIFETIME_INCREMENT) * RENEWABLE_LIFETIME_INCREMENT;
    
    err = kim_options_set_renewal_lifetime(options, (kim_lifetime) newLifetime);
}

#pragma mark String representations

// ---------------------------------------------------------------------------

- (NSString *) principalString
{
    kim_error err = KIM_NO_ERROR;
    kim_string display_string = NULL;
    NSString *result = nil;
    
    if (self.kimIdentity) {
        err = kim_identity_get_display_string(self.kimIdentity, &display_string);
    }
    
    if (!err && display_string) {
        result = [NSString stringWithUTF8String:display_string];
    }
    else {
        result = @"-";
    }
    
    if (err) {
        NSLog(@"%s got error %s", _cmd, error_message(err));
    }
    
    kim_string_free(&display_string);
    
    return result;
}

// ---------------------------------------------------------------------------

- (NSString *) componentsString
{
    kim_error err = KIM_NO_ERROR;
    kim_string display_string = NULL;
    NSString *result = @"";
    
    err = kim_identity_get_display_string(kimIdentity, &display_string);
    // err = kim_identity_get_components(kimIdentity, &display_string);
    
    if (!err) {
        NSRange atRange;
        
        result = [NSString stringWithUTF8String:display_string];
        atRange = [result rangeOfString:@"@" options:NSBackwardsSearch];
        result = [result substringToIndex:atRange.location];
    }
    
    kim_string_free(&display_string);
    
    return result;
}

// ---------------------------------------------------------------------------

- (NSString *) realmString
{
    kim_error err = KIM_NO_ERROR;
    kim_string display_string = NULL;
    NSString *result = @"";
    
    err = kim_identity_get_realm(kimIdentity, &display_string);
    
    if (!err) {
        result = [NSString stringWithUTF8String:display_string];
    }
    
    kim_string_free(&display_string);
    
    return result;
}

// ---------------------------------------------------------------------------

- (kim_error) setPrincipalComponents: (NSString *) componentsString realm: (NSString *) realmString
{
    kim_error err = KIM_NO_ERROR;
    kim_identity new_identity = NULL;
    char *principal_string = NULL;
    
    asprintf(&principal_string, "%s@%s", 
             [componentsString UTF8String], [realmString UTF8String]);
    
    if (principal_string) {
        err = kim_identity_create_from_string(&new_identity, principal_string);
    }
        
    self.kimIdentity = new_identity;
    
    kim_identity_free(&new_identity);
    if (principal_string) {
        free(principal_string);
    }
    
    return err;
}

// ---------------------------------------------------------------------------

- (NSString *) expirationString
{
    NSString *result = nil;
    
    if (expiration_time > 0) {
	time_t now = time(NULL);
	time_t lifetime = expiration_time - now;
	time_t seconds  = (lifetime % 60);
	time_t minutes  = (lifetime / 60 % 60);
	time_t hours    = (lifetime / 3600 % 24);
	time_t days     = (lifetime / 86400);
	
	if (seconds >  0) { seconds = 0; minutes++; }
	if (minutes > 59) { minutes = 0; hours++; }
	if (hours   > 23) { hours   = 0; days++; }
	
	result = [NSString stringWithFormat:@"%02ld:%02ld", hours, minutes];
    } else {
	result = @"--:--";
    }
    
    return result;
}

// ---------------------------------------------------------------------------

- (NSString *) validLifetimeString
{
    return [self stringForLifetime:self.validLifetime];
}

// ---------------------------------------------------------------------------

- (NSString *) renewableLifetimeString
{
    return [self stringForLifetime:self.renewableLifetime];
}

// ---------------------------------------------------------------------------

- (NSString *)stringForLifetime:(NSUInteger)lifetime
{
    NSMutableArray *parts = nil;
    NSUInteger days, hours, minutes, seconds;
    
    days     = (lifetime / 86400);
    hours    = (lifetime / (60 * 60) % 24);
    minutes  = (lifetime / 60 % 60);
    seconds  = (lifetime % 60);
    
    if (seconds >  0) { seconds = 0; minutes++; }
    if (minutes > 59) { minutes = 0; hours++; }
    if (hours   > 23) { hours   = 0; days++; }
    
    parts = [NSMutableArray arrayWithCapacity:3];
    if (days > 0) {
        [parts addObject:[NSString stringWithFormat:@"%d days", days]];
    }
    if (hours > 0) {
        [parts addObject:[NSString stringWithFormat:@"%d hours", hours]];
    }
    if (minutes > 0) {
        [parts addObject:[NSString stringWithFormat:@"%d minutes", minutes]];
    }
    if ([parts count] == 0) {
        [parts addObject:@"0 lifetime"];
    }
    return [parts componentsJoinedByString:@", "];
}

// ---------------------------------------------------------------------------

- (NSString *) description
{
    return [NSString stringWithFormat:@"%@ (%@) %@", self.principalString, self.expirationString, super.description];
}

@end

@interface Identities ()

@property(readwrite, retain) NSArray *favoriteIdentities;
@property(readwrite, retain) NSArray *identities;

@end

@implementation Identities

@synthesize favoriteIdentities;
@synthesize identities;

// ---------------------------------------------------------------------------

+ (void) waitForChange: (NSArray *) portArray
{
    NSAutoreleasePool *pool;
    NSConnection *connection;
    
    pool = [[NSAutoreleasePool alloc] init];    
    
    connection = [NSConnection connectionWithReceivePort: [portArray objectAtIndex: 0]
						sendPort: [portArray objectAtIndex: 1]];
    
    {
	cc_int32 err = ccNoError;
	cc_context_t context = NULL;
	
	err = cc_initialize (&context, ccapi_version_max, NULL, NULL);
	
	while (!err) {
	    // This call puts the thread to sleep
	    err = cc_context_wait_for_change (context);
            
	    if (!err) {
		NSLog (@"%s thread noticed update", __FUNCTION__);
	    } else {
		NSLog (@"%s thread got error %d (%s)", __FUNCTION__, err, error_message (err));
                err = 0; /* The server quit unexpectedly -- just try again */
            }
            
            [(Identities *) [connection rootProxy] update];
	    sleep (1);
        }
	
	if (context) { cc_context_release (context); }
    }
    
    NSLog (@"%s thread exiting", __FUNCTION__);
    [pool release];
}

// ---------------------------------------------------------------------------

- (id) init
{
    if ((self = [super init])) {
        int err = 0;

        threadConnection = NULL;
        
        [self reload];
        
        if (!err) {
            NSPort *port1 = [NSPort port];
            NSPort *port2 = [NSPort port];
            if (!port1 || !port2) { err = ENOMEM; }
            
            if (!err) {
                threadConnection = [[NSConnection alloc] initWithReceivePort: port1
                                                                    sendPort: port2];
                if (!threadConnection) { err = ENOMEM; }
            }
            
            if (!err) {
                [threadConnection setRootObject: self];
                
                [NSThread detachNewThreadSelector: @selector(waitForChange:) 
                                         toTarget: [self class] 
                                       withObject: [NSArray arrayWithObjects: port2, port1, NULL]];            
            }
        }
        
        if (err) {
            [self release];
            return NULL;
        }
    }
        
    return self;
}

// ---------------------------------------------------------------------------

- (void) dealloc
{
    if (identities        ) { [identities release]; }
    if (favoriteIdentities) { [favoriteIdentities release]; }
    if (threadConnection  ) { [threadConnection release]; }
    
    [super dealloc];
}

// ---------------------------------------------------------------------------

- (void) reload
{
    kim_error err = KIM_NO_ERROR;

    NSMutableArray *newFavoriteIdentities = NULL;
    
    favoriteIdentities = NULL;
    
    if (!err) {
        newFavoriteIdentities = [[NSMutableArray alloc] init];
        if (!newFavoriteIdentities) { err = ENOMEM; }
    }
    
    if (!err) {
        kim_preferences preferences = NULL;
        kim_options kimOptions = NULL;
        kim_count i;
        kim_count count = 0;
        
        err = kim_preferences_create(&preferences);
        
        if (!err) {
            err = kim_preferences_get_number_of_favorite_identities(preferences,
                                                                    &count);
        }
        
        for (i = 0; !err && i < count; i++) {
            kim_identity kimIdentity = NULL;
            Identity *identity = NULL;
            
            err = kim_preferences_get_favorite_identity_at_index(preferences,
                                                                 i,
                                                                 &kimIdentity,
                                                                 &kimOptions);
            
            if (!err) {
                identity = [[Identity alloc] initWithFavoriteIdentity: kimIdentity options: kimOptions];
                if (!identity) { err = ENOMEM; }
            }
            
            if (!err) {
                kimIdentity = NULL; /* take ownership */ 
                [newFavoriteIdentities addObject: identity];
            }
            
            if (identity) {
                [identity release];
                identity = nil;
            }
            
            kim_identity_free (&kimIdentity);
        }
        
        kim_preferences_free(&preferences);
    }
    
    if (!err) {
        self.favoriteIdentities = newFavoriteIdentities;
        if (!favoriteIdentities) { err = ENOMEM; }
    }
    
    if (newFavoriteIdentities) {
        [newFavoriteIdentities release];
        newFavoriteIdentities = nil;
    }
    
    if (!err) {
        [identities release];
        identities = nil;
        err = [self update];
    }
}

// ---------------------------------------------------------------------------

- (int) update
{
    kim_error err = KIM_NO_ERROR;
    NSMutableSet *newIdentities = NULL;
    kim_ccache_iterator iterator = NULL;
    
    if (!err) {
        newIdentities = [NSMutableSet set];
        if (!newIdentities) { err = ENOMEM; }            
    }

    if (!err) {
        err = kim_ccache_iterator_create (&iterator);
    }
    
    // Build list of identities with existing ccaches
    
    while (!err) {
        kim_ccache ccache = NULL;
        kim_identity kimIdentity = NULL;
        kim_options kimOptions = NULL;
        kim_credential_state state = kim_credentials_state_valid;
        kim_time expirationTime = 0;
        kim_lifetime lifetime = 0;
        
        err = kim_ccache_iterator_next (iterator, &ccache);
        if (!err && !ccache) { break; }
        
        if (!err) {
            err = kim_ccache_get_client_identity (ccache, &kimIdentity);
        }
        
        if (!err) {
            err = kim_ccache_get_state (ccache, &state);
        }
        
        if (!err && state == kim_credentials_state_valid) {
            err = kim_ccache_get_expiration_time (ccache, &expirationTime);
        }
        
        if (!err) { 
            err = kim_ccache_get_options(ccache, &kimOptions);
        }
        
        if (!err) {
            err = kim_options_get_lifetime(kimOptions, &lifetime);
        }
        
        if (!err) {
            Identity *identity = [[Identity alloc] initWithIdentity: kimIdentity options: kimOptions];
            if (!identity) { err = ENOMEM; }
            
            if (!err) {
                kimIdentity = NULL; /* take ownership */ 
                identity.kimOptions = kimOptions;
                identity.state = state;
                identity.expiration_time = expirationTime;
                [newIdentities addObject: identity];
            }
            
            if (identity) {
                [identity release];
                identity = nil;
            }
        }
        
        if (err == KIM_NO_CREDENTIALS_ERR) {
            /* ccache is empty, just ignore it */
            err = KIM_NO_ERROR;
        }
        
        if (err) {
            NSLog(@"%s got error %s", _cmd, error_message(err));
        }
        
        kim_options_free (&kimOptions);
        kim_identity_free (&kimIdentity);
        kim_ccache_free (&ccache);
    }
    
    kim_ccache_iterator_free (&iterator);
    
    // Copy ccache state to favorites
    for (Identity *identity in self.favoriteIdentities) {
        Identity *matchingIdentity = [newIdentities member:identity];
        if (matchingIdentity) {
            identity.state = matchingIdentity.state;
            identity.expiration_time = matchingIdentity.expiration_time;
            [newIdentities removeObject:matchingIdentity];
        } else {
            identity.state = kim_credentials_state_expired;
            identity.expiration_time = 0;
        }
    }
        
    // Add unused favorites
    [newIdentities unionSet:[NSSet setWithArray:self.favoriteIdentities]];
    
    if (!err) {
        /* Use @property setter to trigger KVO notifications */
        self.identities = [[newIdentities allObjects] sortedArrayUsingSelector:@selector(compare:)];
        if (!identities) { err = ENOMEM; }            
    } else {
        NSLog (@"Got error %s", error_message (err));
    }
    
    return err;
}

// ---------------------------------------------------------------------------

- (kim_error) addIdentity: (Identity *) anIdentity
{
    kim_error err = KIM_NO_ERROR;
    NSMutableArray *newIdentities = nil;
    
    if (![self.identities containsObject:anIdentity]) {
        newIdentities = [self.identities mutableCopy];
        [newIdentities addObject:anIdentity];
        self.identities = newIdentities;
        [newIdentities release];        
    } else {
        err = KIM_IDENTITY_ALREADY_IN_LIST_ERR;
    }
    
    return err;
}

// ---------------------------------------------------------------------------

- (void) synchronizePreferences
{
    // Saves the kim_options for all identities in the list to disk, then rebuilds the Identities array from scratch
    
    kim_error err = KIM_NO_ERROR;
    kim_preferences prefs = NULL;
    
    err = kim_preferences_create(&prefs);
    
    if (!err) {
        err = kim_preferences_remove_all_favorite_identities(prefs);
    }
    
    for (Identity *identity in self.identities) {
        if (!err && identity.favorite == TRUE) {
            err = kim_preferences_add_favorite_identity(prefs, identity.kimIdentity, identity.kimOptions);
        }
    }
    
    if (!err) {
        err = kim_preferences_synchronize(prefs);
    }
    
    kim_preferences_free(&prefs);

    if (err) {
        NSLog(@"%s received error %s", _cmd, error_message(err));
    }

    if (!err) {
        [self reload];
    }
}

// ---------------------------------------------------------------------------

- (NSUInteger)minimumValidLifetime
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

// ---------------------------------------------------------------------------

- (NSUInteger)maximumValidLifetime
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

// ---------------------------------------------------------------------------

- (NSUInteger)minimumRenewableLifetime
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

// ---------------------------------------------------------------------------

- (NSUInteger)maximumRenewableLifetime
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

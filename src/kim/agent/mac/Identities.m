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

@interface Identity ()

- (NSString *)stringForLifetime:(NSUInteger)lifetime;

@end


@implementation Identity

@synthesize identity;
@synthesize options;
@synthesize expirationDate;
@synthesize state;
@synthesize favorite;

#pragma mark Initialization & Comparison

// ---------------------------------------------------------------------------

+ (NSSet *)keyPathsForValuesAffectingValueForKey:(NSString *)key
{
    NSMutableSet *result = [[super keyPathsForValuesAffectingValueForKey:key] mutableCopy];
    NSSet *otherKeys = nil;
        
    [result unionSet:otherKeys];
    
    return [result autorelease];
}

// ---------------------------------------------------------------------------

- (id) init
{
    return [self initWithIdentity: @"" options: [NSDictionary dictionary]];
}

// ---------------------------------------------------------------------------

- (id) initWithKimIdentity: (kim_identity) an_identity kimOptions: (kim_options) some_options
{
    kim_error err = KIM_NO_ERROR;
    kim_string identity_string = NULL;
    
    if (!err) {
        err = kim_identity_get_display_string(an_identity, &identity_string);
    }
    return [self initWithIdentity:[NSString stringWithUTF8String:identity_string] 
                          options:[KIMUtilities dictionaryForKimOptions:some_options]];
}

// ---------------------------------------------------------------------------

- (id) initWithFavoriteIdentity: (kim_identity) an_identity options: (kim_options) some_options
{
    if ((self = [self initWithKimIdentity: an_identity kimOptions: some_options])) {
        self.favorite = TRUE;
    }
    
    return self;
}

// ---------------------------------------------------------------------------

- (id) initWithIdentity: (NSString *) anIdentity options: (NSDictionary *) someOptions
{
    self = [super init];
    if (self != nil) {
        self.identity = anIdentity;
        self.options = someOptions;
        self.state = kim_credentials_state_not_yet_valid;
        self.expirationDate = [NSDate dateWithTimeIntervalSince1970:0];
        self.favorite = NO;
    }
    return self;
}

// ---------------------------------------------------------------------------

- (BOOL) isEqualToKIMIdentity: (kim_identity) comparison_identity
{
    kim_error err = KIM_NO_ERROR;
    kim_comparison comparison;
    kim_identity an_identity = self.kimIdentity;
    
    err = kim_identity_compare (an_identity, comparison_identity, &comparison);

    kim_identity_free(&an_identity);
    
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
    return [self.identity hash];
}

// ---------------------------------------------------------------------------

- (NSComparisonResult) compare: (Identity *)otherIdentity
{
    return ([self.identity compare:otherIdentity.identity]);
}

#pragma mark Actions

// ---------------------------------------------------------------------------

- (void) resetOptions
{
    // property setter converts NULL into actual kim_options with default settings
    kim_error err = KIM_NO_ERROR;
    kim_options some_options = NULL;
    
    err = kim_options_create(&some_options);
    
    if (!err) {
        self.options = [KIMUtilities dictionaryForKimOptions:some_options];
    }
    
    log_kim_error_to_console(err);
    
    kim_options_free(&some_options);
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
    kim_identity an_identity = self.kimIdentity;
    kim_options some_options = self.kimOptions;
    
    err = kim_preferences_create(&preferences);
    
    if (!err) {
	err = kim_preferences_add_favorite_identity(preferences, an_identity, some_options);
    }
    if (!err) {
	err = kim_preferences_synchronize(preferences);
    }

    if (!err) {
	self.favorite = true;
    } else {
        log_kim_error_to_console(err);
    }

    kim_preferences_free(&preferences);
    kim_identity_free(&an_identity);
    kim_options_free(&some_options);
    
    return (err != KIM_NO_ERROR);
}

// ---------------------------------------------------------------------------

- (BOOL) removeFromFavorites
{
    kim_error err = KIM_NO_ERROR;
    kim_preferences preferences = NULL;
    kim_identity an_identity = self.kimIdentity;

    err = kim_preferences_create(&preferences);
    
    if (!err) {
	err = kim_preferences_remove_favorite_identity(preferences, an_identity);
    }
    if (!err) {
	err = kim_preferences_synchronize(preferences);
    }
    if (!err) {
	self.favorite = false;
    } else {
        log_kim_error_to_console(err);
    }

    kim_preferences_free(&preferences);
    kim_identity_free(&an_identity);
    
    return (err != KIM_NO_ERROR);
}

#pragma mark Accessors

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
    kim_error err = KIM_NO_ERROR;
    kim_identity an_identity = NULL;
    err = kim_identity_create_from_string(&an_identity, [self.identity UTF8String]);
    return an_identity;
}

// ---------------------------------------------------------------------------

- (kim_options) kimOptions
{
    return [KIMUtilities kimOptionsForDictionary:self.options];
}

// ---------------------------------------------------------------------------

- (BOOL) isRenewable
{
    return [[self.options valueForKey:@"renewable"] boolValue];
}

// ---------------------------------------------------------------------------

- (void) setIsRenewable: (BOOL) value
{
    [self.options setValue:[NSNumber numberWithBool:value]
                    forKey:@"renewable"];
}

// ---------------------------------------------------------------------------

- (BOOL) isForwardable
{
    return [[self.options valueForKey:@"forwardable"] boolValue];
}

// ---------------------------------------------------------------------------

- (void) setIsForwardable: (BOOL) value
{
    [self.options setValue:[NSNumber numberWithBool:value]
                    forKey:@"forwardable"];
}

// ---------------------------------------------------------------------------

- (BOOL) isAddressless
{
    return [[self.options valueForKey:@"addressless"] boolValue];
}

// ---------------------------------------------------------------------------

- (void) setIsAddressless: (BOOL) value
{
    [self.options setValue:[NSNumber numberWithBool:value]
                    forKey:@"addressless"];
}

// ---------------------------------------------------------------------------

- (BOOL) isProxiable
{
    return [[self.options valueForKey:@"proxiable"] boolValue];
}

// ---------------------------------------------------------------------------

- (void) setIsProxiable: (BOOL) value
{
    [self.options setValue:[NSNumber numberWithBool:value]
                    forKey:@"proxiable"];
}

// ---------------------------------------------------------------------------

- (NSUInteger) validLifetime
{
    return [[self.options valueForKey:@"valid_lifetime"] unsignedIntegerValue];
}

// ---------------------------------------------------------------------------

- (void) setValidLifetime: (NSUInteger) newLifetime
{
    [self.options setValue:[NSNumber numberWithUnsignedInteger:newLifetime]
                    forKey:@"valid_lifetime"];
}

// ---------------------------------------------------------------------------

- (NSUInteger) renewableLifetime
{
    return [[self.options valueForKey:@"renewable_lifetime"] unsignedIntegerValue];
}

// ---------------------------------------------------------------------------

- (void) setRenewableLifetime: (NSUInteger) newLifetime
{
    [self.options setValue:[NSNumber numberWithUnsignedInteger:newLifetime]
                    forKey:@"renewable_lifetime"];
}

#pragma mark String representations

// ---------------------------------------------------------------------------

- (NSString *) expirationString
{
    NSString *result = nil;
    NSTimeInterval lifetime = [self.expirationDate timeIntervalSinceNow];
    if (lifetime > 0) {
	NSTimeInterval seconds  = fmod(lifetime, 60);
	NSTimeInterval minutes  = fmod(lifetime, 60 % 60);
	NSTimeInterval hours    = fmod(lifetime, 3600 % 24);
	NSTimeInterval days     = fmod(lifetime, 86400);
	
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
        [parts addObject:@"0"];
    }
    return [parts componentsJoinedByString:@", "];
}

// ---------------------------------------------------------------------------

- (NSString *) description
{
    return [NSString stringWithFormat:@"%@ (%@) %@", self.identity, self.expirationString, [super description]];
}

@end

@interface Identities ()

@property(readwrite, retain) NSMutableArray *favoriteIdentities;
@property(readwrite, retain) NSMutableArray *identities;

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
	//	NSLog (@"%s thread noticed update", __FUNCTION__);
	    } else {
	//	NSLog (@"%s thread got error %d (%s)", __FUNCTION__, err, [KIMUtilities stringForLastKIMError:err]);
                err = 0; /* The server quit unexpectedly -- just try again */
            }

            //NSLog(@"waited %@", [[NSThread currentThread] description]);
            [(Identities *) [connection rootProxy] reload];
	    sleep (1);
        }
	
	if (context) { cc_context_release (context); }
    }
    
//    NSLog (@"%s thread exiting", __FUNCTION__);
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
                [newFavoriteIdentities addObject: identity];
            }
            
            if (identity) {
                [identity release];
                identity = nil;
            }
            
            kim_options_free(&kimOptions);
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
    //NSLog(@"updating %@", [[NSThread currentThread] description]);
    while (!err) {
        kim_ccache ccache = NULL;
        kim_identity an_identity = NULL;
        kim_options some_options = NULL;
        kim_credential_state state = kim_credentials_state_valid;
        kim_time expiration_time = 0;
        
        err = kim_ccache_iterator_next (iterator, &ccache);
        if (!err && !ccache) { break; }
        
        if (!err) {
            err = kim_ccache_get_client_identity (ccache, &an_identity);
        }
        
        if (!err) {
            err = kim_ccache_get_state (ccache, &state);
        }
        
        if (!err && state == kim_credentials_state_valid) {
            err = kim_ccache_get_expiration_time (ccache, &expiration_time);
        }
        
        if (!err) { 
            err = kim_ccache_get_options(ccache, &some_options);
        }
        
        if (!err) {
            Identity *identity = [[Identity alloc] initWithKimIdentity:an_identity kimOptions:some_options];
            if (!identity) { err = ENOMEM; }
            
            if (!err) {
                identity.state = state;
                identity.expirationDate = [NSDate dateWithTimeIntervalSince1970:expiration_time];
                [newIdentities addObject: identity];
            }
            
            [identity release];
            identity = nil;
        }
        
        if (err == KIM_NO_CREDENTIALS_ERR) {
            /* ccache is empty, just ignore it */
            err = KIM_NO_ERROR;
        }
        
        if (err) {
            log_kim_error_to_console(err);
        }
        
        kim_options_free (&some_options);
        kim_identity_free (&an_identity);
        kim_ccache_free (&ccache);
    }
    
    kim_ccache_iterator_free (&iterator);
    
    
    // Copy ccache state to favorites
    for (Identity *identity in self.favoriteIdentities) {
        Identity *matchingIdentity = [newIdentities member:identity];
        if (matchingIdentity) {
            identity.state = matchingIdentity.state;
            identity.expirationDate = matchingIdentity.expirationDate;
            [newIdentities removeObject:matchingIdentity];
        } else {
            identity.state = kim_credentials_state_expired;
            identity.expirationDate = [NSDate distantPast];
        }
    }


    // Add unused favorites
    [newIdentities unionSet:[NSSet setWithArray:self.favoriteIdentities]];
    
    if (!err) {
//        [self.identities removeAllObjects];
//        [self.identities addObjectsFromArray:[newIdentities allObjects]];
//        [self.identities sortUsingSelector:@selector(compare:)];

        self.identities = [[[[newIdentities allObjects] sortedArrayUsingSelector:@selector(compare:)] mutableCopy] autorelease];
        

        if (!identities) { err = ENOMEM; }            
    } else {
        log_kim_error_to_console(err);
    }
    
    return err;
}

// ---------------------------------------------------------------------------

- (kim_error) addIdentity: (Identity *) anIdentity
{
    kim_error err = KIM_NO_ERROR;

    if (![self.identities containsObject:anIdentity]) {
        NSMutableArray *newArray = [[self.identities mutableCopy] autorelease];
        [newArray addObject:anIdentity];
        self.identities = newArray;
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
        log_kim_error_to_console(err);
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

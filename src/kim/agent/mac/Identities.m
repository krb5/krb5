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

@implementation Identity

@synthesize state;
@synthesize expirationTime;
@synthesize favorite;

// ---------------------------------------------------------------------------

- (id) initWithIdentity: (kim_identity) identity
{
    if ((self = [super init])) {
        kimIdentity = identity;
        state = kim_credentials_state_not_yet_valid;
        expirationTime = 0;
        favorite = FALSE;
    }
    
    return self;
}

// ---------------------------------------------------------------------------

- (id) initWithFavoriteIdentity: (kim_identity) identity
{
    if ((self = [self initWithIdentity: identity])) {
        favorite = TRUE;
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

@end

@implementation Identities

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
        NSMutableArray *newFavoriteIdentities = NULL;
        
        threadConnection = NULL;
        identities = NULL;
        favoriteIdentities = NULL;
    
        if (!err) {
            newFavoriteIdentities = [[[NSMutableArray alloc] init] autorelease];
            if (!newFavoriteIdentities) { err = ENOMEM; }
        }
        
        if (!err) {
            kim_favorite_identities kimFavoriteIdentities = NULL;
            kim_count i;
            kim_count count = 0;
            
            err = kim_favorite_identities_create (&kimFavoriteIdentities);
            
            if (!err) {
                err = kim_favorite_identities_get_number_of_identities (kimFavoriteIdentities,
                                                                        &count);
            }
            
            for (i = 0; !err && i < count; i++) {
                kim_identity kimIdentity = NULL;
                Identity *identity = NULL;
                
                err = kim_favorite_identities_get_identity_at_index (kimFavoriteIdentities, 
                                                                     i, &kimIdentity);
                
                if (!err) {
                    identity = [[[Identity alloc] initWithFavoriteIdentity: kimIdentity] autorelease];
                    if (!identity) { err = ENOMEM; }
                }
                
                if (!err) {
                    kimIdentity = NULL; /* take ownership */ 
                    [newFavoriteIdentities addObject: identity];
                }
                
                kim_identity_free (&kimIdentity);
            }
        
            kim_favorite_identities_free (&kimFavoriteIdentities);
        }
        
        if (!err) {
            favoriteIdentities = [[NSArray alloc] initWithArray: newFavoriteIdentities];
            if (!favoriteIdentities) { err = ENOMEM; }            
        }

        if (!err) {
            err = [self update];
        }
        
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

- (int) update
{
    kim_error err = KIM_NO_ERROR;
    NSMutableArray *newIdentities = NULL;
    kim_ccache_iterator iterator = NULL;
    
    if (!err) {
        newIdentities = [NSMutableArray arrayWithArray: favoriteIdentities];
        if (!newIdentities) { err = ENOMEM; }            
    }

    if (!err) {
        err = kim_ccache_iterator_create (&iterator);
    }
    
    while (!err) {
        kim_ccache ccache = NULL;
        kim_identity kimIdentity = NULL;
        kim_credential_state state = kim_credentials_state_valid;
        kim_time expirationTime = 0;
        
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
            Identity *identity = NULL;
            
            for (Identity *i in newIdentities) {
                if ([i isEqualToKIMIdentity: kimIdentity]) { identity = i; }
            }

            if (!identity) {
                identity = [[[Identity alloc] initWithIdentity: kimIdentity] autorelease];
                if (!identity) { err = ENOMEM; }
                
                if (!err) {
                    kimIdentity = NULL; /* take ownership */ 
                    [newIdentities addObject: identity];
                }
            }
            
            if (!err) {
                [identity setState: state];
                [identity setExpirationTime: expirationTime];
            }
        }
        
        if (err == KIM_NO_CREDENTIALS_ERR) {
            /* ccache is empty, just ignore it */
            err = KIM_NO_ERROR;
        }
        
        kim_identity_free (&kimIdentity);
        kim_ccache_free (&ccache);
    }

    if (!err) {
        if (identities) { [identities release]; }
        
        identities = [[NSArray alloc] initWithArray: newIdentities];
        if (!identities) { err = ENOMEM; }            
    }
    
    
    kim_ccache_iterator_free (&iterator);
    
    if (err) {
        NSLog (@"Got error %s", error_message (err));
    }
    
    return err;
}


@end

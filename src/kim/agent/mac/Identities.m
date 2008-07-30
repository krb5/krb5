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

- (id) initWithIdentity: (kim_identity) identity
{
    if ((self = [super init])) {
        kimIdentity = identity;
        state = kim_credentials_state_not_yet_valid;
        expirationTime = 0;
    }
    
    return self;
}




@end

@implementation Identities

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
    int err = 0;

    threadConnection = NULL;
    favoriteIdentitiesArray = NULL;
    ccacheIdentitiesArray = NULL:
    
    if (!err) {
        self = [super init];
        if (!self) { err = ENOMEM; }
    }
    
    if (!err) {
        favoriteIdentitiesArray = [[NSMutableArray alloc] init];
        if (!favoriteIdentitiesArray) { err = ENOMEM; }
    }
    
    if (!err) {
        kim_error kimErr = KIM_NO_ERROR;
        kim_favorite_identities favoriteIdentities = NULL;
        kim_count count = 0;
        
        kimErr = kim_favorite_identities_create (&favorite_identities);
        err = kim_error_free (&kimErr);
        
        if (!err) {
            kimErr = kim_favorite_identities_get_number_of_identities (favoriteIdentities,
                                                                       &count);
            err = kim_error_free (&kimErr);
        }
        
        for (i = 0; !err && i < count; i++) {
            kim_identity kimIdentity = NULL;
            Identity *identity = NULL:
            
            kimErr = kim_favorite_identities_get_identity_at_index (favoriteIdentities, 
                                                                    i, &kimIdentity);
            err = kim_error_free (&kimErr);
            
            if (!err) {
                Identity *identity = [[[Identity alloc] initWithIdentity: kimIdentity] autorelease];
                if (!identity) { err = ENOMEM; }
            }
             
            if (!err) {
                kimIdentity = NULL; /* take ownership */ 
                [favoriteIdentitiesArray addObject: identity];
            }
            
            kim_identity_free (&kimIdentity);
        }
        
        kim_favorite_identities_free (&favoriteIdentities);
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
    
    return err ? NULL : self;
}

// ---------------------------------------------------------------------------

- (void) dealloc
{
    if (identitiesArray ) { [identitiesArray release]; }
    if (threadConnection) { [threadConnection release]; }
    
    [super dealloc];
}

// ---------------------------------------------------------------------------

- (NSArray *) identities
{
    return identities;
}

// ---------------------------------------------------------------------------

- (int) update
{
    kim_error err = KIM_NO_ERROR;
    kim_ccache_iterator iterator = NULL;
    
    err = kim_ccache_iterator_create (&iterator);
    
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
            
            identity = [self findIdentity: kimIdentity];
            if (identity) {
                [identity updateWithState: state
                           expirationTime: expirationTime];
            } else {
                identity = [[Identity alloc] initWithIdentity: kimIdentity
                                                        state: state
                                               expirationTime: expirationTime];
            }
            
            if (identity) {
                
            }
        }
        
        if (kim_error_get_code (err) == KIM_NO_CREDENTIALS_ECODE) {
            /* ccache is empty, just ignore it */
            kim_error_free (&err);
            err = KIM_NO_ERROR;
        }
        
        kim_identity_free (&identity);
        kim_ccache_free (&ccache);
    }
    
    kim_ccache_iterator_free (&iterator);
    
    if (err) {
        NSLog (@"Got error %s", kim_error_get_display_string (err));
    }
    
    return kim_error_free (&err);
}


@end

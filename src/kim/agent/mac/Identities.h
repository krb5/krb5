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

#import <Cocoa/Cocoa.h>
#import <Kerberos/kim.h>
#import "KIMUtilities.h"

@interface Identity : NSObject {
    kim_identity kimIdentity;
    kim_options kimOptions;
    kim_credential_state state;
    cc_time_t expiration_time;
    BOOL favorite;
}

@property	    kim_identity         kimIdentity;
@property	    kim_options          kimOptions;
@property           kim_credential_state state;
@property           BOOL	         favorite;
@property           cc_time_t		 expiration_time;

// derived properties
@property(readonly) NSString    *principalString;
@property(readonly) NSString    *componentsString;
@property(readonly) NSString    *realmString;
@property(readonly) NSDate      *expirationDate;
@property(readonly) NSString    *expirationString;
@property(readonly) NSString    *validLifetimeString;
@property(readonly) NSString    *renewableLifetimeString;
@property(readonly) BOOL        hasCCache;
@property(readwrite) BOOL       isRenewable;
@property(readwrite) BOOL       isForwardable;
@property(readwrite) BOOL       isAddressless;
@property(readwrite) BOOL       isProxiable;
@property(readwrite) NSUInteger validLifetime;
@property(readwrite) NSUInteger renewableLifetime;

- (id) initWithIdentity: (kim_identity) identity options: (kim_options) options;
- (id) initWithFavoriteIdentity: (kim_identity) identity options: (kim_options) options;

- (BOOL) isEqualToKIMIdentity: (kim_identity) identity;
- (BOOL) isEqual: (Identity *)otherIdentity;

- (kim_error) setPrincipalComponents: (NSString *) componentsString realm: (NSString *) realmString;

- (void) resetOptions;
- (void) toggleFavorite;
- (BOOL) addToFavorites;
- (BOOL) removeFromFavorites;

@end


@interface Identities : NSObject {
    NSArray *favoriteIdentities;
    NSArray *identities;
    NSConnection *threadConnection;
}

@property(readonly, retain) NSArray *identities;
@property(readonly) NSUInteger minimumValidLifetime;
@property(readonly) NSUInteger maximumValidLifetime;
@property(readonly) NSUInteger minimumRenewableLifetime;
@property(readonly) NSUInteger maximumRenewableLifetime;

- (void) reload;
- (int) update;
- (kim_error) addIdentity: (Identity *) anIdentity;
- (void) synchronizePreferences;

@end

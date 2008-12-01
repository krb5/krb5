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
    NSString *identity;
    NSDictionary *options;
    kim_credential_state state;
    NSDate *expirationDate;
    BOOL favorite;
}

@property (readwrite, retain) NSString *identity;
@property (readwrite, retain) NSDictionary *options;
@property (assign) kim_credential_state state;
@property (assign) BOOL favorite;
@property (readwrite, retain) NSDate *expirationDate;

// derived properties
@property (readonly) kim_identity kimIdentity;
@property (readonly) kim_options kimOptions;
@property (readonly) NSString    *expirationString;
@property (readonly) NSString    *validLifetimeString;
@property (readonly) NSString    *renewableLifetimeString;
@property (readonly) BOOL        hasCCache;
@property (readwrite) BOOL       isRenewable;
@property (readwrite) BOOL       isForwardable;
@property (readwrite) BOOL       isAddressless;
@property (readwrite) BOOL       isProxiable;
@property (readwrite) NSUInteger validLifetime;
@property (readwrite) NSUInteger renewableLifetime;

- (id) initWithKimIdentity: (kim_identity) an_identity kimOptions: (kim_options) some_options;
- (id) initWithFavoriteIdentity: (kim_identity) an_identity options: (kim_options) some_options;
- (id) initWithIdentity: (NSString *) anIdentity options: (NSDictionary *) someOptions;

- (BOOL) isEqualToKIMIdentity: (kim_identity) identity;
- (BOOL) isEqual: (Identity *)otherIdentity;

- (void) resetOptions;
- (void) toggleFavorite;
- (BOOL) addToFavorites;
- (BOOL) removeFromFavorites;

@end


@interface Identities : NSObject {
    NSMutableArray *favoriteIdentities;
    NSMutableArray *identities;
    NSConnection *threadConnection;
}

@property(readonly, retain) NSMutableArray *identities;
@property(readonly) NSUInteger minimumValidLifetime;
@property(readonly) NSUInteger maximumValidLifetime;
@property(readonly) NSUInteger minimumRenewableLifetime;
@property(readonly) NSUInteger maximumRenewableLifetime;

- (void) reload;
- (int) update;
- (kim_error) addIdentity: (Identity *) anIdentity;
- (void) synchronizePreferences;

@end

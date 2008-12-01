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
#import "KIMUtilities.h"

@class SelectIdentityController;
@class AuthenticationController;
@class Identities;

@interface IPCClient : NSObject {
    mach_port_t port;
    NSString *name;
    NSString *path;
    NSInteger state;
    NSMutableDictionary *currentInfo;

    SelectIdentityController *selectController;
    AuthenticationController *authController;
}

@property (assign) mach_port_t port;
@property (readwrite, retain) NSString *name;
@property (readwrite, retain) NSString *path;
@property (assign) NSInteger state;
@property (readwrite, retain) NSMutableDictionary *currentInfo;
@property (readonly, retain) SelectIdentityController *selectController;
@property (readonly, retain) AuthenticationController *authController;

- (void) cleanup;
- (void) saveIdentityToFavoritesIfSuccessful;

- (kim_error) selectIdentity: (NSDictionary *) info;
- (kim_error) enterIdentity: (NSDictionary *) info;
- (kim_error) promptForAuth: (NSDictionary *) info;
- (kim_error) changePassword: (NSDictionary *) info;
- (kim_error) handleError: (NSDictionary *) info;

- (void) didCancel;
- (void) didSelectIdentity: (NSString *) identityString 
                   options: (NSDictionary *) options 
       wantsChangePassword: (BOOL) wantsChangePassword;
- (void) didEnterIdentity: (NSString *) identityString 
                  options: (NSDictionary *) options 
      wantsChangePassword: (BOOL) wantsChangePassword;
- (void) didPromptForAuth: (NSString *) responseString saveResponse: (NSNumber *) saveResponse;
- (void) didChangePassword: (NSString *) oldPassword
               newPassword: (NSString *) newPassword
            verifyPassword: (NSString *) verifyPassword;
- (void) didHandleError;

@end

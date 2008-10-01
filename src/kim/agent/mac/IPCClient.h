//
//  IPCClient.h
//  Kerberos5
//
//  Created by Justin Anderson on 9/28/08.
//  Copyright 2008 MIT. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "KIMUtilities.h"

@class SelectIdentityController;
@class AuthenticationController;

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

- (kim_error) selectIdentity: (NSDictionary *) info;
- (kim_error) enterIdentity: (NSDictionary *) info;
- (kim_error) promptForAuth: (NSDictionary *) info;
- (kim_error) changePassword: (NSDictionary *) info;
- (kim_error) handleError: (NSDictionary *) info;

- (void) didCancel;
- (void) didSelectIdentity: (NSString *) identityString;
- (void) didEnterIdentity: (NSString *) identityString;
- (void) didPromptForAuth: (NSString *) responseString saveResponse: (NSNumber *) saveResponse;
- (void) didChangePassword: (NSString *) oldPassword
               newPassword: (NSString *) newPassword
            verifyPassword: (NSString *) verifyPassword;
- (void) didHandleError;

@end

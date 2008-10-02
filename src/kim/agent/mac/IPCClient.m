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


#import "IPCClient.h"
#import "SelectIdentityController.h"
#import "AuthenticationController.h"
#import "KerberosAgentListener.h"

enum krb_agent_client_state {
    ipc_client_state_idle,
    ipc_client_state_init,
    ipc_client_state_enter,
    ipc_client_state_select,
    ipc_client_state_auth_prompt,
    ipc_client_state_change_password,
    ipc_client_state_handle_error,
    ipc_client_state_fini,
};

@interface IPCClient ()

@property (readwrite, retain) SelectIdentityController *selectController;
@property (readwrite, retain) AuthenticationController *authController;

@end


@implementation IPCClient

@synthesize port;
@synthesize name;
@synthesize path;
@synthesize state;
@synthesize currentInfo;
@synthesize selectController;
@synthesize authController;

- (BOOL) isEqual: (IPCClient *) otherClient
{
    return (self.port == otherClient.port);
}

- (NSUInteger) hash
{
    return self.port;
}

- (id) init
{
    self = [super init];
    if (self != nil) {
        self.state = ipc_client_state_init;
        self.selectController = [[[SelectIdentityController alloc] init] autorelease];
        self.authController = [[[AuthenticationController alloc] init] autorelease];
        self.selectController.associatedClient = self;
        self.authController.associatedClient = self;
    }
    return self;
}

- (void) cleanup
{
    [self.selectController close];
    [self.authController close];
}

- (void) didCancel
{
    kim_error err = KIM_USER_CANCELED_ERR;
    if (self.state == ipc_client_state_select) {
        [KerberosAgentListener didSelectIdentity:self.currentInfo error:err];
    }
    else if (self.state == ipc_client_state_enter) {
        [KerberosAgentListener didEnterIdentity:self.currentInfo error:err];
    }
    else if (self.state == ipc_client_state_select) {
        [KerberosAgentListener didSelectIdentity:self.currentInfo error:err];
    }
    else if (self.state == ipc_client_state_auth_prompt) {
        [KerberosAgentListener didPromptForAuth:self.currentInfo error:err];
    }
    else if (self.state == ipc_client_state_change_password) {
        [KerberosAgentListener didChangePassword:self.currentInfo error:err];
    }
    [self.selectController close];
    [self.authController close];
    self.state = ipc_client_state_idle;
}

- (kim_error) selectIdentity: (NSDictionary *) info
{
    self.currentInfo = [[info mutableCopy] autorelease];
    self.state = ipc_client_state_select;

    [self.selectController showWindow:nil];
    
    return 0;
}

- (void) didSelectIdentity: (NSString *) identityString 
                   options: (NSDictionary *) options 
       wantsChangePassword: (BOOL) wantsChangePassword
{
    NSLog(@"%s %@ %@", __FUNCTION__, identityString, options);
    [self.currentInfo setObject:identityString forKey:@"identity_string"];
    // if the user set custom options, use those
    if (options) {
        [self.currentInfo setObject:options forKey:@"options"];
    }
    // else use the options in the hints
    else {
        [self.currentInfo setObject:[self.currentInfo valueForKeyPath:@"hints.options"]
                             forKey:@"options"];
    }
    [self.currentInfo setObject:[NSNumber numberWithBool:wantsChangePassword] forKey:@"wants_change_password"];

    [KerberosAgentListener didSelectIdentity:self.currentInfo error:0];
    
    // clean up state
    self.currentInfo = nil;
    self.state = ipc_client_state_idle;
}

- (kim_error) enterIdentity: (NSDictionary *) info
{
    self.currentInfo = [[info mutableCopy] autorelease];
    self.state = ipc_client_state_enter;

    [self.authController setContent:self.currentInfo];
    [self.authController showEnterIdentity];
    
    return 0;
}

- (void) didEnterIdentity: (NSString *) identityString 
                  options: (NSDictionary *) options
      wantsChangePassword: (BOOL) wantsChangePassword
{
    [self.currentInfo setObject:identityString forKey:@"identity_string"];
    [self.currentInfo setObject:options forKey:@"options"];
    [self.currentInfo setObject:[NSNumber numberWithBool:wantsChangePassword] forKey:@"wants_change_password"];
    [KerberosAgentListener didEnterIdentity:self.currentInfo error:0];
}

- (kim_error) promptForAuth: (NSDictionary *) info
{
    self.currentInfo = [[info mutableCopy] autorelease];
    self.state = ipc_client_state_auth_prompt;
    
    [self.authController setContent:self.currentInfo];
    [self.authController showAuthPrompt];
    
    return 0;
}

- (void) didPromptForAuth: (NSString *) responseString saveResponse: (NSNumber *) saveResponse
{
    [self.currentInfo setObject:responseString forKey:@"prompt_response"];
    [self.currentInfo setObject:saveResponse forKey:@"save_response"];
    [KerberosAgentListener didPromptForAuth:self.currentInfo error:0];
}

- (kim_error) changePassword: (NSDictionary *) info
{
    self.currentInfo = [[info mutableCopy] autorelease];
    self.state = ipc_client_state_change_password;
    
    [self.authController setContent:self.currentInfo];
    [self.authController showChangePassword];
    
    return 0;
}

- (void) didChangePassword: (NSString *) oldPassword 
               newPassword: (NSString *) newPassword 
            verifyPassword: (NSString *) verifyPassword
{
    [self.currentInfo setObject:oldPassword forKey:@"old_password"];
    [self.currentInfo setObject:newPassword forKey:@"new_password"];
    [self.currentInfo setObject:verifyPassword forKey:@"verify_password"];
    [KerberosAgentListener didChangePassword:self.currentInfo error:0];
}


- (kim_error) handleError: (NSDictionary *) info
{
    self.currentInfo = [[info mutableCopy] autorelease];
    self.state = ipc_client_state_handle_error;
    
    [self.authController setContent:self.currentInfo];
    [self.authController showError];
    
    return 0;
}

- (void) didHandleError
{
    [KerberosAgentListener didHandleError:self.currentInfo error:0];
}

@end

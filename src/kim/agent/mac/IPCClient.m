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
#import "Identities.h"

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
        kim_error err = KIM_NO_ERROR;
        kim_preferences prefs = NULL;
        kim_identity identity = NULL;
        kim_string identity_string = NULL;
        
        self.state = ipc_client_state_init;
        self.selectController = [[[SelectIdentityController alloc] init] autorelease];
        self.authController = [[[AuthenticationController alloc] init] autorelease];
        self.selectController.associatedClient = self;
        self.authController.associatedClient = self;
        self.currentInfo = [NSMutableDictionary dictionary];
        
        // pre-populate the identity_string if there's a default identity
        err = kim_preferences_create(&prefs);
        if (!err && prefs) {
            err = kim_preferences_get_client_identity(prefs, &identity);
        }
        if (!err && identity) {
            err = kim_identity_get_display_string(identity, &identity_string);
        }
        if (!err && identity_string) {
            [self.currentInfo setObject:[NSString stringWithUTF8String:identity_string]
                                 forKey:@"identity_string"];
        }
        
        kim_string_free(&identity_string);
        kim_identity_free(&identity);
        kim_preferences_free(&prefs);
    }
    return self;
}

- (void) cleanup
{
    if (![[self.selectController window] isVisible]) {
        [self saveIdentityToFavoritesIfSuccessful];
    }
    [self.selectController close];
    [self.authController close];
    self.selectController = nil;
    self.authController = nil;
    self.currentInfo = nil;
}

- (void) saveIdentityToFavoritesIfSuccessful
{
    NSString *identityString = [self.currentInfo valueForKeyPath:@"identity_string"];
    NSDictionary *options = [self.currentInfo valueForKeyPath:@"options"];
    
    Identities *identities = [[Identities alloc] init];
    Identity *theIdentity = [[Identity alloc] initWithIdentity:identityString 
                                                       options:options];
    for (Identity *anIdentity in [identities identities]) {
        if ([anIdentity isEqual:theIdentity]) {
            if (!anIdentity.favorite) {
                anIdentity.favorite = YES;
                [identities synchronizePreferences];
            }
            break;
        }
    }
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
    
    if ([[self.selectController window] isVisible]) {
        self.state = ipc_client_state_select;
    }
    else {
        self.state = ipc_client_state_idle;
    }
}

- (kim_error) selectIdentity: (NSDictionary *) info
{
    [self.currentInfo addEntriesFromDictionary:info];
    self.state = ipc_client_state_select;
    
    if ([[self.authController window] isVisible]) {
        [self.authController cancelAuthSheet:nil];
    }
    
    [self.selectController setContent:self.currentInfo];
    [self.selectController showWindow:nil];
    
    return 0;
}

- (void) didSelectIdentity: (NSString *) identityString 
                   options: (NSDictionary *) options 
       wantsChangePassword: (BOOL) wantsChangePassword
{
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
    if (!wantsChangePassword) {
        self.state = ipc_client_state_idle;
    }
}

- (kim_error) enterIdentity: (NSDictionary *) info
{
    NSWindow *parentWindow = nil;
    
    [self.currentInfo addEntriesFromDictionary:info];

    if ([[self.selectController window] isVisible]) {
        parentWindow = [selectController window];
    }
    
    self.state = ipc_client_state_enter;

    [self.authController setContent:self.currentInfo];
    [self.authController showEnterIdentity:parentWindow];
    
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
    
    if ([[self.selectController window] isVisible]) {
        self.state = ipc_client_state_select;
    }
    else {
        self.state = ipc_client_state_idle;
    }
}

- (kim_error) promptForAuth: (NSDictionary *) info
{
    NSWindow *parentWindow = nil;
    
    [self.currentInfo addEntriesFromDictionary:info];
    
    if ([[self.selectController window] isVisible]) {
        parentWindow = [selectController window];
    }
    
    self.state = ipc_client_state_auth_prompt;
    
    [self.authController setContent:self.currentInfo];
    [self.authController showAuthPrompt:parentWindow];
    
    return 0;
}

- (void) didPromptForAuth: (NSString *) responseString saveResponse: (NSNumber *) saveResponse
{
    [self.currentInfo setObject:responseString forKey:@"prompt_response"];
    [self.currentInfo setObject:saveResponse forKey:@"save_response"];
    [KerberosAgentListener didPromptForAuth:self.currentInfo error:0];

    if ([[self.selectController window] isVisible]) {
        self.state = ipc_client_state_select;
    }
    else {
        self.state = ipc_client_state_idle;
    }
}

- (kim_error) changePassword: (NSDictionary *) info
{
    NSWindow *parentWindow = nil;
    
    [self.currentInfo addEntriesFromDictionary:info];
    
    if ([[self.selectController window] isVisible]) {
        parentWindow = [selectController window];
    }
    
    self.state = ipc_client_state_change_password;
    
    [self.authController setContent:self.currentInfo];
    [self.authController showChangePassword:parentWindow];
    
    return 0;
}

- (void) didChangePassword: (NSString *) oldPassword 
               newPassword: (NSString *) newPassword 
            verifyPassword: (NSString *) verifyPassword
{
    [self.currentInfo setObject:oldPassword forKey:@"old_password"];
    [self.currentInfo setObject:newPassword forKey:@"new_password"];
    [self.currentInfo setObject:verifyPassword forKey:@"verify_password"];

    if ([[self.selectController window] isVisible]) {
        self.state = ipc_client_state_select;
    }
    else {
        self.state = ipc_client_state_idle;
    }    
    
    [KerberosAgentListener didChangePassword:self.currentInfo error:0];
}


- (kim_error) handleError: (NSDictionary *) info
{
    NSWindow *parentWindow = nil;

    [self.currentInfo addEntriesFromDictionary:info];

    if ([[self.selectController window] isVisible]) {
        parentWindow = [selectController window];
    }
    
    self.state = ipc_client_state_handle_error;
    
    [self.authController setContent:self.currentInfo];
    [self.authController showError:parentWindow];
    
    return 0;
}

- (void) didHandleError
{
    if ([[self.selectController window] isVisible]) {
        self.state = ipc_client_state_select;
    }
    else {
        self.state = ipc_client_state_idle;
    }
    
    [KerberosAgentListener didHandleError:self.currentInfo error:0];
}

@end

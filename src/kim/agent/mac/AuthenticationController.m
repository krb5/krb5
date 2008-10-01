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

#import "AuthenticationController.h"
#import "IPCClient.h"
#import "BadgedImageView.h"

// to get kim_prompt_type enum
#import <Kerberos/kim_ui_plugin.h>

/*
 * glueController KVC mapping is as follows:
 * name = client app name
 * path = client app bundle path
 * title = suggested label for prompt field
 * message = desired large text message
 * description = longer, detailed, small text message
 * username = 'user' part of 'user@REALM.ORG'
 * realm = 'REALM.ORG' part of 'user@REALM.ORG'
 * realm_history = past realms the user has entered
 * prompt_response = auth prompt response
 * allow_save_password = whether or not to show the 'save password in keychain' checkbox
 * should_save_password = whether or not to save the password in the keychain
 * old_password = for change password dialog
 * new_password = "
 * verify_password = "
 */

#define client_name_keypath          @"content.name"
#define client_path_keypath          @"content.path"

#define identity_string_keypath      @"content.identity_string"
#define title_keypath                @"content.title"
#define message_keypath              @"content.message"
#define description_keypath          @"content.description"

#define username_keypath             @"content.username"
#define realm_keypath                @"content.realm"
#define realm_history_keypath        @"content.realm_history"

#define prompt_response_keypath      @"content.prompt_response"
#define allow_save_password_keypath  @"content.allow_save"
#define should_save_password_keypath @"content.save_response"

#define password_expired_keypath     @"content.expired"
#define old_password_keypath         @"content.old_password"
#define new_password_keypath         @"content.new_password"
#define verify_password_keypath      @"content.verify_password"

#define enable_identity_ok_keypath   @"content.isPrincipalValid"
#define enable_prompt_ok_keypath     @"content.isPromptValid"
#define change_password_ok_keypath   @"content.isChangePasswordValid"

#define options_keypath              @"content.options"

#define valid_lifetime_keypath       @"content.valid_lifetime"
#define renewal_lifetime_keypath     @"content.renewal_lifetime"
#define renewable_keypath            @"content.renewable"
#define addressless_keypath          @"content.addressless"
#define forwardable_keypath          @"content.forwardable"

#define min_valid_keypath            @"content.minValidLifetime"
#define max_valid_keypath            @"content.maxValidLifetime"
#define min_renewable_keypath        @"content.minRenewableLifetime"
#define max_renewable_keypath        @"content.maxRenewableLifetime"

#define ACKVOContext                 @"authenticationController"

// localization keys and tables

#define ACLocalizationTable          @"AuthenticationController"

#define ACAppPrincReqKey             @"AuthControllerApplicationPrincipalRequest"
#define ACPrincReqKey                @"AuthControllerPrincipalRequest"
#define ACAppPasswordReqKey          @"AuthControllerApplicationPasswordRequest"
#define ACPasswordReqKey             @"AuthControllerPasswordRequest"
#define ACPasswordChangeExpired      @"ChangePasswordPasswordExpired"
#define ACPasswordChangeApp          @"ChangePasswordApplicationRequest"
#define ACPasswordChangePrinc        @"ChangePasswordPrincipalRequest"

@implementation AuthenticationController

@synthesize associatedClient;

- (id) init
{
    return [self initWithWindowNibName: @"Authentication"];
}

- (void) awakeFromNib
{
    [[self window] center];
    // We need to float over the loginwindow and SecurityAgent so use its hardcoded level.
    [[self window] setLevel:2003];
    
    [glueController addObserver:self 
                     forKeyPath:username_keypath 
                        options:NSKeyValueObservingOptionNew 
                        context:ACKVOContext];
    [glueController addObserver:self
                     forKeyPath:realm_keypath
                        options:NSKeyValueObservingOptionNew
                        context:ACKVOContext];
    [glueController addObserver:self
                     forKeyPath:prompt_response_keypath
                        options:NSKeyValueObservingOptionNew
                        context:ACKVOContext];
    [glueController addObserver:self
                     forKeyPath:old_password_keypath
                        options:NSKeyValueObservingOptionNew
                        context:ACKVOContext];
    [glueController addObserver:self
                     forKeyPath:new_password_keypath
                        options:NSKeyValueObservingOptionNew
                        context:ACKVOContext];
    [glueController addObserver:self
                     forKeyPath:verify_password_keypath
                        options:NSKeyValueObservingOptionNew
                        context:ACKVOContext];
    
}

- (void) dealloc
{
    [glueController removeObserver:self forKeyPath:username_keypath];
    [glueController removeObserver:self forKeyPath:realm_keypath];
    [glueController removeObserver:self forKeyPath:prompt_response_keypath];
    [super dealloc];
}

- (void) observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary *)change context:(void *)context
{
    if ([(NSString *) context isEqualToString:ACKVOContext]) {
	if ([keyPath isEqualToString:username_keypath] || [keyPath isEqualToString:realm_keypath]) {
            BOOL valid = [KIMUtilities validatePrincipalWithName:[glueController valueForKeyPath:username_keypath] 
                                                           realm:[glueController valueForKeyPath:realm_keypath]];
            [glueController setValue:[NSNumber numberWithBool:valid] 
                          forKeyPath:enable_identity_ok_keypath];
	}
        else if ([keyPath isEqualToString:prompt_response_keypath]) {
            BOOL valid = ([[glueController valueForKeyPath:prompt_response_keypath] length] > 0);
            [glueController setValue:[NSNumber numberWithBool:valid] 
                          forKeyPath:enable_prompt_ok_keypath];
	}
        else if ([keyPath isEqualToString:old_password_keypath] ||
                 [keyPath isEqualToString:new_password_keypath] ||
                 [keyPath isEqualToString:verify_password_keypath]) {
            NSString *oldString = [glueController valueForKeyPath:old_password_keypath];
            NSString *newString = [glueController valueForKeyPath:new_password_keypath];
            NSString *verifyString = [glueController valueForKeyPath:verify_password_keypath];
            BOOL valid = ([oldString length] > 0 &&
                          [newString length] > 0 &&
                          [verifyString length] > 0 &&
                          [newString isEqualToString:verifyString]);
            [glueController setValue:[NSNumber numberWithBool:valid] 
                          forKeyPath:change_password_ok_keypath];
        }
    }
    else {
        [super observeValueForKeyPath:keyPath ofObject:object change:change context:context];
    }
}

- (void) setContent: (NSMutableDictionary *) newContent
{
    [self window]; // wake up the nib connections
    [glueController setContent:newContent];
}

- (void) showEnterIdentity
{
    NSString *key = (associatedClient.name) ? ACAppPrincReqKey : ACPrincReqKey;
    NSString *message = [NSString stringWithFormat:
                         NSLocalizedStringFromTable(key, ACLocalizationTable, NULL),
                         associatedClient.name];
    
    // wake up the nib connections and adjust window size
    [self window];
    // set up controls with info from associatedClient
    [[containerView subviews] makeObjectsPerformSelector:@selector(removeFromSuperview)];
    [containerView addSubview:identityView];
    [enterBadge setBadgePath:associatedClient.path];
    [glueController setValue:message
                  forKeyPath:message_keypath];
    [self showWindow:nil];
    [[self window] makeFirstResponder:usernameField];
}

- (void) showAuthPrompt
{
    uint32_t type = [[glueController valueForKeyPath:@"content.prompt_type"] unsignedIntegerValue];
    
    switch (type) {
        case kim_prompt_type_password :
            [self showEnterPassword]; break;
        case kim_prompt_type_preauth :
        default :
            [self showSAM]; break;
    }
}

- (void) showEnterPassword
{
    CGFloat shrinkBy;
    NSRect frame;
    NSString *key = nil;
    NSString *message = nil;
    
    [self window];

    if ([associatedClient.name isEqualToString:[[NSBundle mainBundle] bundlePath]]) {
        key = ACPasswordReqKey;
        message = [NSString stringWithFormat:
                   NSLocalizedStringFromTable(key, ACLocalizationTable, NULL),
                   [glueController valueForKeyPath:identity_string_keypath]];
    } else {
        key = ACAppPasswordReqKey;
        message = [NSString stringWithFormat:
                   NSLocalizedStringFromTable(key, ACLocalizationTable, NULL),
                   associatedClient.name,
                   [glueController valueForKeyPath:identity_string_keypath]];
    }
    [glueController setValue:message
                  forKeyPath:message_keypath];

    // wake up the nib connections and adjust window size
    // set up controls with info from associatedClient
    [[containerView subviews] makeObjectsPerformSelector:@selector(removeFromSuperview)];
    [containerView addSubview:passwordView];
    // set badge
    [passwordBadge setBadgePath:associatedClient.path];
    
    // adjust for checkbox visibility
    if (![[glueController valueForKeyPath:allow_save_password_keypath] boolValue]) {
        shrinkBy = ([passwordField frame].origin.y - 
                    [rememberPasswordInKeychainCheckBox frame].origin.y);
        frame = [[self window] frame];
        frame.origin.y += shrinkBy;
        frame.size.height -= shrinkBy;
        [[self window] setFrame:frame display:NO animate:NO];
    }
    
    [self showWindow:nil];
    [[self window] makeFirstResponder:passwordField];
}

- (void) showSAM
{
    // wake up the nib connections and adjust window size
    [self window];
    // set up controls with info from associatedClient
    [[containerView subviews] makeObjectsPerformSelector:@selector(removeFromSuperview)];
    [containerView addSubview:samView];
    // set badge
    [samBadge setBadgePath:associatedClient.path];

    [glueController setValue:[NSNumber numberWithBool:NO]
                   forKeyPath:allow_save_password_keypath];
    
    [self showWindow:nil];
    [[self window] makeFirstResponder:samPromptField];
}

- (void) showChangePassword
{
    NSString *key = ([glueController valueForKeyPath:password_expired_keypath]) ? ACAppPrincReqKey : ACPrincReqKey;
    NSString *message = [NSString stringWithFormat:
                         NSLocalizedStringFromTable(key, ACLocalizationTable, NULL),
                         associatedClient.name];

                     
    BOOL expired = [[glueController valueForKeyPath:password_expired_keypath] boolValue];
    BOOL calledBySelf = [associatedClient.path isEqualToString:[[NSBundle mainBundle] bundlePath]];
    
    if (calledBySelf) {
        key = ACPasswordChangePrinc;
        message = [NSString stringWithFormat:
                   NSLocalizedStringFromTable(key, ACLocalizationTable, NULL), 
                   [glueController valueForKeyPath:identity_string_keypath]];
        // Please change the Kerberos password for \"%@\"
    } else if (!expired) {
        key = ACPasswordChangeApp;
        message = [NSString stringWithFormat:
                   NSLocalizedStringFromTable(key, ACLocalizationTable, NULL), 
                   associatedClient.name,
                   [glueController valueForKeyPath:identity_string_keypath]];
        // %@ requires that you change the Kerberos password for \"%@\"
    } else {
        key = ACPasswordChangeExpired;
        message = NSLocalizedStringFromTable(key, ACLocalizationTable, NULL);
        // Your password has expired, would you like to change it?
    }
    [glueController setValue:message forKeyPath:message_keypath];
                     
    // wake up the nib connections and adjust window size
    [self window];
    // set up controls with info from associatedClient
    [[containerView subviews] makeObjectsPerformSelector:@selector(removeFromSuperview)];
    [containerView addSubview:changePasswordView];
    // set badge
    [changePasswordBadge setBadgePath:associatedClient.path];
    
    [self showWindow:nil];
    [[self window] makeFirstResponder:oldPasswordField];
}

- (void) showError
{
    // wake up the nib connections and adjust window size
    [self window];
    // set up controls with info from associatedClient
    [[containerView subviews] makeObjectsPerformSelector:@selector(removeFromSuperview)];
    [containerView addSubview:errorView];
    // set badge
    [errorBadge setBadgePath:associatedClient.path];
    
    [self showWindow:nil];
}

- (IBAction) sliderDidChange: (id) sender
{
    NSInteger increment = 0;
    NSInteger newValue = 0;
    NSString *keyPath = nil;
    if ([sender isEqual:validLifetimeSlider]) {
        increment = VALID_LIFETIME_INCREMENT;
        keyPath = valid_lifetime_keypath;
    }
    else if ([sender isEqual:renewableLifetimeSlider]) {
        increment = RENEWABLE_LIFETIME_INCREMENT;
        keyPath = renewal_lifetime_keypath;
    }
    if (increment > 0) {
        newValue = ([sender integerValue] / increment) * increment;
        [ticketOptionsController setValue:[NSNumber numberWithInteger:newValue] 
                               forKeyPath:keyPath];
    }
}

- (IBAction) showTicketOptions: (id) sender
{
    // use a copy of the current options
    [ticketOptionsController setContent:
     [[[glueController valueForKeyPath:options_keypath] mutableCopy] autorelease]];
    
    [ticketOptionsController setValue:[NSNumber numberWithInteger:[KIMUtilities minValidLifetime]]
                           forKeyPath:min_valid_keypath];
    [ticketOptionsController setValue:[NSNumber numberWithInteger:[KIMUtilities maxValidLifetime]]
                           forKeyPath:max_valid_keypath];
    [ticketOptionsController setValue:[NSNumber numberWithInteger:[KIMUtilities minRenewableLifetime]]
                           forKeyPath:min_renewable_keypath];
    [ticketOptionsController setValue:[NSNumber numberWithInteger:[KIMUtilities maxRenewableLifetime]]
                           forKeyPath:max_renewable_keypath];

    [validLifetimeSlider setIntegerValue:
     [[ticketOptionsController valueForKeyPath:valid_lifetime_keypath] integerValue]];
    [renewableLifetimeSlider setIntegerValue:
     [[ticketOptionsController valueForKeyPath:renewal_lifetime_keypath] integerValue]];
    [self sliderDidChange:validLifetimeSlider];
    [self sliderDidChange:renewableLifetimeSlider];
    
    [NSApp beginSheet:ticketOptionsSheet
       modalForWindow:[self window]
        modalDelegate:self 
       didEndSelector:@selector(sheetDidEnd:returnCode:contextInfo:)
          contextInfo:NULL];
}

- (IBAction) cancelTicketOptions: (id) sender
{
    [NSApp endSheet:ticketOptionsSheet returnCode:NSUserCancelledError];
}

- (IBAction) saveTicketOptions: (id) sender
{
    [NSApp endSheet:ticketOptionsSheet];
}

- (void) sheetDidEnd: (NSWindow *) sheet 
          returnCode: (int) returnCode 
         contextInfo: (void *) contextInfo
{
    if (returnCode == NSUserCancelledError) {
        // discard new options
        [ticketOptionsController setContent:nil];
    } else {
        // replace existing options with new
        [glueController setValue:[ticketOptionsController content] forKeyPath:options_keypath];
    }
    [ticketOptionsSheet orderOut:nil];
}

- (IBAction) cancel: (id) sender
{
    [associatedClient didCancel];
    [self close];
}

- (IBAction) enterIdentity: (id) sender
{
    NSString *usernameString = [glueController valueForKeyPath:username_keypath];
    NSString *realmString = [glueController valueForKeyPath:realm_keypath];
    NSString *identityString = [NSString stringWithFormat:@"%@@%@", usernameString, realmString];
    NSDictionary *options = [glueController valueForKeyPath:options_keypath];
    NSLog(@"%s options == %@", __FUNCTION__, options);
    
    // the principal must already be valid to get this far
    [associatedClient didEnterIdentity:identityString options:options];
}

- (IBAction) answerAuthPrompt: (id) sender
{
    NSString *responseString = [glueController valueForKeyPath:prompt_response_keypath];
    NSNumber *saveResponse = [glueController valueForKeyPath:should_save_password_keypath];
    
    if (!saveResponse) {
        saveResponse = [NSNumber numberWithBool:NO];
    }
    [associatedClient didPromptForAuth:responseString
                          saveResponse:saveResponse];
}

- (IBAction) changePassword: (id) sender
{
    NSString *oldString = [glueController valueForKeyPath:old_password_keypath];
    NSString *newString = [glueController valueForKeyPath:new_password_keypath];
    NSString *verifyString = [glueController valueForKeyPath:verify_password_keypath];
    
    [associatedClient didChangePassword:oldString
                            newPassword:newString
                         verifyPassword:verifyString];
}

- (IBAction) showedError: (id) sender
{
    [associatedClient didHandleError];
}

@end

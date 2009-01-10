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
#import "KerberosFormatters.h"
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
@synthesize favoriteIdentities;
@synthesize favoriteOptions;

- (id) init
{
    return [self initWithWindowNibName: @"Authentication"];
}

- (void) awakeFromNib
{
    [[self window] center];
    // We need to float over the loginwindow and SecurityAgent so use its hardcoded level.
    [[self window] setLevel:NSModalPanelWindowLevel];    

    visibleAsSheet = NO;
    
    lifetimeFormatter.displaySeconds = NO;
    lifetimeFormatter.displayShortFormat = NO;
    
    [glueController addObserver:self 
                     forKeyPath:identity_string_keypath 
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
    [glueController removeObserver:self forKeyPath:identity_string_keypath];
    [glueController removeObserver:self forKeyPath:prompt_response_keypath];
    [super dealloc];
}

- (void) observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary *)change context:(void *)context
{
    BOOL valid = NO;
    
    if ([(NSString *) context isEqualToString:ACKVOContext]) {
	if ([keyPath isEqualToString:identity_string_keypath]) {
            valid = [KIMUtilities validateIdentity:[glueController valueForKeyPath:identity_string_keypath]];
            [glueController setValue:[NSNumber numberWithBool:valid] 
                          forKeyPath:enable_identity_ok_keypath];
	}
        else if ([keyPath isEqualToString:prompt_response_keypath]) {
            valid = ([[glueController valueForKeyPath:prompt_response_keypath] length] > 0);
            [glueController setValue:[NSNumber numberWithBool:valid] 
                          forKeyPath:enable_prompt_ok_keypath];
	}
        else if ([keyPath isEqualToString:old_password_keypath] ||
                 [keyPath isEqualToString:new_password_keypath] ||
                 [keyPath isEqualToString:verify_password_keypath]) {
            NSString *oldString = [glueController valueForKeyPath:old_password_keypath];
            NSString *newString = [glueController valueForKeyPath:new_password_keypath];
            NSString *verifyString = [glueController valueForKeyPath:verify_password_keypath];
            valid = ([oldString length] > 0 && [newString length] > 0 &&
                     [verifyString length] > 0 && [newString isEqualToString:verifyString]);
            [glueController setValue:[NSNumber numberWithBool:valid] 
                          forKeyPath:change_password_ok_keypath];
        }
        else {
            [super observeValueForKeyPath:keyPath ofObject:object change:change context:context];
        }
    }
    else {
        [super observeValueForKeyPath:keyPath ofObject:object change:change context:context];
    }
}

- (IBAction) showWindow: (id) sender
{

    [super showWindow:sender];
}

- (void) showWithParent: (NSWindow *) parentWindow
{
    // attach as sheet if given a parentWindow
    if (parentWindow && !visibleAsSheet) {
        [NSApp beginSheet:[self window] 
           modalForWindow:parentWindow
            modalDelegate:self
           didEndSelector:@selector(authSheetDidEnd:returnCode:contextInfo:)
              contextInfo:NULL];
    }
    // else, display as normal
    else {
        [self showWindow:nil];
    }
}

- (void) windowWillBeginSheet: (NSNotification *) notification
{
    visibleAsSheet = YES;
}

- (void) windowDidEndSheet: (NSNotification *) notification
{
    visibleAsSheet = NO;
}

- (void) setContent: (NSMutableDictionary *) newContent
{
    [self window]; // wake up the nib connections
    [glueController setContent:newContent];
}

- (void) swapView: (NSView *) aView
{
    NSWindow *theWindow = [self window];
    NSRect windowFrame;
    NSRect viewFrame;
    
    [[containerView subviews] makeObjectsPerformSelector:@selector(removeFromSuperview)];
    
    windowFrame = [theWindow frame];
    viewFrame = [theWindow frameRectForContentRect:[aView frame]];
    windowFrame.origin.y -= viewFrame.size.height - windowFrame.size.height;
    
    windowFrame.size.width = viewFrame.size.width;
    windowFrame.size.height = viewFrame.size.height;
    
    [theWindow setFrame:windowFrame display:YES animate:YES];
    
    [containerView addSubview:aView];
    
}

- (void) showSpinny
{
    [enterSpinny          startAnimation: nil];
    [passwordSpinny       startAnimation: nil];
    [samSpinny            startAnimation: nil];
    [changePasswordSpinny startAnimation: nil];
    [glueController setValue:[NSNumber numberWithBool:NO]
                  forKeyPath:accepting_input_keypath];
}

- (void) hideSpinny
{
    [enterSpinny          stopAnimation: nil];
    [passwordSpinny       stopAnimation: nil];
    [samSpinny            stopAnimation: nil];
    [changePasswordSpinny stopAnimation: nil];    
    [glueController setValue:[NSNumber numberWithBool:YES]
                  forKeyPath:accepting_input_keypath];
}

- (void) clearSensitiveInputs
{
    [glueController setValue:@"" 
                  forKeyPath:prompt_response_keypath];
}

- (void) clearAllInputs
{
    [glueController setValue:@"" 
                  forKeyPath:old_password_keypath];
    [glueController setValue:@"" 
                  forKeyPath:new_password_keypath];
    [glueController setValue:@"" 
                  forKeyPath:verify_password_keypath];
    [self clearSensitiveInputs];
}

- (void) showEnterIdentity: (NSWindow *) parentWindow
{
    kim_error err = KIM_NO_ERROR;
    NSWindow *theWindow = [self window];
    NSString *key = (associatedClient.name) ? ACAppPrincReqKey : ACPrincReqKey;
    NSString *message = [NSString stringWithFormat:
                         NSLocalizedStringFromTable(key, ACLocalizationTable, NULL),
                         associatedClient.name];
    
    self.favoriteIdentities = [NSMutableArray array];
    self.favoriteOptions = [NSMutableDictionary dictionary];
    // get array of favorite identity strings and associated options
    
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
            kim_string display_string = NULL;
            NSString *identityString = nil;
            
            err = kim_preferences_get_favorite_identity_at_index(preferences,
                                                                 i,
                                                                 &kimIdentity,
                                                                 &kimOptions);
            if (!err) {
                err = kim_identity_get_display_string(kimIdentity, &display_string);
            }
            if (!err && display_string) {
                identityString = [NSString stringWithUTF8String:display_string];
                [favoriteIdentities addObject:identityString];
            }
            if (!err) {
                [favoriteOptions setObject:[KIMUtilities dictionaryForKimOptions:kimOptions]
                                    forKey:identityString];
            }
            
            kim_options_free(&kimOptions);
            kim_string_free (&display_string);
            kim_identity_free (&kimIdentity);
        }
        
        kim_preferences_free(&preferences);
    }
    
    [glueController setValue:favoriteIdentities forKeyPath:favorite_strings_keypath];
    
    // wake up the nib connections and adjust window size
    [self window];
    // set up controls with info from associatedClient
    [enterBadge setBadgePath:associatedClient.path];
    [glueController setValue:message
                  forKeyPath:message_keypath];

    [self hideSpinny];
    [self clearAllInputs];

    [self swapView:identityView];

    [theWindow makeFirstResponder:identityField];

    [self showWithParent: parentWindow];
}

- (void) showAuthPrompt: (NSWindow *) parentWindow
{
    uint32_t type = [[glueController valueForKeyPath:@"content.prompt_type"] unsignedIntegerValue];
    
    [self hideSpinny];

    [self clearSensitiveInputs];

    switch (type) {
        case kim_prompt_type_password :
            [self showEnterPassword: parentWindow]; break;
        case kim_prompt_type_preauth :
        default :
            [self showSAM: parentWindow]; break;
    }
}

- (void) showEnterPassword: (NSWindow *) parentWindow
{
    CGFloat shrinkBy;
    NSRect frame;
    NSString *key = nil;
    NSString *message = nil;
    NSWindow *theWindow = [self window];

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

    // set badge
    [passwordBadge setBadgePath:associatedClient.path];
    
    // adjust for checkbox visibility
    if (![[glueController valueForKeyPath:allow_save_password_keypath] boolValue] &&
        ![rememberPasswordInKeychainCheckBox isHidden]) {
        [rememberPasswordInKeychainCheckBox setHidden:YES];
        frame = [passwordView frame];
        shrinkBy = ([passwordField frame].origin.y - 
                    [rememberPasswordInKeychainCheckBox frame].origin.y);
        frame.size.height -= shrinkBy;
        [passwordView setFrame:frame];
    }
    
    [self swapView:passwordView];
    
    [theWindow makeFirstResponder:passwordField];
    [self showWithParent:parentWindow];
}

- (void) showSAM: (NSWindow *) parentWindow
{
    // set badge
    [samBadge setBadgePath:associatedClient.path];

    [glueController setValue:[NSNumber numberWithBool:NO]
                   forKeyPath:allow_save_password_keypath];
    
    [self swapView:samView];
    
    [[self window] makeFirstResponder:samPromptField];
    [self showWithParent:parentWindow];
}

- (void) showChangePassword: (NSWindow *) parentWindow
{
    NSString *key = ([glueController valueForKeyPath:password_expired_keypath]) ? ACAppPrincReqKey : ACPrincReqKey;
    NSString *message = [NSString stringWithFormat:
                         NSLocalizedStringFromTable(key, ACLocalizationTable, NULL),
                         associatedClient.name];
    NSWindow *theWindow = [self window];

                     
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
        message = [NSString stringWithFormat:
                   NSLocalizedStringFromTable(key, ACLocalizationTable, NULL), 
                   [glueController valueForKeyPath:identity_string_keypath]];
        // Your password has expired, would you like to change it?
    }
    [glueController setValue:message forKeyPath:message_keypath];
    
    // set badge
    [changePasswordBadge setBadgePath:associatedClient.path];
    
    [self hideSpinny];
    
    if (![[self window] isVisible]) {
        [self clearAllInputs];
    }
    
    [self swapView:changePasswordView];

    [self showWithParent:parentWindow];

    [theWindow makeFirstResponder:oldPasswordField];
}

- (void) showError: (NSWindow *) parentWindow
{
    // wake up the nib connections and adjust window size
    [self window];
    // set badge
    [errorBadge setBadgePath:associatedClient.path];

    [self hideSpinny];
    [self swapView:errorView];
    
    [self showWithParent:parentWindow];
}

- (IBAction) checkboxDidChange: (id) sender
{
    if ([[ticketOptionsController valueForKeyPath:uses_default_options_keypath] boolValue]) {
        // merge defaults onto current options
        NSMutableDictionary *currentOptions = [ticketOptionsController content];
        NSDictionary *defaultOptions = [KIMUtilities dictionaryForKimOptions:NULL];
        [currentOptions addEntriesFromDictionary:defaultOptions];
        // update the sliders, since their values aren't bound
        [validLifetimeSlider setDoubleValue:[[ticketOptionsController valueForKeyPath:valid_lifetime_keypath] doubleValue]];
        [renewableLifetimeSlider setDoubleValue:[[ticketOptionsController valueForKeyPath:renewal_lifetime_keypath] doubleValue]];
    }    
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
    NSDictionary *options = nil;
    NSString *expandedString = nil;
    // if this is a favorite, try to load its default options
    [identityField validateEditing];

    expandedString = [KIMUtilities expandedIdentity:[identityField stringValue]];

    // edit the favorite options for this favorite identity
    if (expandedString) {
        options = [favoriteOptions objectForKey:expandedString];
    }
    
    // else, it's not a favorite identity. use default options
    if (!options) {
        options = [KIMUtilities dictionaryForKimOptions:KIM_OPTIONS_DEFAULT];
    }
    
    [ticketOptionsController setContent:[[options mutableCopy] autorelease]];
    
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
       didEndSelector:@selector(ticketOptionsSheetDidEnd:returnCode:contextInfo:)
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

- (IBAction) cancelAuthSheet: (id) sender
{
    [NSApp endSheet:[self window]];
}

- (void) authSheetDidEnd: (NSWindow *) sheet 
              returnCode: (int) returnCode 
             contextInfo: (void *) contextInfo
{
    [sheet orderOut:nil];
}
        
        
- (void) ticketOptionsSheetDidEnd: (NSWindow *) sheet 
                       returnCode: (int) returnCode 
                      contextInfo: (void *) contextInfo
{
    if (returnCode == NSUserCancelledError) {
        // discard new options
        [ticketOptionsController setContent:nil];
    } else {
        kim_error err = KIM_NO_ERROR;
        kim_preferences prefs = NULL;
        kim_identity identity = NULL;
        kim_options options = NULL;
        NSString *expandedString = [KIMUtilities expandedIdentity:[identityField stringValue]];;

        // replace options if favorite exists
        // add to favorites if not already in list
        if (!expandedString) {
            err = KIM_BAD_PRINCIPAL_STRING_ERR;
        }
        if (!err) {
            [favoriteOptions setObject:[ticketOptionsController content] 
                                forKey:expandedString];
        }
        if (!err) {
            err = kim_preferences_create(&prefs);
        }
        if (!err) {
            err = kim_identity_create_from_string(&identity, [[identityField stringValue] UTF8String]);
        }
        if (!err) {
            options = [KIMUtilities kimOptionsForDictionary:[ticketOptionsController content]];
        }
        
        if (!identity) { err = KIM_BAD_PRINCIPAL_STRING_ERR; }
        
        if (!err) {
            err = kim_preferences_remove_favorite_identity(prefs, identity);
        }
        if (!err) {
            err = kim_preferences_add_favorite_identity(prefs, identity, options);
        }
        if (!err) {
            err = kim_preferences_synchronize(prefs);
        }
        
        kim_preferences_free(&prefs);
        kim_options_free(&options);
        kim_identity_free(&identity);
    }
    [ticketOptionsSheet orderOut:nil];
}

- (IBAction) changePasswordGearAction: (id) sender
{
    NSString *expandedString = [KIMUtilities expandedIdentity:[identityField stringValue]];
    NSDictionary *options = [favoriteOptions objectForKey:expandedString];
    
    if (!options) {
        options = [glueController valueForKeyPath:options_keypath];
    }
    
    [self showSpinny];
    
    // the principal must already be valid to get this far
    [associatedClient didEnterIdentity:expandedString options:options wantsChangePassword:YES];
}

- (IBAction) cancel: (id) sender
{
    [NSApp endSheet:[self window]];
    [associatedClient didCancel];
}

- (IBAction) enterIdentity: (id) sender
{
    NSString *expandedString = [KIMUtilities expandedIdentity:[identityField stringValue]];
    NSDictionary *options = [favoriteOptions objectForKey:expandedString];

    if (!options) {
        options = [glueController valueForKeyPath:options_keypath];
    }
    
    [self showSpinny];

    // the principal must already be valid to get this far
    [associatedClient didEnterIdentity:expandedString options:options wantsChangePassword:NO];
}

- (IBAction) answerAuthPrompt: (id) sender
{
    NSString *responseString = [glueController valueForKeyPath:prompt_response_keypath];
    NSNumber *saveResponse = [glueController valueForKeyPath:should_save_password_keypath];
    
    if (!saveResponse) {
        saveResponse = [NSNumber numberWithBool:NO];
    }

    [self showSpinny];
    [associatedClient didPromptForAuth:responseString
                          saveResponse:saveResponse];
}

- (IBAction) changePassword: (id) sender
{
    NSString *oldString = [glueController valueForKeyPath:old_password_keypath];
    NSString *newString = [glueController valueForKeyPath:new_password_keypath];
    NSString *verifyString = [glueController valueForKeyPath:verify_password_keypath];
    
    [self showSpinny];
    
    [associatedClient didChangePassword:oldString
                            newPassword:newString
                         verifyPassword:verifyString];
    [NSApp endSheet:[self window]];
}

- (IBAction) showedError: (id) sender
{
    [associatedClient didHandleError];
}

@end

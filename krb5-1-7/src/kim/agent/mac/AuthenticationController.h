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

@class IPCClient;
@class KerberosTimeFormatter;
@class BadgedImageView;

@interface AuthenticationController : NSWindowController {
    IPCClient *associatedClient;
    
    IBOutlet KerberosTimeFormatter *lifetimeFormatter;
    
    IBOutlet NSView *containerView;
    IBOutlet NSView *identityView;
    IBOutlet NSView *passwordView;
    IBOutlet NSView *samView;
    IBOutlet NSView *changePasswordView;
    IBOutlet NSView *expiredPasswordView;
    IBOutlet NSView *errorView;

    IBOutlet BadgedImageView *enterBadge;
    IBOutlet BadgedImageView *passwordBadge;
    IBOutlet BadgedImageView *samBadge;
    IBOutlet BadgedImageView *changePasswordBadge;
    IBOutlet BadgedImageView *errorBadge;
    
    IBOutlet NSProgressIndicator *enterSpinny;
    IBOutlet NSProgressIndicator *passwordSpinny;
    IBOutlet NSProgressIndicator *samSpinny;
    IBOutlet NSProgressIndicator *changePasswordSpinny;
    
    // Controls that need to be made key
    IBOutlet NSTextField *identityField;
    IBOutlet NSTextField *passwordField;
    IBOutlet NSTextField *samPromptField;
    IBOutlet NSTextField *oldPasswordField;
    
    // Other controls of interest
    IBOutlet NSButton *rememberPasswordInKeychainCheckBox;
    
    IBOutlet NSObjectController *glueController;

    IBOutlet NSWindow *ticketOptionsSheet;
    IBOutlet NSObjectController *ticketOptionsController;
    BOOL visibleAsSheet;
    
    IBOutlet NSSlider *validLifetimeSlider;
    IBOutlet NSSlider *renewableLifetimeSlider;
    
    NSMutableArray *favoriteIdentities;
    NSMutableDictionary *favoriteOptions;
}

@property (readwrite, retain) IPCClient *associatedClient;
@property (readwrite, retain) NSMutableArray *favoriteIdentities;
@property (readwrite, retain) NSMutableDictionary *favoriteOptions;

- (void) setContent: (NSMutableDictionary *) newContent;

- (void) showEnterIdentity: (NSWindow *) parentWindow;
- (void) showAuthPrompt: (NSWindow *) parentWindow;
- (void) showEnterPassword: (NSWindow *) parentWindow;
- (void) showSAM: (NSWindow *) parentWindow;
- (void) showChangePassword: (NSWindow *) parentWindow;
- (void) showError: (NSWindow *) parentWindow;

- (IBAction) cancel: (id) sender;
- (IBAction) enterIdentity: (id) sender;
- (IBAction) answerAuthPrompt: (id) sender;
- (IBAction) changePassword: (id) sender;
- (IBAction) showedError: (id) sender;

- (IBAction) checkboxDidChange: (id) sender;
- (IBAction) sliderDidChange: (id) sender;

- (IBAction) showTicketOptions: (id) sender;
- (IBAction) cancelTicketOptions: (id) sender;
- (IBAction) saveTicketOptions: (id) sender;

- (IBAction) cancelAuthSheet: (id) sender;

- (void) authSheetDidEnd: (NSWindow *) sheet 
              returnCode: (int) returnCode 
             contextInfo: (void *) contextInfo;
- (void) ticketOptionsSheetDidEnd: (NSWindow *) sheet 
          returnCode: (int) returnCode 
         contextInfo: (void *) contextInfo;

- (IBAction) changePasswordGearAction: (id) sender;

- (void) swapView: (NSView *) aView;
- (void) showSpinny;
- (void) hideSpinny;
- (void) clearSensitiveInputs;
- (void) clearAllInputs;

@end

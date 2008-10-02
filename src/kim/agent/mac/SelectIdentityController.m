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

#import "SelectIdentityController.h"
#import "IPCClient.h"

#define identities_key_path @"identities"

@implementation SelectIdentityController

@synthesize associatedClient;

// ---------------------------------------------------------------------------

- (id) init
{
    return [self initWithWindowNibName: @"SelectIdentity"];
}

// ---------------------------------------------------------------------------

- (void) dealloc
{
    [refreshTimer release];
    [identities release];
    [super dealloc];
}

// ---------------------------------------------------------------------------

- (void) awakeFromNib 
{
    NSString *key = nil;
    NSString *message = nil;

    // We need to float over the loginwindow and SecurityAgent so use its hardcoded level.
    [[self window] center];
    [[self window] setLevel:2003];

    [identityTableView setDoubleAction:@selector(select:)];
    identities = [[Identities alloc] init];
    [identitiesController setContent:identities];
    refreshTimer = [NSTimer scheduledTimerWithTimeInterval:60.0 target:self selector:@selector(timedRefresh:) userInfo:nil repeats:true];    

    [kerberosIconImageView setBadgePath:associatedClient.path];
    
    if ([associatedClient.name isEqualToString:[[NSBundle mainBundle] bundlePath]]) {
        key = @"SelectIdentityRequest";
        message = NSLocalizedStringFromTable(key, @"SelectIdentity", NULL);
    }
    else {
        key = @"SelectIdentityApplicationRequest";
        message = [NSString stringWithFormat:
                   NSLocalizedStringFromTable(key, @"SelectIdentity", NULL),
                   associatedClient.name];
    }
    [headerTextField setStringValue:message];
    [explanationTextField setStringValue:@"explanation!"];
}

// ---------------------------------------------------------------------------

- (void) setContent: (NSMutableDictionary *) newContent
{
    [self window]; // wake up the nib connections
//    [glueController setContent:newContent];
}

// ---------------------------------------------------------------------------

- (IBAction) newIdentity: (id) sender
{
    Identity *newIdentity = [[Identity alloc] init];

    newIdentity.favorite = TRUE;
    identityOptionsController.content = newIdentity;
    [newIdentity release];

    [self showOptions:@"new"];
}

// ---------------------------------------------------------------------------

- (IBAction) addToFavorites: (id) sender
{
    Identity *anIdentity = [identityArrayController.selectedObjects lastObject];
    identityOptionsController.content = nil;

    anIdentity.favorite = TRUE;
    
    [self saveOptions];
}

// ---------------------------------------------------------------------------

- (IBAction) removeFromFavorites: (id) sender
{
    Identity *anIdentity = [identityArrayController.selectedObjects lastObject];
    identityOptionsController.content = anIdentity;

    anIdentity.favorite = FALSE;
    
    [self saveOptions];
}

// ---------------------------------------------------------------------------

- (IBAction) changePassword: (id) sender
{
    
}

// ---------------------------------------------------------------------------

- (IBAction) select: (id) sender
{
    Identity *selectedIdentity = nil;
    
    // ignore double-click on header
    if ([sender respondsToSelector:@selector(clickedRow)] && [sender clickedRow] < 0) {
        return;
    }
    selectedIdentity = [[identityArrayController selectedObjects] lastObject];

    [associatedClient didSelectIdentity: selectedIdentity.identity
                                options: [identityOptionsController valueForKeyPath:@"content.options"]
                    wantsChangePassword: NO];
}

// ---------------------------------------------------------------------------

- (IBAction) cancel: (id) sender
{
    [associatedClient didCancel];
    [self close];
}

// ---------------------------------------------------------------------------

- (IBAction) editOptions: (id) sender
{
    Identity *anIdentity = [identityArrayController.selectedObjects lastObject];
    anIdentity.favorite = TRUE;
    [identityOptionsController setContent: anIdentity];
    
    [self showOptions:@"edit"];
}

// ---------------------------------------------------------------------------

- (IBAction) resetOptions: (id) sender
{
    Identity *anIdentity = identityOptionsController.content;
    // reset options to default settings
    [anIdentity resetOptions];
}

// ---------------------------------------------------------------------------

- (IBAction) cancelOptions: (id) sender
{
    identityOptionsController.content = nil;
    [NSApp endSheet:identityOptionsWindow returnCode:NSUserCancelledError];
    
    // dump changed settings
    [identities reload];
}

// ---------------------------------------------------------------------------

- (IBAction) doneOptions: (id) sender
{
//    Identity *anIdentity = identityOptionsController.content;
    
    
    [NSApp endSheet: identityOptionsWindow];
}

- (IBAction) sliderDidChange: (id) sender
{
    
}

- (void)controlTextDidChange:(NSNotification *)aNotification
{
//    BOOL valid = [KIMUtilities validateIdentity:];
    [ticketOptionsOkButton setEnabled:false];
    [ticketOptionsOkButton setNeedsDisplay];
}

// ---------------------------------------------------------------------------

- (void) showOptions: (NSString *) contextInfo
{
    Identity *anIdentity = [[identityArrayController selectedObjects] lastObject];
    // use a copy of the current options
    [identityOptionsController setContent:
     [[[glueController valueForKeyPath:options_keypath] mutableCopy] autorelease]];

    [identityField setStringValue:anIdentity.identity];
    [staticIdentityField setStringValue:anIdentity.identity];
    
    [identityOptionsController setContent:
     [[[glueController valueForKeyPath:options_keypath] mutableCopy] autorelease]];
    
    [identityOptionsController setValue:[NSNumber numberWithInteger:[KIMUtilities minValidLifetime]]
                           forKeyPath:min_valid_keypath];
    [identityOptionsController setValue:[NSNumber numberWithInteger:[KIMUtilities maxValidLifetime]]
                           forKeyPath:max_valid_keypath];
    [identityOptionsController setValue:[NSNumber numberWithInteger:[KIMUtilities minRenewableLifetime]]
                           forKeyPath:min_renewable_keypath];
    [identityOptionsController setValue:[NSNumber numberWithInteger:[KIMUtilities maxRenewableLifetime]]
                           forKeyPath:max_renewable_keypath];
    
    [validLifetimeSlider setIntegerValue:
     [[identityOptionsController valueForKeyPath:valid_lifetime_keypath] integerValue]];
    [renewableLifetimeSlider setIntegerValue:
     [[identityOptionsController valueForKeyPath:renewal_lifetime_keypath] integerValue]];
    [self sliderDidChange:validLifetimeSlider];
    [self sliderDidChange:renewableLifetimeSlider];
    
    [NSApp beginSheet: identityOptionsWindow 
       modalForWindow: [self window] 
        modalDelegate: self 
       didEndSelector: @selector(didEndSheet:returnCode:contextInfo:)
          contextInfo: contextInfo];
}

// ---------------------------------------------------------------------------

- (void) didEndSheet: (NSWindow *) sheet returnCode: (int) returnCode contextInfo: (void *) contextInfo
{
    kim_error err = KIM_NO_ERROR;
    if (returnCode != NSUserCancelledError) {
        if ([(NSString *)contextInfo isEqualToString:@"new"]) {
            Identity *newIdentity = identityOptionsController.content;
            err = [identities addIdentity:newIdentity];
            
            if (err) {
                NSLog(@"%s received error %@ trying to add identity %@", _cmd, [KIMUtilities stringForLastKIMError:err], [newIdentity description]);
            }
            [self saveOptions];
        }
        else if ([(NSString *)contextInfo isEqualToString:@"edit"]) {
            [self saveOptions];
        }
    }
    [sheet orderOut:self];
}

// ---------------------------------------------------------------------------

- (void) saveOptions
{
    // attempt to preserve the selection
    Identity *anIdentity = [[identityArrayController selectedObjects] lastObject];
    NSUInteger a, b, c;
    
    a = [identityArrayController.content indexOfObject: anIdentity];
    b = NSNotFound;
    
    [identities synchronizePreferences];
    
    /*
     * select same object as before if it's still in the array
     * if not, select same index as before or end of array, whichever is less
     */
    
    b = [identityArrayController.content indexOfObject:anIdentity];
    c = [identityArrayController.content count] - 1;
    
    [identityArrayController setSelectionIndex: (b == NSNotFound) ? (a > c) ? c : a : b];
}

// ---------------------------------------------------------------------------

- (void) timedRefresh:(NSTimer *)timer
{
    // refetch data to update expiration times
    [identityArrayController rearrangeObjects];
}

@end

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
#import "KerberosFormatters.h"

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
    [identityOptionsController removeObserver:self forKeyPath:identity_string_keypath];
    [refreshTimer release];
    [identities release];
    [super dealloc];
}

// ---------------------------------------------------------------------------

- (void) awakeFromNib 
{
    NSString *key = nil;
    NSString *message = nil;
    
    [[self window] center];
    [[self window] setLevel:NSModalPanelWindowLevel];
    
    longTimeFormatter.displaySeconds = NO;
    longTimeFormatter.displayShortFormat = NO;
    
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
    
    optionsBoxHeight = [ticketOptionsBox frame].size.height + [ticketOptionsBox frame].origin.y - [ticketOptionsToggleButton frame].origin.y - [ticketOptionsToggleButton frame].size.height;
    [self toggleOptionsVisibility:nil];
    
    [identityOptionsController addObserver:self
                                forKeyPath:identity_string_keypath
                                   options:NSKeyValueObservingOptionNew
                                   context:NULL];
}

- (void)  observeValueForKeyPath:(NSString *) keyPath ofObject: (id) object change: (NSDictionary *) change context:(void *) context
{
    if (object == identityOptionsController && [keyPath isEqualToString:identity_string_keypath]) {
        BOOL enabled = [KIMUtilities validateIdentity:[identityOptionsController valueForKeyPath:identity_string_keypath]];
        [identityOptionsController setValue:[NSNumber numberWithBool:enabled] 
                                 forKeyPath:@"content.canClickOK"];
    }
    else {
        [super observeValueForKeyPath:keyPath ofObject:object change:change context:context];
    }
}

// ---------------------------------------------------------------------------

- (NSRect) windowWillUseStandardFrame: (NSWindow *) window defaultFrame: (NSRect) defaultFrame
{
    NSRect newFrame = [window frame];
    CGFloat oldHeight = [[identityTableScrollView contentView] frame].size.height;
    CGFloat newHeight = [identityTableView numberOfRows] * 
                        ([identityTableView rowHeight] + [identityTableView intercellSpacing].height);
    CGFloat yDelta = newHeight - oldHeight;
    
    newFrame.origin.y -= yDelta;
    newFrame.size.height += yDelta;
    
    return newFrame;
}

// ---------------------------------------------------------------------------

- (void) setContent: (NSMutableDictionary *) newContent
{
    [self window]; // wake up the nib connections
    [glueController setContent:newContent];
}

// ---------------------------------------------------------------------------

- (IBAction) newIdentity: (id) sender
{
    identityOptionsController.content = [[[glueController valueForKeyPath:@"content.hints.options"] 
                                          mutableCopy] autorelease];

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
    identityOptionsController.content = nil;

    anIdentity.favorite = FALSE;
    
    [self saveOptions];
}

// ---------------------------------------------------------------------------

- (IBAction) changePassword: (id) sender
{
    Identity *selectedIdentity = nil;
    
    // ignore double-click on header
    if ([sender respondsToSelector:@selector(clickedRow)] && [sender clickedRow] < 0) {
        return;
    }
    selectedIdentity = [[identityArrayController selectedObjects] lastObject];
    
    [associatedClient didSelectIdentity: selectedIdentity.identity
                                options: [identityOptionsController valueForKeyPath:@"content.options"]
                    wantsChangePassword: YES];
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
                                options: [identityOptionsController content]
                    wantsChangePassword: NO];
}

// ---------------------------------------------------------------------------

- (IBAction) cancel: (id) sender
{
    [associatedClient didCancel];
}

// ---------------------------------------------------------------------------

- (IBAction) editOptions: (id) sender
{
    Identity *anIdentity = [identityArrayController.selectedObjects lastObject];
    anIdentity.favorite = TRUE;
    
    [identityOptionsController setContent:anIdentity.options];
    
    [self showOptions:@"edit"];
}

// ---------------------------------------------------------------------------

- (IBAction) cancelOptions: (id) sender
{
    identityOptionsController.content = nil;
    [NSApp endSheet:ticketOptionsWindow returnCode:NSUserCancelledError];
    
    // dump changed settings
    [identities reload];
}

// ---------------------------------------------------------------------------

- (IBAction) doneOptions: (id) sender
{
//    Identity *anIdentity = identityOptionsController.content;
    
    
    [NSApp endSheet: ticketOptionsWindow];
}

// ---------------------------------------------------------------------------

- (IBAction) checkboxDidChange: (id) sender
{
    if ([[identityOptionsController valueForKeyPath:uses_default_options_keypath] boolValue]) {
        // merge defaults onto current options
        NSMutableDictionary *currentOptions = [identityOptionsController content];
        NSDictionary *defaultOptions = [KIMUtilities dictionaryForKimOptions:NULL];
        NSLog(@"using default ticket options");
        [currentOptions addEntriesFromDictionary:defaultOptions];
        // update the sliders, since their values aren't bound
        [validLifetimeSlider setDoubleValue:[[identityOptionsController valueForKeyPath:valid_lifetime_keypath] doubleValue]];
        [renewableLifetimeSlider setDoubleValue:[[identityOptionsController valueForKeyPath:renewal_lifetime_keypath] doubleValue]];
    }    
}

// ---------------------------------------------------------------------------

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
        [identityOptionsController setValue:[NSNumber numberWithInteger:
                                             (newValue < increment) ? increment : newValue] 
                                 forKeyPath:keyPath];
    }
}

// ---------------------------------------------------------------------------

- (void) showOptions: (NSString *) contextInfo
{
    Identity *anIdentity = [[identityArrayController selectedObjects] lastObject];
    BOOL isIdentityNameNotEditable = (!anIdentity.hasCCache || [contextInfo isEqualToString:@"new"]);
    NSString *identityString = ([contextInfo isEqualToString:@"new"]) ? @"" : anIdentity.identity;
    
    [identityOptionsController setValue:identityString
                             forKeyPath:identity_string_keypath];    
    [identityOptionsController setValue:[NSNumber numberWithInteger:[KIMUtilities minValidLifetime]]
                           forKeyPath:min_valid_keypath];
    [identityOptionsController setValue:[NSNumber numberWithInteger:[KIMUtilities maxValidLifetime]]
                           forKeyPath:max_valid_keypath];
    [identityOptionsController setValue:[NSNumber numberWithInteger:[KIMUtilities minRenewableLifetime]]
                           forKeyPath:min_renewable_keypath];
    [identityOptionsController setValue:[NSNumber numberWithInteger:[KIMUtilities maxRenewableLifetime]]
                           forKeyPath:max_renewable_keypath];
    [identityOptionsController setValue:[NSNumber numberWithBool:!isIdentityNameNotEditable]
                             forKeyPath:@"content.hasCCache"];
    
    [validLifetimeSlider setIntegerValue:
     [[identityOptionsController valueForKeyPath:valid_lifetime_keypath] integerValue]];
    [renewableLifetimeSlider setIntegerValue:
     [[identityOptionsController valueForKeyPath:renewal_lifetime_keypath] integerValue]];
    [self sliderDidChange:validLifetimeSlider];
    [self sliderDidChange:renewableLifetimeSlider];
    
    [NSApp beginSheet: ticketOptionsWindow 
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
            Identity *newIdentity = [[Identity alloc] 
                                     initWithIdentity:[identityOptionsController valueForKeyPath:identity_string_keypath] 
                                     options:identityOptionsController.content];
            newIdentity.favorite = YES;

            err = [identities addIdentity:newIdentity];

            if (err) {
                NSLog(@"%s received error %@ trying to add identity %@", _cmd, [KIMUtilities stringForLastKIMError:err], [newIdentity description]);
            }
            [newIdentity release];
            [self saveOptions];

        }
        else if ([(NSString *)contextInfo isEqualToString:@"edit"]) {
            Identity *editedIdentity = [[identityArrayController selectedObjects] lastObject];
            editedIdentity.favorite = YES;
            editedIdentity.identity = [identityOptionsController valueForKeyPath:identity_string_keypath];
            editedIdentity.options = identityOptionsController.content;

            [self saveOptions];
            
        }
    } else {
        [identityOptionsController setContent:nil];
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

- (IBAction) toggleOptionsVisibility: (id) sender
{
    NSRect newFrame = [NSWindow contentRectForFrameRect:[ticketOptionsWindow frame] styleMask:[ticketOptionsWindow styleMask]];
    CGFloat newHeight;
    
    if ([ticketOptionsBox isHidden]) {
        newHeight = newFrame.size.height + optionsBoxHeight;
        newFrame.origin.y += newFrame.size.height;
        newFrame.origin.y -= newHeight;
        newFrame.size.height = newHeight;
        newFrame = [NSWindow frameRectForContentRect:newFrame styleMask:[ticketOptionsWindow styleMask]];

        [ticketOptionsWindow setFrame:newFrame display:YES animate:YES];
        [ticketOptionsBox setHidden:NO];
        [sender setTitle:NSLocalizedStringFromTable(@"SelectIdentityHideOptions", @"SelectIdentity", NULL)];
    }
    else {
        newHeight = newFrame.size.height - optionsBoxHeight;
        newFrame.origin.y += newFrame.size.height;
        newFrame.origin.y -= newHeight;
        newFrame.size.height = newHeight;
        newFrame = [NSWindow frameRectForContentRect:newFrame styleMask:[ticketOptionsWindow styleMask]];
        
        [ticketOptionsBox setHidden:YES];
        [ticketOptionsWindow setFrame:newFrame display:YES animate:YES];
        [sender setTitle:NSLocalizedStringFromTable(@"SelectIdentityShowOptions", @"SelectIdentity", NULL)];
    }
}

// ---------------------------------------------------------------------------

- (void) timedRefresh:(NSTimer *)timer
{
    // refetch data to update expiration times
    [identityArrayController rearrangeObjects];
}

@end

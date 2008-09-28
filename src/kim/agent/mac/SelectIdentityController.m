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

#define identities_key_path @"identities"

@implementation SelectIdentityController

// ---------------------------------------------------------------------------

- (id) initWithWindowNibName: (NSString *) windowNibName
{
    if ((self = [super initWithWindowNibName: windowNibName])) {
        identities = [[Identities alloc] init];
        [identities addObserver:self 
                     forKeyPath:identities_key_path 
                        options:NSKeyValueObservingOptionNew 
                        context:@"selectIdentityController"];
        refreshTimer = [NSTimer scheduledTimerWithTimeInterval:60.0 target:self selector:@selector(timedRefresh:) userInfo:nil repeats:true];
    }
    
    return self;
}

// ---------------------------------------------------------------------------

- (id) init
{
    return [self initWithWindowNibName: @"SelectIdentity"];
}

// ---------------------------------------------------------------------------

- (void) dealloc
{
    [refreshTimer release];
    [identities removeObserver:self forKeyPath:identities_key_path];
    [identities release];
    [super dealloc];
}

// ---------------------------------------------------------------------------

- (void) awakeFromNib 
{
    [headerTextField setStringValue: @"Some header text"];
    [identityTableView setDoubleAction:@selector(select:)];
}

// ---------------------------------------------------------------------------

- (void) windowDidLoad
{
    [explanationTextField setStringValue: @"Some explanation text"];
    [identitiesController setContent:identities];
}    

// ---------------------------------------------------------------------------

- (IBAction) newIdentity: (id) sender
{
    Identity *newIdentity = [[Identity alloc] init];

    newIdentity.favorite = TRUE;
    identityOptionsController.content = newIdentity;
    [newIdentity release];

    NSLog(@"New identity %@", [newIdentity description]);
    [self showOptions:@"new"];
}

// ---------------------------------------------------------------------------

- (IBAction) addToFavorites: (id) sender
{
    Identity *anIdentity = [identityArrayController.selectedObjects lastObject];
    identityOptionsController.content = nil;
    NSLog(@"Add %@ to favorites", [anIdentity description]);
    anIdentity.favorite = TRUE;
    
    [self saveOptions];
}

// ---------------------------------------------------------------------------

- (IBAction) removeFromFavorites: (id) sender
{
    Identity *anIdentity = [identityArrayController.selectedObjects lastObject];
    identityOptionsController.content = anIdentity;
    NSLog(@"Remove %@ from favorites", [anIdentity description]);
    anIdentity.favorite = FALSE;
    
    [self saveOptions];
}

// ---------------------------------------------------------------------------

- (IBAction) select: (id) sender
{
    // ignore double-click on header
    if ([sender respondsToSelector:@selector(clickedRow)] && [sender clickedRow] < 0) {
        return;
    }
    NSLog(@"Select identity: %@", identityArrayController.selectedObjects.description);
}

// ---------------------------------------------------------------------------

- (IBAction) cancel: (id) sender
{
    NSLog(@"Cancel identity selection");
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
    Identity *anIdentity = identityOptionsController.content;
    
    [anIdentity setPrincipalComponents: [nameField stringValue] 
                                 realm: [realmField stringValue]];
    
    [NSApp endSheet: identityOptionsWindow];
}

// ---------------------------------------------------------------------------

- (int) runWindow
{
    //[[NSApp delegate] addActiveWindow: [self window]];
    //NSWindow *window = [self window];
    
    //[window center];
    [self showWindow: self];
//    [NSApp run];
//    [self close];
    
    //[[NSApp delegate] removeActiveWindow: [self window]];
    
    return 0;
}

// ---------------------------------------------------------------------------

- (void) showOptions: (NSString *) contextInfo
{
    Identity *anIdentity = identityOptionsController.content;
    
    [nameField setStringValue:anIdentity.componentsString];
    [realmField setStringValue:anIdentity.realmString];
    
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
            
#warning Add validation to prevent the addition of existing principals and invalid principals
            if (err) {
                NSLog(@"%s received error %@ trying to add identity %@", _cmd, [NSString stringForLastKIMError:err], [newIdentity description]);
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

- (void) observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary *)change context:(void *)context
{
    if ([(NSString *) context isEqualToString:@"selectIdentityController"]) {
	if ([keyPath isEqualToString:identities_key_path]) {
//            [self reloadData];
	}
    }
    else {
        [super observeValueForKeyPath:keyPath ofObject:object change:change context:context];
    }
}

// ---------------------------------------------------------------------------

- (void) reloadData
{
    // Preserve selection
    Identity *selectedIdentity = [[identityArrayController.selectedObjects lastObject] retain];
    NSUInteger a, b, c;
    a = [identityArrayController selectionIndex];
    b = [[identityArrayController content] count];
    c = NSNotFound;
    
    NSLog(@"== updating table == %s", _cmd);
    identityArrayController.content = identities.identities;

    c = [identityArrayController.content indexOfObject:selectedIdentity];
    if ([[identityArrayController content] count] >= a)
        [identityArrayController setSelectionIndex:(c == NSNotFound) ? (a > b) ? b : a : c];
    
    [selectedIdentity release];
}

// ---------------------------------------------------------------------------

- (void) refreshTable
{
    [identityArrayController rearrangeObjects];
}

// ---------------------------------------------------------------------------

- (void) timedRefresh:(NSTimer *)timer
{
    // refetch data to update expiration times
    [self refreshTable];
}

@end

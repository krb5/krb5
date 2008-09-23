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


@implementation SelectIdentityController

// ---------------------------------------------------------------------------

- (id) initWithWindowNibName: (NSString *) windowNibName
{
    if ((self = [super initWithWindowNibName: windowNibName])) {
        NSLog (@"SelectIdentityController initializing");
        identities = [[Identities alloc] init];
        [identities addObserver:self 
                     forKeyPath:@"identities" 
                        options:NSKeyValueObservingOptionNew 
                        context:@"SelectIdentityController"];
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
    [identities removeObserver:self forKeyPath:@"identities"];
    [identities release];
    [super dealloc];
}

// ---------------------------------------------------------------------------

- (void) awakeFromNib 
{
    [headerTextField setStringValue: @"Some header text"];    
}

// ---------------------------------------------------------------------------

- (void) windowDidLoad
{
    
    [explanationTextField setStringValue: @"Some explanation text"];
    
}    

// ---------------------------------------------------------------------------

- (IBAction) add: (id) sender
{
    NSLog(@"Add identity");
}

// ---------------------------------------------------------------------------

- (IBAction) remove: (id) sender
{
    NSLog(@"Remove identity");
}

// ---------------------------------------------------------------------------

- (IBAction) select: (id) sender
{
    NSLog(@"Select identity: %@", identityArrayController.selectedObjects.description);
}

// ---------------------------------------------------------------------------

- (IBAction) cancel: (id) sender
{
    NSLog(@"Cancel identity selection");
}

// ---------------------------------------------------------------------------

- (int) runWindow
{
    //[[NSApp delegate] addActiveWindow: [self window]];
    //NSWindow *window = [self window];
    
    //[window center];
    [self showWindow: self];
    [NSApp run];
    [self close];
    
    //[[NSApp delegate] removeActiveWindow: [self window]];
    
    return 0;
}

// ---------------------------------------------------------------------------

- (void) observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary *)change context:(void *)context
{
    if ([(NSString *)context isEqualToString:@"SelectIdentityController"]) {
        NSLog(@"========== identities array changed ==========");
        identityArrayController.content = [[identities.identities mutableCopy] autorelease];
    }
    else {
        [super observeValueForKeyPath:keyPath ofObject:object change:change context:context];
    }
}

- (void) timedRefresh:(NSTimer *)timer
{
    [identityArrayController rearrangeObjects];
}


@end

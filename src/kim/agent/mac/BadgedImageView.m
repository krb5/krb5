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

#import "BadgedImageView.h"


@implementation BadgedImageView

// ---------------------------------------------------------------------------

- (id) initWithFrame: (NSRect) frameRect
{
    if ((self = [super initWithFrame: frameRect])) {
        iconImage = NULL;
        badgeImage = NULL;
    }
    return self;
}

// ---------------------------------------------------------------------------

- (void) dealloc
{
    if (iconImage ) { [iconImage release]; }
    if (badgeImage) { [badgeImage release]; }   
    
    [super dealloc];
}

// ---------------------------------------------------------------------------

- (void) setBadgeImage: (NSImage *) image
{
    if (badgeImage) { [badgeImage release]; }
    
    badgeImage = [image retain];
    [self setNeedsDisplay: YES];
}

// ---------------------------------------------------------------------------

- (void) setBadgePath: (NSString *) path
{
    NSImage *newImage = [[NSWorkspace sharedWorkspace] iconForFile: path];
    [self setBadgeImage: newImage];
}

// ---------------------------------------------------------------------------

- (void) drawRect: (NSRect) rect
{
    float frameSize = [self frame].size.width;
    float iconSize = 64.0;
    float badgeSize = 32.0;
    
    if (!iconImage) {
        iconImage = [[NSImage imageNamed: @"NSApplicationIcon"] retain];
    }
    
    if (iconImage) {
        [self lockFocus];
        
        // Clear an old badged icon
        [[NSColor windowBackgroundColor] set];
        NSRectFill ([self frame]);
        
        [iconImage setScalesWhenResized: YES];
        [iconImage setSize: NSMakeSize (iconSize, iconSize)];
        [iconImage compositeToPoint: NSMakePoint (0.0, frameSize - iconSize)
                          operation: NSCompositeSourceOver];
        
        if (badgeImage) {
            // draw badge
            [badgeImage setScalesWhenResized: YES];
            [badgeImage setSize: NSMakeSize (badgeSize, badgeSize)];
            [badgeImage compositeToPoint: NSMakePoint (frameSize - badgeSize, 0.0)
                               operation: NSCompositeSourceOver];
        }
        [self unlockFocus];
    }    
}

@end

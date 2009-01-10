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

#import "KerberosAgentController.h"
#import "SelectIdentityController.h"
#import "AuthenticationController.h"
#import "KerberosAgentListener.h"
#import "IPCClient.h"
#import "ServerDemux.h"

#define SECONDS_BEFORE_AUTO_QUIT_ON_START 600
#define SECONDS_BEFORE_AUTO_QUIT_ON_NO_CLIENTS 1

@implementation KerberosAgentController

@synthesize clients;

// ---------------------------------------------------------------------------

- (void) applicationDidFinishLaunching: (NSNotification *) notification
{
    self.clients = [NSMutableArray array];
    [KerberosAgentListener startListening];
    
    [NSApp activateIgnoringOtherApps:YES];
    
    autoQuitTimer = [NSTimer scheduledTimerWithTimeInterval:SECONDS_BEFORE_AUTO_QUIT_ON_START
                                                     target:self
                                                   selector:@selector(quitIfIdle:)
                                                   userInfo:nil 
                                                    repeats:NO];
}

- (void) dealloc
{
    self.clients = nil;
    [autoQuitTimer invalidate];
    [autoQuitTimer release];
    
    [super dealloc];
}

- (void) quitIfIdle: (NSTimer *) timer
{
    if ([self.clients count] == 0) {
        [NSApp terminate:nil];
    }
    autoQuitTimer = nil;
}

- (IPCClient *)clientForPort:(mach_port_t)client_port
{
    IPCClient *aClient = nil;
    
    for (aClient in self.clients) {
        if (aClient.port == client_port) {
            break;
        }
    }
    
    return aClient;
}

- (IPCClient *)clientForInfo:(NSDictionary *)info
{
    mach_port_t client_port = [[info objectForKey:@"client_port"] integerValue];
    return [self clientForPort:client_port];
}

- (IBAction) fakeANewClient: (id) sender
{
    IPCClient *aClient = [[IPCClient alloc] init];
    aClient.port = 1;
    aClient.name = @"Barry";
    aClient.path = [[NSBundle mainBundle] bundlePath];
    [self.clients addObject:aClient];
    [aClient release];
}

#pragma mark Client actions

// init
- (void) addClient: (NSDictionary *) info
{
    int32_t err = 0;
    IPCClient *aClient = [self clientForInfo:info];

    if (aClient) {
        // already registered
        err = KIM_IDENTITY_ALREADY_IN_LIST_ERR;
    } else {
        aClient = [[IPCClient alloc] init];
        aClient.port = [[info objectForKey:@"client_port"] integerValue];
        aClient.name = [info objectForKey:@"name"];
        aClient.path = [info objectForKey:@"path"];
        [self.clients addObject:aClient];
        [aClient release];
    }
    
    [autoQuitTimer invalidate];
    autoQuitTimer = nil;
    
    [KerberosAgentListener didAddClient:info error:err];
    [info release];
}

// enter
- (void) enterIdentity: (NSDictionary *) info
{
    kim_error err = KIM_NO_ERROR;
    IPCClient *aClient = nil;

    // get client object for matching info, creating if it doesn't exist
    aClient = [self clientForInfo:info];
    if (!aClient) { err = KIM_IDENTITY_NOT_IN_LIST_ERR; }
    else {
        err = [aClient enterIdentity:info];
    }
    if (err) {
        [KerberosAgentListener didEnterIdentity:info error:err];
    }
}

// select
- (void) selectIdentity: (NSDictionary *) info
{
    kim_error err = KIM_NO_ERROR;
    IPCClient *aClient = nil;
    
    // get client object for matching info, creating if it doesn't exist
    aClient = [self clientForInfo:info];
    if (!aClient) { err = KIM_IDENTITY_NOT_IN_LIST_ERR; }
    else {
        err = [aClient selectIdentity:info];
    }
    if (err) {
        [KerberosAgentListener didSelectIdentity:info error:err];
    }
}

// auth
- (void) promptForAuth: (NSDictionary *) info
{
    kim_error err = KIM_NO_ERROR;
    IPCClient *aClient = nil;
    
    aClient = [self clientForInfo:info];
    if (!aClient) { err = KIM_IDENTITY_NOT_IN_LIST_ERR; }
    else {
        err = [aClient promptForAuth:info];
    }
}

// change password
- (void) changePassword: (NSDictionary *) info
{
    kim_error err = KIM_NO_ERROR;
    IPCClient *aClient = nil;
    
    aClient = [self clientForInfo:info];
    if (!aClient) { err = KIM_IDENTITY_NOT_IN_LIST_ERR; }
    else {
        err = [aClient changePassword:info];
    }
}

// error
- (void) handleError: (NSDictionary *) info
{
    kim_error err = KIM_NO_ERROR;
    IPCClient *aClient = nil;
    
    aClient = [self clientForInfo:info];
    if (!aClient) { err = KIM_IDENTITY_NOT_IN_LIST_ERR; }
    else {
        err = [aClient handleError:info];
    }
}

// fini
- (void) removeClient: (NSDictionary *) info
{
    kim_error err = KIM_NO_ERROR;
    IPCClient *aClient = [self clientForInfo:info];
    
    if (!aClient) {
        err = KIM_IDENTITY_NOT_IN_LIST_ERR;
    } else {
        // close all windows associated with it
        [aClient cleanup];
        [self.clients removeObject:aClient];
        if ([self.clients count] == 0) {
            // the client removes itself after select identity,
            // but might come back shortly afterward in need of an auth prompt
            [autoQuitTimer invalidate];
            autoQuitTimer = [NSTimer scheduledTimerWithTimeInterval:SECONDS_BEFORE_AUTO_QUIT_ON_NO_CLIENTS
                                                             target:self
                                                           selector:@selector(quitIfIdle:)
                                                           userInfo:nil 
                                                            repeats:NO];
        }
    }
    
    // called after user finishes prompt
    [KerberosAgentListener didRemoveClient:info error:err];
    [info release];
}

@end

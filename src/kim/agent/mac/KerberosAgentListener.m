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


#import "KerberosAgentListener.h"
#import "KIMUtilities.h"
#import "ServerDemux.h"
#import "IPCClient.h"

@implementation KerberosAgentListener

@synthesize thread;

- (id) init
{
    self = [super init];
    if (self != nil) {
        self.thread = [[NSThread alloc] initWithTarget:self selector:@selector(threadMain) object:nil];
    }
    return self;
}

static KerberosAgentListener *sharedListener = nil;

+ (KerberosAgentListener *) sharedListener
{
    @synchronized(self) {
        if (sharedListener == nil) {
            [[self alloc] init]; // assignment not done here
        }
    }
    return sharedListener;
}

+ (id)allocWithZone:(NSZone *)zone
{
    @synchronized(self) {
        if (sharedListener == nil) {
            sharedListener = [super allocWithZone:zone];
            return sharedListener;  // assignment and return on first allocation
        }
    }
    return nil; //on subsequent allocation attempts return nil
}

- (id)copyWithZone:(NSZone *)zone
{
    return self;
}

- (id)retain
{
    return self;
}

- (unsigned)retainCount
{
    return UINT_MAX;  //denotes an object that cannot be released
}

- (void)release
{
    //do nothing
}

- (id)autorelease
{
    return self;
}

#pragma mark Thread management

// called from main thread to start listen thread
+ (void) startListening
{
//    NSLog(@"%s %@ thread", __FUNCTION__, ([NSThread isMainThread]) ? @"main" : @"not main");

    [[KerberosAgentListener sharedListener].thread start];
}

- (void) threadMain
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    int32_t err = 0;
    
//    NSLog(@"%s starting up", __FUNCTION__);
    
    while (!err && ![self.thread isCancelled]) {
        err = kim_agent_listen_loop();
        if (!err) {
//            NSLog (@"%s loop resetting %@", __FUNCTION__, [[NSThread currentThread] description]);
        } else {
            NSLog (@"%s got error %d (%@) %@", __FUNCTION__, err, [KIMUtilities stringForLastKIMError:err], [[NSThread currentThread] description]);
            err = 0; /* The server quit unexpectedly -- just try again */
        }
        sleep(10);
    }
    
    [pool release];
}

#pragma mark IPC handlers

+ (void) addClientWithPort: (mach_port_t) client_port
                 replyPort: (mach_port_t) reply_port
                      name: (kim_string) name
                      path: (kim_string) path
{
    NSDictionary *info = [[NSDictionary alloc] initWithObjectsAndKeys:
                          [NSNumber numberWithInteger:client_port], @"client_port",
                          [NSNumber numberWithInteger:reply_port], @"reply_port",
                          [NSString stringWithUTF8String:name], @"name",
                          [NSString stringWithUTF8String:path], @"path",
                          nil];
    [[NSApp delegate] performSelectorOnMainThread:@selector(addClient:) 
                                       withObject:info
                                    waitUntilDone:NO];
}

+ (void) didAddClient: (NSDictionary *) info 
                error: (kim_error) error
{
    kim_error err = KIM_NO_ERROR;
    mach_port_t reply_port = [[info objectForKey:@"reply_port"] integerValue];
    err = kim_handle_reply_init(reply_port, error);
}

+ (void) enterIdentityWithClientPort: (mach_port_t) client_port
                           replyPort: (mach_port_t) reply_port
                             options: (kim_options) options
{
    NSDictionary *info = [[NSDictionary alloc] initWithObjectsAndKeys:
                          [NSNumber numberWithInteger:client_port], @"client_port",
                          [NSNumber numberWithInteger:reply_port], @"reply_port",
                          [KIMUtilities dictionaryForKimOptions:options], @"options",
                          nil];
    [[NSApp delegate] performSelectorOnMainThread:@selector(enterIdentity:) 
                                       withObject:info
                                    waitUntilDone:NO];
}

// contains reply_port, identity_string
+ (void) didEnterIdentity: (NSDictionary *) info 
                    error: (kim_error) error
{
    kim_error err = KIM_NO_ERROR;
    mach_port_t reply_port = [[info objectForKey:@"reply_port"] integerValue];
    NSString *identityString = [info objectForKey:@"identity_string"];
    kim_identity identity = NULL;
    kim_options options = NULL;
    BOOL wants_change_password = [[info objectForKey:@"wants_change_password"] boolValue];
    
    if (identityString) {
        err = kim_identity_create_from_string (&identity, [identityString UTF8String]);
    }
    
    if (!err) {
        options = [KIMUtilities kimOptionsForDictionary:[info objectForKey:@"options"]];
        
    }

    if (!err) {
        err = kim_handle_reply_enter_identity(reply_port, identity, options, wants_change_password, error);
    }
    
    kim_options_free (&options);
}

+ (void) selectIdentityWithClientPort: (mach_port_t) client_port
                            replyPort: (mach_port_t) reply_port
                                hints: (kim_selection_hints) hints
{
    NSDictionary *info = nil;
    
    info = [[NSDictionary alloc] initWithObjectsAndKeys:
            [NSNumber numberWithInteger:client_port], @"client_port",
            [NSNumber numberWithInteger:reply_port], @"reply_port",
            [KIMUtilities dictionaryForKimSelectionHints:hints], @"hints", 
            nil];
    
    [[NSApp delegate] performSelectorOnMainThread:@selector(selectIdentity:) 
                                       withObject:info
                                    waitUntilDone:NO];
}

// contains reply_port, identity_string
+ (void) didSelectIdentity: (NSDictionary *) info 
                     error: (int32_t) error
{
    kim_error err = KIM_NO_ERROR;
    NSNumber *portNumber = [info objectForKey:@"reply_port"];
    NSString *identityString = [info objectForKey:@"identity_string"];
    mach_port_t reply_port = [portNumber integerValue];
    kim_identity identity = NULL;
    kim_options options = NULL;
    BOOL wants_change_password = [[info objectForKey:@"wants_change_password"] boolValue];

    if (identityString) {
        err = kim_identity_create_from_string(&identity, [identityString UTF8String]);
    }

    if (!err) {
        options = [KIMUtilities kimOptionsForDictionary:[info objectForKey:@"options"]];
    }

    if (!err) {
        err = kim_handle_reply_select_identity(reply_port, identity, options, wants_change_password, error);
    }
    
    kim_options_free (&options);
}

+ (void) promptForAuthWithClientPort: (mach_port_t) client_port
                           replyPort: (mach_port_t) reply_port
                            identity: (kim_string) identity_string
                          promptType: (uint32_t) prompt_type
                           allowSave: (kim_boolean) allow_save  
                           hideReply: (kim_boolean) hide_reply
                               title: (kim_string) title
                             message: (kim_string) message
                         description: (kim_string) description
{
    NSDictionary *info = [[NSDictionary alloc] initWithObjectsAndKeys:
                          [NSNumber numberWithInteger:client_port], @"client_port",
                          [NSNumber numberWithInteger:reply_port], @"reply_port",
                          [NSString stringWithUTF8String:identity_string], @"identity_string",
                          [NSNumber numberWithUnsignedInt:prompt_type], @"prompt_type",
                          [NSNumber numberWithBool:allow_save], @"allow_save",
                          [NSNumber numberWithBool:hide_reply], @"hide_reply",
                          [NSString stringWithUTF8String:title], @"title",
                          [NSString stringWithUTF8String:message], @"message",
                          [NSString stringWithUTF8String:description], @"description",
                          nil];
    [[NSApp delegate] performSelectorOnMainThread:@selector(promptForAuth:) 
                                       withObject:info
                                    waitUntilDone:NO];
}

// contains reply_port, (string) prompt_response
+ (void) didPromptForAuth: (NSDictionary *) info 
                    error: (int32_t) error
{
    kim_error err = KIM_NO_ERROR;
    mach_port_t reply_port = [[info objectForKey:@"reply_port"] integerValue];
    kim_string prompt_response = [[info objectForKey:@"prompt_response"] UTF8String];
    kim_boolean save_response = [[info objectForKey:@"save_response"] boolValue];

    err = kim_handle_reply_auth_prompt(reply_port, prompt_response, save_response, error);
}

+ (void) changePasswordWithClientPort: (mach_port_t) client_port
                            replyPort: (mach_port_t) reply_port
                             identity: (kim_string) identity_string
                              expired: (kim_boolean) expired
{
    NSDictionary *info = [[NSDictionary alloc] initWithObjectsAndKeys:
                          [NSNumber numberWithInteger:client_port], @"client_port",
                          [NSNumber numberWithInteger:reply_port], @"reply_port",
                          [NSString stringWithUTF8String:identity_string], @"identity_string",
                          [NSNumber numberWithBool:expired], @"expired",
                          nil];
    [[NSApp delegate] performSelectorOnMainThread:@selector(changePassword:) 
                                       withObject:info
                                    waitUntilDone:NO];
}

// contains reply_port, old password, new password, verify password
+ (void) didChangePassword: (NSDictionary *) info 
                     error: (int32_t) error
{
    kim_error err = KIM_NO_ERROR;
    mach_port_t reply_port = [[info objectForKey:@"reply_port"] integerValue];
    kim_string old_pw = [[info objectForKey:@"old_password"] UTF8String];
    kim_string new_pw = [[info objectForKey:@"new_password"] UTF8String];
    kim_string verify_pw = [[info objectForKey:@"verify_password"] UTF8String];

    err = kim_handle_reply_change_password(reply_port, old_pw, new_pw, verify_pw, error);
}

+ (void) handleErrorWithClientPort: (mach_port_t) client_port
                         replyPort: (mach_port_t) reply_port
                          identity: (kim_string) identity_string
                             error: (kim_error) error
                           message: (kim_string) message
                       description: (kim_string) description
{
    NSDictionary *info = [[NSDictionary alloc] initWithObjectsAndKeys:
                          [NSNumber numberWithInteger:client_port], @"client_port",
                          [NSNumber numberWithInteger:reply_port], @"reply_port",
                          [NSString stringWithUTF8String:identity_string], @"identity_string",
                          [NSNumber numberWithUnsignedInt:error], @"error",
                          [NSString stringWithUTF8String:message], @"message",
                          [NSString stringWithUTF8String:description], @"description",
                          nil];
    [[NSApp delegate] performSelectorOnMainThread:@selector(handleError:) 
                                       withObject:info
                                    waitUntilDone:NO];
    
}

// contains reply_port
+ (void) didHandleError: (NSDictionary *) info 
                  error: (int32_t) error
{
    kim_error err = KIM_NO_ERROR;
    mach_port_t reply_port = [[info objectForKey:@"reply_port"] integerValue];

    err = kim_handle_reply_handle_error(reply_port, error);
}

+ (void) removeClientMatchingPort: (mach_port_t) client_port
                        replyPort: (mach_port_t) reply_port
{
    NSDictionary *info = [[NSDictionary alloc] initWithObjectsAndKeys:
                          [NSNumber numberWithInteger:client_port], @"client_port",
                          [NSNumber numberWithInteger:reply_port], @"reply_port",
                          nil];
    [[NSApp delegate] performSelectorOnMainThread:@selector(removeClient:) 
                                       withObject:info
                                    waitUntilDone:NO];
}

// contains reply_port
+ (void) didRemoveClient: (NSDictionary *)info
                   error: (int32_t) error
{
    kim_error err = KIM_NO_ERROR;
    mach_port_t reply_port = [[info objectForKey:@"reply_port"] integerValue];
    if (reply_port) {
        err = kim_handle_reply_fini(reply_port, error);
    }
}

@end

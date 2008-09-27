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
#import "ServerThread.h"
#import <Kerberos/kim.h>
#import <Kerberos/kipc_server.h>
#import "kim_migServer.h"


@implementation ClientConnection

@synthesize port;

/* ------------------------------------------------------------------------ */

- (id) initWithPort: (mach_port_t) connectionPort
               name: (NSString *) name
               path: (NSString *) path
      front_process: (bool) frontProcess
{
    if ((self = [super init])) {
        port = connectionPort;
        callerIsFrontProcess = frontProcess;
        applicationName = [name retain];
        applicationPath = [path retain];
    }
    
    return self;
}

/* ------------------------------------------------------------------------ */

- (kim_identity) enterIdentityWithError: (kim_error *) outError
{
    kim_error err = KIM_NO_ERROR;
    kim_identity identity = NULL;
    
    *outError = err;
    return identity;
}

/* ------------------------------------------------------------------------ */

- (kim_identity) selectIdentityWithHints: (kim_selection_hints) hints
                                 error: (kim_error *) outError
{
    kim_error err = KIM_NO_ERROR;
    kim_identity identity = NULL;
    
    *outError = err;
    return identity;
}

/* ------------------------------------------------------------------------ */

- (NSString *) authPromptWithIdentity: (kim_identity) identity
                                 type: (kim_prompt_type) type
                            hideReply: (bool) hideReply
                                title: (NSString *) title
                              message: (NSString *) message
                          description: (NSString *) description
                                error: (kim_error *) outError
{
    kim_error err = KIM_NO_ERROR;
    NSString *reply = @"A reply";
    
    *outError = err;
    return reply;
}

/* ------------------------------------------------------------------------ */

- (NSArray *) changePasswordWithIdentity: (kim_identity) identity
                    oldPasswordIsExpired: (bool) oldPasswordIsExpired
                                   error: (kim_error *) outError
{
    kim_error err = KIM_NO_ERROR;
    NSString *oldPassword = @"an old password";
    NSString *newPassword = @"a new password";
    NSString *verifyPassword = @"a verify password";
    
    *outError = err;
    return !err ? [NSArray arrayWithObjects: oldPassword, newPassword, verifyPassword, NULL] : NULL;    
}

/* ------------------------------------------------------------------------ */

- (kim_error) handleError: (kim_error) error
                 identity: (kim_identity) identity
                  message: (NSString *) message
              description: (NSString *) description
{
    kim_error err = KIM_NO_ERROR;
    
    return err;
}

/* ------------------------------------------------------------------------ */

- (void) dealloc
{
    [applicationName release];
    [applicationPath release];
    [super dealloc];
}

@end

@implementation ServerThread

/* ------------------------------------------------------------------------ */

+ (ServerThread *) sharedServerThread
{
    static ServerThread *gServerThread = NULL;
    
    if (!gServerThread) {
        gServerThread = [[ServerThread alloc] init];
    }
    
    return gServerThread;
}

/* ------------------------------------------------------------------------ */

- (id) init
{
    if ((self = [super init])) {
        connections = [[NSMutableArray alloc] init];
        if (!connections) {
            [self release];
            self = nil;
        }
    }
    
    return self;
}

/* ------------------------------------------------------------------------ */

- (void) dealloc
{
    [connections release];
    [super dealloc];
}

/* ------------------------------------------------------------------------ */

- (kern_return_t) listen
{
    return kipc_server_run_server (kim_server);
}

/* ------------------------------------------------------------------------ */

- (void) addConnectionWithPort: (mach_port_t) port
                          name: (NSString *) name
                          path: (NSString *) path
                  frontProcess: (bool) frontProcess
{
    ClientConnection *client = [[ClientConnection alloc] initWithPort: port
                                                                 name: name
                                                                 path: path
                                                        front_process: frontProcess];
    if (client) {
        [connections addObject: client];
    }
    
    [client release];
}

/* ------------------------------------------------------------------------ */

- (void) removeConnectionWithPort: (mach_port_t) port
{
    for (ClientConnection *client in connections) {
        if (client.port == port) {
            [connections removeObject: client];
        }
    }
    
    if (![connections count]) {
        kipc_server_quit ();
    }
}


/* ------------------------------------------------------------------------ */

- (ClientConnection *) connectionForPort: (mach_port_t) port
{
    for (ClientConnection *client in connections) {
        if (client.port == port) {
            return client;
        }
    }    
    return NULL;
}

@end


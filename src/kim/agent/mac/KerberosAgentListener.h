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
#import <Kerberos/kim.h>

#define kCheckinMessage 100

@interface KerberosAgentListener : NSObject {
    NSThread *thread;
}

@property (readwrite, retain) NSThread *thread;

+ (KerberosAgentListener *) sharedListener;

+ (void) startListening;

- (void) threadMain;

+ (void) addClientWithPort: (mach_port_t) client_port
                 replyPort: (mach_port_t) reply_port
                      name: (kim_string) name
                      path: (kim_string) path;

// contains reply_port
+ (void) didAddClient: (NSDictionary *) info 
                error: (int32_t) error;

+ (void) enterIdentityWithClientPort: (mach_port_t) client_port
                           replyPort: (mach_port_t) reply_port
                             options: (kim_options) options;

// contains reply_port, kim_identity
+ (void) didEnterIdentity: (NSDictionary *) info 
                    error: (int32_t) error;

+ (void) selectIdentityWithClientPort: (mach_port_t) client_port
                            replyPort: (mach_port_t) reply_port
                                hints: (kim_selection_hints) hints;

// contains reply_port, kim_identity
+ (void) didSelectIdentity: (NSDictionary *) info 
                     error: (int32_t) error;

+ (void) promptForAuthWithClientPort: (mach_port_t) client_port
                           replyPort: (mach_port_t) reply_port
                            identity: (kim_string) identity_string
                          promptType: (uint32_t) prompt_type
                           allowSave: (kim_boolean) allow_save  
                           hideReply: (kim_boolean) hide_reply
                               title: (kim_string) title
                             message: (kim_string) message
                         description: (kim_string) description;

// contains reply_port, (string) prompt_response
+ (void) didPromptForAuth: (NSDictionary *) info 
                    error: (int32_t) error;

+ (void) changePasswordWithClientPort: (mach_port_t) client_port
                            replyPort: (mach_port_t) reply_port
                             identity: (kim_string) identity_string
                              expired: (kim_boolean) expired;

// contains reply_port, old password, new password, verify password
+ (void) didChangePassword: (NSDictionary *) info 
                     error: (int32_t) error;

+ (void) handleErrorWithClientPort: (mach_port_t) client_port
                         replyPort: (mach_port_t) reply_port
                          identity: (kim_string) identity_string
                             error: (kim_error) error
                           message: (kim_string) message
                       description: (kim_string) description;

// contains reply_port
+ (void) didHandleError: (NSDictionary *) info 
                  error: (int32_t) error;


+ (void) removeClientMatchingPort: (mach_port_t) client_port
                        replyPort: (mach_port_t) reply_port;

+ (void) didRemoveClient: (NSDictionary *)info
                   error: (int32_t) error;

@end

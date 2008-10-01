//
//  KerberosAgentListener.h
//  Kerberos5
//
//  Created by Justin Anderson on 9/28/08.
//  Copyright 2008 MIT. All rights reserved.
//

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

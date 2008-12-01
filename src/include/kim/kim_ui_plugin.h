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

#ifndef KIM_UI_PLUGIN_H
#define KIM_UI_PLUGIN_H

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * The type of prompt which needs to be displayed.
 * This value determines what type of user interface is displayed.
 * See \ref kim_options_custom_prompt_callback for more information.
 */
typedef uint32_t kim_prompt_type;

enum kim_prompt_type_enum {
    kim_prompt_type_password = 0,
    kim_prompt_type_preauth = 1
};

/*
 * Plugins for Controlling Identity Selection and Credential Acquisition
 * 
 * In order to acquire credentials, Kerberos needs to obtain one or more secrets from the user.
 * These secrets may be a certificate, password, SecurID pin, or information from a smart card.  
 * If obtaining the secret requires interaction with the user, the Kerberos libraries call a
 * "prompter callback" to display a dialog or command line prompt to request information from
 * the user.  If you want to provide your own custom dialogs or command line prompts, 
 * the KIM APIs provide a plugin mechanism for replacing the default prompt ui with your own.  
 *
 * The function table / structure which a KIM ui plugin module must export 
 * as "kim_ui_0".  If the interfaces work correctly, future versions of the 
 * table will add either more callbacks or more arguments to callbacks, and 
 * in both cases we'll be able to wrap the v0 functions.
 */
/* extern kim_ui_plugin_ftable_v0 kim_ui_0; */

    
typedef struct kim_ui_plugin_ftable_v0 {
    int minor_version;		/* currently 0 */
    
    /* Called before other calls to allow the UI to initialize.
     * Return an error if you can't display your UI in this environment. 
     * To allow your plugin to be called from multiple threads, pass back
     * state associated with this instance of your UI in out_context.  
     * The same context pointer will be provided to all plugin calls for
     * this ui. */
    kim_error (*init) (void **out_context);
    
    /* Present UI which allows the user to enter a new identity.
     * This is typically called when the user selects a "new tickets" 
     * control or menu item from a ticket management utility.
     * If this UI calls into KIM to get new credentials it may 
     * call auth_prompt below. 
     * If out_change_password is set to TRUE, KIM will call change_password
     * on the identity and then call enter_identity again, allowing you
     * to have a change password option on your UI. */
    kim_error (*enter_identity) (void         *in_context,
                                 kim_options   io_options,
                                 kim_identity *out_identity,
                                 kim_boolean  *out_change_password);
    
    /* Present UI to select which identity to use.
     * This is typically called the first time an application tries to use
     * Kerberos and is used to establish a hints preference for the application.
     * If this UI calls into KIM to get new credentials it may 
     * call auth_prompt below. 
     * If out_change_password is set to TRUE, KIM will call change_password
     * on the identity and then call select_identity again, allowing you
     * to have a change password option on your UI. */
    kim_error (*select_identity) (void                *in_context,
                                  kim_selection_hints  io_hints,
                                  kim_identity        *out_identity,
                                  kim_boolean         *out_change_password);
    
    /* Present UI to display authentication to the user */
    /* If in_allow_save_reply is FALSE do not display UI to allow the user
     * to save their password. In this case the value of out_save_reply will
     * be ignored. */
    kim_error (*auth_prompt) (void              *in_context,
                              kim_identity       in_identity,
                              kim_prompt_type    in_type,
                              kim_boolean        in_allow_save_reply, 
                              kim_boolean        in_hide_reply, 
                              kim_string         in_title,
                              kim_string         in_message,
                              kim_string         in_description,
                              char             **out_reply,
                              kim_boolean       *out_save_reply);
    
    /* Prompt to change the identity's password. 
     * May be combined with an auth_prompt if additional auth is required,
     * eg: SecurID pin. 
     * If in_old_password_expired is true, this callback is in response
     * to an expired password error.  If this is the case the same context
     * which generated the error will be used for this callback. */
    kim_error (*change_password) (void          *in_context,
                                  kim_identity   in_identity,
                                  kim_boolean    in_old_password_expired,
                                  char         **out_old_password,
                                  char         **out_new_password,
                                  char         **out_verify_password);
    
    /* Display an error to the user; may be called after any of the prompts */
    kim_error (*handle_error) (void         *in_context,
                               kim_identity  in_identity,
                               kim_error     in_error,
                               kim_string    in_error_message,
                               kim_string    in_error_description);
    
    /* Free strings returned by the UI. Will be called once for each string
     * returned from a plugin callback.  If you have returned a string twice
     * just make sure your free function checks for NULL and sets the pointer
     * to NULL when done freeing memory.  */
    void (*free_string) (void  *in_context,
                         char **io_string);
    
    /* Called after the last prompt (even on error) to allow the UI to
     * free allocated resources associated with its context. */
    kim_error (*fini) (void *io_context);

} kim_ui_plugin_ftable_v0;

    
#ifdef __cplusplus
}
#endif

#endif /* KIM_UI_PLUGIN_H */

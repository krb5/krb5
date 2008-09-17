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

typedef struct kim_ui_plugin_ftable_v1 {
    int minor_version;		/* currently 0 */
    
    /* Called before other calls to allow the UI to initialize.
     * Return an error if you can't display your UI in this environment. */
    kim_error (*init)(void         **out_context,
                      kim_identity   in_identity);
    
    /* Present UI to select which identity to use.
     * If this UI calls into KIM to get new credentials it may 
     * call acquire_new_credentials below. */
    kim_error (*select_identity)(void                *in_context,
                                 kim_selection_hints  in_hints,
                                 kim_identity_t      *out_identity);
    
    /* Present UI to display authentication to the user */
    typedef kim_error (*auth_prompt) (void              *in_context,
                                      kim_prompt_type    in_type,
                                      kim_string         in_title,
                                      kim_string         in_message,
                                      kim_string         in_description,
                                      char             **out_reply);
    
    /* Prompt to change the identity's password. 
     * May be combined with an auth prompt if additional auth is required,
     * eg: SecurID pin. 
     * If in_old_password_expired is true, this callback is in response
     * to an expired password error.  If this is the case the same context
     * which generated the error will be used for this callback. */
    kim_error (*change_password)(void          *in_context,
                                 kim_identity   in_identity,
                                 kim_boolean    in_old_password_expired,
                                 char         **out_old_password,
                                 char         **out_new_password,
                                 char         **out_verify_password);
    
    /* Display an error to the user; may be called after any of the prompts */
    kim_error (*display_error)(void       *in_context,
                               kim_error   in_error,
                               kim_string  in_error_message,
                               kim_string  in_error_description);
    
    /* Free strings returned by the UI */
    void (*free_string)(void *in_context,
                        char *io_string);
    
    /* Called after the last prompt (even on error) to allow the UI to
     * free allocated resources. */
    kim_error (*fini)(void         *io_context,
                      kim_identity  in_identity);

} kim_ui_plugin_ftable_v1;

    
#ifdef __cplusplus
}
#endif

#endif /* KIM_UI_PLUGIN_H */

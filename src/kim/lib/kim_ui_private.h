/*
 * $Header$
 *
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

#ifndef KIM_UI_PRIVATE_H
#define KIM_UI_PRIVATE_H

#include <kim/kim.h>

enum kim_ui_type {
    kim_ui_type_gui_plugin,
    kim_ui_type_gui_builtin,
    kim_ui_type_cli,
    kim_ui_type_none
};

enum kim_ui_error_type {
    kim_ui_error_type_authentication,
    kim_ui_error_type_change_password,
    kim_ui_error_type_selection,
    kim_ui_error_type_generic
};

/* declare struct on stack.  Deep contents will be freed by kim_ui_fini. */
typedef struct kim_ui_context {
    kim_boolean initialized;
    enum kim_ui_type type;
    void *tcontext;
    kim_identity identity;
    kim_count prompt_count;
    kim_string password_to_save;
} kim_ui_context;



kim_error kim_ui_init (kim_ui_context *io_context);

kim_error kim_ui_enter_identity (kim_ui_context *in_context,
                                 kim_options     io_options,
                                 kim_identity   *out_identity,
                                 kim_boolean    *out_change_password);

kim_error kim_ui_select_identity (kim_ui_context       *in_context,
                                  kim_selection_hints   io_hints,
                                  kim_identity         *out_identity,
                                  kim_boolean          *out_change_password);

krb5_error_code kim_ui_prompter (krb5_context  in_krb5_context,
                                 void         *in_context,
                                 const char   *in_name,
                                 const char   *in_banner,
                                 int           in_num_prompts,
                                 krb5_prompt   in_prompts[]);

kim_error kim_ui_change_password (kim_ui_context  *in_context,
                                  kim_identity     in_identity,
                                  kim_boolean      in_old_password_expired,
                                  char           **out_old_password,
                                  char           **out_new_password,
                                  char           **out_verify_password);

/* Helper function */
kim_error kim_ui_handle_kim_error (kim_ui_context         *in_context,
                                   kim_identity            in_identity,
                                   enum kim_ui_error_type  in_type,
                                   kim_error               in_error);

kim_error kim_ui_handle_error (kim_ui_context *in_context,
                               kim_identity    in_identity,
                               kim_error       in_error,
                               kim_string      in_error_message,
                               kim_string      in_error_description);

void kim_ui_free_string (kim_ui_context  *in_context,
                         char           **io_string);

kim_error kim_ui_fini (kim_ui_context *io_context);

#endif /* KIM_UI_PRIVATE_H */

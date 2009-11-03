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

#ifdef KIM_BUILTIN_UI

#include "kim_private.h"

// ---------------------------------------------------------------------------

static kim_error kim_ui_cli_read_string (kim_string   *out_string,
                                         kim_boolean   in_hide_reply,
                                         const char   *in_format, ...)
{
    kim_error err = KIM_NO_ERROR;
    krb5_context k5context = NULL;
    krb5_prompt prompts[1];
    char prompt_string [BUFSIZ];
    krb5_data reply_data;
    char reply_string [BUFSIZ];

    if (!err && !out_string) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_format ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = krb5_init_context (&k5context);
    }

    if (!err) {
        unsigned int count;
        va_list args;

        va_start (args, in_format);
        count = vsnprintf (prompt_string, sizeof (prompt_string),
                                  in_format, args);
        va_end (args);

        if (count > sizeof (prompt_string)) {
            kim_debug_printf ("%s(): WARNING! Prompt should be %d characters\n",
                              __FUNCTION__, count);
            prompt_string [sizeof (prompt_string) - 1] = '\0';
        }
    }

    if (!err) {
        /* Build the prompt structures */
        prompts[0].prompt        = prompt_string;
        prompts[0].hidden        = in_hide_reply;
        prompts[0].reply         = &reply_data;
        prompts[0].reply->data   = reply_string;
        prompts[0].reply->length = sizeof (reply_string);

        err = krb5_prompter_posix (k5context, NULL, NULL, NULL, 1, prompts);
        if (err == KRB5_LIBOS_PWDINTR || err == KRB5_LIBOS_CANTREADPWD) {
            err = check_error (KIM_USER_CANCELED_ERR);
        }
    }

    if (!err) {
        err = kim_string_create_from_buffer (out_string,
                                             prompts[0].reply->data,
                                             prompts[0].reply->length);
    }

    if (k5context) { krb5_free_context (k5context); }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_ui_cli_init (kim_ui_context *io_context)
{
    if (io_context) {
        io_context->tcontext = NULL;
    }

    return KIM_NO_ERROR;
}

/* ------------------------------------------------------------------------ */

kim_error kim_ui_cli_enter_identity (kim_ui_context *in_context,
                                     kim_options     io_options,
                                     kim_identity   *out_identity,
                                     kim_boolean    *out_change_password)
{
    kim_error err = KIM_NO_ERROR;
    kim_string enter_identity_string = NULL;
    kim_string identity_string = NULL;

    if (!err && !io_options         ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_identity       ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_change_password) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_os_string_create_localized (&enter_identity_string,
                                              "Please enter your Kerberos identity");
    }

    if (!err) {
        err = kim_ui_cli_read_string (&identity_string,
                                      0, enter_identity_string);
    }

    if (!err) {
        err = kim_identity_create_from_string (out_identity, identity_string);
    }

    if (!err) {
        *out_change_password = 0;
    }

    kim_string_free (&identity_string);
    kim_string_free (&enter_identity_string);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_ui_cli_select_identity (kim_ui_context      *in_context,
                                      kim_selection_hints  io_hints,
                                      kim_identity        *out_identity,
                                      kim_boolean         *out_change_password)
{
    kim_error err = KIM_NO_ERROR;
    kim_options options = NULL;

    if (!err && !io_hints           ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_identity       ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_change_password) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_selection_hints_get_options (io_hints, &options);
    }

    if (!err) {
        err = kim_ui_cli_enter_identity (in_context, options,
                                         out_identity,
                                         out_change_password);
    }

    if (!err) {
        err = kim_selection_hints_set_options (io_hints, options);
    }

    kim_options_free (&options);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_ui_cli_auth_prompt (kim_ui_context      *in_context,
                                  kim_identity         in_identity,
                                  kim_prompt_type      in_type,
                                  kim_boolean          in_allow_save_reply,
                                  kim_boolean          in_hide_reply,
                                  kim_string           in_title,
                                  kim_string           in_message,
                                  kim_string           in_description,
                                  char               **out_reply,
                                  kim_boolean         *out_save_reply)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_reply  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    /* in_title, in_message or in_description may be NULL */

    if (!err) {
        if (in_type == kim_prompt_type_password) {
            kim_string enter_password_format = NULL;
            kim_string identity_string = NULL;

            err = kim_os_string_create_localized (&enter_password_format,
                                                  "Please enter the password for %s");

            if (!err) {
                err = kim_identity_get_display_string (in_identity,
                                                       &identity_string);
            }

            if (!err) {
                err = kim_ui_cli_read_string ((kim_string *) out_reply,
                                              1, enter_password_format,
                                              identity_string);
            }

            kim_string_free (&identity_string);
            kim_string_free (&enter_password_format);

        } else {
            krb5_context k5context = NULL;
            krb5_prompt prompts[1];
            krb5_data reply_data;
            char reply_string [BUFSIZ];

            prompts[0].prompt        = (char *) in_description;
            prompts[0].hidden        = in_hide_reply;
            prompts[0].reply         = &reply_data;
            prompts[0].reply->data   = reply_string;
            prompts[0].reply->length = sizeof (reply_string);

            err = krb5_init_context (&k5context);

            if (!err) {
                err = krb5_prompter_posix (k5context, in_context, in_title,
                                           in_message, 1, prompts);
                if (err == KRB5_LIBOS_PWDINTR || err == KRB5_LIBOS_CANTREADPWD) {
                    err = check_error (KIM_USER_CANCELED_ERR);
                }
            }

            if (!err) {
                err = kim_string_create_from_buffer ((kim_string *) out_reply,
                                                     prompts[0].reply->data,
                                                     prompts[0].reply->length);
                if (!err) {
                    /* always allow password saving */
                    *out_save_reply = (in_allow_save_reply &&
                                       in_type == kim_prompt_type_password);
                }
            }

            if (k5context) { krb5_free_context (k5context); }
        }
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

static kim_error kim_ui_cli_ask_change_password (kim_string in_identity_string)
{
    kim_error err = KIM_NO_ERROR;
    kim_string ask_change_password = NULL;
    kim_string yes = NULL;
    kim_string no = NULL;
    kim_string unknown_response = NULL;
    kim_boolean done = 0;
    kim_comparison no_comparison, yes_comparison;

    if (!err) {
        err = kim_os_string_create_localized (&ask_change_password,
                                              "Your password has expired, would you like to change it? (yes/no)");
    }

    if (!err) {
        err = kim_os_string_create_localized (&yes, "yes");
    }

    if (!err) {
        err = kim_os_string_create_localized (&no, "no");
    }

    if (!err) {
        err = kim_os_string_create_localized (&unknown_response,
                                              "%s is not a response I understand.  Please try again.");
    }

    while (!err && !done) {
        kim_string answer = NULL;

        err = kim_ui_cli_read_string (&answer, 0, ask_change_password);

        if (!err) {
            err = kim_os_string_compare (answer, no,
                                         1 /* case insensitive */,
                                         &no_comparison);
        }

        if (!err && kim_comparison_is_equal_to (no_comparison)) {
            err = check_error (KIM_USER_CANCELED_ERR);
        }

        if (!err) {
            err = kim_os_string_compare (answer, yes,
                                         1 /* case insensitive */,
                                         &yes_comparison);
        }

        if (!err) {
            if (kim_comparison_is_equal_to (yes_comparison)) {
                done = 1;
            } else {
                fprintf (stdout, unknown_response, answer);
                fprintf (stdout, "\n");
            }
        }

        kim_string_free (&answer);
    }

    kim_string_free (&ask_change_password);
    kim_string_free (&yes);
    kim_string_free (&no);
    kim_string_free (&unknown_response);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_ui_cli_change_password (kim_ui_context  *in_context,
                                      kim_identity     in_identity,
                                      kim_boolean      in_old_password_expired,
                                      char           **out_old_password,
                                      char           **out_new_password,
                                      char           **out_verify_password)
{
    kim_error err = KIM_NO_ERROR;
    kim_string enter_old_password_format = NULL;
    kim_string enter_new_password_format = NULL;
    kim_string enter_verify_password_format = NULL;
    kim_string identity_string = NULL;
    kim_string old_password = NULL;
    kim_string new_password = NULL;
    kim_string verify_password = NULL;
    kim_boolean done = 0;

    if (!err && !in_identity        ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_old_password   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_new_password   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_verify_password) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_identity_get_display_string (in_identity, &identity_string);
    }

    if (!err && in_old_password_expired) {
        err = kim_ui_cli_ask_change_password (identity_string);
    }

    if (!err) {
        err = kim_os_string_create_localized (&enter_old_password_format,
                                              "Please enter the old password for %s");
    }

    if (!err) {
        err = kim_os_string_create_localized (&enter_new_password_format,
                                              "Please enter the new password for %s");
    }

    if (!err) {
        err = kim_os_string_create_localized (&enter_verify_password_format,
                                              "Verifying, please re-enter the new password for %s again");
    }

    while (!err && !done) {
        kim_boolean was_prompted = 0;  /* ignore because we always prompt */

        kim_string_free (&old_password);

        err = kim_ui_cli_read_string (&old_password,
                                      1, enter_old_password_format,
                                      identity_string);

        if (!err && strlen (old_password) < 1) {
            /* Empty password: Synthesize bad password err */
            err = KRB5KRB_AP_ERR_BAD_INTEGRITY;
        }

        if (!err) {
            err = kim_credential_create_for_change_password ((kim_credential *) &in_context->tcontext,
                                                             in_identity,
                                                             old_password,
                                                             in_context,
                                                             &was_prompted);
        }

        if (err && err != KIM_USER_CANCELED_ERR) {
            /*  new creds failed, report error to user */
            err = kim_ui_handle_kim_error (in_context, in_identity,
                                           kim_ui_error_type_change_password,
                                           err);

        } else {
            done = 1;
       }
    }

    if (!err) {
        err = kim_ui_cli_read_string (&new_password,
                                      1, enter_new_password_format,
                                      identity_string);
    }

    if (!err) {
        err = kim_ui_cli_read_string (&verify_password,
                                      1, enter_verify_password_format,
                                      identity_string);
    }

    if (!err) {
        *out_old_password = (char *) old_password;
        old_password = NULL;
        *out_new_password = (char *) new_password;
        new_password = NULL;
        *out_verify_password = (char *) verify_password;
        verify_password = NULL;
    }

    kim_string_free (&old_password);
    kim_string_free (&new_password);
    kim_string_free (&verify_password);
    kim_string_free (&identity_string);
    kim_string_free (&enter_old_password_format);
    kim_string_free (&enter_new_password_format);
    kim_string_free (&enter_verify_password_format);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_ui_cli_handle_error (kim_ui_context *in_context,
                                   kim_identity    in_identity,
                                   kim_error       in_error,
                                   kim_string      in_error_message,
                                   kim_string      in_error_description)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_error_message    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_error_description) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        fprintf (stdout, "%s\n%s\n\n", in_error_message, in_error_description);
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

void kim_ui_cli_free_string (kim_ui_context  *in_context,
                             char           **io_string)
{
    kim_string_free ((kim_string *) io_string);
}

/* ------------------------------------------------------------------------ */

kim_error kim_ui_cli_fini (kim_ui_context *io_context)
{
    if (io_context) {
        kim_credential_free ((kim_credential *) &io_context->tcontext);
    }

    return KIM_NO_ERROR;
}

#endif /* KIM_BUILTIN_UI */

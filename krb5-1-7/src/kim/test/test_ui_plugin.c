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

#include <kim/kim.h>
#include <kim/kim_ui_plugin.h>
#include <asl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct {
    const char *magic;
    aslclient asl_context;
    int got_error;
} *test_ui_context;

const char *magic = "test_ui_context_magic";

/* ------------------------------------------------------------------------ */

static void test_ui_vlog (test_ui_context  in_context,
                          const char      *in_format, 
                          va_list          in_args)
{
    if (!in_context) {
        asl_log (NULL, NULL, ASL_LEVEL_ERR, "NULL context!");
        
    } else if (strcmp (in_context->magic, magic)) {
        asl_log (NULL, NULL, ASL_LEVEL_ERR, 
                 "Magic mismatch.  Context corrupted!");
        
    } else {
        asl_vlog (in_context->asl_context, NULL, ASL_LEVEL_NOTICE, 
                  in_format, in_args);
    }
}

/* ------------------------------------------------------------------------ */

static void test_ui_log_ (void       *in_context,
                          const char *in_function, 
                          const char *in_format, ...)
{
    test_ui_context context = in_context;
    char *format = NULL;
    va_list args;
    
    asprintf (&format, "%s: %s", in_function, in_format);
    
    va_start (args, in_format);    
    test_ui_vlog (context, format, args);
    va_end (args);
              
    free (format);
}

#define test_ui_log(context, format, ...) test_ui_log_(context, __FUNCTION__, format, ## __VA_ARGS__)

#pragma mark -

/* ------------------------------------------------------------------------ */

static kim_error test_ui_init (void **out_context)
{
    kim_error err = KIM_NO_ERROR;
    test_ui_context context = NULL;
    
    if (!err) {
        context = malloc (sizeof (*context));
        if (!context) { err = KIM_OUT_OF_MEMORY_ERR; }
    } 
    
    if (!err) {
        context->got_error = 0;
        context->magic = magic;
        context->asl_context = asl_open (NULL, 
                                         "com.apple.console", 
                                         ASL_OPT_NO_DELAY | ASL_OPT_STDERR);
        if (!context->asl_context) { err = KIM_OUT_OF_MEMORY_ERR; }
    }
    
    if (!err) {
        test_ui_log (context, "returning with no error.");
    } else {
        kim_string estring = NULL;
        
        kim_string_create_for_last_error (&estring, err);
        test_ui_log (NULL, "returning %d: %s", err, estring);
        kim_string_free (&estring);
    }
    
    if (!err) {        
        *out_context = context;
        context = NULL;
    }
    
    free (context);
    
    return err;
}

/* ------------------------------------------------------------------------ */

static kim_error test_ui_enter_identity (void         *in_context,
                                         kim_options   io_options,
                                         kim_identity *out_identity,
                                         kim_boolean  *out_change_password)
{
    kim_error err = KIM_NO_ERROR;
    kim_identity identity = NULL;
    
    test_ui_log (in_context, "entering...");
    
    if (!err) {
        test_ui_context context = in_context;
        if (context->got_error > 1) {
            test_ui_log (in_context, "\tfailed twice, giving up...");
            context->got_error = 0;
            err = KIM_USER_CANCELED_ERR;
        }
    }
    
    if (!err) {
        err = kim_options_set_lifetime (io_options, 1800);
    }
    
    if (!err) {
        err = kim_options_set_renewal_lifetime (io_options, 3600);
    }
    
    if (!err) {
        err = kim_identity_create_from_string (&identity,
                                               "nobody@TEST-KERBEROS-1.5");
    }
    
    if (!err) {
        *out_identity = identity;
        identity = NULL;
        *out_change_password = 0;
    }
    
    kim_identity_free (&identity);
    
    if (!err) {
        test_ui_log (in_context, "returning with no error.");
    } else {
        kim_string estring = NULL;
        
        kim_string_create_for_last_error (&estring, err);
        test_ui_log (in_context, "returning %d: %s", err, estring);
        kim_string_free (&estring);
    }
    
    return err;    
}

/* ------------------------------------------------------------------------ */

static kim_error test_ui_select_identity (void                *in_context,
                                          kim_selection_hints  io_hints,
                                          kim_identity        *out_identity,
                                          kim_boolean         *out_change_password)
{
    kim_error err = KIM_NO_ERROR;
    kim_identity identity = NULL;
    kim_options options = NULL;
    
    test_ui_log (in_context, "entering...");
    
    if (!err) {
        test_ui_context context = in_context;
        if (context->got_error > 1) {
            test_ui_log (in_context, "\tfailed twice, giving up...");
            context->got_error = 0;
            err = KIM_USER_CANCELED_ERR;
        }
    }
    
    if (!err) {
        err = kim_selection_hints_get_options (io_hints, &options);
    }
    
    if (!err && !options) {
        err = kim_options_create (&options);
    }
    
    if (!err) {
        err = kim_options_set_lifetime (options, 1800);
    }
    
    if (!err) {
        err = kim_options_set_renewal_lifetime (options, 3600);
    }
    
    if (!err) {
        err = kim_selection_hints_set_options (io_hints, options);
    }
    
    if (!err) {
        err = kim_identity_create_from_string (&identity,
                                               "nobody@TEST-KERBEROS-1.5");
    }
    
    if (!err) {
        *out_identity = identity;
        identity = NULL;
        *out_change_password = 0;
    }
    
    kim_options_free (&options);
    kim_identity_free (&identity);
    
    if (!err) {
        test_ui_log (in_context, "returning with no error.");
    } else {
        kim_string estring = NULL;
        
        kim_string_create_for_last_error (&estring, err);
        test_ui_log (in_context, "returning %d: %s", err, estring);
        kim_string_free (&estring);
    }
    
    return err;    
}    

/* ------------------------------------------------------------------------ */

static kim_error test_ui_auth_prompt (void              *in_context,
                                      kim_identity       in_identity,
                                      kim_prompt_type    in_type,
                                      kim_boolean        in_allow_save_reply, 
                                      kim_boolean        in_hide_reply, 
                                      kim_string         in_title,
                                      kim_string         in_message,
                                      kim_string         in_description,
                                      char             **out_reply,
                                      kim_boolean       *out_save_reply)
{
    kim_error err = KIM_NO_ERROR;
    kim_string string = NULL;
    char *reply = NULL;
    
    test_ui_log (in_context, "entering...");
    
    if (!err) {
        err = kim_identity_get_display_string (in_identity, &string);
    }
    
    if (!err) {
        test_ui_log (in_context, "\tidentity = %s",         string);
        test_ui_log (in_context, "\ttype = %d",             in_type);
        test_ui_log (in_context, "\tallow_save_reply = %d", in_allow_save_reply);
        test_ui_log (in_context, "\thide_reply = %d",       in_hide_reply);
        test_ui_log (in_context, "\ttitle = %s",            in_title);
        test_ui_log (in_context, "\tmessage = %s",          in_message);
        test_ui_log (in_context, "\tdescription = %s",      in_description);
        
        reply = strdup ("ydobon");
        if (!reply) { err = KIM_OUT_OF_MEMORY_ERR; }
    }
    
    if (!err) {
        test_ui_context context = in_context;
        if (context->got_error > 1) {
            test_ui_log (in_context, "\tfailed twice, giving up...");
            context->got_error = 0;
            err = KIM_USER_CANCELED_ERR;
        }
    }
    
    if (!err) {
        *out_reply = reply;
        reply = NULL;
        *out_save_reply = 0;
    }
    
    free (reply);
    kim_string_free (&string);
    
    if (!err) {
        test_ui_log (in_context, "returning with no error.");
    } else {
        kim_string estring = NULL;
        
        kim_string_create_for_last_error (&estring, err);
        test_ui_log (in_context, "returning %d: %s", err, estring);
        kim_string_free (&estring);
    }
    
    return err;
}

/* ------------------------------------------------------------------------ */

static kim_error test_ui_change_password (void          *in_context,
                                          kim_identity   in_identity,
                                          kim_boolean    in_old_password_expired,
                                          char         **out_old_password,
                                          char         **out_new_password,
                                          char         **out_verify_password)
{
    kim_error err = KIM_NO_ERROR;
    kim_string string = NULL;
    char *old_password = NULL;
    char *new_password = NULL;
    char *vfy_password = NULL;
    
    test_ui_log (in_context, "entering...");
    
    if (!err) {
        err = kim_identity_get_display_string (in_identity, &string);
    }
    
    if (!err) {
        test_ui_log (in_context, "\tidentity = %s", string);
        test_ui_log (in_context, "\told_password_expired = %d", 
                     in_old_password_expired);

        old_password = strdup ("ydobon");
        new_password = strdup ("foo");
        vfy_password = strdup ("foo");
        if (!old_password || !new_password || !vfy_password) { 
            err = KIM_OUT_OF_MEMORY_ERR; 
        }
    }
    
    if (!err) {
        test_ui_context context = in_context;
        if (context->got_error > 1) {
            test_ui_log (in_context, "\tfailed twice, giving up...");
            context->got_error = 0;
            err = KIM_USER_CANCELED_ERR;
        }
    }

    if (!err) {
        *out_old_password = old_password;
        old_password = NULL;
        *out_new_password = new_password;
        new_password = NULL;
        *out_verify_password = vfy_password;
        vfy_password = NULL;
    }
    
    free (old_password);
    free (new_password);
    free (vfy_password);
    kim_string_free (&string);
    
    if (!err) {
        test_ui_log (in_context, "returning with no error.");
    } else {
        kim_string estring = NULL;
        
        kim_string_create_for_last_error (&estring, err);
        test_ui_log (in_context, "returning %d: %s", err, estring);
        kim_string_free (&estring);
    }
    
    return err;
}

/* ------------------------------------------------------------------------ */

static kim_error test_ui_handle_error (void         *in_context,
                                       kim_identity  in_identity,
                                       kim_error     in_error,
                                       kim_string    in_error_message,
                                       kim_string    in_error_description)
{
    kim_error err = KIM_NO_ERROR;
    kim_string string = NULL;
    
    test_ui_log (in_context, "entering...");
    
    if (!err) {
        err = kim_identity_get_display_string (in_identity, &string);
    }
    
    if (!err) {
        test_ui_context context = in_context;

        test_ui_log (in_context, "\tidentity = %s",    string);
        test_ui_log (in_context, "\terror = %d",       in_error);
        test_ui_log (in_context, "\tmessage = %s",     in_error_message);
        test_ui_log (in_context, "\tdescription = %s", in_error_description);
        
        context->got_error++;
    }
    
    kim_string_free (&string);
    
    if (!err) {
        test_ui_log (in_context, "returning with no error.");
    } else {
        kim_string estring = NULL;
        
        kim_string_create_for_last_error (&estring, err);
        test_ui_log (in_context, "returning %d: %s", err, estring);
        kim_string_free (&estring);
    }
    
    return err;
}

/* ------------------------------------------------------------------------ */

static void test_ui_free_string (void  *in_context,
                                 char **io_string)
{
    /* strings zeroed by caller so just print pointer value */
    test_ui_log (in_context, "freeing string %p", *io_string);

    free (*io_string);
    *io_string = NULL;
}

/* ------------------------------------------------------------------------ */

static kim_error test_ui_fini (void *io_context)
{
    kim_error err = KIM_NO_ERROR;

    test_ui_log (io_context, "deallocating...");
    
    if (io_context) {
        test_ui_context context = io_context;
        
        asl_close (context->asl_context);
        free (context);
    }
    
    return err;
}

/* ------------------------------------------------------------------------ */

kim_ui_plugin_ftable_v0 kim_ui_0 = {
    0,
    test_ui_init,
    test_ui_enter_identity,
    test_ui_select_identity,
    test_ui_auth_prompt,
    test_ui_change_password,
    test_ui_handle_error,
    test_ui_free_string,
    test_ui_fini
};

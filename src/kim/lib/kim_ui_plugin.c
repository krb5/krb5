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

#include "k5-int.h"

#include "kim_private.h"


const char * const *kim_ui_plugin_files = NULL;
#if TARGET_OS_MAC
static const char *kim_ui_plugin_dirs[] = { KRB5_KIM_UI_PLUGIN_BUNDLE_DIR, LIBDIR "/krb5/plugins/kimui", NULL };
#else
static const char *kim_ui_plugin_dirs[] = { LIBDIR "/krb5/plugins/kimui", NULL };
#endif


struct kim_ui_plugin_context {
    krb5_context kcontext;
    struct plugin_dir_handle plugins;
    struct kim_ui_plugin_ftable_v0 *ftable;
    void **ftables;
    void *plugin_context;
};


/* ------------------------------------------------------------------------ */

static void kim_ui_plugin_context_free (kim_ui_plugin_context *io_context)
{
    if (io_context && *io_context) { 
        if ((*io_context)->ftables) {
            krb5int_free_plugin_dir_data ((*io_context)->ftables);
        }
        if (PLUGIN_DIR_OPEN (&(*io_context)->plugins)) { 
            krb5int_close_plugin_dirs (&(*io_context)->plugins); 
        }
        if ((*io_context)->kcontext) { 
            krb5_free_context ((*io_context)->kcontext); 
        }
        free (*io_context);
        *io_context = NULL;
    }
}

/* ------------------------------------------------------------------------ */

static kim_error kim_ui_plugin_context_allocate (kim_ui_plugin_context *out_context)
{
    kim_error err = KIM_NO_ERROR;
    kim_ui_plugin_context context = NULL;
    
    if (!err && !out_context) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        context = malloc (sizeof (*context));
        if (!context) { err = KIM_OUT_OF_MEMORY_ERR; }
    }
    
    if (!err) {
        err = krb5_error (NULL, krb5_init_context (&context->kcontext));
    }
    
    if (!err) {
        PLUGIN_DIR_INIT(&context->plugins);
        context->ftable = NULL;
        context->ftables = NULL;
        context->plugin_context = NULL;
        
        *out_context = context;
        context = NULL;
    }
    
    kim_ui_plugin_context_free (&context);
    
    return check_error (err);    
}

#pragma mark -

/* ------------------------------------------------------------------------ */

kim_error kim_ui_plugin_init (kim_ui_context *io_context)
{
    kim_error err = KIM_NO_ERROR;
    kim_ui_plugin_context context = NULL;
    
    if (!err && !io_context) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_ui_plugin_context_allocate (&context);
    }
    
    if (!err) {
        PLUGIN_DIR_INIT(&context->plugins);

        err = krb5_error (context->kcontext,
                          krb5int_open_plugin_dirs (kim_ui_plugin_dirs, 
                                                    kim_ui_plugin_files, 
                                                    &context->plugins, 
                                                    &context->kcontext->err));
    }
    
    if (!err) {
        err = krb5_error (context->kcontext,
                          krb5int_get_plugin_dir_data (&context->plugins,
                                                       "kim_ui_0",
                                                       &context->ftables, 
                                                       &context->kcontext->err));
    }
    
    if (!err && context->ftables) {
        int i;
        
        for (i = 0; context->ftables[i]; i++) {
            struct kim_ui_plugin_ftable_v0 *ftable = context->ftables[i];
            context->plugin_context = NULL;
            
            err = ftable->init (&context->plugin_context);
            
            if (!err) {
                context->ftable = ftable;
                break; /* use first plugin that initializes correctly */
            }
            
            err = KIM_NO_ERROR; /* ignore failed plugins */
        }
    }
    
    if (!err && !context->ftable) {
        err = check_error (KRB5_PLUGIN_NO_HANDLE);
    }
        
    if (!err) {
        io_context->tcontext = context;
        context = NULL;
    }
    
    kim_ui_plugin_context_free (&context);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_ui_plugin_enter_identity (kim_ui_context *in_context,
                                        kim_options     io_options,
                                        kim_identity   *out_identity,
                                        kim_boolean    *out_change_password)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_context         ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !io_options         ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_identity       ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_change_password) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        kim_ui_plugin_context context = (kim_ui_plugin_context) in_context->tcontext;

        err = context->ftable->enter_identity (context->plugin_context,
                                               io_options,
                                               out_identity,
                                               out_change_password);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_ui_plugin_select_identity (kim_ui_context      *in_context,
                                         kim_selection_hints  io_hints,
                                         kim_identity        *out_identity,
                                         kim_boolean         *out_change_password)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_context         ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !io_hints           ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_identity       ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_change_password) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        kim_ui_plugin_context context = (kim_ui_plugin_context) in_context->tcontext;
        
        err = context->ftable->select_identity (context->plugin_context,
                                                io_hints, 
                                                out_identity,
                                                out_change_password);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_ui_plugin_auth_prompt (kim_ui_context      *in_context,
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
    
    if (!err && !in_context ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_reply  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    /* in_title, in_message or in_description may be NULL */
    
    if (!err) {
        kim_ui_plugin_context context = (kim_ui_plugin_context) in_context->tcontext;
        
        err = context->ftable->auth_prompt (context->plugin_context,
                                            in_identity, 
                                            in_type,
                                            in_allow_save_reply,
                                            in_hide_reply,
                                            in_title,
                                            in_message,
                                            in_description,
                                            out_reply,
                                            out_save_reply);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_ui_plugin_change_password (kim_ui_context  *in_context,
                                         kim_identity     in_identity,
                                         kim_boolean      in_old_password_expired,
                                         char           **out_old_password,
                                         char           **out_new_password,
                                         char           **out_verify_password)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_context         ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_identity        ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_old_password   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_new_password   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_verify_password) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        kim_ui_plugin_context context = (kim_ui_plugin_context) in_context->tcontext;
        
        err = context->ftable->change_password (context->plugin_context,
                                                in_identity, 
                                                in_old_password_expired,
                                                out_old_password,
                                                out_new_password,
                                                out_verify_password);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_ui_plugin_handle_error (kim_ui_context *in_context,
                                      kim_identity    in_identity,
                                      kim_error       in_error,
                                      kim_string      in_error_message,
                                      kim_string      in_error_description)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_context          ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_error_message    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_error_description) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        kim_ui_plugin_context context = (kim_ui_plugin_context) in_context->tcontext;
        
        err = context->ftable->handle_error (context->plugin_context,
                                             in_identity, 
                                             in_error,
                                             in_error_message,
                                             in_error_description);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

void kim_ui_plugin_free_string (kim_ui_context  *in_context,
                                char           **io_string)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_context) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !io_string ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        kim_ui_plugin_context context = (kim_ui_plugin_context) in_context->tcontext;
        
        context->ftable->free_string (context->plugin_context, 
                                      io_string);
    }
 }

/* ------------------------------------------------------------------------ */

kim_error kim_ui_plugin_fini (kim_ui_context *io_context)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_context) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        kim_ui_plugin_context context = (kim_ui_plugin_context) io_context->tcontext;
        
        if (context) {
            err = context->ftable->fini (context->plugin_context);
        }

        if (!err) {
            kim_ui_plugin_context_free (&context);
            io_context->tcontext = NULL;
        }
    }
    
    return check_error (err);
}

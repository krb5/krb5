/*
 * $Header$
 *
 * Copyright 2006 Massachusetts Institute of Technology.
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
#include <com_err.h>
#include <CredentialsCache.h>

static k5_mutex_t kim_error_lock = K5_MUTEX_PARTIAL_INITIALIZER;

MAKE_INIT_FUNCTION(kim_error_initialize);
MAKE_FINI_FUNCTION(kim_error_terminate);

/* ------------------------------------------------------------------------ */

typedef struct kim_last_error {
    kim_error code;
    char message[2048];
} *kim_last_error;

/* ------------------------------------------------------------------------ */

static kim_error kim_error_set_message (kim_error  in_error,
                                        kim_string in_message)
{
    int lock_err = 0;
    kim_error err = KIM_NO_ERROR;
    kim_last_error last_error = NULL; 
    
    err = lock_err = k5_mutex_lock (&kim_error_lock);
    
    if (!err) {
        last_error = k5_getspecific (K5_KEY_KIM_ERROR_MESSAGE);
        
        if (!last_error) {
            last_error = malloc (sizeof (*last_error));
            if (!last_error) {
                err = KIM_OUT_OF_MEMORY_ERR;
            } else {
                last_error->code = KIM_NO_ERROR;
                err = k5_setspecific (K5_KEY_KIM_ERROR_MESSAGE, last_error);
            }
        }
    }
    
    if (!err) {
        strncpy (last_error->message, in_message, sizeof (last_error->message));
        last_error->message[sizeof (last_error->message)-1] = '\0';
        last_error->code = in_error;
    }
    
    if (!lock_err) { k5_mutex_unlock (&kim_error_lock); }
    
    return err;
}

/* ------------------------------------------------------------------------ */

static void kim_error_free_message (void *io_error)
{
    kim_last_error error = io_error;
    
    if (error) {
        if (error->message) {
            free (error->message);
        }
        free (error);
    }
}

#pragma mark -

/* ------------------------------------------------------------------------ */

static kim_boolean kim_error_is_builtin (kim_error in_error)
{
    return (in_error == KIM_NO_ERROR ||
            in_error == KIM_OUT_OF_MEMORY_ERR);
}

/* ------------------------------------------------------------------------ */
/* Warning: only remap to error strings with the same format!               */

static kim_error kim_error_remap (kim_error in_error)
{
    /* some krb5 errors are confusing.  remap to better ones */
    switch (in_error) {
        case KRB5KRB_AP_ERR_BAD_INTEGRITY:
            return KIM_BAD_PASSWORD_ERR;
            
        case KRB5KDC_ERR_PREAUTH_FAILED:
            return KIM_PREAUTH_FAILED_ERR;
            
        case KRB5KRB_AP_ERR_SKEW:
            return KIM_CLOCK_SKEW_ERR;
    }
    
    return in_error;
}

/* ------------------------------------------------------------------------ */

kim_string kim_error_message (kim_error in_error)
{
    int lock_err = 0;
    kim_last_error last_error = NULL; 
    kim_string message = NULL;
    
    lock_err = k5_mutex_lock (&kim_error_lock);
    
    if (!lock_err) {
        last_error = k5_getspecific (K5_KEY_KIM_ERROR_MESSAGE);
        if (last_error && last_error->code == in_error) {
            message = last_error->message;
         }
    }
    
    if (!lock_err) { k5_mutex_unlock (&kim_error_lock); }
    
    return message ? message : error_message (kim_error_remap (in_error));    
}

#pragma mark -- Generic Functions --

/* ------------------------------------------------------------------------ */

kim_error kim_error_set_message_for_code (kim_error in_error, 
                                          ...)
{
    kim_error err = KIM_NO_ERROR;
    va_list args;
    
    va_start (args, in_error);
    err = kim_error_set_message_for_code_va (in_error, args);
    va_end (args);
    
    return check_error (err);    
}

/* ------------------------------------------------------------------------ */

kim_error kim_error_set_message_for_code_va (kim_error in_code, 
                                             va_list   in_args)
{
    kim_error err = KIM_NO_ERROR;
    kim_error code = kim_error_remap (in_code);

    if (!kim_error_is_builtin (code)) {
        kim_string message = NULL;
        
        err = kim_string_create_from_format_va_retcode (&message, 
                                                        error_message (code), 
                                                        in_args);
        
        if (!err) {
            err = kim_error_set_message (code, message);
        }
        
        kim_string_free (&message);
    }
    
    return err ? err : code;
}


/* ------------------------------------------------------------------------ */

kim_error kim_error_set_message_for_krb5_error (krb5_context    in_context, 
                                                krb5_error_code in_code)
{
    kim_error err = KIM_NO_ERROR;
    krb5_error_code code = kim_error_remap (in_code);
    
    if (code != in_code) {
        /* error was remapped to a KIM error */
        err = kim_error_set_message (code, error_message (code));

    } else if (!kim_error_is_builtin (code)) {
        const char *message = krb5_get_error_message (in_context, code);
        
        if (message) {
            err = kim_error_set_message (code, message);
            
            krb5_free_error_message (in_context, message);
        }
    }
    
    return err ? err : code;
}

#pragma mark -- Debugging Functions --

/* ------------------------------------------------------------------------ */

int kim_error_initialize (void)
{
    int err = 0;
    
    if (!err) {
	err = k5_mutex_finish_init (&kim_error_lock);
    }
    
    if (!err) {
	err = k5_key_register (K5_KEY_KIM_ERROR_MESSAGE, 
                               kim_error_free_message);
    }
    
    return err;
}

/* ------------------------------------------------------------------------ */

void kim_error_terminate (void)
{
    if (!INITIALIZER_RAN (kim_error_initialize) || PROGRAM_EXITING ()) {
	return;
    }
    
    k5_key_delete (K5_KEY_KIM_ERROR_MESSAGE);
    k5_mutex_destroy (&kim_error_lock);
}


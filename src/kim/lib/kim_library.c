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

#define KRB5_PRIVATE 1

#include <pthread.h>
#include <stdarg.h>
#include <krb5/krb5.h>
#include <profile.h>

#include "kim_private.h"
#include "kim_os_private.h"

/* ------------------------------------------------------------------------ */

void __kim_library_debug_printf (kim_string in_function, 
                                 kim_string in_format, 
                                 ...)
{
    kim_error err = KIM_NO_ERROR;
    kim_string format = NULL;
    kim_string string = NULL;
    
    if (!err && !in_function) { err = param_error (1, "in_function", "NULL"); }
    if (!err && !in_format  ) { err = param_error (2, "in_format", "NULL"); }
   
    if (!err) {
        err = kim_string_create_from_format (&format, "%s(): %s", in_function, in_format);
    }
    
    if (!err) {
        va_list args;
        va_start (args, in_format);
        err = kim_string_create_from_format_va (&string, format, args);
        va_end (args);
    }
    
    if (!err) {
        kim_os_library_debug_print (string);
    }
    
    kim_string_free (&format);
    kim_string_free (&string);
    kim_error_free (&err);
}

#pragma mark -- Allow Home Directory Access --

static pthread_mutex_t g_allow_home_directory_access_mutex = PTHREAD_MUTEX_INITIALIZER;
kim_boolean g_allow_home_directory_access = TRUE;

/* ------------------------------------------------------------------------ */

kim_error kim_library_set_allow_home_directory_access (kim_boolean in_allow_access)
{
    kim_error err = KIM_NO_ERROR;
    
    int mutex_err = pthread_mutex_lock (&g_allow_home_directory_access_mutex);
    if (mutex_err) { err = os_error (mutex_err); }
    
    if (!err) {
        g_allow_home_directory_access = in_allow_access;
    }
    
    if (!mutex_err) { pthread_mutex_unlock (&g_allow_home_directory_access_mutex); }
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_library_get_allow_home_directory_access (kim_boolean *out_allow_access)
{
    kim_error err = KIM_NO_ERROR;
    int mutex_err = 0;
    
    if (!err && !out_allow_access) { err = param_error (3, "out_allow_access", "NULL"); }
    
    if (!err) {
        mutex_err = pthread_mutex_lock (&g_allow_home_directory_access_mutex);;
        if (mutex_err) { err = os_error (mutex_err); }
    }
    
    if (!err) {
        *out_allow_access = g_allow_home_directory_access;
    }
    
    if (!mutex_err) { pthread_mutex_unlock (&g_allow_home_directory_access_mutex); }
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_boolean kim_library_allow_home_directory_access (void)
{
    kim_boolean allow_access = FALSE;
    kim_error err = kim_library_get_allow_home_directory_access (&allow_access);
    
    kim_error_free (&err);
    
    return allow_access;
}


#pragma mark -- Allow Automatic Prompting --

static pthread_mutex_t g_allow_automatic_prompting_mutex = PTHREAD_MUTEX_INITIALIZER;
kim_boolean g_allow_automatic_prompting = TRUE;

/* ------------------------------------------------------------------------ */

kim_error kim_library_set_allow_automatic_prompting (kim_boolean in_allow_automatic_prompting)
{
    kim_error err = KIM_NO_ERROR;
    
    int mutex_err = pthread_mutex_lock (&g_allow_automatic_prompting_mutex);
    if (mutex_err) { err = os_error (mutex_err); }
    
    if (!err) {
        g_allow_automatic_prompting = in_allow_automatic_prompting;
    }
    
    if (!mutex_err) { pthread_mutex_unlock (&g_allow_automatic_prompting_mutex); }
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_library_get_allow_automatic_prompting (kim_boolean *out_allow_automatic_prompting)
{
    kim_error err = KIM_NO_ERROR;
    int mutex_err = 0;
    
    if (!err && !out_allow_automatic_prompting) { err = param_error (3, "out_allow_automatic_prompting", "NULL"); }
    
    if (!err) {
        mutex_err = pthread_mutex_lock (&g_allow_automatic_prompting_mutex);;
        if (mutex_err) { err = os_error (mutex_err); }
    }
    
    if (!err) {
        *out_allow_automatic_prompting = g_allow_automatic_prompting;
    }
    
    if (!mutex_err) { pthread_mutex_unlock (&g_allow_automatic_prompting_mutex); }
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_boolean kim_library_allow_automatic_prompting (void)
{
    kim_boolean allow_automatic_prompting = TRUE;
    kim_error err = kim_library_get_allow_automatic_prompting (&allow_automatic_prompting);
    
    if (allow_automatic_prompting && getenv ("KERBEROSLOGIN_NEVER_PROMPT")) {
        kim_debug_printf ("KERBEROSLOGIN_NEVER_PROMPT is set.");
        allow_automatic_prompting = FALSE;
    }
    
    if (allow_automatic_prompting && getenv ("KIM_NEVER_PROMPT")) {
        kim_debug_printf ("KIM_NEVER_PROMPT is set.");
        allow_automatic_prompting = FALSE;
    }

    if (allow_automatic_prompting) {
        /* Make sure there is at least 1 config file. We don't support DNS 
         * domain-realm lookup, so if there is no config, Kerberos won't work. */
        
        kim_boolean kerberos_config_exists = FALSE;
        char **files = NULL;
        profile_t profile = NULL;
        
        if (krb5_get_default_config_files (&files) == 0) {
            if (profile_init ((const_profile_filespec_t *) files, &profile) == 0) {
                kerberos_config_exists = TRUE;
            }
        }
        
        if (!kerberos_config_exists) {
            kim_debug_printf ("No valid config file.");
            allow_automatic_prompting = FALSE;
        }
        
        if (profile) { profile_abandon (profile); }
        if (files  ) { krb5_free_config_files (files); }        
    }
    
    kim_error_free (&err);

    return allow_automatic_prompting;
}

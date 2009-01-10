/*
 * $Header$
 *
 * Copyright 2006-2008 Massachusetts Institute of Technology.
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

#include "k5-int.h"
#include "k5-thread.h"
#include <krb5/krb5.h>
#include <profile.h>

#include "kim_private.h"
#include "kim_os_private.h"

#if KIM_TO_KLL_SHIM
#include "KerberosLoginErrors.h"
#endif

MAKE_INIT_FUNCTION(kim_error_init);
MAKE_FINI_FUNCTION(kim_error_fini);

/* ------------------------------------------------------------------------ */

static int kim_error_init (void)
{
    add_error_table (&et_KIM_error_table);
#if KIM_TO_KLL_SHIM
    add_error_table (&et_KLL_error_table);    
#endif
    return 0;
}

/* ------------------------------------------------------------------------ */

static void kim_error_fini (void)
{
    if (!INITIALIZER_RAN (kim_error_init) || PROGRAM_EXITING ()) {
	return;
    }

    remove_error_table (&et_KIM_error_table);
#if KIM_TO_KLL_SHIM
    remove_error_table (&et_KLL_error_table);
#endif
}

/* ------------------------------------------------------------------------ */

kim_error kim_library_init (void)
{
    return CALL_INIT_FUNCTION (kim_error_init);
}

#pragma mark -

static k5_mutex_t g_allow_home_directory_access_mutex = K5_MUTEX_PARTIAL_INITIALIZER;
static k5_mutex_t g_allow_automatic_prompting_mutex = K5_MUTEX_PARTIAL_INITIALIZER;
static k5_mutex_t g_ui_environment_mutex = K5_MUTEX_PARTIAL_INITIALIZER;
static k5_mutex_t g_application_name_mutex = K5_MUTEX_PARTIAL_INITIALIZER;

kim_boolean g_allow_home_directory_access = TRUE;
kim_boolean g_allow_automatic_prompting = TRUE;
kim_ui_environment g_ui_environment = KIM_UI_ENVIRONMENT_AUTO;
kim_string g_application_name = NULL;

MAKE_INIT_FUNCTION(kim_thread_init);
MAKE_FINI_FUNCTION(kim_thread_fini);

/* ------------------------------------------------------------------------ */

static int kim_thread_init (void)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err) {
        err = k5_mutex_finish_init (&g_allow_home_directory_access_mutex);
    }
    
    if (!err) {
        err = k5_mutex_finish_init (&g_allow_automatic_prompting_mutex);
    }
    
    if (!err) {
        err = k5_mutex_finish_init (&g_ui_environment_mutex);
    }
    
    if (!err) {
        err = k5_mutex_finish_init (&g_application_name_mutex);
    }
    
    return err;
}

/* ------------------------------------------------------------------------ */

static void kim_thread_fini (void)
{
    if (!INITIALIZER_RAN (kim_thread_init) || PROGRAM_EXITING ()) {
	return;
    }
    
    k5_mutex_destroy (&g_allow_home_directory_access_mutex);
    k5_mutex_destroy (&g_allow_automatic_prompting_mutex);
    k5_mutex_destroy (&g_ui_environment_mutex);
    k5_mutex_destroy (&g_application_name_mutex);
}

#pragma mark -- Allow Home Directory Access --

/* ------------------------------------------------------------------------ */

kim_error kim_library_set_allow_home_directory_access (kim_boolean in_allow_access)
{
    kim_error err = CALL_INIT_FUNCTION (kim_thread_init);
    kim_error mutex_err = KIM_NO_ERROR;
    
    if (!err) {
        mutex_err = k5_mutex_lock (&g_allow_home_directory_access_mutex);
        if (mutex_err) { err = mutex_err; }
    }
    
    if (!err) {
        g_allow_home_directory_access = in_allow_access;
    }
    
    if (!mutex_err) { k5_mutex_unlock (&g_allow_home_directory_access_mutex); }
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

static kim_error kim_library_get_allow_home_directory_access (kim_boolean *out_allow_access)
{
    kim_error err = CALL_INIT_FUNCTION (kim_thread_init);
    kim_error mutex_err = KIM_NO_ERROR;
    
    if (!err && !out_allow_access) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        mutex_err = k5_mutex_lock (&g_allow_home_directory_access_mutex);;
        if (mutex_err) { err = mutex_err; }
    }
    
    if (!err) {
        *out_allow_access = g_allow_home_directory_access;
    }
    
    if (!mutex_err) { k5_mutex_unlock (&g_allow_home_directory_access_mutex); }
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_boolean kim_library_allow_home_directory_access (void)
{
    kim_boolean allow_access = FALSE;
    kim_error err = kim_library_get_allow_home_directory_access (&allow_access);
    
    return !err ? allow_access : FALSE;
}


#pragma mark -- Allow Automatic Prompting --


/* ------------------------------------------------------------------------ */

kim_error kim_library_set_allow_automatic_prompting (kim_boolean in_allow_automatic_prompting)
{
    kim_error err = CALL_INIT_FUNCTION (kim_thread_init);
    kim_error mutex_err = KIM_NO_ERROR;
    
    if (!err) {
        mutex_err = k5_mutex_lock (&g_allow_automatic_prompting_mutex);
        if (mutex_err) { err = mutex_err; }
    }
    
    if (!err) {
        g_allow_automatic_prompting = in_allow_automatic_prompting;
    }
    
    if (!mutex_err) { k5_mutex_unlock (&g_allow_automatic_prompting_mutex); }
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

static kim_error kim_library_get_allow_automatic_prompting (kim_boolean *out_allow_automatic_prompting)
{
    kim_error err = CALL_INIT_FUNCTION (kim_thread_init);
    kim_error mutex_err = KIM_NO_ERROR;
    
    if (!err && !out_allow_automatic_prompting) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        mutex_err = k5_mutex_lock (&g_allow_automatic_prompting_mutex);;
        if (mutex_err) { err = mutex_err; }
    }
    
    if (!err) {
        *out_allow_automatic_prompting = g_allow_automatic_prompting;
    }
    
    if (!mutex_err) { k5_mutex_unlock (&g_allow_automatic_prompting_mutex); }
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_boolean kim_library_allow_automatic_prompting (void)
{
    kim_boolean allow_automatic_prompting = TRUE;
    kim_error err = kim_library_get_allow_automatic_prompting (&allow_automatic_prompting);
    if (err) { allow_automatic_prompting = TRUE; }
    
    if (allow_automatic_prompting && getenv ("KERBEROSLOGIN_NEVER_PROMPT")) {
        kim_debug_printf ("KERBEROSLOGIN_NEVER_PROMPT is set.");
        allow_automatic_prompting = FALSE;
    }
    
    if (allow_automatic_prompting && getenv ("KIM_NEVER_PROMPT")) {
        kim_debug_printf ("KIM_NEVER_PROMPT is set.");
        allow_automatic_prompting = FALSE;
    }
    
    if (allow_automatic_prompting && !kim_os_library_caller_uses_gui ()) {
        kim_debug_printf ("Caller is not using gui.");
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
    
    return allow_automatic_prompting;
}

#pragma mark -- UI Environment --

/* ------------------------------------------------------------------------ */

kim_error kim_library_set_ui_environment (kim_ui_environment in_ui_environment)
{
    kim_error err = CALL_INIT_FUNCTION (kim_thread_init);
    kim_error mutex_err = KIM_NO_ERROR;
    
    if (!err) {
        mutex_err = k5_mutex_lock (&g_ui_environment_mutex);
        if (mutex_err) { err = mutex_err; }
    }
    
    if (!err) {
        g_ui_environment = in_ui_environment;
    }
    
    if (!mutex_err) { k5_mutex_unlock (&g_ui_environment_mutex); }
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

static kim_error kim_library_get_ui_environment (kim_ui_environment *out_ui_environment)
{
    kim_error err = CALL_INIT_FUNCTION (kim_thread_init);
    kim_error mutex_err = KIM_NO_ERROR;
    
    if (!err && !out_ui_environment) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        mutex_err = k5_mutex_lock (&g_ui_environment_mutex);;
        if (mutex_err) { err = mutex_err; }
    }
    
    if (!err) {
        *out_ui_environment = g_ui_environment;
    }
    
    if (!mutex_err) { k5_mutex_unlock (&g_ui_environment_mutex); }
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_ui_environment kim_library_ui_environment (void)
{
    kim_error err = KIM_NO_ERROR;
    kim_ui_environment ui_environment = KIM_UI_ENVIRONMENT_AUTO;
    
    err = kim_library_get_ui_environment (&ui_environment);
    
    if (!err && ui_environment == KIM_UI_ENVIRONMENT_AUTO) {
        ui_environment = kim_os_library_get_ui_environment ();
    }
    
    return !err ? ui_environment : KIM_UI_ENVIRONMENT_NONE;
}

#pragma mark -- Application Name --

/* ------------------------------------------------------------------------ */

kim_error kim_library_set_application_name (kim_string in_application_name)
{
    kim_error err = CALL_INIT_FUNCTION (kim_thread_init);
    kim_error mutex_err = KIM_NO_ERROR;
    
    if (!err) {
        mutex_err = k5_mutex_lock (&g_application_name_mutex);
        if (mutex_err) { err = mutex_err; }
    }
    
    if (!err) {
        kim_string old_application_name = g_application_name;
        
        if (in_application_name) {
            err = kim_string_copy (&g_application_name, in_application_name);
        } else {
            g_application_name = NULL;
        }

        if (!err) { kim_string_free (&old_application_name); }
    }
    
    if (!mutex_err) { k5_mutex_unlock (&g_application_name_mutex); }
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_library_get_application_name (kim_string *out_application_name)
{
    kim_error err = CALL_INIT_FUNCTION (kim_thread_init);
    kim_error mutex_err = KIM_NO_ERROR;
    kim_string application_name = NULL;
    
    if (!err && !out_application_name) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        mutex_err = k5_mutex_lock (&g_application_name_mutex);
        if (mutex_err) { err = mutex_err; }
    }
    
    if (!err && g_application_name) {
        err = kim_string_copy (&application_name, g_application_name);
    }
    
    if (!mutex_err) { k5_mutex_unlock (&g_application_name_mutex); }
    
    if (!err && !application_name) {
        err = kim_os_library_get_caller_name (&application_name);
    }
    
    if (!err) {
        *out_application_name = application_name;
        application_name = NULL;
        
    }
    
    kim_string_free (&application_name);
    
    return check_error (err);
}

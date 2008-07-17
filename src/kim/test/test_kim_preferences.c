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

#include "test_kim_preferences.h"

/* ------------------------------------------------------------------------ */

void test_kim_preferences_create (kim_test_state_t state)
{
    
    start_test (state, "kim_preferences_create");

    {
        kim_error err = NULL;
        kim_preferences prefs = NULL;

        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
        
        kim_preferences_free (&prefs);
        kim_error_free (&err);
    }
    
    end_test (state);
}

/* ------------------------------------------------------------------------ */

void test_kim_preferences_copy (kim_test_state_t state)
{
    
    start_test (state, "test_kim_preferences_copy");
    
    {
        kim_error err = NULL;
        kim_preferences prefs = NULL;
        kim_preferences prefs_copy = NULL;
        
        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
 
        if (!err) {
            err = kim_preferences_copy (&prefs_copy, prefs);
            fail_if_error (state, "kim_preferences_copy", err, 
                           "while copying preferences");            
        }
        
        kim_preferences_free (&prefs_copy);
        kim_preferences_free (&prefs);
        kim_error_free (&err);
    }
    
    end_test (state);
}

/* ------------------------------------------------------------------------ */

void test_kim_preferences_set_options (kim_test_state_t state)
{
    
    start_test (state, "kim_preferences_set_options");
    
    {
        kim_error err = NULL;
        kim_preferences prefs = NULL;
        kim_options old_options = NULL;
        kim_options new_options = NULL;
        kim_options verify_options = NULL;
        const char *custom_data = "Some custom data";
        const char *verify_custom_data = NULL;
        
        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
        
        if (!err) {
            err = kim_preferences_get_options (prefs, &old_options);
            fail_if_error (state, "kim_preferences_get_options", err, 
                           "while getting old options");
       }
        
        if (!err) {
            err = kim_options_create (&new_options);
            fail_if_error (state, "kim_options_create", err, 
                           "while creating options");            
        }

        if (!err) {
            err = kim_options_set_data (new_options, custom_data);
            fail_if_error (state, "kim_options_set_data", err, 
                           "while setting the custom data to %s", custom_data);            
        }
        
        if (!err) {
            err = kim_preferences_set_options (prefs, new_options);
            fail_if_error (state, "kim_preferences_set_options", err, 
                           "while setting the new options");
        }

        if (!err) {
            err = kim_preferences_get_options (prefs, &verify_options);
            fail_if_error (state, "kim_preferences_get_options", err, 
                           "while getting options for verification");
        }
        
        if (!err) {
            err = kim_options_get_data (verify_options, (const void **)&verify_custom_data);
            fail_if_error (state, "kim_options_get_data", err, 
                           "while getting the custom data of the verify options");            
        }
        
        if (!err && custom_data != verify_custom_data) {
            log_failure (state, "Unexpected custom data in options (got %p, expected %p)", 
                         verify_custom_data, custom_data);
        }
        
        if (!err) {
            err = kim_preferences_set_options (prefs, old_options);
            fail_if_error (state, "kim_preferences_set_options", err, 
                           "while restoring the options");
        }

        kim_options_free (&old_options);
        kim_options_free (&new_options);
        kim_options_free (&verify_options);
        kim_preferences_free (&prefs);
        kim_error_free (&err);
    }
    
     end_test (state);
}

/* ------------------------------------------------------------------------ */

void test_kim_preferences_set_remember_options (kim_test_state_t state)
{
    
    start_test (state, "kim_preferences_set_remember_options");
    
    {
        kim_error err = NULL;
        kim_preferences prefs = NULL;
        kim_boolean remember_options = FALSE;
        
        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
        
        if (!err) {
            err = kim_preferences_set_remember_options (prefs, TRUE);
            fail_if_error (state, "kim_preferences_set_remember_options", err, 
                           "while setting the preference to remember options");
        }
        
        if (!err) {
            err = kim_preferences_get_remember_options (prefs, &remember_options);
            fail_if_error (state, "kim_preferences_get_remember_options", err, 
                           "while getting the preference to remember options");
        }
        
        if (!err && !remember_options) {
            log_failure (state, "Unexpected remember options preference (got %d, expected TRUE)", 
                         remember_options);
        }
        
        if (!err) {
            err = kim_preferences_set_remember_options (prefs, FALSE);
            fail_if_error (state, "kim_preferences_set_remember_options", err, 
                           "while setting the preference to remember options");
        }
        
        if (!err) {
            err = kim_preferences_get_remember_options (prefs, &remember_options);
            fail_if_error (state, "kim_preferences_get_remember_options", err, 
                           "while getting the preference to remember options");
        }
        
        if (!err && remember_options) {
            log_failure (state, "Unexpected remember options preference (got %d, expected 0)", 
                         remember_options);
        }
        
        kim_preferences_free (&prefs);
        kim_error_free (&err);
    }
    
    end_test (state);
}

/* ------------------------------------------------------------------------ */

void test_kim_preferences_set_client_identity (kim_test_state_t state)
{
    
    start_test (state, "kim_preferences_set_client_identity");
    
    {
        kim_error err = NULL;
        kim_preferences prefs = NULL;
        kim_string test_string = "user@EXAMPLE.COM";
        kim_identity test_identity = KIM_IDENTITY_ANY;
        kim_string string = NULL;
        kim_identity identity = KIM_IDENTITY_ANY;
        kim_comparison comparison = 0;
        
        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
        
        if (!err) {
            err = kim_identity_create_from_string (&test_identity, test_string);
            fail_if_error (state, "kim_identity_create_from_string", err, 
                           "while creating the identity for %s", test_string);
        }
        
        if (!err) {
            err = kim_preferences_set_client_identity (prefs, KIM_IDENTITY_ANY);
            fail_if_error (state, "kim_preferences_set_client_identity", err, 
                           "while setting the identity to KIM_IDENTITY_ANY");
        }
        
        if (!err) {
            err = kim_preferences_get_client_identity (prefs, &identity);
            fail_if_error (state, "kim_preferences_get_client_identity", err, 
                           "while getting the client identity preference");
        }
        
        if (!err && identity != KIM_IDENTITY_ANY) {
            log_failure (state, "Unexpected client identity preference (got %p, expected %p)", 
                         identity, KIM_IDENTITY_ANY);
            kim_identity_free (&identity);
        }
        
        if (!err) {
            err = kim_preferences_set_client_identity (prefs, test_identity);
            fail_if_error (state, "kim_preferences_set_client_identity", err, 
                           "while setting the identity to %s", test_string);
        }
        
        if (!err) {
            err = kim_preferences_get_client_identity (prefs, &identity);
            fail_if_error (state, "kim_preferences_get_client_identity", err, 
                           "while getting the client identity preference");
        }
        
        if (!err && identity) {
            err = kim_identity_get_string (identity, &string);
            fail_if_error (state, "kim_identity_get_string", err, 
                           "while getting the string for client identity preference");
        }

        if (!err) {
            err = kim_identity_compare (identity, test_identity, &comparison);
            fail_if_error (state, "kim_identity_compare", err, 
                           "while comparing %s to the identity preference %s", 
                           test_string, string ? string : "NULL");
        }
        
        if (!err && !kim_comparison_is_equal_to (comparison)) {
            log_failure (state, "Unexpected client identity preference (got %s, expected %s)", 
                         string ? string : "NULL", test_string);
            kim_identity_free (&identity);
        }
         
        kim_string_free (&string);
        kim_identity_free (&identity);
        kim_identity_free (&test_identity);
        kim_preferences_free (&prefs);
        kim_error_free (&err);
    }
    
    end_test (state);
}

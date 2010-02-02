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

#include "test_kim_selection_hints.h"

#define KSH_TEST_ID           "edu.mit.Kerberos.test_kim"

#define KSH_IDENTITY          "jdoe@USERS.EXAMPLE.COM"

typedef struct test_selection_hint_d {
    kim_string key;
    kim_string hint;
} test_selection_hint;

test_selection_hint test_hints[] = {
    { kim_hint_key_service_identity, "service/server.example.com@EXAMPLE.COM" },
    { kim_hint_key_service,          "service" },
    { kim_hint_key_server,           "server.example.com" },
    { kim_hint_key_service_realm,    "EXAMPLE.COM" },
    { kim_hint_key_user,             "jdoe" },
    { kim_hint_key_client_realm,     "USERS.EXAMPLE.COM" },
    { NULL, NULL }
};

/* ------------------------------------------------------------------------ */

void test_kim_selection_hints_set_hint (kim_test_state_t state)
{
    kim_error err = KIM_NO_ERROR;
    kim_count i = 0;
    
    start_test (state, "test_kim_selection_hints_set_hint");

    for (i = 0; !err && test_hints[i].key; i++) {
        kim_selection_hints hints = NULL;
        kim_string string = NULL;
        kim_comparison comparison = 0;
        
        printf (".");

        err = kim_selection_hints_create (&hints, KSH_TEST_ID);
        fail_if_error (state, "kim_selection_hints_create", err, 
                       "while creating selection hints for %s", KSH_TEST_ID);
        
        if (!err) {
            err = kim_selection_hints_set_hint (hints, test_hints[i].key, test_hints[i].hint);
            fail_if_error (state, "kim_selection_hints_set_hint", 
                           err, "while setting hint %s to %s", 
                           test_hints[i].key, test_hints[i].hint); 
        }
        
        if (!err) {
            err = kim_selection_hints_get_hint (hints, test_hints[i].key, &string);
            fail_if_error (state, "kim_selection_hints_get_hint", 
                           err, "while getting hint %s", test_hints[i].key);
        }
        
        if (!err) {
            err = kim_string_compare (test_hints[i].hint, string, &comparison);
            fail_if_error (state, "kim_identity_compare", err, 
                           "while comparing %s to %s (hint %s)", 
                           test_hints[i].hint, 
                           string ? string : "NULL", test_hints[i].key);
        }
        
        if (!err && !kim_comparison_is_equal_to (comparison)) {
            log_failure (state, "Unexpected hint %s (got %s, expected %s)", 
                         test_hints[i].key, 
                         string ? string : "NULL", 
                         test_hints[i].hint);
        }
        
        kim_string_free (&string);
        kim_selection_hints_free (&hints);
    }
    
    end_test (state);    
}



/* ------------------------------------------------------------------------ */

void test_kim_selection_hints_remember_identity (kim_test_state_t state)
{
    kim_error err = KIM_NO_ERROR;
    kim_selection_hints hints = NULL;
    kim_count i = 0;
    kim_identity client_identity = NULL;
    kim_string string = NULL;
    kim_identity identity = KIM_IDENTITY_ANY;
    kim_comparison comparison = 0;
  
    start_test (state, "kim_selection_hints_remember_identity");
    
    if (!err) {
        err = kim_selection_hints_create (&hints, KSH_TEST_ID);
        fail_if_error (state, "kim_selection_hints_create", err, 
                       "while creating selection hints for %s", KSH_TEST_ID);
    }
    
    for (i = 0; !err && test_hints[i].key; i++) {        
        err = kim_selection_hints_set_hint (hints, test_hints[i].key, test_hints[i].hint);
        fail_if_error (state, "kim_selection_hints_set_hint", 
                       err, "while setting hint %s to %s", 
                       test_hints[i].key, test_hints[i].hint);
    }
    
    if (!err) {
        err = kim_identity_create_from_string (&client_identity, 
                                               KSH_IDENTITY);
        fail_if_error (state, "kim_identity_create_from_string", err, 
                       "while creating an identity for %s", 
                       KSH_IDENTITY);
    }
    
    if (!err) {
        err = kim_selection_hints_remember_identity (hints, client_identity);
        fail_if_error (state, "kim_selection_hints_remember_identity", 
                       err, "while remembering identity %s", 
                       KSH_IDENTITY);
    }
    
    if (!err) {
        err = kim_selection_hints_get_identity (hints, &identity);
        fail_if_error (state, "kim_selection_hints_get_identity", 
                       err, "while checking if identity is %s", 
                       KSH_IDENTITY);
    }
    
    if (!err && identity) {
        err = kim_identity_get_string (identity, &string);
        fail_if_error (state, "kim_identity_get_string", err, 
                       "while getting the string for the client identity hint");
    }
    
    if (!err) {
        err = kim_identity_compare (client_identity, identity, &comparison);
        fail_if_error (state, "kim_identity_compare", err, 
                       "while comparing %s to the identity hint %s", 
                       KSH_IDENTITY, string ? string : "NULL");
    }
    
    if (!err && !kim_comparison_is_equal_to (comparison)) {
        log_failure (state, "Unexpected client identity hint (got %s, expected %s)", 
                     string ? string : "NULL", KSH_IDENTITY);
    }
    
    kim_string_free (&string);
    kim_identity_free (&identity);
    kim_identity_free (&client_identity);
    kim_selection_hints_free (&hints);
    
    end_test (state);
}

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
#define KSH_SERVICE_IDENTITY  "service/server.example.com@EXAMPLE.COM"
#define KSH_SERVICE           "service"
#define KSH_SERVER            "server.example.com"
#define KSH_SERVICE_REALM     "EXAMPLE.COM"
#define KSH_USER              "jdoe"
#define KSH_CLIENT_REALM      "USERS.EXAMPLE.COM"

#define KSH_IDENTITY          "jdoe@USERS.EXAMPLE.COM"


/* ------------------------------------------------------------------------ */

void test_kim_selection_hints_set_service_identity_hint (kim_test_state_t state)
{
    kim_error err = NULL;
    kim_selection_hints hints = NULL;
    kim_identity service_identity = NULL;
    kim_identity identity = KIM_IDENTITY_ANY;
    kim_string string = NULL;
    kim_comparison comparison = 0;

    start_test (state, "kim_selection_hints_set_service_identity_hint");

    if (!err) {
        err = kim_selection_hints_create (&hints, KSH_TEST_ID);
        fail_if_error (state, "kim_selection_hints_create", err, 
                       "while creating selection hints for %s", KSH_TEST_ID);
    }
    
    if (!err) {
        err = kim_identity_create_from_string (&service_identity, 
                                               KSH_SERVICE_IDENTITY);
        fail_if_error (state, "kim_identity_create_from_string", err, 
                       "while creating an identity for %s", 
                       KSH_SERVICE_IDENTITY);
    }
    
    if (!err) {
        err = kim_selection_hints_set_service_identity_hint (hints, service_identity);
        fail_if_error (state, "kim_selection_hints_set_service_identity_hint", 
                       err, "while setting service identity to %s", 
                       KSH_SERVICE_IDENTITY);
    }

    if (!err) {
        err = kim_selection_hints_get_service_identity_hint (hints, &identity);
        fail_if_error (state, "kim_selection_hints_get_service_identity_hint", 
                       err, "while getting service identity  %s", 
                       KSH_SERVICE_IDENTITY);
    }
    
    if (!err && identity) {
        err = kim_identity_get_string (identity, &string);
        fail_if_error (state, "kim_identity_get_string", err, 
                       "while getting the string for the service identity hint");
    }
    
    if (!err) {
        err = kim_identity_compare (service_identity, identity, &comparison);
        fail_if_error (state, "kim_identity_compare", err, 
                       "while comparing %s to the identity hint %s", 
                       KSH_SERVICE_IDENTITY, string ? string : "NULL");
    }
    
    if (!err && !kim_comparison_is_equal_to (comparison)) {
        log_failure (state, "Unexpected service identity hint (got %s, expected %s)", 
                     string ? string : "NULL", KSH_SERVICE_IDENTITY);
        kim_identity_free (&identity);
    }

    kim_string_free (&string);
    kim_identity_free (&service_identity);
    kim_selection_hints_free (&hints);
    
    end_test (state);    
}

/* ------------------------------------------------------------------------ */

void test_kim_selection_hints_set_client_realm_hint (kim_test_state_t state)
{
    kim_error err = NULL;
    kim_selection_hints hints = NULL;
    kim_string string = NULL;
    kim_comparison comparison = 0;
    
    start_test (state, "kim_selection_hints_set_client_realm_hint");
    
    if (!err) {
        err = kim_selection_hints_create (&hints, KSH_TEST_ID);
        fail_if_error (state, "kim_selection_hints_create", err, 
                       "while creating selection hints for %s", KSH_TEST_ID);
    }
    
    if (!err) {
        err = kim_selection_hints_set_client_realm_hint (hints, KSH_CLIENT_REALM);
        fail_if_error (state, "kim_selection_hints_set_client_realm_hint", 
                       err, "while setting client realm hint to %s", 
                       KSH_CLIENT_REALM); 
    }
    
    if (!err) {
        err = kim_selection_hints_get_client_realm_hint (hints, &string);
        fail_if_error (state, "kim_selection_hints_get_client_realm_hint", 
                       err, "while getting the client realm %s", 
                       KSH_CLIENT_REALM);
    }
    
    if (!err) {
        err = kim_string_compare (KSH_CLIENT_REALM, string, &comparison);
        fail_if_error (state, "kim_identity_compare", err, 
                       "while comparing %s to the client realm hint %s", 
                       KSH_CLIENT_REALM, string ? string : "NULL");
    }
    
    if (!err && !kim_comparison_is_equal_to (comparison)) {
        log_failure (state, "Unexpected client realm hint (got %s, expected %s)", 
                     string ? string : "NULL", KSH_CLIENT_REALM);
    }
    
    kim_string_free (&string);
    kim_selection_hints_free (&hints);
    
    end_test (state);    
}

/* ------------------------------------------------------------------------ */

void test_kim_selection_hints_set_user_hint (kim_test_state_t state)
{
    kim_error err = NULL;
    kim_selection_hints hints = NULL;
    kim_string string = NULL;
    kim_comparison comparison = 0;
    
    start_test (state, "kim_selection_hints_set_user_hint");
    
    if (!err) {
        err = kim_selection_hints_create (&hints, KSH_TEST_ID);
        fail_if_error (state, "kim_selection_hints_create", err, 
                       "while creating selection hints for %s", KSH_TEST_ID);
    }
    
    if (!err) {
        err = kim_selection_hints_set_user_hint (hints, KSH_USER);
        fail_if_error (state, "kim_selection_hints_set_user_hint", 
                       err, "while setting user hint to %s", 
                       KSH_USER);
    }
    
    if (!err) {
        err = kim_selection_hints_get_user_hint (hints, &string);
        fail_if_error (state, "kim_selection_hints_get_user_hint", 
                       err, "while getting the user hint %s", 
                       KSH_USER);
    }
    
    if (!err) {
        err = kim_string_compare (KSH_USER, string, &comparison);
        fail_if_error (state, "kim_identity_compare", err, 
                       "while comparing %s to the user hint %s", 
                       KSH_USER, string ? string : "NULL");
    }
    
    if (!err && !kim_comparison_is_equal_to (comparison)) {
        log_failure (state, "Unexpected user hint (got %s, expected %s)", 
                     string ? string : "NULL", KSH_USER);
    }
    
    kim_string_free (&string);
    kim_selection_hints_free (&hints);
    
    end_test (state);    
}

/* ------------------------------------------------------------------------ */

void test_kim_selection_hints_set_service_realm_hint (kim_test_state_t state)
{
    kim_error err = NULL;
    kim_selection_hints hints = NULL;
    kim_string string = NULL;
    kim_comparison comparison = 0;
    
    start_test (state, "kim_selection_hints_set_service_realm_hint");
    
    if (!err) {
        err = kim_selection_hints_create (&hints, KSH_TEST_ID);
        fail_if_error (state, "kim_selection_hints_create", err, 
                       "while creating selection hints for %s", KSH_TEST_ID);
    }
    
    if (!err) {
        err = kim_selection_hints_set_service_realm_hint (hints, KSH_SERVICE_REALM);
        fail_if_error (state, "kim_selection_hints_set_service_realm_hint", 
                       err, "while setting service realm to %s", 
                       KSH_SERVICE_REALM);
    }
    
    if (!err) {
        err = kim_selection_hints_get_service_realm_hint (hints, &string);
        fail_if_error (state, "kim_selection_hints_get_service_realm_hint", 
                       err, "while getting the service realm hint %s", 
                       KSH_SERVICE_REALM);
    }
    
    if (!err) {
        err = kim_string_compare (KSH_SERVICE_REALM, string, &comparison);
        fail_if_error (state, "kim_identity_compare", err, 
                       "while comparing %s to the service realm hint %s", 
                       KSH_SERVICE_REALM, string ? string : "NULL");
    }
    
    if (!err && !kim_comparison_is_equal_to (comparison)) {
        log_failure (state, "Unexpected service realm hint (got %s, expected %s)", 
                     string ? string : "NULL", KSH_SERVICE_REALM);
    }
    
    kim_string_free (&string);
    kim_selection_hints_free (&hints);
    
    end_test (state);    
}

/* ------------------------------------------------------------------------ */

void test_kim_selection_hints_set_service_hint (kim_test_state_t state)
{
    kim_error err = NULL;
    kim_selection_hints hints = NULL;
    kim_string string = NULL;
    kim_comparison comparison = 0;
    
    start_test (state, "kim_selection_hints_set_service_hint");
    
    if (!err) {
        err = kim_selection_hints_create (&hints, KSH_TEST_ID);
        fail_if_error (state, "kim_selection_hints_create", err, 
                       "while creating selection hints for %s", KSH_TEST_ID);
    }
    
    if (!err) {
        err = kim_selection_hints_set_service_hint (hints, KSH_SERVICE);
        fail_if_error (state, "kim_selection_hints_set_service_hint", 
                       err, "while setting service hint to %s", 
                       KSH_SERVICE);
    }
    
    if (!err) {
        err = kim_selection_hints_get_service_hint (hints, &string);
        fail_if_error (state, "kim_selection_hints_get_service_hint", 
                       err, "while getting the service hint %s", 
                       KSH_SERVICE);
    }
    
    if (!err) {
        err = kim_string_compare (KSH_SERVICE, string, &comparison);
        fail_if_error (state, "kim_identity_compare", err, 
                       "while comparing %s to the service hint %s", 
                       KSH_SERVICE, string ? string : "NULL");
    }
    
    if (!err && !kim_comparison_is_equal_to (comparison)) {
        log_failure (state, "Unexpected service hint (got %s, expected %s)", 
                     string ? string : "NULL", KSH_SERVICE);
    }
    
    kim_string_free (&string);
    kim_selection_hints_free (&hints);
    
    end_test (state);    
}

/* ------------------------------------------------------------------------ */

void test_kim_selection_hints_set_server_hint (kim_test_state_t state)
{
    kim_error err = NULL;
    kim_selection_hints hints = NULL;
    kim_string string = NULL;
    kim_comparison comparison = 0;
    
    start_test (state, "kim_selection_hints_set_server_hint");
    
    if (!err) {
        err = kim_selection_hints_create (&hints, KSH_TEST_ID);
        fail_if_error (state, "kim_selection_hints_create", err, 
                       "while creating selection hints for %s", KSH_TEST_ID);
    }
    
    if (!err) {
        err = kim_selection_hints_set_server_hint (hints, KSH_SERVER);
        fail_if_error (state, "kim_selection_hints_set_server_hint", 
                       err, "while setting server hint to %s", 
                       KSH_SERVER);
    }
    
    if (!err) {
        err = kim_selection_hints_get_server_hint (hints, &string);
        fail_if_error (state, "kim_selection_hints_get_server_hint", 
                       err, "while getting the server hint %s", 
                       KSH_SERVER);
    }
    
    if (!err) {
        err = kim_string_compare (KSH_SERVER, string, &comparison);
        fail_if_error (state, "kim_identity_compare", err, 
                       "while comparing %s to the server hint %s", 
                       KSH_SERVER, string ? string : "NULL");
    }
    
    if (!err && !kim_comparison_is_equal_to (comparison)) {
        log_failure (state, "Unexpected server hint (got %s, expected %s)", 
                     string ? string : "NULL", KSH_SERVER);
    }
    
    kim_string_free (&string);
    kim_selection_hints_free (&hints);
    
    end_test (state);    
}

/* ------------------------------------------------------------------------ */

void test_kim_selection_hints_remember_identity (kim_test_state_t state)
{
    kim_error err = NULL;
    kim_selection_hints hints = NULL;
    kim_identity service_identity = NULL;
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
    
    if (!err) {
        err = kim_identity_create_from_string (&service_identity, 
                                               KSH_SERVICE_IDENTITY);
        fail_if_error (state, "kim_identity_create_from_string", err, 
                       "while creating an identity for %s", 
                       KSH_SERVICE_IDENTITY);
    }
    
    if (!err) {
        err = kim_identity_create_from_string (&client_identity, 
                                               KSH_IDENTITY);
        fail_if_error (state, "kim_identity_create_from_string", err, 
                       "while creating an identity for %s", 
                       KSH_IDENTITY);
    }
    
    if (!err) {
        err = kim_selection_hints_set_service_identity_hint (hints, service_identity);
        fail_if_error (state, "kim_selection_hints_set_service_identity_hint", 
                       err, "while setting service identity to %s", 
                       KSH_SERVICE_IDENTITY);
    }
    
    if (!err) {
        err = kim_selection_hints_set_client_realm_hint (hints, KSH_CLIENT_REALM);
        fail_if_error (state, "kim_selection_hints_set_client_realm_hint", 
                       err, "while setting client realm to %s", 
                       KSH_CLIENT_REALM);
    }
    
    if (!err) {
        err = kim_selection_hints_set_user_hint (hints, KSH_USER);
        fail_if_error (state, "kim_selection_hints_set_user_hint", 
                       err, "while setting user to %s", 
                       KSH_USER);
    }
    
    if (!err) {
        err = kim_selection_hints_set_service_realm_hint (hints, KSH_SERVICE_REALM);
        fail_if_error (state, "kim_selection_hints_set_service_realm_hint", 
                       err, "while setting service realm to %s", 
                       KSH_SERVICE_REALM);
    }
    
    if (!err) {
        err = kim_selection_hints_set_service_hint (hints, KSH_SERVICE);
        fail_if_error (state, "kim_selection_hints_set_service_hint", 
                       err, "while setting service to %s", 
                       KSH_SERVICE);
    }
    
    if (!err) {
        err = kim_selection_hints_set_server_hint (hints, KSH_SERVER);
        fail_if_error (state, "kim_selection_hints_set_server_hint", 
                       err, "while setting server to %s", 
                       KSH_SERVER);
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
    kim_identity_free (&service_identity);
    kim_selection_hints_free (&hints);
    
    end_test (state);
}

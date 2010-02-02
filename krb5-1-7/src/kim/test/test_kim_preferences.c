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

#define TEST_LIFETIME 7777

void print_favorites(kim_test_state_t state);
kim_boolean favorites_contains_identity(kim_test_state_t state, kim_identity identity);

/* ------------------------------------------------------------------------ */

void print_favorites(kim_test_state_t state)
{
    kim_error err = KIM_NO_ERROR;
    kim_preferences prefs = NULL;
    kim_count count, j;
    kim_string string;
    
    err = kim_preferences_create (&prefs);
    fail_if_error (state, "kim_preferences_create", err, 
                   "while creating preferences");
    
    if (!err) {
        err = kim_preferences_get_number_of_favorite_identities (prefs, &count);
        fail_if_error (state, "kim_preferences_get_number_of_favorite_identities", err, 
                       "while getting number of favorite identities");
        printf("%qu favorites...\n", count);
    }
    
    
    for (j = 0; j < count; j++) {
        kim_identity compare_identity = NULL;
        kim_options compare_options = NULL;
        err = kim_preferences_get_favorite_identity_at_index (prefs, j, 
                                                              &compare_identity, 
                                                              &compare_options);
        fail_if_error (state, "kim_preferences_get_favorite_identity_at_index", err, 
                       "while getting favorite identity %d", (int) j);
        
        if (!err)
        {
            kim_identity_get_display_string(compare_identity, &string);
            printf("  %2qu: %s\n", j, string);
        }
        
        kim_identity_free (&compare_identity);
        kim_options_free (&compare_options);
    }
    
    kim_preferences_free (&prefs);    
}

/* ------------------------------------------------------------------------ */

kim_boolean favorites_contains_identity(kim_test_state_t state, kim_identity identity)
{
    kim_error err = KIM_NO_ERROR;
    kim_preferences prefs = NULL;
    kim_count count, j;
    kim_boolean found = 0;
    
    err = kim_preferences_create (&prefs);
    fail_if_error (state, "kim_preferences_create", err, 
                   "while creating preferences");
    
    if (!err) {
        err = kim_preferences_get_number_of_favorite_identities (prefs, &count);
        fail_if_error (state, "kim_preferences_get_number_of_favorite_identities", err, 
                       "while getting number of favorite identities");
    }
    
    for (j = 0; j < count; j++) {
        kim_identity compare_identity = NULL;
        kim_options compare_options = NULL;
        kim_comparison comparison = 0;
        
        err = kim_preferences_get_favorite_identity_at_index (prefs, j, 
                                                              &compare_identity, 
                                                              &compare_options);
        fail_if_error (state, "kim_preferences_get_favorite_identity_at_index", err, 
                       "while getting favorite identity %d", (int) j);
        
        if (!err) {
            kim_string display_string = NULL;
            err = kim_identity_compare (identity, compare_identity, 
                                        &comparison);
            if (err) {
                kim_identity_get_display_string(identity, &display_string);
                fail_if_error (state, "kim_identity_compare", err, 
                               "while comparing %s to favorite identity %d", 
                               display_string, (int) j);
            }
        }
        
        if (!err && kim_comparison_is_equal_to (comparison)) {
            found = 1;
        }
        
        kim_identity_free (&compare_identity);
        kim_options_free (&compare_options);
    }
    
    kim_preferences_free (&prefs);
    
    return found;
}

/* ------------------------------------------------------------------------ */

void test_kim_preferences_create (kim_test_state_t state)
{
    
    start_test (state, "kim_preferences_create");

    {
        kim_error err = KIM_NO_ERROR;
        kim_preferences prefs = NULL;

        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
        
        kim_preferences_free (&prefs);
    }
    
    end_test (state);
}

/* ------------------------------------------------------------------------ */

void test_kim_preferences_copy (kim_test_state_t state)
{
    
    start_test (state, "test_kim_preferences_copy");
    
    {
        kim_error err = KIM_NO_ERROR;
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
    }
    
    end_test (state);
}

/* ------------------------------------------------------------------------ */

void test_kim_preferences_set_options (kim_test_state_t state)
{
    kim_error err = KIM_NO_ERROR;
    
    start_test (state, "kim_preferences_set_options");
    
    if (!err) {
        kim_preferences prefs = NULL;
        kim_options options = NULL;
        
        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
        
        if (!err) {
            err = kim_preferences_get_options (prefs, &options);
            fail_if_error (state, "kim_preferences_get_options", err, 
                           "while getting old options");
        }
        
        if (!err) {
            err = kim_options_set_lifetime (options, TEST_LIFETIME);
            fail_if_error (state, "kim_options_set_lifetime", err, 
                           "while setting the lifetime to %d", TEST_LIFETIME);            
        }
        
        if (!err) {
            err = kim_preferences_set_options (prefs, options);
            fail_if_error (state, "kim_preferences_set_options", err, 
                           "while setting the new options");
        }
        
        if (!err) {
            err = kim_preferences_synchronize (prefs);
            fail_if_error (state, "kim_preferences_synchronize", err, 
                           "while setting the identity to KIM_IDENTITY_ANY");
        }
        
        kim_options_free (&options);
        kim_preferences_free (&prefs);
    }
    
    if (!err) {
        kim_preferences prefs = NULL;
        kim_options verify_options = NULL;
        kim_lifetime lifetime = 0;
       
        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
        
        
        if (!err) {
            err = kim_preferences_get_options (prefs, &verify_options);
            fail_if_error (state, "kim_preferences_get_options", err, 
                           "while getting options for verification");
        }
        
        if (!err) {
            err = kim_options_get_lifetime (verify_options, &lifetime);
            fail_if_error (state, "kim_options_get_data", err, 
                           "while getting the custom data of the verify options");            
        }
        
        if (!err && lifetime != TEST_LIFETIME) {
            log_failure (state, "Unexpected lifetime in options (got %d, expected %d)", 
                         (int) lifetime, TEST_LIFETIME);
        }
 
        kim_options_free (&verify_options);
        kim_preferences_free (&prefs);
    }
    
    end_test (state);
}

/* ------------------------------------------------------------------------ */

void test_kim_preferences_set_remember_options (kim_test_state_t state)
{
    
    kim_error err = KIM_NO_ERROR;
   
    start_test (state, "kim_preferences_set_remember_options");
    
    if (!err) {
        kim_preferences prefs = NULL;
        
        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
        
        if (!err) {
            err = kim_preferences_set_remember_options (prefs, TRUE);
            fail_if_error (state, "kim_preferences_set_remember_options", err, 
                           "while setting the preference to remember options");
        }
        
        if (!err) {
            err = kim_preferences_synchronize (prefs);
            fail_if_error (state, "kim_preferences_synchronize", err, 
                           "while setting the identity to KIM_IDENTITY_ANY");
        }
        
        kim_preferences_free (&prefs);
    }
    
    if (!err) {
        kim_preferences prefs = NULL;
        kim_boolean remember_options = TRUE;
        
        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
        
        if (!err) {
            err = kim_preferences_get_remember_options (prefs, &remember_options);
            fail_if_error (state, "kim_preferences_get_remember_options", err, 
                           "while getting the preference to remember options");
        }
        
        if (!err && !remember_options) {
            log_failure (state, "Unexpected remember options preference (got %d, expected TRUE)", 
                         remember_options);
        }
        
        kim_preferences_free (&prefs);
    }
    
    if (!err) {
        kim_preferences prefs = NULL;
        
        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
                
        if (!err) {
            err = kim_preferences_set_remember_options (prefs, FALSE);
            fail_if_error (state, "kim_preferences_set_remember_options", err, 
                           "while setting the preference to remember options");
        }
        
        if (!err) {
            err = kim_preferences_synchronize (prefs);
            fail_if_error (state, "kim_preferences_synchronize", err, 
                           "while setting the identity to KIM_IDENTITY_ANY");
        }
        
        kim_preferences_free (&prefs);
    }
    
    if (!err) {
        kim_preferences prefs = NULL;
        kim_boolean remember_options = FALSE;
        
        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
        
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
    }
    
    end_test (state);
}

/* ------------------------------------------------------------------------ */

void test_kim_preferences_set_client_identity (kim_test_state_t state)
{
    
    kim_error err = KIM_NO_ERROR;
    kim_string test_string = "user@EXAMPLE.COM";
    kim_identity test_identity = KIM_IDENTITY_ANY;
    kim_identity identity = KIM_IDENTITY_ANY;
    kim_comparison comparison = 0;
    
    start_test (state, "kim_preferences_set_client_identity");
    
    
    if (!err) {
        err = kim_identity_create_from_string (&test_identity, test_string);
        fail_if_error (state, "kim_identity_create_from_string", err, 
                       "while creating the identity for %s", test_string);
    }
    
    if (!err) {
        kim_preferences prefs = NULL;

        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
        
        if (!err) {
            err = kim_preferences_set_client_identity (prefs, KIM_IDENTITY_ANY);
            fail_if_error (state, "kim_preferences_set_client_identity", err, 
                           "while setting the identity to KIM_IDENTITY_ANY");
        }
        
        if (!err) {
            err = kim_preferences_synchronize (prefs);
            fail_if_error (state, "kim_preferences_synchronize", err, 
                           "while setting the identity to KIM_IDENTITY_ANY");
        }
    
        kim_preferences_free (&prefs);
    }
    
    if (!err) {
        kim_preferences prefs = NULL;

        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
        
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
        
        kim_preferences_free (&prefs);
    }
    
    if (!err) {
        kim_preferences prefs = NULL;

        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
        
        if (!err) {
            err = kim_preferences_set_client_identity (prefs, test_identity);
            fail_if_error (state, "kim_preferences_set_client_identity", err, 
                           "while setting the identity to %s", test_string);
        }
        
        if (!err) {
            err = kim_preferences_synchronize (prefs);
            fail_if_error (state, "kim_preferences_synchronize", err, 
                           "while setting the identity to KIM_IDENTITY_ANY");
        }
        
        kim_preferences_free (&prefs);
    }
    
    
    if (!err) {
        kim_preferences prefs = NULL;
        kim_string string = NULL;

        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
        
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
        kim_preferences_free (&prefs);
    }
    
    kim_identity_free (&identity);
    kim_identity_free (&test_identity);

    end_test (state);
}


struct favorite_identity {
    kim_string identity;
    kim_lifetime lifetime;
    kim_lifetime renewal_lifetime;
};

struct favorite_identity fids[] = {
{ "bob@EXAMPLE.COM", 7777, 8888 },
{ "alice@UNIVERSITY.EDU", 12345, 54321 },
{ "bob@COMPANY.COM", 5555, 6666 },
{ "alice/admin@EXAMPLE.COM", 2222, 3333 },
{ NULL, 0, 0 }
};

/* ------------------------------------------------------------------------ */

void test_kim_preferences_add_favorite_identity (kim_test_state_t state)
{
    kim_error err = KIM_NO_ERROR;
    
    start_test (state, "kim_preferences_add_favorite_identity");
    
    if (!err) {
        kim_preferences prefs = NULL;
        kim_options options = NULL;
        kim_count i;
        
        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
        
        if (!err) {
            err = kim_preferences_remove_all_favorite_identities (prefs);
            fail_if_error (state, "kim_preferences_remove_all_favorite_identities", err, 
                           "while removing all favorite identities");
        }
        
        if (!err) {
            err = kim_options_create (&options);
            fail_if_error (state, "kim_options_create", err, 
                           "while creating options");
        }        
        
        for (i = 0; !err && fids[i].identity; i++) {
            kim_identity identity = NULL;
            
            err = kim_identity_create_from_string (&identity, fids[i].identity);
            fail_if_error (state, "kim_identity_create_from_string", err, 
                           "while creating the identity for %s", 
                           fids[i].identity);
            
            if (!err) {
                err = kim_options_set_lifetime (options, fids[i].lifetime);
                fail_if_error (state, "kim_options_set_lifetime", err, 
                               "while setting the lifetime to %d", 
                               (int) fids[i].lifetime);            
            }
 
            if (!err) {
                err = kim_options_set_renewal_lifetime (options, fids[i].renewal_lifetime);
                fail_if_error (state, "kim_options_set_renewal_lifetime", err, 
                               "while setting the renewal lifetime to %d", 
                               (int) fids[i].renewal_lifetime);            
            }
            
            if (!err) {
                err = kim_preferences_add_favorite_identity (prefs, identity, options);
                fail_if_error (state, "kim_preferences_add_favorite_identity", err, 
                               "while adding %s to the favorite identities", 
                               fids[i].identity);            
            }
            
            kim_identity_free (&identity);
        }
        
        if (!err) {
            err = kim_preferences_synchronize (prefs);
            fail_if_error (state, "kim_preferences_synchronize", err, 
                           "while setting the favorite identities");
        }
        
        kim_options_free (&options);
        kim_preferences_free (&prefs);
    }
    
    if (!err) {
        kim_preferences prefs = NULL;
        kim_count count, i;
        
        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
        
        if (!err) {
            err = kim_preferences_get_number_of_favorite_identities (prefs, &count);
            fail_if_error (state, "kim_preferences_get_number_of_favorite_identities", err, 
                           "while getting number of favorite identities");
        }
        
        
        for (i = 0; !err && fids[i].identity; i++) {
            kim_identity identity = NULL;
            kim_count j;
            kim_boolean found = 0;
            
            err = kim_identity_create_from_string (&identity, fids[i].identity);
            fail_if_error (state, "kim_identity_create_from_string", err, 
                           "while creating the identity for %s", 
                           fids[i].identity);

            for (j = 0; j < count; j++) {
                kim_identity compare_identity = NULL;
                kim_options compare_options = NULL;
                kim_comparison comparison;

                err = kim_preferences_get_favorite_identity_at_index (prefs, j, 
                                                                      &compare_identity, 
                                                                      &compare_options);
                fail_if_error (state, "kim_preferences_get_favorite_identity_at_index", err, 
                               "while getting favorite identity %d", (int) j);
            
                if (!err) {
                    err = kim_identity_compare (identity, compare_identity, 
                                                &comparison);
                    fail_if_error (state, "kim_identity_compare", err, 
                                   "while comparing %s to favorite identity %d", 
                                   fids[i].identity, (int) i);
                }
                
                if (!err && kim_comparison_is_equal_to (comparison)) {
                    kim_lifetime compare_lifetime;
                    kim_lifetime compare_renewal_lifetime;
                   
                    found = 1;
                    
                    err = kim_options_get_lifetime (compare_options, &compare_lifetime);
                    fail_if_error (state, "kim_options_get_lifetime", err, 
                                   "while getting the lifetime for %s", 
                                   fids[i].identity);            
                    
                    if (!err && fids[i].lifetime != compare_lifetime) {
                        log_failure (state, "Unexpected lifetime for %s (got %d, expected %d)", 
                                     fids[i].identity, (int) compare_lifetime,
                                     (int) fids[i].lifetime);                
                    }
                    
                    if (!err) {
                        err = kim_options_get_renewal_lifetime (compare_options, 
                                                                &compare_renewal_lifetime);
                        fail_if_error (state, "kim_options_get_renewal_lifetime", err, 
                                       "while getting the lifetime for %s", 
                                       fids[i].identity);            
                    }
                    
                    if (!err && fids[i].renewal_lifetime != compare_renewal_lifetime) {
                        log_failure (state, "Unexpected renewal lifetime for %s (got %d, expected %d)", 
                                     fids[i].identity, 
                                     (int) compare_renewal_lifetime,
                                     (int) fids[i].renewal_lifetime);                
                    }
                }
                
                kim_identity_free (&compare_identity);
                kim_options_free (&compare_options);
            }
                
            if (!err && !found) {
                log_failure (state, "Favorite identity %s not found in favorite identities list", 
                             fids[i].identity);
            }
            
            kim_identity_free (&identity);
        }
        
        if (!err && i != count) {
            log_failure (state, "Unexpected number of favorite identities (got %d, expected %d)", 
                         (int) count, (int) i);
        }
        
        kim_preferences_free (&prefs);
    }
    
    end_test (state);
}

/* ------------------------------------------------------------------------ */

void test_kim_preferences_remove_favorite_identity (kim_test_state_t state)
{
    kim_error err = KIM_NO_ERROR;
    
    start_test (state, "kim_preferences_remove_favorite_identity");
    /*
     * 1. Remove all favorites to start with a clean slate
     * 2. Add some favorites
     * 3. Verify added favorites
     * 4. Remove those favorites one by one, checking each time to make sure they were removed
     */
    
    // Remove old and add new
    if (!err) {
        kim_preferences prefs = NULL;
        kim_options options = NULL;
        kim_count i;
        
        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
        
        if (!err) {
            err = kim_preferences_remove_all_favorite_identities (prefs);
            fail_if_error (state, "kim_preferences_remove_all_favorite_identities", err, 
                           "while removing all favorite identities");
        }
        
        if (!err) {
            err = kim_preferences_get_number_of_favorite_identities (prefs, &i);
            fail_if_error (state, "kim_preferences_get_number_of_favorite_identities", err, 
                           "while getting number of favorite identities after clearing");
        }        
        
        if (!err) {
            err = kim_options_create (&options);
            fail_if_error (state, "kim_options_create", err, 
                           "while creating options");
        }        
        
        for (i = 0; !err && fids[i].identity; i++) {
            kim_identity identity = NULL;
            
            err = kim_identity_create_from_string (&identity, fids[i].identity);
            fail_if_error (state, "kim_identity_create_from_string", err, 
                           "while creating the identity for %s", 
                           fids[i].identity);
            
            if (!err) {
                err = kim_options_set_lifetime (options, fids[i].lifetime);
                fail_if_error (state, "kim_options_set_lifetime", err, 
                               "while setting the lifetime to %d", 
                               (int) fids[i].lifetime);            
            }
            
            if (!err) {
                err = kim_options_set_renewal_lifetime (options, fids[i].renewal_lifetime);
                fail_if_error (state, "kim_options_set_renewal_lifetime", err, 
                               "while setting the renewal lifetime to %d", 
                               (int) fids[i].renewal_lifetime);            
            }
            
            if (!err) {
                err = kim_preferences_add_favorite_identity (prefs, identity, options);
                fail_if_error (state, "kim_preferences_add_favorite_identity", err, 
                               "while adding %s to the favorite identities", 
                               fids[i].identity);            
            }
            
            kim_identity_free (&identity);
        }
        
        if (!err) {
            err = kim_preferences_synchronize (prefs);
            fail_if_error (state, "kim_preferences_synchronize", err, 
                           "while setting the favorite identities");
        }
        
        kim_options_free (&options);
        kim_preferences_free (&prefs);
    }
    
    // Verify add
    if (!err) {
        kim_preferences prefs = NULL;
        kim_count count, i;
        
        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
        
        if (!err) {
            err = kim_preferences_get_number_of_favorite_identities (prefs, &count);
            fail_if_error (state, "kim_preferences_get_number_of_favorite_identities", err, 
                           "while getting number of favorite identities");
        }
        
        
        for (i = 0; !err && fids[i].identity; i++) {
            kim_identity identity = NULL;
            kim_count j;
            kim_boolean found = 0;
            
            err = kim_identity_create_from_string (&identity, fids[i].identity);
            fail_if_error (state, "kim_identity_create_from_string", err, 
                           "while creating the identity for %s", 
                           fids[i].identity);
            
            for (j = 0; j < count; j++) {
                kim_identity compare_identity = NULL;
                kim_options compare_options = NULL;
                kim_comparison comparison;
                
                err = kim_preferences_get_favorite_identity_at_index (prefs, j, 
                                                                      &compare_identity, 
                                                                      &compare_options);
                fail_if_error (state, "kim_preferences_get_favorite_identity_at_index", err, 
                               "while getting favorite identity %d", (int) j);
                
                if (!err) {
                    err = kim_identity_compare (identity, compare_identity, 
                                                &comparison);
                    fail_if_error (state, "kim_identity_compare", err, 
                                   "while comparing %s to favorite identity %d", 
                                   fids[i].identity, (int) i);
                }
                
                if (!err && kim_comparison_is_equal_to (comparison)) {
                    kim_lifetime compare_lifetime;
                    kim_lifetime compare_renewal_lifetime;
                    
                    found = 1;
                    
                    err = kim_options_get_lifetime (compare_options, &compare_lifetime);
                    fail_if_error (state, "kim_options_get_lifetime", err, 
                                   "while getting the lifetime for %s", 
                                   fids[i].identity);            
                    
                    if (!err && fids[i].lifetime != compare_lifetime) {
                        log_failure (state, "Unexpected lifetime for %s (got %d, expected %d)", 
                                     fids[i].identity, (int) compare_lifetime,
                                     (int) fids[i].lifetime);                
                    }
                    
                    if (!err) {
                        err = kim_options_get_renewal_lifetime (compare_options, 
                                                                &compare_renewal_lifetime);
                        fail_if_error (state, "kim_options_get_renewal_lifetime", err, 
                                       "while getting the lifetime for %s", 
                                       fids[i].identity);            
                    }
                    
                    if (!err && fids[i].renewal_lifetime != compare_renewal_lifetime) {
                        log_failure (state, "Unexpected renewal lifetime for %s (got %d, expected %d)", 
                                     fids[i].identity, 
                                     (int) compare_renewal_lifetime,
                                     (int) fids[i].renewal_lifetime);                
                    }
                }
                
                kim_identity_free (&compare_identity);
                kim_options_free (&compare_options);
            }
            
            if (!err && !found) {
                log_failure (state, "Favorite identity %s not found in favorite identities list", 
                             fids[i].identity);
            }
            
            kim_identity_free (&identity);
        }
        
        if (!err && i != count) {
            log_failure (state, "Unexpected number of favorite identities (got %d, expected %d)", 
                         (int) count, (int) i);
        }
        
        kim_preferences_free (&prefs);
    }
    
    // Remove one by one
    if (!err) {
        kim_preferences prefs = NULL;
        kim_count count, j;
        
        err = kim_preferences_create (&prefs);
        fail_if_error (state, "kim_preferences_create", err, 
                       "while creating preferences");
        
        if (!err) {
            err = kim_preferences_get_number_of_favorite_identities (prefs, &count);
            fail_if_error (state, "kim_preferences_get_number_of_favorite_identities", err, 
                           "while getting number of favorite identities");
        }
        
        for (j = 0; j < count; j++) {
            kim_identity compare_identity = NULL;
            kim_options compare_options = NULL;
            kim_string string = NULL;
            
            err = kim_preferences_get_favorite_identity_at_index (prefs, 0, 
                                                                  &compare_identity, 
                                                                  &compare_options);
            fail_if_error (state, "kim_preferences_get_favorite_identity_at_index", err, 
                           "while getting favorite identity %d", (int) j);
            
            if (!err) {
                err = kim_identity_get_display_string(compare_identity, &string);
                fail_if_error (state, "kim_identity_get_display_string", err, 
                               "while getting the display string for identity %d", (int) j);
            }
            
            if (!err) {
                err = kim_preferences_remove_favorite_identity(prefs, compare_identity);
                fail_if_error (state, "kim_preferences_remove_favorite_identity", err, 
                               "while removing favorite identity %d \"%s\"", (int) j, string);
            }

            if (!err) {
                err = kim_preferences_synchronize (prefs);
                fail_if_error (state, "kim_preferences_synchronize", err, 
                               "while removing favorite %qu: %s", j, string);
            }
            
            if (!err && favorites_contains_identity(state, compare_identity)) {
                kim_string display_string = NULL;
                kim_identity_get_display_string(compare_identity, &display_string);
                log_failure (state, "Favorite identities still contains %s after removal", 
                             display_string);
            }
            
            kim_string_free (&string);
            kim_identity_free (&compare_identity);
            kim_options_free (&compare_options);
        }
        
        kim_preferences_free (&prefs);
    }
    
    end_test (state);
}

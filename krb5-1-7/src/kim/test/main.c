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

#include "test_kim_identity.h"
#include "test_kim_preferences.h"
#include "test_kim_selection_hints.h"

int main (int argc, const char * argv[]) 
{
    kim_test_state_t state = NULL;
    
    if (test_init (&state)) {
        return 1;
    }
    
    test_kim_identity_create_from_krb5_principal (state);

    test_kim_identity_create_from_string (state);
    
    test_kim_identity_create_from_components (state);
    
    test_kim_identity_copy (state);
    
    test_kim_identity_compare (state);
    
    test_kim_identity_get_display_string (state);
    
    test_kim_identity_get_realm (state);
    
    test_kim_identity_get_number_of_components (state);
    
    test_kim_identity_get_component_at_index (state);
 
    test_kim_identity_get_krb5_principal (state);
    
    test_kim_preferences_create (state);
    
    test_kim_preferences_copy (state);
    
    test_kim_preferences_set_options (state);
    
    test_kim_preferences_set_remember_options (state);
    
    test_kim_preferences_set_client_identity (state);
    
    test_kim_selection_hints_set_hint (state);
    
    test_kim_selection_hints_remember_identity (state);
    
    test_kim_preferences_add_favorite_identity (state);
    
    test_kim_preferences_remove_favorite_identity(state);
    
    return test_cleanup (state);
}

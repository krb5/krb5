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

#define KIM_SELECTION_HINTS_FILE CFSTR("edu.mit.Kerberos.SelectionHints")

#define KIM_SELECTION_HINTS_ARRAY CFSTR("Hints")

#define KIM_SERVICE_IDENTITY_HINT CFSTR("KIMServiceIdentityHint")
#define KIM_APPLICATION_ID_HINT   CFSTR("KIMApplicationIDHint")
#define KIM_USER_HINT             CFSTR("KIMUserHint")
#define KIM_CLIENT_REALM_HINT     CFSTR("KIMClientRealmHint")
#define KIM_SERVICE_HINT          CFSTR("KIMServiceHint")
#define KIM_SERVICE_REALM_HINT    CFSTR("KIMServiceRealmHint")
#define KIM_SERVER_HINT           CFSTR("KIMServerHint")
#define KIM_IDENTITY_HINT         CFSTR("KIMIdentityHint")

#define KIM_MAX_HINTS 8 /* the number of hint types above */

#include "kim_os_private.h"

#pragma mark -

/* ------------------------------------------------------------------------ */

static kim_error kim_os_selection_hints_get_selection_hints_array (CFArrayRef *out_selection_hints_array)
{
    kim_error err = KIM_NO_ERROR;
    CFPropertyListRef value = NULL;
    CFStringRef users[] = { kCFPreferencesCurrentUser, kCFPreferencesAnyUser, NULL };
    CFStringRef hosts[] = { kCFPreferencesCurrentHost, kCFPreferencesAnyHost, NULL };
    
    if (!err && !out_selection_hints_array) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        kim_count u, h;
        
        if (!kim_library_allow_home_directory_access()) {
            users[0] = kCFPreferencesAnyUser;
            users[1] = NULL;
        }
        
        for (u = 0; !value && users[u]; u++) {
            for (h = 0; !value && hosts[h]; h++) {
                value = CFPreferencesCopyValue (KIM_SELECTION_HINTS_ARRAY, 
                                                KIM_SELECTION_HINTS_FILE, 
                                                users[u], hosts[h]);
            }
        }        
        
        if (value && CFGetTypeID (value) != CFArrayGetTypeID ()) {
            err = check_error (KIM_PREFERENCES_READ_ERR);
        }
    }
    
    if (!err) {
        *out_selection_hints_array = value;
        value = NULL;
    }
    
    if (value) { CFRelease (value); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

static kim_error kim_os_selection_hints_set_selection_hints_array (CFArrayRef in_selection_hints_array)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_selection_hints_array) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        kim_boolean homedir_ok = kim_library_allow_home_directory_access();
        CFStringRef user = homedir_ok ? kCFPreferencesCurrentUser : kCFPreferencesAnyUser;
        CFStringRef host = homedir_ok ? kCFPreferencesAnyHost : kCFPreferencesCurrentHost;
        
        CFPreferencesSetValue (KIM_SELECTION_HINTS_ARRAY, in_selection_hints_array, 
                               KIM_SELECTION_HINTS_FILE, user, host);
        if (!CFPreferencesSynchronize (KIM_SELECTION_HINTS_FILE, user, host)) {
            err = check_error (KIM_PREFERENCES_WRITE_ERR);
        }
    }
    
    return check_error (err);
}

#pragma mark -

/* ------------------------------------------------------------------------ */

static kim_error kim_os_selection_hints_create_dictionary (kim_selection_hints  in_selection_hints,
                                                           kim_identity         in_identity,
                                                           CFDictionaryRef     *out_hints_dictionary)
{
    kim_error err = KIM_NO_ERROR;
    kim_selection_hints_preference_strings preference_strings = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };
    kim_string identity_string = NULL;
    CFStringRef keys[KIM_MAX_HINTS] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
    CFStringRef values[KIM_MAX_HINTS] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
    CFIndex i = 0;
    
    if (!err && !in_selection_hints  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_identity         ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_hints_dictionary) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_selection_hints_get_preference_strings (in_selection_hints, &preference_strings);
    }
    
    if (!err) {
        err = kim_identity_get_string (in_identity, &identity_string);
    }
    
    if (!err) {
        keys[i] = KIM_APPLICATION_ID_HINT;
        err = kim_os_string_get_cfstring (preference_strings.application_identifier, &values[i]);
    }
    
    if (!err) {
        keys[++i] = KIM_IDENTITY_HINT;
        err = kim_os_string_get_cfstring (identity_string, &values[i]);
    }
    
    if (!err && preference_strings.service_identity) {
        keys[++i] = KIM_SERVICE_IDENTITY_HINT;
        err = kim_os_string_get_cfstring (preference_strings.service_identity, &values[i]);
    }
    
    if (!err && preference_strings.user) {
        keys[++i] = KIM_USER_HINT;
        err = kim_os_string_get_cfstring (preference_strings.user, &values[i]);
    }
    
    if (!err && preference_strings.client_realm) {
        keys[++i] = KIM_CLIENT_REALM_HINT;
        err = kim_os_string_get_cfstring (preference_strings.client_realm, &values[i]);
    }
    
    if (!err && preference_strings.service) {
        keys[++i] = KIM_SERVICE_HINT;
        err = kim_os_string_get_cfstring (preference_strings.service, &values[i]);
    }
    
    if (!err && preference_strings.service_realm) {
        keys[++i] = KIM_SERVICE_REALM_HINT;
        err = kim_os_string_get_cfstring (preference_strings.service_realm, &values[i]);
    }
    
    if (!err && preference_strings.server) {
        keys[++i] = KIM_SERVER_HINT;
        err = kim_os_string_get_cfstring (preference_strings.server, &values[i]);
    }
    
    if (!err) {
        *out_hints_dictionary = CFDictionaryCreate (kCFAllocatorDefault, 
                                                    (const void **) keys, 
                                                    (const void **) values, 
                                                    i+1, /* number of hints */
                                                    &kCFTypeDictionaryKeyCallBacks, 
                                                    &kCFTypeDictionaryValueCallBacks); 
    }
    
    for (i = 0; i < KIM_MAX_HINTS; i++) { if (values[i]) { CFRelease (values[i]); } }
    kim_string_free (&identity_string);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

static kim_boolean kim_os_selection_hints_compare_hint (kim_string  in_string,
                                                        CFStringRef in_value)
{
    kim_boolean equal = 0;
    
    if (!in_string && !in_value) { 
        equal = 1; 
        
    } else if (in_string && in_value) {
        if (CFGetTypeID (in_value) == CFStringGetTypeID ()) {
            kim_comparison comparison;
            
            kim_error err = kim_os_string_compare_to_cfstring (in_string, in_value, 
                                                               &comparison);
            
            if (!err && kim_comparison_is_equal_to (comparison)) {
                equal = 1;
            }
        } else {
            kim_debug_printf ("%s: Malformed string in hints dictionary.", __FUNCTION__);
        }
    }
    
    return equal;
}

/* ------------------------------------------------------------------------ */

static kim_error kim_os_selection_hints_compare_to_dictionary (kim_selection_hints  in_selection_hints,
                                                               CFDictionaryRef      in_hints_dictionary,
                                                               kim_boolean         *out_hints_equal)
{
    kim_error err = KIM_NO_ERROR;
    kim_selection_hints_preference_strings preference_strings = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };
    kim_boolean hints_equal = 1;
    
    if (!err && !in_selection_hints ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_hints_dictionary) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_hints_equal    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_selection_hints_get_preference_strings (in_selection_hints, &preference_strings);
    }
    
    if (!err && hints_equal) {
        hints_equal = kim_os_selection_hints_compare_hint (preference_strings.application_identifier, 
                                                           CFDictionaryGetValue (in_hints_dictionary, 
                                                                                 KIM_APPLICATION_ID_HINT));
    }
    
    if (!err && hints_equal) {
        hints_equal = kim_os_selection_hints_compare_hint (preference_strings.service_identity, 
                                                           CFDictionaryGetValue (in_hints_dictionary, 
                                                                                 KIM_SERVICE_IDENTITY_HINT));
    }
    
    if (!err && hints_equal) {
        hints_equal = kim_os_selection_hints_compare_hint (preference_strings.user, 
                                                           CFDictionaryGetValue (in_hints_dictionary, 
                                                                                 KIM_USER_HINT));
    }
    
    if (!err && hints_equal) {
        hints_equal = kim_os_selection_hints_compare_hint (preference_strings.client_realm, 
                                                           CFDictionaryGetValue (in_hints_dictionary, 
                                                                                 KIM_CLIENT_REALM_HINT));
    }
    
    if (!err && hints_equal) {
        hints_equal = kim_os_selection_hints_compare_hint (preference_strings.service, 
                                                           CFDictionaryGetValue (in_hints_dictionary, 
                                                                                 KIM_SERVICE_HINT));
    }
    
    if (!err && hints_equal) {
        hints_equal = kim_os_selection_hints_compare_hint (preference_strings.service_realm, 
                                                           CFDictionaryGetValue (in_hints_dictionary, 
                                                                                 KIM_SERVICE_REALM_HINT));
    }
    
    if (!err && hints_equal) {
        hints_equal = kim_os_selection_hints_compare_hint (preference_strings.server, 
                                                           CFDictionaryGetValue (in_hints_dictionary, 
                                                                                 KIM_SERVER_HINT));
    }
    
    if (!err) {
        *out_hints_equal = hints_equal;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

static kim_error kim_os_selection_hints_get_dictionary_identity (CFDictionaryRef  in_dictionary,
                                                                 kim_identity    *out_identity)
{
    kim_error err = KIM_NO_ERROR;
    CFStringRef identity_cfstr = NULL;
    kim_string identity_string = NULL;
    
    identity_cfstr = CFDictionaryGetValue (in_dictionary, KIM_IDENTITY_HINT);
    if (!identity_cfstr || CFGetTypeID (identity_cfstr) != CFStringGetTypeID ()) {
        kim_debug_printf ("%s: Malformed hints dictionary (invalid identity).", __FUNCTION__);
        err = check_error (KIM_PREFERENCES_READ_ERR);
    }
    
    if (!err) {
        err = kim_os_string_create_from_cfstring (&identity_string, identity_cfstr);
    }
    
    if (!err) {
        err = kim_identity_create_from_string (out_identity, identity_string);
    }
    
    kim_string_free (&identity_string);
    
    return check_error (err);
}

#pragma mark -

/* ------------------------------------------------------------------------ */

kim_error kim_os_selection_hints_lookup_identity (kim_selection_hints  in_selection_hints,
                                                  kim_identity        *out_identity)
{
    kim_error err = KIM_NO_ERROR;
    CFArrayRef hints_array = NULL;
    CFIndex i = 0;
    CFIndex count = 0;
    kim_boolean found = 0;
    CFDictionaryRef found_dictionary = NULL;
    
    if (!err && !in_selection_hints) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_identity      ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_os_selection_hints_get_selection_hints_array (&hints_array);
    }
    
    if (!err && hints_array) {
        count = CFArrayGetCount (hints_array);
    }
    
    for (i = 0; !err && !found && i < count; i++) {
        CFDictionaryRef dictionary = NULL;
        
        dictionary = CFArrayGetValueAtIndex (hints_array, i);
        if (!dictionary) { err = KIM_OUT_OF_MEMORY_ERR; }
        
        if (!err && CFGetTypeID (dictionary) != CFDictionaryGetTypeID ()) {
            kim_debug_printf ("%s: Malformed entry in hints array.", __FUNCTION__);
            continue; /* skip entries which aren't dictionaries */
        }
        
        if (!err) {
            err = kim_os_selection_hints_compare_to_dictionary (in_selection_hints, 
                                                                dictionary,
                                                                &found);
        }
        
        if (!err && found) {
            found_dictionary = dictionary;
        }
    }
    
    if (!err && found) {
        err = kim_os_selection_hints_get_dictionary_identity (found_dictionary,
                                                              out_identity);
    }
    
    if (hints_array) { CFRelease (hints_array); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_selection_hints_remember_identity (kim_selection_hints in_selection_hints,
                                                    kim_identity        in_identity)
{
    kim_error err = KIM_NO_ERROR;
    CFArrayRef old_hints_array = NULL;
    CFMutableArrayRef new_hints_array = NULL;
    CFIndex count = 0;
    CFIndex i = 0;
    kim_boolean hint_already_exists = 0;
    kim_boolean hints_array_changed = 0;
    
    if (!err && !in_selection_hints) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_identity       ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_os_selection_hints_get_selection_hints_array (&old_hints_array);
    }
    
    if (!err) {
        if (old_hints_array) {
            new_hints_array = CFArrayCreateMutableCopy (kCFAllocatorDefault, 0, 
                                                        old_hints_array);
        } else {
            new_hints_array = CFArrayCreateMutable (kCFAllocatorDefault, 0, 
                                                    &kCFTypeArrayCallBacks);            
        }
        if (!new_hints_array) { err = KIM_OUT_OF_MEMORY_ERR; }
    }
    
    if (!err) {
        count = CFArrayGetCount (new_hints_array);
    }
    
    for (i = 0; !err && i < count; i++) {
        CFDictionaryRef dictionary = NULL;
        kim_identity identity = NULL;
        kim_boolean hints_equal = 0;
        
        dictionary = CFArrayGetValueAtIndex (new_hints_array, i);
        if (!dictionary) { err = KIM_OUT_OF_MEMORY_ERR; }
        
        if (!err && CFGetTypeID (dictionary) != CFDictionaryGetTypeID ()) {
            kim_debug_printf ("%s: Malformed entry in hints array.", __FUNCTION__);
            continue; /* skip entries which aren't dictionaries */
        }
        
        if (!err) {
            err = kim_os_selection_hints_compare_to_dictionary (in_selection_hints, 
                                                                dictionary,
                                                                &hints_equal);
        }
        
        if (!err && hints_equal) {
            kim_comparison comparison;
            
            err = kim_os_selection_hints_get_dictionary_identity (dictionary,
                                                                  &identity);
            
            if (!err) {
                err = kim_identity_compare (in_identity, identity, &comparison);
            }
            
            if (!err) {
                if (kim_comparison_is_equal_to (comparison) && !hint_already_exists) {
                    hint_already_exists = 1;
                } else {
                    CFArrayRemoveValueAtIndex (new_hints_array, i);
                    i--; /* back up one index so we don't skip */
                    count = CFArrayGetCount (new_hints_array); /* count changed */
                    hints_array_changed = 1;
                }
            }
            
            kim_identity_free (&identity);
        }
    }
    
    if (!err && !hint_already_exists) {
        CFDictionaryRef new_hint_dictionary = NULL;
        
        err = kim_os_selection_hints_create_dictionary (in_selection_hints, 
                                                        in_identity,
                                                        &new_hint_dictionary);
        
        if (!err) {
            CFArrayInsertValueAtIndex (new_hints_array, 0, new_hint_dictionary);
            hints_array_changed = 1;
        }
        
        if (new_hint_dictionary) { CFRelease (new_hint_dictionary); }
    }
    
    if (!err && hints_array_changed) {
        err = kim_os_selection_hints_set_selection_hints_array (new_hints_array);
    }
    
    if (new_hints_array ) { CFRelease (new_hints_array); }
    if (old_hints_array ) { CFRelease (old_hints_array); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_selection_hints_forget_identity (kim_selection_hints in_selection_hints)
{
    kim_error err = KIM_NO_ERROR;
    CFArrayRef old_hints_array = NULL;
    CFMutableArrayRef new_hints_array = NULL;
    CFIndex count = 0;
    CFIndex i = 0;
    
    if (!err && !in_selection_hints) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_os_selection_hints_get_selection_hints_array (&old_hints_array);
    }
    
    if (!err) {
        new_hints_array = CFArrayCreateMutableCopy (kCFAllocatorDefault, 0, 
                                                    old_hints_array);
        if (!new_hints_array) { err = KIM_OUT_OF_MEMORY_ERR; }
    }
    
    if (!err) {
        count = CFArrayGetCount (new_hints_array);
    }
    
    for (i = 0; !err && i < count; i++) {
        CFDictionaryRef dictionary = NULL;
        kim_boolean hints_equal = 0;
        
        dictionary = CFArrayGetValueAtIndex (new_hints_array, i);
        if (!dictionary) { err = KIM_OUT_OF_MEMORY_ERR; }
        
        if (!err && CFGetTypeID (dictionary) != CFDictionaryGetTypeID ()) {
            kim_debug_printf ("%s: Malformed entry in hints array.", __FUNCTION__);
            continue; /* skip entries which aren't dictionaries */
        }
        
        if (!err) {
            err = kim_os_selection_hints_compare_to_dictionary (in_selection_hints, 
                                                                dictionary,
                                                                &hints_equal);
        }
        
        if (!err && hints_equal) {
            CFArrayRemoveValueAtIndex (new_hints_array, i);
            i--; /* back up one index so we don't skip */
            count = CFArrayGetCount (new_hints_array); /* count changed */
        }
    }
    
    if (!err) {
        err = kim_os_selection_hints_set_selection_hints_array (new_hints_array);
    }
    
    if (new_hints_array) { CFRelease (new_hints_array); }
    
    return check_error (err);
}


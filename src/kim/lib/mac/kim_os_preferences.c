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

#include <CoreFoundation/CoreFoundation.h>

#include "kim_os_private.h"

#define KIM_PREFERENCES_FILE CFSTR("edu.mit.Kerberos.IdentityManagement")
#define KLL_PREFERENCES_FILE CFSTR("edu.mit.Kerberos.KerberosLogin")

#define kim_os_preference_any_identity "KIM_IDENTITY_ANY"

/* ------------------------------------------------------------------------ */

static kim_error kim_os_preferences_cfstring_for_key (kim_preference_key in_key,
                                                      CFStringRef          *out_kim_string_key,
                                                      CFStringRef          *out_kll_string_key)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !out_kim_string_key) { err = param_error (2, "out_kim_string_key", "NULL"); }
    if (!err && !out_kll_string_key) { err = param_error (3, "out_kll_string_key", "NULL"); }
    
    if (!err) {
        if (in_key == kim_preference_key_lifetime) {
            *out_kim_string_key = CFSTR ("CredentialLifetime");
            *out_kll_string_key = CFSTR ("KLDefaultTicketLifetime");
            
        } else if (in_key == kim_preference_key_renewable) {
            *out_kim_string_key = CFSTR ("RenewableCredentials");
            *out_kll_string_key = CFSTR ("KLGetRenewableTickets");
            
        } else if (in_key == kim_preference_key_renewal_lifetime) {
            *out_kim_string_key = CFSTR ("CredentialRenewalLifetime");
            *out_kll_string_key = CFSTR ("KLDefaultRenewableLifetime");
            
        } else if (in_key == kim_preference_key_forwardable) {
            *out_kim_string_key = CFSTR ("ForwardableCredentials");
            *out_kll_string_key = CFSTR ("KLDefaultForwardableTicket");
            
        } else if (in_key == kim_preference_key_proxiable) {
            *out_kim_string_key = CFSTR ("ProxiableCredentials");
            *out_kll_string_key = CFSTR ("KLGetProxiableTickets");
            
        } else if (in_key == kim_preference_key_addressless) {
            *out_kim_string_key = CFSTR ("AddresslessCredentials");
            *out_kll_string_key = CFSTR ("KLGetAddresslessTickets");
            
        } else if (in_key == kim_preference_key_remember_options) {
            *out_kim_string_key = CFSTR ("RememberCredentialAttributes");
            *out_kll_string_key = CFSTR ("KLRememberExtras");
            
        } else if (in_key == kim_preference_key_client_identity) {
            *out_kim_string_key = CFSTR ("ClientIdentity");
            *out_kll_string_key = CFSTR ("KLName");
            
        } else if (in_key == kim_preference_key_remember_client_identity) {
            *out_kim_string_key = CFSTR ("RememberClientIdentity");
            *out_kll_string_key = CFSTR ("KLRememberPrincipal");
            
        } else if (in_key == kim_preference_key_favorite_identities) {
            *out_kim_string_key = CFSTR ("FavoriteIdentities");
            *out_kll_string_key = CFSTR ("KLFavoriteIdentities");
            
        } else if (in_key == kim_preference_key_minimum_lifetime) {
            *out_kim_string_key = CFSTR ("MinimumLifetime");
            *out_kll_string_key = CFSTR ("KLMinimumTicketLifetime");
            
        } else if (in_key == kim_preference_key_maximum_lifetime) {
            *out_kim_string_key = CFSTR ("MaximumLifetime");
            *out_kll_string_key = CFSTR ("KLMaximumTicketLifetime");
            
        } else if (in_key == kim_preference_key_minimum_renewal_lifetime) {
            *out_kim_string_key = CFSTR ("MinimumRenewalLifetime");
            *out_kll_string_key = CFSTR ("KLMinimumRenewableLifetime");
            
        } else if (in_key == kim_preference_key_maximum_renewal_lifetime) {
            *out_kim_string_key = CFSTR ("MaximumRenewalLifetime");
            *out_kll_string_key = CFSTR ("KLMaximumRenewableLifetime");
            
        } else {
            err = param_error (1, "in_key", "not in kim_preference_key_enum");
        }
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

static kim_error kim_os_preferences_get_value (kim_preference_key  in_key, 
                                               CFTypeID              in_type, 
                                               CFPropertyListRef    *out_value)
{
    
    kim_error err = KIM_NO_ERROR;
    CFPropertyListRef value = NULL;
    CFStringRef users[] = { kCFPreferencesCurrentUser, kCFPreferencesAnyUser, NULL };
    CFStringRef files[] = { KIM_PREFERENCES_FILE, KLL_PREFERENCES_FILE, NULL };
    CFStringRef hosts[] = { kCFPreferencesCurrentHost, kCFPreferencesAnyHost, NULL };
    CFStringRef keys[] = { NULL, NULL, NULL };
    
    if (!err && !out_value) { err = param_error (3, "out_value", "NULL"); }
    
    if (!err) {
        /* Index must correspond to the appropriate file */
        err = kim_os_preferences_cfstring_for_key (in_key, &keys[0], &keys[1]);
    }
    
    if (!err) {
        kim_count u, f, h;
        
        if (!kim_library_allow_home_directory_access()) {
            users[0] = kCFPreferencesAnyUser;
            users[1] = NULL;
        }
        
        for (u = 0; !value && users[u]; u++) {
            for (f = 0; !value && files[f]; f++) {
                for (h = 0; !value && hosts[h]; h++) {
                    value = CFPreferencesCopyValue (keys[f], files[f], users[u], hosts[h]);
                }
            }
        }        
        
        if (value && CFGetTypeID (value) != in_type) {
            err = kim_error_create_from_code (KIM_PREFERENCES_READ_ECODE);
        }
    }
    
    
    if (!err) {
        *out_value = value;
        value = NULL;
    }
    
    if (value) { CFRelease (value); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

static kim_error kim_os_preferences_set_value (kim_preference_key in_key, 
                                               CFPropertyListRef    in_value)
{
    kim_error err = KIM_NO_ERROR;
    CFStringRef kim_key = NULL;
    CFStringRef kll_key = NULL;
    
    if (!err && !in_value) { err = param_error (2, "in_value", "NULL"); }
    
    if (!err) {
        err = kim_os_preferences_cfstring_for_key (in_key, &kim_key, &kll_key);
    }
    
    if (!err) {
        kim_boolean homedir_ok = kim_library_allow_home_directory_access();
        CFStringRef user = homedir_ok ? kCFPreferencesCurrentUser : kCFPreferencesAnyUser;
        CFStringRef host = homedir_ok ? kCFPreferencesAnyHost : kCFPreferencesCurrentHost;
        
        CFPreferencesSetValue (kim_key, in_value, KIM_PREFERENCES_FILE, user, host);
        if (!CFPreferencesSynchronize (KIM_PREFERENCES_FILE, user, host)) {
            err = kim_error_create_from_code (KIM_PREFERENCES_WRITE_ECODE);
        }
    }
    
    return check_error (err);
}

#pragma mark -

/* ------------------------------------------------------------------------ */

kim_error kim_os_preferences_get_identity_for_key (kim_preference_key  in_key, 
                                                   kim_identity        in_hardcoded_default,
                                                   kim_identity       *out_identity)
{
    kim_error err = KIM_NO_ERROR;
    kim_string string = NULL;
    CFStringRef value = NULL;
    
    if (!err && !out_identity) { err = param_error (2, "out_identity", "NULL"); }
    
    if (!err) {
        err = kim_os_preferences_get_value (in_key, CFStringGetTypeID (), 
                                            (CFPropertyListRef *) &value);
    }
    
    if (!err) {
        if (value) {
            err = kim_os_string_create_from_cfstring (&string, value);
            
            if (!err) {
                if (!strcmp (kim_os_preference_any_identity, string)) {
                    *out_identity = KIM_IDENTITY_ANY;
                    
                } else {
                    err = kim_identity_create_from_string (out_identity, string);
                }
            }
        } else {
            err = kim_identity_copy (out_identity, in_hardcoded_default);
        }
    }
    
    kim_string_free (&string);
    if (value) { CFRelease (value); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_preferences_set_identity_for_key (kim_preference_key in_key, 
                                                   kim_identity       in_identity)
{
    kim_error err = KIM_NO_ERROR;
    CFStringRef value = NULL;
    kim_string string = NULL;
    
    /* in_identity can be KIM_IDENTITY_ANY */
    
    if (!err) {
        if (in_identity) {
            err = kim_identity_get_string (in_identity, &string);
            
        } else {
            err = kim_string_copy (&string, kim_os_preference_any_identity);
        }
    }
    
    if (!err) {
        err = kim_os_string_get_cfstring (string, &value);
    }
    
    if (!err) {
        err = kim_os_preferences_set_value (in_key, value);
    }
    
    if (value) { CFRelease (value); }
    kim_string_free (&string);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_preferences_get_favorite_identities_for_key (kim_preference_key       in_key, 
                                                              kim_favorite_identities  in_hardcoded_default,
                                                              kim_favorite_identities *out_favorite_identities)
{
    kim_error err = KIM_NO_ERROR;
    CFArrayRef value = NULL;
    
    if (!err && !out_favorite_identities) { err = param_error (2, "out_favorite_identities", "NULL"); }
    
    if (!err) {
        err = kim_os_preferences_get_value (in_key, CFArrayGetTypeID (), 
                                            (CFPropertyListRef *) &value);
    }
    
    if (!err) {
        if (!value || CFArrayGetCount (value) < 1) {
            err = kim_favorite_identities_copy (out_favorite_identities, in_hardcoded_default);
            
        } else {
            kim_favorite_identities favorite_identities = NULL;
            CFIndex count = CFArrayGetCount (value);
            CFIndex i;
            
            err = kim_favorite_identities_create (&favorite_identities);
            
            for (i = 0; !err && i < count; i++) {
                CFStringRef cfstring = NULL;
                kim_string string = NULL;
                kim_identity identity = NULL;
                
                cfstring = (CFStringRef) CFArrayGetValueAtIndex (value, i);
                if (!cfstring || CFGetTypeID (cfstring) != CFStringGetTypeID ()) {
                    err = kim_error_create_from_code (KIM_PREFERENCES_READ_ECODE);
                }
                
                if (!err) {
                    err = kim_os_string_create_from_cfstring (&string, cfstring);
                }
                
                if (!err) {
                    err = kim_identity_create_from_string (&identity, string);
                }
                
                if (!err) {
                    err = kim_favorite_identities_add_identity (favorite_identities, identity);
                }
                
                kim_identity_free (&identity);
                kim_string_free (&string);
            }
            
            if (!err) {
                *out_favorite_identities = favorite_identities;
                favorite_identities = NULL;
            }
            
            kim_favorite_identities_free (&favorite_identities);
        }
    }
    
    if (value) { CFRelease (value); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_preferences_set_favorite_identities_for_key (kim_preference_key      in_key, 
                                                              kim_favorite_identities in_favorite_identities)
{
    kim_error err = KIM_NO_ERROR;
    kim_count count = 0;
    CFMutableArrayRef value = NULL;
    
    if (!err && !in_favorite_identities) { err = param_error (2, "in_favorite_identities", "NULL"); }
    
    if (!err) {
        err = kim_favorite_identities_get_number_of_identities (in_favorite_identities, &count);
    }
    
    if (!err) {
        value = CFArrayCreateMutable (kCFAllocatorDefault, count, &kCFTypeArrayCallBacks);
        if (!value) { err = os_error (ENOMEM); }
    }
    
    if (!err) {
        kim_count i;
        
        for (i = 0; !err && i < count; i++) {
            kim_identity identity = NULL;
            kim_string string = NULL;
            CFStringRef cfstring = NULL;
            
            err = kim_favorite_identities_get_identity_at_index (in_favorite_identities, i, &identity);
            
            if (!err) {
                err = kim_identity_get_string (identity, &string);
            }
            
            if (!err) {
                err = kim_os_string_get_cfstring (string, &cfstring);
            }
            
            if (!err) {
                CFArrayAppendValue (value, cfstring);
            }
            
            if (cfstring) { CFRelease (cfstring); }
            kim_string_free (&string);
            kim_identity_free (&identity);
        }
    }
    
    if (!err) {
        err = kim_os_preferences_set_value (in_key, value);
    }
    
    if (value) { CFRelease (value); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_preferences_get_time_for_key (kim_preference_key  in_key,  
                                               kim_time            in_hardcoded_default,
                                               kim_time           *out_time)
{
    kim_error err = KIM_NO_ERROR;
    CFNumberRef value = NULL;
    
    if (!err && !out_time) { err = param_error (2, "out_time", "NULL"); }
    
    if (!err) {
        err = kim_os_preferences_get_value (in_key, CFNumberGetTypeID (), 
                                            (CFPropertyListRef *) &value);
    }
    
    if (!err) {
        if (value) {
            SInt32 number; // CFNumbers are signed so we need to cast
            if (CFNumberGetValue (value, kCFNumberSInt32Type, &number) != TRUE) {
                err = os_error (ENOMEM);
            } else {
                *out_time = number;
            }
        } else {
            *out_time = in_hardcoded_default;
        }
    }
    
    if (value) { CFRelease (value); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_preferences_set_time_for_key (kim_preference_key in_key, 
                                               kim_time           in_time)
{
    kim_error err = KIM_NO_ERROR;
    CFNumberRef value = NULL;
    SInt32 number = (SInt32) in_time;
    
    if (!err) {
        value = CFNumberCreate (kCFAllocatorDefault, kCFNumberSInt32Type, &number);
        if (!value) { err = os_error (ENOMEM); }
    }
    
    if (!err) {
        err = kim_os_preferences_set_value (in_key, value);
    }
    
    if (value) { CFRelease (value); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_preferences_get_lifetime_for_key (kim_preference_key  in_key, 
                                                   kim_lifetime        in_hardcoded_default,
                                                   kim_lifetime       *out_lifetime)
{
    kim_error err = KIM_NO_ERROR;
    CFNumberRef value = NULL;
    
    if (!err && !out_lifetime) { err = param_error (2, "out_lifetime", "NULL"); }
    
    if (!err) {
        err = kim_os_preferences_get_value (in_key, CFNumberGetTypeID (), 
                                            (CFPropertyListRef *) &value);
    }
    
    if (!err) {
        if (value) {
            SInt32 number; // CFNumbers are signed so we need to cast
            if (CFNumberGetValue (value, kCFNumberSInt32Type, &number) != TRUE) {
                err = os_error (ENOMEM);
            } else {
                *out_lifetime = number;
            }
        } else {
            *out_lifetime = in_hardcoded_default;
        }
    }
    
    if (value) { CFRelease (value); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_preferences_set_lifetime_for_key (kim_preference_key in_key, 
                                                   kim_lifetime       in_lifetime)
{
    kim_error err = KIM_NO_ERROR;
    CFNumberRef value = NULL;
    SInt32 number = (SInt32) in_lifetime;
    
    if (!err) {
        value = CFNumberCreate (kCFAllocatorDefault, kCFNumberSInt32Type, &number);
        if (!value) { err = os_error (ENOMEM); }
    }
    
    if (!err) {
        err = kim_os_preferences_set_value (in_key, value);
    }
    
    if (value) { CFRelease (value); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_preferences_get_boolean_for_key (kim_preference_key  in_key, 
                                                  kim_boolean         in_hardcoded_default,
                                                  kim_boolean        *out_boolean)
{
    kim_error err = KIM_NO_ERROR;
    CFBooleanRef value = NULL;
    
    if (!err && !out_boolean) { err = param_error (2, "out_boolean", "NULL"); }
    
    if (!err) {
        err = kim_os_preferences_get_value (in_key, CFBooleanGetTypeID (), 
                                            (CFPropertyListRef *) &value);
    }
    
    if (!err) {
        if (value) {
            *out_boolean = CFBooleanGetValue (value);
        } else {
            *out_boolean = in_hardcoded_default;
        }
    }
    
    if (value) { CFRelease (value); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_preferences_set_boolean_for_key (kim_preference_key in_key, 
                                                  kim_boolean        in_boolean)
{
    kim_error err = KIM_NO_ERROR;
    CFBooleanRef value = in_boolean ? kCFBooleanTrue : kCFBooleanFalse;
    
    if (!err) {
        err = kim_os_preferences_set_value (in_key, value);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

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

#define kim_os_preference_any_identity "KIM_IDENTITY_ANY"

#pragma mark -

/* ------------------------------------------------------------------------ */

static CFStringRef kim_os_preferences_cfstring_for_key (kim_preference_key in_key)
{
    if (in_key == kim_preference_key_options) {
        return CFSTR ("CredentialOptions");

    } else if (in_key == kim_preference_key_lifetime) {
        return CFSTR ("CredentialLifetime");

    } else if (in_key == kim_preference_key_renewable) {
        return CFSTR ("RenewableCredentials");

    } else if (in_key == kim_preference_key_renewal_lifetime) {
        return CFSTR ("CredentialRenewalLifetime");

    } else if (in_key == kim_preference_key_forwardable) {
        return CFSTR ("ForwardableCredentials");

    } else if (in_key == kim_preference_key_proxiable) {
        return CFSTR ("ProxiableCredentials");

    } else if (in_key == kim_preference_key_addressless) {
        return CFSTR ("AddresslessCredentials");

    } else if (in_key == kim_preference_key_remember_options) {
        return CFSTR ("RememberCredentialAttributes");

    } else if (in_key == kim_preference_key_client_identity) {
        return CFSTR ("ClientIdentity");

    } else if (in_key == kim_preference_key_remember_client_identity) {
        return CFSTR ("RememberClientIdentity");

    } else if (in_key == kim_preference_key_favorites) {
        return CFSTR ("FavoriteIdentities");

    } else if (in_key == kim_preference_key_minimum_lifetime) {
        return CFSTR ("MinimumLifetime");

    } else if (in_key == kim_preference_key_maximum_lifetime) {
        return CFSTR ("MaximumLifetime");

    } else if (in_key == kim_preference_key_minimum_renewal_lifetime) {
        return CFSTR ("MinimumRenewalLifetime");

    } else if (in_key == kim_preference_key_maximum_renewal_lifetime) {
        return CFSTR ("MaximumRenewalLifetime");

    }

    return NULL; /* ignore unsupported keys */
}

/* ------------------------------------------------------------------------ */

static CFStringRef kim_os_preferences_compat_cfstring_for_key (kim_preference_key in_key)
{
    if (in_key == kim_preference_key_lifetime) {
        return CFSTR ("KLDefaultTicketLifetime");

    } else if (in_key == kim_preference_key_renewable) {
        return CFSTR ("KLGetRenewableTickets");

    } else if (in_key == kim_preference_key_renewal_lifetime) {
        return CFSTR ("KLDefaultRenewableLifetime");

    } else if (in_key == kim_preference_key_forwardable) {
        return CFSTR ("KLDefaultForwardableTicket");

    } else if (in_key == kim_preference_key_proxiable) {
        return CFSTR ("KLGetProxiableTickets");

    } else if (in_key == kim_preference_key_addressless) {
        return CFSTR ("KLGetAddresslessTickets");

    } else if (in_key == kim_preference_key_remember_options) {
        return CFSTR ("KLRememberExtras");

    } else if (in_key == kim_preference_key_client_identity) {
        return CFSTR ("KLName");

    } else if (in_key == kim_preference_key_remember_client_identity) {
        return CFSTR ("KLRememberPrincipal");

    } else if (in_key == kim_preference_key_favorites) {
        return CFSTR ("KLFavoriteIdentities");

    } else if (in_key == kim_preference_key_minimum_lifetime) {
        return CFSTR ("KLMinimumTicketLifetime");

    } else if (in_key == kim_preference_key_maximum_lifetime) {
        return CFSTR ("KLMaximumTicketLifetime");

    } else if (in_key == kim_preference_key_minimum_renewal_lifetime) {
        return CFSTR ("KLMinimumRenewableLifetime");

    } else if (in_key == kim_preference_key_maximum_renewal_lifetime) {
        return CFSTR ("KLMaximumRenewableLifetime");

    }

    return NULL; /* ignore unsupported keys */
}

/* ------------------------------------------------------------------------ */

static kim_error kim_os_preferences_copy_value_for_file (CFStringRef         in_key,
                                                         CFTypeID            in_type,
                                                         CFStringRef         in_file,
                                                         CFPropertyListRef  *out_value)
{

    kim_error err = KIM_NO_ERROR;
    CFPropertyListRef value = NULL;
    CFStringRef users[] = { kCFPreferencesCurrentUser, kCFPreferencesAnyUser, NULL };
    CFStringRef hosts[] = { kCFPreferencesCurrentHost, kCFPreferencesAnyHost, NULL };

    if (!err && !in_key   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_file  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_value) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        kim_count u, h;

        if (!kim_library_allow_home_directory_access()) {
            users[0] = kCFPreferencesAnyUser;
            users[1] = NULL;
        }

        for (u = 0; !value && users[u]; u++) {
            for (h = 0; !value && hosts[h]; h++) {
                value = CFPreferencesCopyValue (in_key, in_file, users[u], hosts[h]);
            }
        }

        if (value && CFGetTypeID (value) != in_type) {
            err = check_error (KIM_PREFERENCES_READ_ERR);
        }
    }


    if (!err) {
        *out_value = value;
        value = NULL;
    }

    if (value) { CFRelease (value); }

    return check_error (err);
}

#pragma mark -

/* ------------------------------------------------------------------------ */

static kim_error kim_os_preferences_copy_value (kim_preference_key  in_key,
                                                CFTypeID            in_type,
                                                CFPropertyListRef  *out_value)
{
    kim_error err = KIM_NO_ERROR;
    CFStringRef key = kim_os_preferences_cfstring_for_key (in_key);

    err = kim_os_preferences_copy_value_for_file (key, in_type,
                                                  KIM_PREFERENCES_FILE,
                                                  out_value);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

static kim_error kim_os_preferences_copy_value_compat (kim_preference_key  in_key,
                                                       CFTypeID            in_type,
                                                       CFPropertyListRef  *out_value)
{
    kim_error err = KIM_NO_ERROR;
    CFStringRef key = kim_os_preferences_compat_cfstring_for_key (in_key);

    err = kim_os_preferences_copy_value_for_file (key, in_type,
                                                  KLL_PREFERENCES_FILE,
                                                  out_value);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

static kim_error kim_os_preferences_set_value (kim_preference_key in_key,
                                               CFPropertyListRef  in_value)
{
    kim_error err = KIM_NO_ERROR;
    CFStringRef key = NULL;

    /* in_value may be NULL if removing the key */

    if (!err) {
        key = kim_os_preferences_cfstring_for_key (in_key);
    }

    if (!err && key) {
        kim_boolean homedir_ok = kim_library_allow_home_directory_access();
        CFStringRef user = homedir_ok ? kCFPreferencesCurrentUser : kCFPreferencesAnyUser;
        CFStringRef host = homedir_ok ? kCFPreferencesAnyHost : kCFPreferencesCurrentHost;

        CFPreferencesSetValue (key, in_value, KIM_PREFERENCES_FILE, user, host);
        if (!CFPreferencesSynchronize (KIM_PREFERENCES_FILE, user, host)) {
            err = check_error (KIM_PREFERENCES_WRITE_ERR);
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

    if (!err && !out_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_os_preferences_copy_value (in_key, CFStringGetTypeID (),
                                             (CFPropertyListRef *) &value);

    }

    if (!err && !value) {
        err = kim_os_preferences_copy_value_compat (in_key, CFStringGetTypeID (),
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

kim_error kim_os_preferences_get_lifetime_for_key (kim_preference_key  in_key,
                                                   kim_lifetime        in_hardcoded_default,
                                                   kim_lifetime       *out_lifetime)
{
    kim_error err = KIM_NO_ERROR;
    CFNumberRef value = NULL;

    if (!err && !out_lifetime) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_os_preferences_copy_value (in_key, CFNumberGetTypeID (),
                                             (CFPropertyListRef *) &value);
    }

    if (!err && !value) {
        err = kim_os_preferences_copy_value_compat (in_key, CFNumberGetTypeID (),
                                                    (CFPropertyListRef *) &value);
    }

    if (!err) {
        if (value) {
            SInt32 number; // CFNumbers are signed so we need to cast
            if (CFNumberGetValue (value, kCFNumberSInt32Type, &number) != TRUE) {
                err = KIM_OUT_OF_MEMORY_ERR;
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
        if (!value) { err = KIM_OUT_OF_MEMORY_ERR; }
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

    if (!err && !out_boolean) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_os_preferences_copy_value (in_key, CFBooleanGetTypeID (),
                                             (CFPropertyListRef *) &value);
    }

    if (!err && !value) {
        err = kim_os_preferences_copy_value_compat (in_key, CFBooleanGetTypeID (),
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

#pragma mark -

/* ------------------------------------------------------------------------ */

static kim_error kim_os_preferences_copy_value_for_dict_key (CFDictionaryRef     in_dictionary,
                                                             kim_preference_key  in_key,
                                                             CFTypeID            in_type,
                                                             CFPropertyListRef  *out_value)
{
    kim_error err = KIM_NO_ERROR;
    CFPropertyListRef value = NULL;

    if (!err && !in_dictionary) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_value    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        CFStringRef key = kim_os_preferences_cfstring_for_key (in_key);

        value = CFDictionaryGetValue (in_dictionary, key);
        if (value && CFGetTypeID (value) != in_type) {
            err = check_error (KIM_PREFERENCES_READ_ERR);
        }
    }

    if (!err) {
        *out_value = value;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

static kim_error kim_os_preferences_set_value_for_dict_key (CFMutableDictionaryRef in_dictionary,
                                                            kim_preference_key     in_key,
                                                            CFPropertyListRef      in_value)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_dictionary) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_value     ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        CFStringRef key = kim_os_preferences_cfstring_for_key (in_key);

        CFDictionarySetValue (in_dictionary, key, in_value);
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

static kim_error kim_os_preferences_dictionary_to_options (CFDictionaryRef  in_dictionary,
                                                           kim_options     *out_options)
{
    kim_error err = KIM_NO_ERROR;
    kim_options options = KIM_OPTIONS_DEFAULT;
    kim_boolean found_options = 0;

    if (!err && !in_dictionary) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_options  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_options_create_empty (&options);
    }

    if (!err) {
        CFBooleanRef value = NULL;

        err = kim_os_preferences_copy_value_for_dict_key (in_dictionary,
                                                          kim_preference_key_renewable,
                                                          CFBooleanGetTypeID (),
                                                          (CFPropertyListRef *) &value);

        if (!err && value) {
            found_options = 1;
            err = kim_options_set_renewable (options, CFBooleanGetValue (value));
        }
    }

    if (!err) {
        CFNumberRef value = NULL;
        SInt32 lifetime; // CFNumbers are signed so we need to cast

        err = kim_os_preferences_copy_value_for_dict_key (in_dictionary,
                                                          kim_preference_key_lifetime,
                                                          CFNumberGetTypeID (),
                                                          (CFPropertyListRef *) &value);

        if (!err && value && CFNumberGetValue (value, kCFNumberSInt32Type,
                                               &lifetime)) {
            found_options = 1;
            err = kim_options_set_lifetime (options, lifetime);
        }
    }

    if (!err) {
        CFNumberRef value = NULL;
        SInt32 lifetime; // CFNumbers are signed so we need to cast

        err = kim_os_preferences_copy_value_for_dict_key (in_dictionary,
                                                          kim_preference_key_renewal_lifetime,
                                                          CFNumberGetTypeID (),
                                                          (CFPropertyListRef *) &value);

        if (!err && value && CFNumberGetValue (value, kCFNumberSInt32Type,
                                               &lifetime)) {
            found_options = 1;
            err = kim_options_set_renewal_lifetime (options, lifetime);
        }    }

    if (!err) {
        CFBooleanRef value = NULL;

        err = kim_os_preferences_copy_value_for_dict_key (in_dictionary,
                                                          kim_preference_key_forwardable,
                                                          CFBooleanGetTypeID (),
                                                          (CFPropertyListRef *) &value);

        if (!err && value) {
            found_options = 1;
            err = kim_options_set_forwardable (options, CFBooleanGetValue (value));
        }
    }

    if (!err) {
        CFBooleanRef value = NULL;

        err = kim_os_preferences_copy_value_for_dict_key (in_dictionary,
                                                          kim_preference_key_proxiable,
                                                          CFBooleanGetTypeID (),
                                                          (CFPropertyListRef *) &value);

        if (!err && value) {
            found_options = 1;
            err = kim_options_set_proxiable (options, CFBooleanGetValue (value));
        }
    }

    if (!err) {
        CFBooleanRef value = NULL;

        err = kim_os_preferences_copy_value_for_dict_key (in_dictionary,
                                                          kim_preference_key_addressless,
                                                          CFBooleanGetTypeID (),
                                                          (CFPropertyListRef *) &value);

        if (!err && value) {
            found_options = 1;
            err = kim_options_set_addressless (options, CFBooleanGetValue (value));
        }
    }

    if (!err && !found_options) {
        kim_options_free (&options);
        options = KIM_OPTIONS_DEFAULT;
    }

    if (!err) {
        *out_options = options;
        options = NULL;
    }

    kim_options_free (&options);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

static kim_error kim_os_preferences_options_to_dictionary (kim_options            in_options,
                                                           CFMutableDictionaryRef io_dictionary)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_options   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !io_dictionary) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        CFNumberRef value = NULL;
        kim_lifetime lifetime;

        err = kim_options_get_lifetime (in_options, &lifetime);

        if (!err) {
            SInt32 number = (SInt32) lifetime;

            value = CFNumberCreate (kCFAllocatorDefault,
                                    kCFNumberSInt32Type, &number);
            if (!value) { err = KIM_OUT_OF_MEMORY_ERR; }
        }

        if (!err) {
            err = kim_os_preferences_set_value_for_dict_key (io_dictionary,
                                                             kim_preference_key_lifetime,
                                                             value);
        }

        if (value) { CFRelease (value); }
    }

    if (!err) {
        kim_boolean boolean;

        err = kim_options_get_renewable (in_options, &boolean);

        if (!err) {
            CFBooleanRef value = boolean ? kCFBooleanTrue : kCFBooleanFalse;

            err = kim_os_preferences_set_value_for_dict_key (io_dictionary,
                                                             kim_preference_key_renewable,
                                                             value);
        }
    }

    if (!err) {
        CFNumberRef value = NULL;
        kim_lifetime lifetime;

        err = kim_options_get_renewal_lifetime (in_options, &lifetime);

        if (!err) {
            SInt32 number = (SInt32) lifetime;

            value = CFNumberCreate (kCFAllocatorDefault,
                                    kCFNumberSInt32Type, &number);
            if (!value) { err = KIM_OUT_OF_MEMORY_ERR; }
        }

        if (!err) {
            err = kim_os_preferences_set_value_for_dict_key (io_dictionary,
                                                             kim_preference_key_renewal_lifetime,
                                                             value);
        }

        if (value) { CFRelease (value); }
    }

    if (!err) {
        kim_boolean boolean;

        err = kim_options_get_forwardable (in_options, &boolean);

        if (!err) {
            CFBooleanRef value = boolean ? kCFBooleanTrue : kCFBooleanFalse;

            err = kim_os_preferences_set_value_for_dict_key (io_dictionary,
                                                             kim_preference_key_forwardable,
                                                             value);
        }
    }

    if (!err) {
        kim_boolean boolean;

        err = kim_options_get_proxiable (in_options, &boolean);

        if (!err) {
            CFBooleanRef value = boolean ? kCFBooleanTrue : kCFBooleanFalse;

            err = kim_os_preferences_set_value_for_dict_key (io_dictionary,
                                                             kim_preference_key_proxiable,
                                                             value);
        }
    }

    if (!err) {
        kim_boolean boolean;

        err = kim_options_get_addressless (in_options, &boolean);

        if (!err) {
            CFBooleanRef value = boolean ? kCFBooleanTrue : kCFBooleanFalse;

            err = kim_os_preferences_set_value_for_dict_key (io_dictionary,
                                                             kim_preference_key_addressless,
                                                             value);
        }
    }

    return check_error (err);
}



#pragma mark -

/* ------------------------------------------------------------------------ */

static kim_error kim_os_preferences_get_options_compat (kim_options *out_options)
{
    kim_error err = KIM_NO_ERROR;
    kim_options options = KIM_OPTIONS_DEFAULT;
    kim_boolean found_options = 0;

    if (!err && !out_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_options_create_empty (&options);
    }

    if (!err) {
        CFNumberRef value = NULL;
        SInt32 lifetime; // CFNumbers are signed so we need to cast

        err = kim_os_preferences_copy_value_compat (kim_preference_key_lifetime,
                                                    CFNumberGetTypeID (),
                                                    (CFPropertyListRef *) &value);

        if (!err && value && CFNumberGetValue (value, kCFNumberSInt32Type,
                                               &lifetime)) {
            found_options = 1;
            err = kim_options_set_lifetime (options, lifetime);
        }

        if (value) { CFRelease (value); }
    }

    if (!err) {
        CFBooleanRef value = NULL;

        err = kim_os_preferences_copy_value_compat (kim_preference_key_renewable,
                                                    CFBooleanGetTypeID (),
                                                    (CFPropertyListRef *) &value);

        if (!err && value) {
            found_options = 1;
            err = kim_options_set_renewable (options, CFBooleanGetValue (value));
        }

        if (value) { CFRelease (value); }
    }

    if (!err) {
        CFNumberRef value = NULL;
        SInt32 lifetime; // CFNumbers are signed so we need to cast

        err = kim_os_preferences_copy_value_compat (kim_preference_key_renewal_lifetime,
                                                    CFNumberGetTypeID (),
                                                    (CFPropertyListRef *) &value);

        if (!err && value && CFNumberGetValue (value, kCFNumberSInt32Type,
                                               &lifetime)) {
            found_options = 1;
            err = kim_options_set_renewal_lifetime (options, lifetime);
        }

        if (value) { CFRelease (value); }
    }

    if (!err) {
        CFBooleanRef value = NULL;

        err = kim_os_preferences_copy_value_compat (kim_preference_key_forwardable,
                                                    CFBooleanGetTypeID (),
                                                    (CFPropertyListRef *) &value);

        if (!err && value) {
            found_options = 1;
            err = kim_options_set_forwardable (options, CFBooleanGetValue (value));
        }

        if (value) { CFRelease (value); }
    }

    if (!err) {
        CFBooleanRef value = NULL;

        err = kim_os_preferences_copy_value_compat (kim_preference_key_proxiable,
                                                    CFBooleanGetTypeID (),
                                                    (CFPropertyListRef *) &value);

        if (!err && value) {
            found_options = 1;
            err = kim_options_set_proxiable (options, CFBooleanGetValue (value));
        }

        if (value) { CFRelease (value); }
    }

    if (!err) {
        CFBooleanRef value = NULL;

        err = kim_os_preferences_copy_value_compat (kim_preference_key_addressless,
                                                    CFBooleanGetTypeID (),
                                                    (CFPropertyListRef *) &value);

        if (!err && value) {
            found_options = 1;
            err = kim_options_set_addressless (options, CFBooleanGetValue (value));
        }

        if (value) { CFRelease (value); }
    }

    if (!err && !found_options) {
        kim_options_free (&options);
        options = KIM_OPTIONS_DEFAULT;
    }

    if (!err) {
        *out_options = options;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_preferences_get_options_for_key (kim_preference_key  in_key,
                                                  kim_options        *out_options)
{
    kim_error err = KIM_NO_ERROR;
    CFDictionaryRef dictionary = NULL;
    kim_options options = KIM_OPTIONS_DEFAULT;

    if (!err && !out_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_os_preferences_copy_value (in_key, CFDictionaryGetTypeID (),
                                             (CFPropertyListRef *) &dictionary);

        if (!err && dictionary) {
            err = kim_os_preferences_dictionary_to_options (dictionary, &options);
        }
    }

    if (!err && !dictionary) {
        err = kim_os_preferences_get_options_compat (&options);
    }

    if (!err) {
        *out_options = options;
    }

    if (dictionary) { CFRelease (dictionary); }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_preferences_set_options_for_key (kim_preference_key in_key,
                                                  kim_options        in_options)
{
    kim_error err = KIM_NO_ERROR;
    CFMutableDictionaryRef dictionary = NULL;

    /* in_options may be KIM_OPTIONS_DEFAULT, in which case we empty the dict */

    if (!err && in_options) {
        dictionary = CFDictionaryCreateMutable (kCFAllocatorDefault, 0,
                                                &kCFTypeDictionaryKeyCallBacks,
                                                &kCFTypeDictionaryValueCallBacks);
        if (!dictionary) { err = check_error (KIM_OUT_OF_MEMORY_ERR); }

        if (!err) {
            err = kim_os_preferences_options_to_dictionary (in_options, dictionary);
        }
    }

    if (!err) {
        /* NULL dictioray will remove any entry for this key */
        err = kim_os_preferences_set_value (in_key, dictionary);
    }

    if (dictionary) { CFRelease (dictionary); }

    return check_error (err);
}

#pragma mark -

/* ------------------------------------------------------------------------ */

kim_error kim_os_preferences_get_favorites_for_key (kim_preference_key in_key,
                                                    kim_favorites      io_favorites)
{
    kim_error err = KIM_NO_ERROR;
    CFArrayRef value = NULL;

    if (!err && !io_favorites) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_os_preferences_copy_value (in_key, CFArrayGetTypeID (),
                                             (CFPropertyListRef *) &value);
    }

    if (!err && value) {
        if (!value || CFArrayGetCount (value) < 1) {
            err =  kim_favorites_remove_all_identities (io_favorites);

        } else {
            CFIndex count = CFArrayGetCount (value);
            CFIndex i;

            for (i = 0; !err && i < count; i++) {
                CFDictionaryRef dictionary = NULL;
                CFStringRef cfstring = NULL;

                dictionary = (CFDictionaryRef) CFArrayGetValueAtIndex (value, i);
                if (!dictionary || CFGetTypeID (dictionary) != CFDictionaryGetTypeID ()) {
                    err = check_error (KIM_PREFERENCES_READ_ERR);
                }

                if (!err) {
                    err = kim_os_preferences_copy_value_for_dict_key (dictionary,
                                                                      kim_preference_key_client_identity,
                                                                      CFStringGetTypeID (),
                                                                      (CFPropertyListRef *) &cfstring);
                }

                if (!err && cfstring) {
                    kim_string string = NULL;
                    kim_identity identity = NULL;
                    kim_options options = KIM_OPTIONS_DEFAULT;

                    err = kim_os_string_create_from_cfstring (&string, cfstring);

                    if (!err) {
                        err = kim_identity_create_from_string (&identity, string);
                    }

                    if (!err && (CFDictionaryGetCount (dictionary) > 1)) {
                        err = kim_os_preferences_dictionary_to_options (dictionary,
                                                                        &options);
                    }

                    if (!err) {
                        err = kim_favorites_add_identity (io_favorites, identity,
                                                          options);
                    }

                    kim_string_free (&string);
                    kim_options_free (&options);
                    kim_identity_free (&identity);
                }
            }

            if (err) {
                kim_favorites_remove_all_identities (io_favorites);
            }
        }
    }

    if (value) { CFRelease (value); }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */
kim_error kim_os_preferences_set_favorites_for_key (kim_preference_key in_key,
                                                    kim_favorites      in_favorites)
{
    kim_error err = KIM_NO_ERROR;
    kim_count count = 0;
    CFMutableArrayRef array = NULL;

    if (!err && !in_favorites) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_favorites_get_number_of_identities (in_favorites, &count);
    }

    if (!err) {
        array = CFArrayCreateMutable (kCFAllocatorDefault, count,
                                      &kCFTypeArrayCallBacks);
        if (!array) { err = KIM_OUT_OF_MEMORY_ERR; }
    }

    if (!err) {
        kim_count i;

        for (i = 0; !err && i < count; i++) {
            kim_identity identity = NULL;
            kim_options options = NULL;
            kim_string string = NULL;
            CFStringRef cfstring = NULL;
            CFMutableDictionaryRef dictionary = NULL;

            err = kim_favorites_get_identity_at_index (in_favorites, i,
                                                       &identity,
                                                       &options);

            if (!err) {
                err = kim_identity_get_string (identity, &string);
            }

            if (!err) {
                err = kim_os_string_get_cfstring (string, &cfstring);
            }

            if (!err) {
                dictionary = CFDictionaryCreateMutable (kCFAllocatorDefault, 0,
                                                        &kCFTypeDictionaryKeyCallBacks,
                                                        &kCFTypeDictionaryValueCallBacks);
                if (!dictionary) { err = check_error (KIM_OUT_OF_MEMORY_ERR); }
            }

            if (!err) {
                err = kim_os_preferences_set_value_for_dict_key (dictionary,
                                                                 kim_preference_key_client_identity,
                                                                 cfstring);
            }

            if (!err && options) {
                err = kim_os_preferences_options_to_dictionary (options,
                                                                dictionary);
            }

            if (!err) {
                CFArrayAppendValue (array, dictionary);
            }

            if (dictionary) { CFRelease (dictionary); }
            if (cfstring  ) { CFRelease (cfstring); }
            kim_string_free (&string);
            kim_options_free (&options);
            kim_identity_free (&identity);
        }
    }

    if (!err) {
        err = kim_os_preferences_set_value (in_key, array);
    }

    if (array) { CFRelease (array); }

    return check_error (err);
}

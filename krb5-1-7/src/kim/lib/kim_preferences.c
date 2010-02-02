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

#include "kim_private.h"

struct kim_favorites_opaque {
    kim_count count;
    kim_identity *identities;
    kim_options *options;
};

struct kim_preferences_opaque {
    kim_options options;
    kim_boolean options_changed;
    kim_boolean remember_options;
    kim_boolean remember_options_changed;
    kim_identity client_identity;
    kim_boolean client_identity_changed;
    kim_boolean remember_client_identity;
    kim_boolean remember_client_identity_changed;
    kim_lifetime minimum_lifetime;
    kim_lifetime maximum_lifetime;
    kim_boolean lifetime_range_changed;
    kim_lifetime minimum_renewal_lifetime;
    kim_lifetime maximum_renewal_lifetime;
    kim_boolean renewal_lifetime_range_changed;
    struct kim_favorites_opaque favorites;
    kim_boolean favorites_changed;
};

const struct kim_favorites_opaque kim_default_favorites = { 0, NULL, NULL };

struct kim_preferences_opaque kim_preferences_initializer = { 
KIM_OPTIONS_DEFAULT, 
FALSE,
kim_default_remember_options, 
FALSE,
kim_default_client_identity, 
FALSE,
kim_default_remember_client_identity, 
FALSE,
kim_default_minimum_lifetime,
kim_default_maximum_lifetime,
FALSE,
kim_default_minimum_renewal_lifetime,
kim_default_maximum_renewal_lifetime,
FALSE,
{ 0, NULL, NULL },
FALSE
};


/* ------------------------------------------------------------------------ */

static kim_error kim_favorites_resize (kim_favorites io_favorites,
                                       kim_count     in_new_count)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_favorites) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err && io_favorites->count != in_new_count) {
        kim_identity *identities = NULL;
        kim_options *options = NULL;
        
        if (in_new_count == 0) {
            if (io_favorites->identities) {
                free (io_favorites->identities);
            }
            if (io_favorites->options) {
                free (io_favorites->options);
            }
        } else {
            if (!io_favorites->identities) {
                identities = malloc (sizeof (*identities) * in_new_count);
            } else {
                identities = realloc (io_favorites->identities, 
                                      sizeof (*identities) * in_new_count);
            }
            if (!identities) { err = KIM_OUT_OF_MEMORY_ERR; }
            
            if (!err) {
                if (!io_favorites->options) {
                    options = malloc (sizeof (*options) * in_new_count);
                } else {
                    options = realloc (io_favorites->options, 
                                       sizeof (*options) * in_new_count);
                }
                if (!options) { err = KIM_OUT_OF_MEMORY_ERR; }
            }
        }
        
        if (!err) {
            io_favorites->count = in_new_count;
            io_favorites->identities = identities;
            io_favorites->options = options;
            identities = NULL;
            options = NULL;
        }
        
        if (identities) { free (identities); }
        if (options   ) { free (options); }
    }
    
    return check_error (err);        
}

/* ------------------------------------------------------------------------ */

static kim_error kim_favorites_copy (kim_favorites in_favorites,
                                     kim_favorites io_favorites)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_favorites) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !io_favorites) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_favorites_resize (io_favorites, in_favorites->count);
    }
    
    if (!err) {
        kim_count i;
        
        for (i = 0; !err && i < io_favorites->count; i++) {
            err = kim_identity_copy (&io_favorites->identities[i], 
                                     in_favorites->identities[i]);
            
            if (!err) {
                err = kim_options_copy (&io_favorites->options[i], 
                                        in_favorites->options[i]);
            }
        }
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_favorites_get_number_of_identities (kim_favorites  in_favorites,
                                                  kim_count     *out_number_of_identities)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_favorites            ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_number_of_identities) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        *out_number_of_identities = in_favorites->count;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_favorites_get_identity_at_index (kim_favorites  in_favorites,
                                               kim_count      in_index,
                                               kim_identity  *out_identity,
                                               kim_options   *out_options)
{
    kim_error err = KIM_NO_ERROR;
    kim_identity identity = NULL;
    kim_options options = KIM_OPTIONS_DEFAULT;
    
    if (!err && !in_favorites) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    /* out_options may be NULL */
    
    if (!err) {
        if (in_index >= in_favorites->count) {
            err = kim_error_set_message_for_code (KIM_BAD_IDENTITY_INDEX_ERR, 
                                                  in_index);
        }
    }
    
    if (!err) {
        err = kim_identity_copy (&identity, in_favorites->identities[in_index]);
    }
    
    if (!err && in_favorites->options[in_index]) {
        err = kim_options_copy (&options, in_favorites->options[in_index]);
    }
    
    if (!err) {
        *out_identity = identity;
        identity = NULL;
        
        if (out_options) {
            *out_options = options;
            options = NULL;
        }
    }
    
    kim_identity_free (&identity);
    kim_options_free (&options);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_favorites_add_identity (kim_favorites io_favorites,
                                      kim_identity  in_identity,
                                      kim_options   in_options)
{
    kim_error err = KIM_NO_ERROR;
    kim_identity identity = NULL;
    kim_options options = KIM_OPTIONS_DEFAULT;
    kim_count insert_at = 0;
    
    if (!err && !io_favorites) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_identity ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    /* in_options may be KIM_OPTIONS_DEFAULT (NULL) */
    
    if (!err) {
        err = kim_identity_copy (&identity, in_identity);
    }
    
    if (!err) {
        err = kim_options_copy (&options, in_options);
    }
    
    if (!err) {
        kim_count i;
        
        for (i = 0; !err && i < io_favorites->count; i++) {
            kim_comparison comparison = 0;
            
            err = kim_identity_compare (io_favorites->identities[i],
                                        in_identity, 
                                        &comparison);
            
            if (!err) {
                if (kim_comparison_is_greater_than (comparison)) {
                    /* insert before the first entry that is greater than us */
                    break; 
                    
                } else if (kim_comparison_is_equal_to (comparison)) {
                    /* already in list */
                    kim_string display_string = NULL;
                    
                    err = kim_identity_get_display_string (in_identity, 
                                                           &display_string);
                    
                    if (!err) {
                        err = kim_error_set_message_for_code (KIM_IDENTITY_ALREADY_IN_LIST_ERR, 
                                                              display_string);
                    }
                    
                    kim_string_free (&display_string);
                }
            }
        }
        
        insert_at = i;  /* Remember where we are going to insert */
    }
    
    if (!err) {
        err = kim_favorites_resize (io_favorites, 
                                    io_favorites->count + 1);
    }
    
    if (!err) {
        kim_count move_count = io_favorites->count - 1 - insert_at;
        
        memmove (&io_favorites->identities[insert_at + 1],
                 &io_favorites->identities[insert_at],
                 move_count * sizeof (*io_favorites->identities));
        io_favorites->identities[insert_at] = identity;
        identity = NULL;
        
        memmove (&io_favorites->options[insert_at + 1],
                 &io_favorites->options[insert_at],
                 move_count * sizeof (*io_favorites->options));
        io_favorites->options[insert_at] = options;
        options = NULL;
    }
    
    kim_options_free (&options);
    kim_identity_free (&identity);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_favorites_remove_identity (kim_favorites io_favorites,
                                         kim_identity  in_identity)
{
    kim_error err = KIM_NO_ERROR;
    kim_boolean found = 0;
    kim_count i;
    
    if (!err && !io_favorites) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_identity ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        for (i = 0; !err && !found && i < io_favorites->count; i++) {
            kim_identity identity = io_favorites->identities[i];
            kim_options options = io_favorites->options[i];
            kim_comparison comparison;
            
            err = kim_identity_compare (in_identity, identity, &comparison);
            
            if (!err && kim_comparison_is_equal_to (comparison)) {
                kim_error terr = KIM_NO_ERROR;
                kim_count new_count = io_favorites->count - 1;
                
                found = 1;
                
                memmove (&io_favorites->identities[i], 
                         &io_favorites->identities[i + 1],
                         (new_count - i) * sizeof (*io_favorites->identities));
                
                memmove (&io_favorites->options[i], 
                         &io_favorites->options[i + 1],
                         (new_count - i) * sizeof (*io_favorites->options));
                
                terr = kim_favorites_resize (io_favorites, new_count);
                if (terr) {
                    kim_debug_printf ("failed to resize list to %d.  Continuing.", new_count);
                }
                
                kim_options_free (&options);
                kim_identity_free (&identity);
            }
        }
    }
    
    if (!err && !found) {
        kim_string display_string = NULL;
        
        err = kim_identity_get_display_string (in_identity, &display_string);
        
        if (!err) {
            err = kim_error_set_message_for_code (KIM_IDENTITY_NOT_IN_LIST_ERR, 
                                                  display_string);
        }
        
        kim_string_free (&display_string);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_favorites_remove_all_identities (kim_favorites io_favorites)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_favorites) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        kim_count i;
        
        for (i = 0; i < io_favorites->count; i++) {
            kim_identity_free (&io_favorites->identities[i]);
            kim_options_free (&io_favorites->options[i]);
        }
        free (io_favorites->identities);
        free (io_favorites->options);
        io_favorites->count = 0;
        io_favorites->identities = NULL;
        io_favorites->options = NULL;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

static void kim_favorites_free (kim_favorites io_favorites)
{
    kim_count i;
    
    for (i = 0; i < io_favorites->count; i++) {
        kim_identity_free (&io_favorites->identities[i]);
        kim_options_free (&io_favorites->options[i]);
    }
    free (io_favorites->identities);
    free (io_favorites->options);
}

#pragma mark -

/* ------------------------------------------------------------------------ */

static kim_error kim_preferences_read (kim_preferences in_preferences)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_preferences) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        kim_options options = NULL;
        
        err = kim_os_preferences_get_options_for_key (kim_preference_key_options,
                                                      &options);
        
        if (!err) {
            kim_options_free (&in_preferences->options);
            in_preferences->options = options;
        }
    }
    
    if (!err) {
        err = kim_os_preferences_get_boolean_for_key (kim_preference_key_remember_options,
                                                      kim_default_remember_options,
                                                      &in_preferences->remember_options);
    }
    
    if (!err) {
        kim_identity default_identity = kim_default_client_identity;
        kim_identity identity = NULL;
        
        err = kim_os_identity_create_for_username (&default_identity);
        
        if (!err) {
            err = kim_os_preferences_get_identity_for_key (kim_preference_key_client_identity,
                                                           default_identity,
                                                           &identity);
        }
        
        if (!err) {
            kim_identity_free (&in_preferences->client_identity);
            in_preferences->client_identity = identity;
            identity = NULL;
        }
        
        kim_identity_free (&default_identity);
        kim_identity_free (&identity);
    }
    
    if (!err) {
        err = kim_os_preferences_get_boolean_for_key (kim_preference_key_remember_client_identity,
                                                      kim_default_remember_client_identity,
                                                      &in_preferences->remember_client_identity);
    }
    
    if (!err) {
        struct kim_favorites_opaque favorites = kim_default_favorites;
        
        err = kim_os_preferences_get_favorites_for_key (kim_preference_key_favorites,
                                                        &favorites);
        
        if (!err) {
            kim_favorites_remove_all_identities (&in_preferences->favorites);
            in_preferences->favorites = favorites;
        }
    }
    
    if (!err) {
        err = kim_os_preferences_get_lifetime_for_key (kim_preference_key_minimum_lifetime,
                                                       kim_default_minimum_lifetime,
                                                       &in_preferences->minimum_lifetime);
    }
    
    if (!err) {
        err = kim_os_preferences_get_lifetime_for_key (kim_preference_key_maximum_lifetime,
                                                       kim_default_maximum_lifetime,
                                                       &in_preferences->maximum_lifetime);
    }
    
    if (!err) {
        err = kim_os_preferences_get_lifetime_for_key (kim_preference_key_minimum_renewal_lifetime,
                                                       kim_default_minimum_renewal_lifetime,
                                                       &in_preferences->minimum_renewal_lifetime);
    }
    
    if (!err) {
        err = kim_os_preferences_get_lifetime_for_key (kim_preference_key_maximum_renewal_lifetime,
                                                       kim_default_maximum_renewal_lifetime,
                                                       &in_preferences->maximum_renewal_lifetime);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

static kim_error kim_preferences_write (kim_preferences in_preferences)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_preferences) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err && in_preferences->options_changed) {
        err = kim_os_preferences_set_options_for_key (kim_preference_key_options,
                                                      in_preferences->options);        
    }
    
    if (!err && in_preferences->remember_options_changed) {
        err = kim_os_preferences_set_boolean_for_key (kim_preference_key_remember_options, 
                                                      in_preferences->remember_options);
    }
    
    if (!err && in_preferences->client_identity_changed) {
        kim_identity default_identity = kim_default_client_identity;
        
        err = kim_os_identity_create_for_username (&default_identity);
        
        if (!err) {
            err = kim_os_preferences_set_identity_for_key (kim_preference_key_client_identity, 
                                                           in_preferences->client_identity);
        }
        
        kim_identity_free (&default_identity);
    }
    
    if (!err && in_preferences->remember_client_identity_changed) {
        err = kim_os_preferences_set_boolean_for_key (kim_preference_key_remember_client_identity, 
                                                      in_preferences->remember_client_identity);
    }
    
    if (!err && in_preferences->favorites_changed) {
        err = kim_os_preferences_set_favorites_for_key (kim_preference_key_favorites, 
                                                        &in_preferences->favorites);
    }
    
    if (!err && in_preferences->lifetime_range_changed) {
        err = kim_os_preferences_set_lifetime_for_key (kim_preference_key_minimum_lifetime, 
                                                       in_preferences->minimum_lifetime);
        if (!err) {
            err = kim_os_preferences_set_lifetime_for_key (kim_preference_key_maximum_lifetime, 
                                                           in_preferences->maximum_lifetime);
        }
    }
    
    if (!err && in_preferences->renewal_lifetime_range_changed) {
        err = kim_os_preferences_set_lifetime_for_key (kim_preference_key_minimum_renewal_lifetime, 
                                                       in_preferences->minimum_renewal_lifetime);
        if (!err) {
            err = kim_os_preferences_set_lifetime_for_key (kim_preference_key_maximum_renewal_lifetime, 
                                                           in_preferences->maximum_renewal_lifetime);
        }
    }
    
    if (!err) {
        in_preferences->options_changed = 0;
        in_preferences->remember_options_changed = 0;
        in_preferences->client_identity_changed = 0;
        in_preferences->remember_client_identity_changed = 0;
        in_preferences->lifetime_range_changed = 0;
        in_preferences->renewal_lifetime_range_changed = 0;
        in_preferences->favorites_changed = 0;
    }
    
    return check_error (err);
}

#pragma mark -

/* ------------------------------------------------------------------------ */

static inline kim_error kim_preferences_allocate (kim_preferences *out_preferences)
{
    kim_error err = kim_library_init ();
    kim_preferences preferences = NULL;
    
    if (!err && !out_preferences) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        preferences = malloc (sizeof (*preferences));
        if (!preferences) { err = KIM_OUT_OF_MEMORY_ERR; }
    }
    
    if (!err) {
        *preferences = kim_preferences_initializer;
        *out_preferences = preferences;
        preferences = NULL;
    }
    
    kim_preferences_free (&preferences);
    
    return check_error (err);    
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_create (kim_preferences *out_preferences)
{
    kim_error err = KIM_NO_ERROR;
    kim_preferences preferences = NULL;
    
    if (!err && !out_preferences) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_preferences_allocate (&preferences);
    }
    
    if (!err) {
        err = kim_preferences_read (preferences);
    }
    
    if (!err) {
        *out_preferences = preferences;
        preferences = NULL;
    }
    
    kim_preferences_free (&preferences);
    
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_copy (kim_preferences *out_preferences,
                                kim_preferences  in_preferences)
{
    kim_error err = KIM_NO_ERROR;
    kim_preferences preferences = NULL;
    
    if (!err && !out_preferences) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_preferences ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_preferences_allocate (&preferences);
    }
    
    if (!err) {
        preferences->remember_options = in_preferences->remember_options;
        err = kim_options_copy (&preferences->options, in_preferences->options);
    }
    
    if (!err) {
        preferences->remember_client_identity = in_preferences->remember_client_identity;
        err = kim_identity_copy (&preferences->client_identity, in_preferences->client_identity);
    }
    
    if (!err) {
        err = kim_favorites_copy (&preferences->favorites, 
                                  &in_preferences->favorites);
    }
    
    if (!err) {
        *out_preferences = preferences;
        preferences = NULL;
    }
    
    kim_preferences_free (&preferences);
    
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_set_options (kim_preferences io_preferences,
                                       kim_options     in_options)
{
    kim_error err = KIM_NO_ERROR;
    kim_options options = NULL;
    
    if (!err && !io_preferences) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_options    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_options_copy (&options, in_options);
    }
    
    if (!err) {
        kim_options_free (&io_preferences->options);
        io_preferences->options = options;
        io_preferences->options_changed = TRUE;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_get_options (kim_preferences  in_preferences,
                                       kim_options     *out_options)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_preferences) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_options   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_options_copy (out_options, in_preferences->options);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_set_remember_options (kim_preferences io_preferences,
                                                kim_boolean     in_remember_options)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_preferences) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        io_preferences->remember_options = in_remember_options;
        io_preferences->remember_options_changed = TRUE;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_get_remember_options (kim_preferences  in_preferences,
                                                kim_boolean     *out_remember_options)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_preferences      ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_remember_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        *out_remember_options = in_preferences->remember_options;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_set_client_identity (kim_preferences io_preferences,
                                               kim_identity    in_client_identity)
{
    kim_error err = KIM_NO_ERROR;
    kim_identity identity = KIM_IDENTITY_ANY;
    
    if (!err && !io_preferences    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    /* in_client_identity may be KIM_IDENTITY_ANY */
    
    if (!err && in_client_identity) {
        err = kim_identity_copy (&identity, in_client_identity);
    }
    
    if (!err) {
        kim_identity_free (&io_preferences->client_identity);
        io_preferences->client_identity = identity;
        io_preferences->client_identity_changed = TRUE;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_get_client_identity (kim_preferences  in_preferences,
                                               kim_identity    *out_client_identity)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_preferences     ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_client_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_identity_copy (out_client_identity, in_preferences->client_identity);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_set_remember_client_identity (kim_preferences io_preferences,
                                                        kim_boolean     in_remember_client_identity)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_preferences) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        io_preferences->remember_client_identity = in_remember_client_identity;
        io_preferences->remember_client_identity_changed = TRUE;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_get_remember_client_identity (kim_preferences  in_preferences,
                                                        kim_boolean     *out_remember_client_identity)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_preferences              ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_remember_client_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        *out_remember_client_identity = in_preferences->remember_client_identity;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_set_minimum_lifetime (kim_preferences io_preferences,
                                                kim_lifetime    in_minimum_lifetime)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_preferences) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        io_preferences->minimum_lifetime = in_minimum_lifetime;
        io_preferences->lifetime_range_changed = TRUE;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_get_minimum_lifetime (kim_preferences  in_preferences,
                                                kim_lifetime    *out_minimum_lifetime)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_preferences      ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_minimum_lifetime) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        *out_minimum_lifetime = in_preferences->minimum_lifetime;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_set_maximum_lifetime (kim_preferences io_preferences,
                                                kim_lifetime    in_maximum_lifetime)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_preferences) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        io_preferences->maximum_lifetime = in_maximum_lifetime;
        io_preferences->lifetime_range_changed = TRUE;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_get_maximum_lifetime (kim_preferences  in_preferences,
                                                kim_lifetime    *out_maximum_lifetime)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_preferences      ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_maximum_lifetime) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        *out_maximum_lifetime = in_preferences->maximum_lifetime;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_set_minimum_renewal_lifetime (kim_preferences io_preferences,
                                                        kim_lifetime    in_minimum_renewal_lifetime)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_preferences) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        io_preferences->minimum_renewal_lifetime = in_minimum_renewal_lifetime;
        io_preferences->renewal_lifetime_range_changed = TRUE;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_get_minimum_renewal_lifetime (kim_preferences  in_preferences,
                                                        kim_lifetime    *out_minimum_renewal_lifetime)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_preferences              ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_minimum_renewal_lifetime) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        *out_minimum_renewal_lifetime = in_preferences->minimum_renewal_lifetime;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_set_maximum_renewal_lifetime (kim_preferences io_preferences,
                                                        kim_lifetime    in_maximum_renewal_lifetime)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_preferences) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        io_preferences->maximum_renewal_lifetime = in_maximum_renewal_lifetime;
        io_preferences->renewal_lifetime_range_changed = TRUE;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_get_maximum_renewal_lifetime (kim_preferences  in_preferences,
                                                        kim_lifetime    *out_maximum_renewal_lifetime)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_preferences              ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_maximum_renewal_lifetime) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        *out_maximum_renewal_lifetime = in_preferences->maximum_renewal_lifetime;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_get_number_of_favorite_identities (kim_preferences  in_preferences,
                                                             kim_count       *out_number_of_identities)
{
    return check_error (kim_favorites_get_number_of_identities (&in_preferences->favorites,
                                                                out_number_of_identities));
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_get_favorite_identity_at_index (kim_preferences  in_preferences,
                                                          kim_count        in_index,
                                                          kim_identity    *out_identity,
                                                          kim_options     *out_options)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_preferences) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_identity  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    /* out_options may be NULL */
    
    if (!err) {
        err = kim_favorites_get_identity_at_index (&in_preferences->favorites,
                                                   in_index,
                                                   out_identity,
                                                   out_options);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_add_favorite_identity (kim_preferences io_preferences,
                                                 kim_identity    in_identity,
                                                 kim_options     in_options)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_preferences) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_identity   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    /* in_options may be KIM_OPTIONS_DEFAULT (NULL) */
    
    if (!err) {
        err = kim_favorites_add_identity (&io_preferences->favorites,
                                          in_identity, in_options);
    }
    
    if (!err) {
        io_preferences->favorites_changed = 1;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_remove_favorite_identity (kim_preferences io_preferences,
                                                    kim_identity    in_identity)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_preferences) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_identity   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_favorites_remove_identity (&io_preferences->favorites,
                                             in_identity);
    }
    
    if (!err) {
        io_preferences->favorites_changed = 1;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_remove_all_favorite_identities (kim_preferences io_preferences)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_preferences) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_favorites_remove_all_identities (&io_preferences->favorites);
    }
    
    if (!err) {
        io_preferences->favorites_changed = 1;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_preferences_synchronize (kim_preferences in_preferences)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_preferences) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_preferences_write (in_preferences);
    }
    
    if (!err) {
        err = kim_preferences_read (in_preferences);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

void kim_preferences_free (kim_preferences *io_preferences)
{
    if (io_preferences && *io_preferences) {
        kim_options_free (&(*io_preferences)->options);
        kim_identity_free (&(*io_preferences)->client_identity);
        kim_favorites_free (&(*io_preferences)->favorites);

        free (*io_preferences);
        *io_preferences = NULL;
    }
}


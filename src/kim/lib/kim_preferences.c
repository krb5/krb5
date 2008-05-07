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

#pragma mark -- KIM Favorite Realms --
    
struct kim_favorite_identities_opaque {
    kim_count_t count;
    kim_identity_t *identities;
};

struct kim_favorite_identities_opaque kim_favorite_identities_initializer = { 0, NULL };
struct kim_favorite_identities_opaque kim_empty_favorite_identities_struct = { 0, NULL };
const kim_favorite_identities_t kim_empty_favorite_identities = &kim_empty_favorite_identities_struct;


/* ------------------------------------------------------------------------ */

static inline kim_error_t kim_favorite_identities_allocate (kim_favorite_identities_t *out_favorite_identities)
{
    kim_error_t err = KIM_NO_ERROR;
    kim_favorite_identities_t favorite_identities = NULL;
    
    if (!err && !out_favorite_identities) { err = param_error (1, "out_favorite_identities", "NULL"); }
    
    if (!err) {
        favorite_identities = malloc (sizeof (*favorite_identities));
        if (!favorite_identities) { err = os_error (errno); }
    }
    
    if (!err) {
        *favorite_identities = kim_favorite_identities_initializer;
        *out_favorite_identities = favorite_identities;
        favorite_identities = NULL;
    }
    
    kim_favorite_identities_free (&favorite_identities);
    
    return check_error (err);    
}

/* ------------------------------------------------------------------------ */

static inline kim_error_t kim_favorite_identities_resize (kim_favorite_identities_t io_favorite_identities,
                                                          kim_count_t               in_new_count)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !io_favorite_identities) { err = param_error (1, "io_favorite_identities", "NULL"); }
    
    if (!err && io_favorite_identities->count != in_new_count) {
        kim_identity_t *identities = NULL;

        if (in_new_count == 0) {
            if (io_favorite_identities->identities) {
                free (io_favorite_identities->identities);
            }
        } else {
            if (!io_favorite_identities->identities) {
                identities = malloc (sizeof (*identities) * in_new_count);
            } else {
                identities = realloc (io_favorite_identities->identities, 
                                      sizeof (*identities) * in_new_count);
            }
            if (!identities) { err = os_error (errno); }
        }
        
        if (!err) {
            io_favorite_identities->count = in_new_count;
            io_favorite_identities->identities = identities;
            identities = NULL;
        }
        
        if (identities) { free (identities); }
    }
    
    return check_error (err);        
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_favorite_identities_create (kim_favorite_identities_t *out_favorite_identities)
{
    kim_error_t err = KIM_NO_ERROR;
    kim_favorite_identities_t favorite_identities = NULL;
    
    if (!err && !out_favorite_identities) { err = param_error (1, "out_favorite_identities", "NULL"); }
    
    if (!err) {
        err = kim_favorite_identities_allocate (&favorite_identities);
    }
    
    if (!err) {
        *out_favorite_identities = favorite_identities;
        favorite_identities = NULL;
    }
    
    kim_favorite_identities_free (&favorite_identities);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_favorite_identities_copy (kim_favorite_identities_t *out_favorite_identities,
                                          kim_favorite_identities_t  in_favorite_identities)
{
    kim_error_t err = KIM_NO_ERROR;
    kim_favorite_identities_t favorite_identities = NULL;
    
    if (!err && !out_favorite_identities) { err = param_error (1, "out_favorite_identities", "NULL"); }
    if (!err && !in_favorite_identities ) { err = param_error (2, "in_favorite_identities", "NULL"); }
    
    if (!err) {
        err = kim_favorite_identities_allocate (&favorite_identities);
    }
    
    if (!err) {
        err = kim_favorite_identities_resize (favorite_identities, in_favorite_identities->count);
    }
    
    if (!err) {
        kim_count_t i;
        
        for (i = 0; !err && i < favorite_identities->count; i++) {
            err = kim_identity_copy (&favorite_identities->identities[i], 
                                     in_favorite_identities->identities[i]);
        }
    }
    
    if (!err) {
        *out_favorite_identities = favorite_identities;
        favorite_identities = NULL;
    }
    
    kim_favorite_identities_free (&favorite_identities);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_favorite_identities_get_number_of_identities (kim_favorite_identities_t  in_favorite_identities,
                                                              kim_count_t               *out_number_of_identities)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_favorite_identities  ) { err = param_error (1, "in_favorite_identities", "NULL"); }
    if (!err && !out_number_of_identities) { err = param_error (2, "out_number_of_identities", "NULL"); }
    
    if (!err) {
        *out_number_of_identities = in_favorite_identities->count;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_favorite_identities_get_identity_at_index (kim_favorite_identities_t  in_favorite_identities,
                                                           kim_count_t                in_index,
                                                           kim_identity_t            *out_identity)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_favorite_identities) { err = param_error (1, "in_favorite_identities", "NULL"); }
    if (!err && !out_identity          ) { err = param_error (3, "out_identity", "NULL"); }
    
    if (!err) {
        if (in_index >= in_favorite_identities->count) {
            err = kim_error_create_from_code (KIM_BAD_IDENTITY_INDEX_ECODE, in_index);
        }
    }
    
    if (!err) {
        err = kim_identity_copy (out_identity, in_favorite_identities->identities[in_index]);
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_favorite_identities_add_identity (kim_favorite_identities_t io_favorite_identities,
                                                  kim_identity_t            in_identity)
{
    kim_error_t err = KIM_NO_ERROR;
    kim_identity_t identity = NULL;
    kim_count_t insert_at = 0;
    
    if (!err && !io_favorite_identities) { err = param_error (1, "io_favorite_identities", "NULL"); }
    if (!err && !in_identity           ) { err = param_error (2, "in_identity", "NULL"); }
    
    if (!err) {
        err = kim_identity_copy (&identity, in_identity);
    }
    
    if (!err) {
        kim_count_t i;
        
        for (i = 0; !err && i < io_favorite_identities->count; i++) {
            kim_comparison_t identity_comparison = 0;
            
            err = kim_identity_compare (in_identity, io_favorite_identities->identities[i], &identity_comparison);
            
            if (!err) {
                if (kim_comparison_is_greater_than (identity_comparison)) {
                    break; /* found the first greater one so insert here */
                    
                } else if (kim_comparison_is_equal_to (identity_comparison)) {
                    /* already in list */
                    kim_string_t display_string = NULL;
                    
                    err = kim_identity_get_display_string (in_identity, &display_string);
                    
                    if (!err) {
                        err = kim_error_create_from_code (KIM_IDENTITY_ALREADY_IN_IDENTITIES_LIST, 
                                                          display_string);
                    }
                    
                    kim_string_free (&display_string);
                }
            }
        }
        
        insert_at = i;  /* Remember where we are going to insert */
    }
    
    if (!err) {
        err = kim_favorite_identities_resize (io_favorite_identities, io_favorite_identities->count + 1);
    }
    
    if (!err) {
        kim_count_t move_count = io_favorite_identities->count - 1 - insert_at;
        
        memmove (&io_favorite_identities->identities[insert_at + 1],
                 &io_favorite_identities->identities[insert_at],
                 move_count * sizeof (*io_favorite_identities->identities));
        io_favorite_identities->identities[insert_at] = identity;
        identity = NULL;
    }
    
    kim_identity_free (&identity);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_favorite_identities_remove_identity (kim_favorite_identities_t io_favorite_identities,
                                                     kim_identity_t            in_identity)
{
    kim_error_t err = KIM_NO_ERROR;
    kim_boolean_t found = FALSE;
    kim_count_t i;
    
    if (!err && !io_favorite_identities) { err = param_error (1, "io_favorite_identities", "NULL"); }
    if (!err && !in_identity           ) { err = param_error (2, "in_identity", "NULL"); }
    
    if (!err) {
        for (i = 0; !err && !found && i < io_favorite_identities->count; i++) {
            kim_identity_t identity = io_favorite_identities->identities[i];
            
            err = kim_identity_compare (in_identity, identity, &found);
            
            if (!err && found) {
                kim_count_t new_count = io_favorite_identities->count - 1;
                memmove (&io_favorite_identities->identities[i], 
                         &io_favorite_identities->identities[i + 1],
                         (new_count - i) * sizeof (*io_favorite_identities->identities));
                
                kim_error_t terr = kim_favorite_identities_resize (io_favorite_identities, new_count);
                if (terr) {
                    kim_debug_printf ("failed to resize list to %d.  Continuing.", new_count);
                    kim_error_free (&terr);
                }
                
                kim_identity_free (&identity);
            }
        }
    }
    
    if (!err && !found) {
        kim_string_t display_string = NULL;
        
        err = kim_identity_get_display_string (in_identity, &display_string);
        
        if (!err) {
            err = kim_error_create_from_code (KIM_IDENTITY_NOT_IN_IDENTITIES_LIST, display_string);
        }
        
        kim_string_free (&display_string);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_favorite_identities_remove_all_identities (kim_favorite_identities_t io_favorite_identities)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !io_favorite_identities) { err = param_error (1, "io_favorite_identities", "NULL"); }
    
    if (!err) {
        kim_count_t i;
        
        for (i = 0; i < io_favorite_identities->count; i++) {
            kim_identity_free (&io_favorite_identities->identities[i]);
        }
        free (io_favorite_identities->identities);
        io_favorite_identities->count = 0;
        io_favorite_identities->identities = NULL;
    }
 
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

void kim_favorite_identities_free (kim_favorite_identities_t *io_favorite_identities)
{
    if (io_favorite_identities && *io_favorite_identities && 
        *io_favorite_identities != kim_default_favorite_identities) {
        kim_count_t i;
        
        for (i = 0; i < (*io_favorite_identities)->count; i++) {
            kim_identity_free (&(*io_favorite_identities)->identities[i]);
        }
        free ((*io_favorite_identities)->identities);
        free (*io_favorite_identities);
        *io_favorite_identities = NULL;
    }
}

#pragma mark -- KIM Preferences --

struct kim_preferences_opaque {
    kim_options_t options;
    kim_boolean_t options_changed;
    kim_boolean_t remember_options;
    kim_boolean_t remember_options_changed;
    kim_identity_t client_identity;
    kim_boolean_t client_identity_changed;
    kim_boolean_t remember_client_identity;
    kim_boolean_t remember_client_identity_changed;
    kim_lifetime_t minimum_lifetime;
    kim_lifetime_t maximum_lifetime;
    kim_boolean_t lifetime_range_changed;
    kim_lifetime_t minimum_renewal_lifetime;
    kim_lifetime_t maximum_renewal_lifetime;
    kim_boolean_t renewal_lifetime_range_changed;
    kim_favorite_identities_t favorite_identities;
    kim_boolean_t favorite_identities_changed;
};

struct kim_preferences_opaque kim_preferences_initializer = { 
    NULL, 
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
    NULL,
    FALSE
};

/* ------------------------------------------------------------------------ */

static kim_error_t kim_preferences_read (kim_preferences_t in_preferences)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_preferences) { err = param_error (1, "in_preferences", "NULL"); }
    
    if (!err) {
        kim_lifetime_t lifetime = kim_default_lifetime;
        
        err = kim_os_preferences_get_lifetime_for_key (kim_preference_key_lifetime,
                                                       kim_default_lifetime,
                                                       &lifetime);
        
        if (!err) {
            err = kim_options_set_lifetime (in_preferences->options, lifetime);
        }
    }
    
    if (!err) {
        kim_boolean_t renewable = kim_default_renewable;
        
        err = kim_os_preferences_get_boolean_for_key (kim_preference_key_renewable,
                                                      kim_default_renewable,
                                                      &renewable);
        
        if (!err) {
            err = kim_options_set_renewable (in_preferences->options, renewable);
        }
    }
    
    if (!err) {
        kim_lifetime_t renewal_lifetime = kim_default_renewal_lifetime;
        
        err = kim_os_preferences_get_lifetime_for_key (kim_preference_key_renewal_lifetime,
                                                       kim_default_renewal_lifetime,
                                                       &renewal_lifetime);
        
        if (!err) {
            err = kim_options_set_renewal_lifetime (in_preferences->options, renewal_lifetime);
        }
    }
    
    if (!err) {
        kim_boolean_t forwardable = kim_default_forwardable;
        
        err = kim_os_preferences_get_boolean_for_key (kim_preference_key_forwardable,
                                                      kim_default_forwardable,
                                                      &forwardable);
        
        if (!err) {
            err = kim_options_set_forwardable (in_preferences->options, forwardable);
        }
    }
    
    if (!err) {
        kim_boolean_t proxiable = kim_default_proxiable;
        
        err = kim_os_preferences_get_boolean_for_key (kim_preference_key_proxiable,
                                                      kim_default_proxiable,
                                                      &proxiable);
        
        if (!err) {
            err = kim_options_set_proxiable (in_preferences->options, proxiable);
        }
    }
    
    if (!err) {
        kim_boolean_t addressless = kim_default_addressless;
        
        err = kim_os_preferences_get_boolean_for_key (kim_preference_key_addressless,
                                                      kim_default_addressless,
                                                      &addressless);
        
        if (!err) {
            err = kim_options_set_addressless (in_preferences->options, addressless);
        }
    }
    
    if (!err) {
        err = kim_os_preferences_get_boolean_for_key (kim_preference_key_remember_options,
                                                      kim_default_remember_options,
                                                      &in_preferences->remember_options);
    }
    
    if (!err) {
        kim_identity_t default_identity = kim_default_client_identity;
        
        err = kim_os_identity_create_for_username (&default_identity);
        
        if (!err) {
            err = kim_os_preferences_get_identity_for_key (kim_preference_key_client_identity,
                                                           default_identity,
                                                           &in_preferences->client_identity);
        }
        
        kim_identity_free (&default_identity);
    }
    
    if (!err) {
        err = kim_os_preferences_get_boolean_for_key (kim_preference_key_remember_client_identity,
                                                      kim_default_remember_client_identity,
                                                      &in_preferences->remember_client_identity);
    }
    
    if (!err) {
        err = kim_os_preferences_get_favorite_identities_for_key (kim_preference_key_favorite_identities,
                                                                  kim_default_favorite_identities,
                                                                  &in_preferences->favorite_identities);
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

static kim_error_t kim_preferences_write (kim_preferences_t in_preferences)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_preferences) { err = param_error (1, "in_preferences", "NULL"); }
    
    if (!err && in_preferences->remember_options && in_preferences->options_changed) {
        kim_lifetime_t lifetime = kim_default_lifetime;
        
        err = kim_options_get_lifetime (in_preferences->options, &lifetime);
        
        if (!err) {
            err = kim_os_preferences_set_lifetime_for_key (kim_preference_key_lifetime, 
                                                           lifetime);
        }
        
        if (!err) {
            kim_boolean_t renewable = kim_default_renewable;
            
            err = kim_options_get_renewable (in_preferences->options, &renewable);
            
            if (!err) {
                err = kim_os_preferences_set_boolean_for_key (kim_preference_key_renewable, 
                                                              renewable);
            }
        }
        
        if (!err) {
            kim_lifetime_t renewal_lifetime = kim_default_renewal_lifetime;
            
            err = kim_options_get_renewal_lifetime (in_preferences->options, &renewal_lifetime);
            
            if (!err) {
                err = kim_os_preferences_set_lifetime_for_key (kim_preference_key_renewal_lifetime, 
                                                               renewal_lifetime);
            }
        }
        
        if (!err) {
            kim_boolean_t forwardable = kim_default_forwardable;
            
            err = kim_options_get_forwardable (in_preferences->options, &forwardable);
            
            if (!err) {
                err = kim_os_preferences_set_boolean_for_key (kim_preference_key_forwardable, 
                                                              forwardable);
            }
        }
        
        if (!err) {
            kim_boolean_t proxiable = kim_default_proxiable;
            
            err = kim_options_get_proxiable (in_preferences->options, &proxiable);
            
            if (!err) {
                err = kim_os_preferences_set_boolean_for_key (kim_preference_key_proxiable, 
                                                              proxiable);
            }
        }
        
        if (!err) {
            kim_boolean_t addressless = kim_default_addressless;
            
            err = kim_options_get_addressless (in_preferences->options, &addressless);
            
            if (!err) {
                err = kim_os_preferences_set_boolean_for_key (kim_preference_key_addressless, 
                                                              addressless);
            }
        }
    }
    
    if (!err && in_preferences->remember_options_changed) {
        err = kim_os_preferences_set_boolean_for_key (kim_preference_key_remember_options, 
                                                      in_preferences->remember_options);
    }
    
    if (!err && in_preferences->remember_client_identity && in_preferences->client_identity_changed) {
        kim_identity_t default_identity = kim_default_client_identity;
        
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
    
    if (!err && in_preferences->favorite_identities_changed) {
        err = kim_os_preferences_set_favorite_identities_for_key (kim_preference_key_favorite_identities, 
                                                                  in_preferences->favorite_identities);
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
    
    return check_error (err);
}

#pragma mark -

/* ------------------------------------------------------------------------ */

static inline kim_error_t kim_preferences_allocate (kim_preferences_t *out_preferences)
{
    kim_error_t err = KIM_NO_ERROR;
    kim_preferences_t preferences = NULL;
    
    if (!err && !out_preferences) { err = param_error (1, "out_preferences", "NULL"); }
    
    if (!err) {
        preferences = malloc (sizeof (*preferences));
        if (!preferences) { err = os_error (errno); }
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

kim_error_t kim_preferences_create (kim_preferences_t *out_preferences)
{
    kim_error_t err = KIM_NO_ERROR;
    kim_preferences_t preferences = NULL;
    
    if (!err && !out_preferences) { err = param_error (1, "out_preferences", "NULL"); }
    
    if (!err) {
        err = kim_preferences_allocate (&preferences);
    }
    
    if (!err) {
        err = kim_options_create_from_defaults (&preferences->options);
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

kim_error_t kim_preferences_copy (kim_preferences_t *out_preferences,
                                  kim_preferences_t  in_preferences)
{
    kim_error_t err = KIM_NO_ERROR;
    kim_preferences_t preferences = NULL;
    
    if (!err && !out_preferences) { err = param_error (1, "out_preferences", "NULL"); }
    if (!err && !in_preferences ) { err = param_error (2, "in_preferences", "NULL"); }
    
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
        err = kim_favorite_identities_copy (&preferences->favorite_identities, in_preferences->favorite_identities);
    }
    
    if (!err) {
        *out_preferences = preferences;
        preferences = NULL;
    }
    
    kim_preferences_free (&preferences);
    
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_preferences_set_options (kim_preferences_t io_preferences,
                                         kim_options_t     in_options)
{
    kim_error_t err = KIM_NO_ERROR;
    kim_options_t options = NULL;
    
    if (!err && !io_preferences) { err = param_error (1, "io_preferences", "NULL"); }
    if (!err && !in_options    ) { err = param_error (2, "in_options", "NULL"); }
    
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

kim_error_t kim_preferences_get_options (kim_preferences_t  in_preferences,
                                         kim_options_t     *out_options)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_preferences) { err = param_error (1, "in_preferences", "NULL"); }
    if (!err && !out_options   ) { err = param_error (2, "out_options", "NULL"); }
    
    if (!err) {
        err = kim_options_copy (out_options, in_preferences->options);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_preferences_set_remember_options (kim_preferences_t io_preferences,
                                                  kim_boolean_t     in_remember_options)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !io_preferences) { err = param_error (1, "io_preferences", "NULL"); }
    
    if (!err) {
        io_preferences->remember_options = in_remember_options;
        io_preferences->remember_options_changed = TRUE;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_preferences_get_remember_options (kim_preferences_t  in_preferences,
                                                  kim_boolean_t     *out_remember_options)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_preferences      ) { err = param_error (1, "in_preferences", "NULL"); }
    if (!err && !out_remember_options) { err = param_error (2, "out_remember_options", "NULL"); }
    
    if (!err) {
        *out_remember_options = in_preferences->remember_options;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_preferences_set_client_identity (kim_preferences_t io_preferences,
                                                 kim_identity_t    in_client_identity)
{
    kim_error_t err = KIM_NO_ERROR;
    kim_identity_t identity = KIM_IDENTITY_ANY;
    
    if (!err && !io_preferences    ) { err = param_error (1, "io_preferences", "NULL"); }
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

kim_error_t kim_preferences_get_client_identity (kim_preferences_t  in_preferences,
                                                 kim_identity_t    *out_client_identity)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_preferences     ) { err = param_error (1, "in_preferences", "NULL"); }
    if (!err && !out_client_identity) { err = param_error (2, "out_client_identity", "NULL"); }
    
    if (!err) {
        err = kim_identity_copy (out_client_identity, in_preferences->client_identity);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_preferences_set_remember_client_identity (kim_preferences_t io_preferences,
                                                          kim_boolean_t     in_remember_client_identity)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !io_preferences) { err = param_error (1, "io_preferences", "NULL"); }
    
    if (!err) {
        io_preferences->remember_client_identity = in_remember_client_identity;
        io_preferences->remember_client_identity_changed = TRUE;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_preferences_get_remember_client_identity (kim_preferences_t  in_preferences,
                                                          kim_boolean_t     *out_remember_client_identity)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_preferences              ) { err = param_error (1, "in_preferences", "NULL"); }
    if (!err && !out_remember_client_identity) { err = param_error (2, "out_remember_client_identity", "NULL"); }
    
    if (!err) {
        *out_remember_client_identity = in_preferences->remember_client_identity;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_preferences_set_minimum_lifetime (kim_preferences_t io_preferences,
                                                  kim_lifetime_t    in_minimum_lifetime)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !io_preferences) { err = param_error (1, "io_preferences", "NULL"); }
    
    if (!err) {
        io_preferences->minimum_lifetime = in_minimum_lifetime;
        io_preferences->lifetime_range_changed = TRUE;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_preferences_get_minimum_lifetime (kim_preferences_t  in_preferences,
                                                  kim_lifetime_t    *out_minimum_lifetime)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_preferences      ) { err = param_error (1, "in_preferences", "NULL"); }
    if (!err && !out_minimum_lifetime) { err = param_error (2, "out_minimum_lifetime", "NULL"); }
    
    if (!err) {
        *out_minimum_lifetime = in_preferences->minimum_lifetime;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_preferences_set_maximum_lifetime (kim_preferences_t io_preferences,
                                                  kim_lifetime_t    in_maximum_lifetime)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !io_preferences) { err = param_error (1, "io_preferences", "NULL"); }
    
    if (!err) {
        io_preferences->maximum_lifetime = in_maximum_lifetime;
        io_preferences->lifetime_range_changed = TRUE;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_preferences_get_maximum_lifetime (kim_preferences_t  in_preferences,
                                                  kim_lifetime_t    *out_maximum_lifetime)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_preferences      ) { err = param_error (1, "in_preferences", "NULL"); }
    if (!err && !out_maximum_lifetime) { err = param_error (2, "out_maximum_lifetime", "NULL"); }
    
    if (!err) {
        *out_maximum_lifetime = in_preferences->maximum_lifetime;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_preferences_set_minimum_renewal_lifetime (kim_preferences_t io_preferences,
                                                          kim_lifetime_t    in_minimum_renewal_lifetime)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !io_preferences) { err = param_error (1, "io_preferences", "NULL"); }
    
    if (!err) {
        io_preferences->minimum_renewal_lifetime = in_minimum_renewal_lifetime;
        io_preferences->renewal_lifetime_range_changed = TRUE;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_preferences_get_minimum_renewal_lifetime (kim_preferences_t  in_preferences,
                                                          kim_lifetime_t    *out_minimum_renewal_lifetime)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_preferences              ) { err = param_error (1, "in_preferences", "NULL"); }
    if (!err && !out_minimum_renewal_lifetime) { err = param_error (2, "out_minimum_renewal_lifetime", "NULL"); }
    
    if (!err) {
        *out_minimum_renewal_lifetime = in_preferences->minimum_renewal_lifetime;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_preferences_set_maximum_renewal_lifetime (kim_preferences_t io_preferences,
                                                          kim_lifetime_t    in_maximum_renewal_lifetime)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !io_preferences) { err = param_error (1, "io_preferences", "NULL"); }
    
    if (!err) {
        io_preferences->maximum_renewal_lifetime = in_maximum_renewal_lifetime;
        io_preferences->renewal_lifetime_range_changed = TRUE;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_preferences_get_maximum_renewal_lifetime (kim_preferences_t  in_preferences,
                                                          kim_lifetime_t    *out_maximum_renewal_lifetime)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_preferences              ) { err = param_error (1, "in_preferences", "NULL"); }
    if (!err && !out_maximum_renewal_lifetime) { err = param_error (2, "out_maximum_renewal_lifetime", "NULL"); }
    
    if (!err) {
        *out_maximum_renewal_lifetime = in_preferences->maximum_renewal_lifetime;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_preferences_set_favorite_identities (kim_preferences_t     io_preferences,
                                                 kim_favorite_identities_t in_favorite_identities)
{
    kim_error_t err = KIM_NO_ERROR;
    kim_favorite_identities_t favorite_identities = NULL;
    
    if (!err && !io_preferences        ) { err = param_error (1, "io_preferences", "NULL"); }
    if (!err && !in_favorite_identities) { err = param_error (2, "in_favorite_identities", "NULL"); }
    
    if (!err) {
        err = kim_favorite_identities_copy (&favorite_identities, in_favorite_identities);
    }
    
    if (!err) {
        kim_favorite_identities_free (&io_preferences->favorite_identities);
        io_preferences->favorite_identities = favorite_identities;
        io_preferences->favorite_identities_changed = TRUE;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_preferences_get_favorite_identities (kim_preferences_t      in_preferences,
                                                 kim_favorite_identities_t *out_favorite_identities)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_preferences         ) { err = param_error (1, "in_preferences", "NULL"); }
    if (!err && !out_favorite_identities) { err = param_error (2, "out_favorite_identities", "NULL"); }
    
    if (!err) {
        err = kim_favorite_identities_copy (out_favorite_identities, in_preferences->favorite_identities);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_preferences_synchronize (kim_preferences_t in_preferences)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_preferences) { err = param_error (1, "in_preferences", "NULL"); }
    
    if (!err) {
        err = kim_preferences_write (in_preferences);
    }
    
    if (!err) {
        err = kim_preferences_read (in_preferences);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

void kim_preferences_free (kim_preferences_t *io_preferences)
{
    if (io_preferences && *io_preferences) {
        kim_options_free (&(*io_preferences)->options);
        kim_identity_free (&(*io_preferences)->client_identity);
        kim_favorite_identities_free (&(*io_preferences)->favorite_identities);
        free (*io_preferences);
        *io_preferences = NULL;
    }
}


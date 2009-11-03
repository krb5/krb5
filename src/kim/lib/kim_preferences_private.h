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

#ifndef KIM_PREFERENCES_PRIVATE_H
#define KIM_PREFERENCES_PRIVATE_H

#include <kim/kim.h>

typedef struct kim_favorites_opaque *kim_favorites;

typedef enum kim_preference_key_enum {
    kim_preference_key_options,
    kim_preference_key_lifetime,
    kim_preference_key_renewable,
    kim_preference_key_renewal_lifetime,
    kim_preference_key_forwardable,
    kim_preference_key_proxiable,
    kim_preference_key_addressless,
    kim_preference_key_remember_options,
    kim_preference_key_client_identity,
    kim_preference_key_remember_client_identity,
    kim_preference_key_favorites,
    kim_preference_key_minimum_lifetime,
    kim_preference_key_maximum_lifetime,
    kim_preference_key_minimum_renewal_lifetime,
    kim_preference_key_maximum_renewal_lifetime
} kim_preference_key;


#define kim_default_lifetime                   10*60*60
#define kim_default_renewable                  TRUE
#define kim_default_renewal_lifetime           7*24*60*60
#define kim_default_forwardable                TRUE
#define kim_default_proxiable                  TRUE
#define kim_default_addressless                TRUE
#define kim_default_remember_options           TRUE
#define kim_default_client_identity            KIM_IDENTITY_ANY
#define kim_default_remember_client_identity   TRUE
#define kim_default_minimum_lifetime           10*60
#define kim_default_maximum_lifetime           10*60*60
#define kim_default_minimum_renewal_lifetime   10*60
#define kim_default_maximum_renewal_lifetime   7*24*60*60

extern const struct kim_favorites_opaque kim_default_favorites;


/* Helper functions for use by kim_os_preferences_get_favorites_for_key
 * and kim_os_preferences_set_favorites_for_key */

kim_error kim_favorites_get_number_of_identities (kim_favorites  in_favorites,
                                                  kim_count     *out_number_of_identities);

kim_error kim_favorites_get_identity_at_index (kim_favorites  in_favorites,
                                               kim_count      in_index,
                                               kim_identity  *out_identity,
                                               kim_options   *out_options);

kim_error kim_favorites_add_identity (kim_favorites io_favorites,
                                      kim_identity  in_identity,
                                      kim_options   in_options);

kim_error kim_favorites_remove_identity (kim_favorites io_favorites,
                                         kim_identity  in_identity);

kim_error kim_favorites_remove_all_identities (kim_favorites io_favorites);


/* OS-specific functions to be implemented per-platform */

kim_error kim_os_preferences_get_options_for_key (kim_preference_key  in_key,
                                                   kim_options       *out_options);

kim_error kim_os_preferences_set_options_for_key (kim_preference_key in_key,
                                                  kim_options        in_options);

kim_error kim_os_preferences_get_identity_for_key (kim_preference_key  in_key,
                                                   kim_identity        in_hardcoded_default,
                                                   kim_identity       *out_identity);

kim_error kim_os_preferences_set_identity_for_key (kim_preference_key in_key,
                                                   kim_identity       in_identity);

kim_error kim_os_preferences_get_favorites_for_key (kim_preference_key in_key,
                                                    kim_favorites      io_favorites);

kim_error kim_os_preferences_set_favorites_for_key (kim_preference_key in_key,
                                                    kim_favorites      in_favorites);

kim_error kim_os_preferences_get_lifetime_for_key (kim_preference_key  in_key,
                                                   kim_lifetime        in_hardcoded_default,
                                                   kim_lifetime       *out_lifetime);

kim_error kim_os_preferences_set_lifetime_for_key (kim_preference_key in_key,
                                                   kim_lifetime       in_lifetime);

kim_error kim_os_preferences_get_boolean_for_key (kim_preference_key  in_key,
                                                  kim_boolean         in_hardcoded_default,
                                                  kim_boolean        *out_boolean);

kim_error kim_os_preferences_set_boolean_for_key (kim_preference_key in_key,
                                                  kim_boolean        in_boolean);

#endif /* KIM_PREFERENCES_PRIVATE_H */

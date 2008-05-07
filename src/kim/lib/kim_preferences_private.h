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

extern const kim_favorite_identities_t kim_empty_favorite_identities;

typedef enum kim_preference_key_enum {
    kim_preference_key_lifetime,
    kim_preference_key_renewable,
    kim_preference_key_renewal_lifetime,
    kim_preference_key_forwardable,
    kim_preference_key_proxiable,
    kim_preference_key_addressless,
    kim_preference_key_remember_options,
    kim_preference_key_client_identity,
    kim_preference_key_remember_client_identity,
    kim_preference_key_favorite_identities,
    kim_preference_key_minimum_lifetime,
    kim_preference_key_maximum_lifetime,
    kim_preference_key_minimum_renewal_lifetime,
    kim_preference_key_maximum_renewal_lifetime
} kim_preference_key_t;

#define kim_default_lifetime                   10*60*60
#define kim_default_renewable                  TRUE
#define kim_default_renewal_lifetime           7*24*60*60
#define kim_default_forwardable                TRUE
#define kim_default_proxiable                  TRUE
#define kim_default_addressless                TRUE
#define kim_default_remember_options           TRUE
#define kim_default_client_identity            KIM_IDENTITY_ANY
#define kim_default_remember_client_identity   TRUE
#define kim_default_favorite_identities        kim_empty_favorite_identities
#define kim_default_minimum_lifetime           10*60
#define kim_default_maximum_lifetime           10*60*60
#define kim_default_minimum_renewal_lifetime   10*60
#define kim_default_maximum_renewal_lifetime   7*24*60*60


kim_error_t kim_os_preferences_get_identity_for_key (kim_preference_key_t  in_key, 
                                                     kim_identity_t        in_hardcoded_default,
                                                     kim_identity_t       *out_identity);

kim_error_t kim_os_preferences_set_identity_for_key (kim_preference_key_t in_key, 
                                                     kim_identity_t       in_identity);

kim_error_t kim_os_preferences_get_favorite_identities_for_key (kim_preference_key_t       in_key, 
                                                                kim_favorite_identities_t  in_hardcoded_default,
                                                                kim_favorite_identities_t *out_favorite_identities);

kim_error_t kim_os_preferences_set_favorite_identities_for_key (kim_preference_key_t      in_key, 
                                                                kim_favorite_identities_t in_favorite_identities);

kim_error_t kim_os_preferences_get_time_for_key (kim_preference_key_t  in_key, 
                                                 kim_time_t            in_hardcoded_default,
                                                 kim_time_t           *out_time);

kim_error_t kim_os_preferences_set_time_for_key (kim_preference_key_t in_key, 
                                                 kim_time_t           in_time);

kim_error_t kim_os_preferences_get_lifetime_for_key (kim_preference_key_t  in_key, 
                                                     kim_lifetime_t        in_hardcoded_default,
                                                     kim_lifetime_t       *out_lifetime);

kim_error_t kim_os_preferences_set_lifetime_for_key (kim_preference_key_t in_key, 
                                                     kim_lifetime_t       in_lifetime);

kim_error_t kim_os_preferences_get_boolean_for_key (kim_preference_key_t  in_key, 
                                                    kim_boolean_t         in_hardcoded_default,
                                                    kim_boolean_t        *out_boolean);

kim_error_t kim_os_preferences_set_boolean_for_key (kim_preference_key_t in_key, 
                                                    kim_boolean_t        in_boolean);

#endif /* KIM_PREFERENCES_PRIVATE_H */

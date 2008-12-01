/*
 * Copyright 2005-2006 Massachusetts Institute of Technology.
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

#ifndef KIM_PREFERENCES_H
#define KIM_PREFERENCES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <kim/kim_types.h>
    
/*!
 * \page kim_preferences_overview KIM Preferences Overview
 *
 * \section kim_preferences_introduction Introduction
 *
 * In addition to the site preferences stored in the Kerberos configuration, users may also
 * want to have their own personal preferences for controlling credential acquisition.  
 * As a result, KIM provides user preferences for initial credential options and 
 * user interface behavior such as the default client identity and the favorite identities list.
 *
 * \section kim_preferences_edit Viewing and Editing the Preferences
 * 
 * In order to view and edit the user's preferences, call #kim_preferences_create() to acquire a 
 * preferences object containing the user's preferences.  You can examine preferences
 * with the functions starting with "kim_preferences_get_" and change preferences with
 * the functions starting with "kim_preferences_set_".  Once you are done making changes,
 * you can write changes back out to the user's preferences with #kim_preferences_synchronize().
 *
 * \note The location of user preferences and the semantics of
 * preference synchronization is platform-specific.  Where possible KIM will use
 * platform-specific preference mechanisms.
 *
 * \section kim_preferences_options Initial Credential Options Preferences
 *
 * KIM provides user preferences for initial credential options.  These
 * are the options #kim_options_create() will use when creating a new KIM 
 * options object.  They are also the options specified by KIM_OPTIONS_DEFAULT.
 * You can view and edit the initial credential options using 
 * #kim_preferences_get_options() and #kim_preferences_set_options(). 
 *
 * \note Not all credential options in the kim_options_t object have corresponding 
 * user preferences.  For example, the prompt callback function is not stored
 * in the user preferences since it has no meaning outside of the current 
 * application.  Some options which are not currently stored in the
 * preferences may be stored there in the future. 
 *
 * If you are implementing a user interface for credentials acquisition, 
 * you should be aware that KIM has a user preference to manage the initial
 * credential options preferences. If the user successfully acquires credentials 
 * with non-default options and #kim_preferences_get_remember_options() is set 
 * to TRUE, you should store the options used to get credentials with 
 * #kim_preferences_set_options().  
 *
 * \section kim_preferences_client_identity Client Identity Preferences
 *
 * KIM also provides user preferences for the default client identity.   
 * This identity is used whenever KIM needs to display a graphical dialog for
 * credential acquisition but does not know what client identity to use.
 * You can view and edit the default client identity using 
 * #kim_preferences_get_client_identity() and 
 * #kim_preferences_set_client_identity(). 
 *
 * If you are implementing a user interface for credentials acquisition, 
 * you should be aware that KIM has a user preference to manage 
 * the client identity preferences. If the user successfully acquires credentials 
 * with non-default options and #kim_preferences_get_remember_client_identity() is  
 * set to TRUE, you should store the client identity for which credentials were
 * acquired using #kim_preferences_set_client_identity(). 
 * 
 * \section kim_preferences_favorite_identities Favorite Identities Preferences
 *
 * As Kerberos becomes more widespread, the number of possible Kerberos
 * identities and realms a user might want to use will become very large.
 * Sites may list hundreds of realms in their Kerberos configuration files. 
 * In addition, sites may wish to use DNS SRV records to avoid having to list
 * all the realms they use in their Kerberos configuration.  As a result, the 
 * list of realms in the Kerberos configuration may be exceedingly large and/or 
 * incomplete.  Users may also use multiple identities from the same realm.
 *
 * On platforms which use a GUI to acquire credentials, the KIM would like
 * to to display a list of identities for the user to select from.  Depending on 
 * what is appropriate for the platform, identities may be displayed in a popup 
 * menu or other list.  
 *
 * To solve this problem, the KIM maintains a list of favorite identities 
 * specifically for identity selection.  This list is a set of unique identities 
 * in alphabetical order (as appropriate for the user's language localization).  
 *
 * Each identity may optionally have its own options for ticket acquisition.
 * This allows KIM UIs to remember what ticket options worked for a specific
 * identity.  For example if the user normally wants renewable tickets but
 * they have one identity at a KDC which rejects requests for renewable tickets,
 * the "not renewable" option can be associated with that identity without 
 * changing the user's default preference to get renewable tickets.  If an
 * identity should use the default options, just pass KIM_OPTIONS_DEFAULT.
 *
 * Most callers will not need to use the favorite identities APIs.  However if you
 * are implementing your own graphical prompt callback or a credential management 
 * application, you may to view and/or edit the user's favorite identities.
 *
 * \section kim_favorite_identities_edit Viewing and Editing the Favorite Identities
 * 
 * First, you need to acquire the Favorite Identities stored in the user's
 * preferences using #kim_preferences_create().
 * 
 * Then use #kim_preferences_get_number_of_favorite_identities() and 
 * #kim_preferences_get_favorite_identity_at_index() to display the identities list.  
 * Use #kim_preferences_add_favorite_identity() and #kim_preferences_remove_favorite_identity() 
 * to change which identities are in the identities list.  Identities are always stored in
 * alphabetical order and duplicate identities are not permitted, so when you add or remove a
 * identity you should redisplay the entire list.  If you wish to replace the
 * identities list entirely, use #kim_preferences_remove_all_favorite_identities()
 * to clear the list before adding your identities.
 *
 * Once you are done editing the favorite identities list, store changes in the 
 * user's preference file using #kim_preferences_synchronize().
 * 
 * See \ref kim_preferences_reference for information on specific APIs.
 */

/*!
 * \defgroup kim_preferences_reference KIM Preferences Documentation
 * @{
 */

/*!
 * \param out_preferences on exit, a new preferences object.  
 *                        Must be freed with kim_preferences_free().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Create a new preferences object from the current user's preferences.
 */
kim_error kim_preferences_create (kim_preferences *out_preferences);

/*!
 * \param out_preferences on exit, a new preferences object which is a copy of in_preferences.  
 *                        Must be freed with kim_preferences_free().
 * \param in_preferences  a preferences object. 
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Copy a preferences object.
 */
kim_error kim_preferences_copy (kim_preferences *out_preferences,
                                  kim_preferences  in_preferences);

/*!
 * \param io_preferences a preferences object to modify.
 * \param in_options     an options object.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Set the user's preferred options.
 * \sa kim_preferences_get_options()
 */
kim_error kim_preferences_set_options (kim_preferences io_preferences,
                                         kim_options     in_options);

/*!
 * \param in_preferences a preferences object.
 * \param out_options    on exit, the options specified in \a in_preferences.
 *                       May be KIM_OPTIONS_DEFAULT.
 *                       If not, must be freed with kim_options_free().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the user's preferred options.
 * \sa kim_preferences_set_options()
 */
kim_error kim_preferences_get_options (kim_preferences  in_preferences,
                                         kim_options     *out_options);

/*!
 * \param io_preferences      a preferences object to modify.
 * \param in_remember_options a boolean value indicating whether or not to remember the last 
 *                            options used to acquire a credential.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Set whether or not to remember the last options the user used to acquire a credential.
 * \sa kim_preferences_get_remember_options()
 */
kim_error kim_preferences_set_remember_options (kim_preferences io_preferences,
                                                  kim_boolean     in_remember_options);

/*!
 * \param in_preferences       a preferences object.
 * \param out_remember_options on exit, a boolean value indicating whether or \a in_preferences will 
 *                             remember the last options used to acquire a credential.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get whether or not to remember the last options the user used to acquire a credential.
 * \sa kim_preferences_set_remember_options()
 */
kim_error kim_preferences_get_remember_options (kim_preferences  in_preferences,
                                                  kim_boolean     *out_remember_options);

/*!
 * \param io_preferences      a preferences object to modify.
 * \param in_client_identity  a client identity object.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Set the user's preferred client identity.
 * \sa kim_preferences_get_client_identity()
 */
kim_error kim_preferences_set_client_identity (kim_preferences io_preferences,
                                                 kim_identity    in_client_identity);

/*!
 * \param in_preferences       a preferences object.
 * \param out_client_identity  on exit, the client identity specified in \a in_preferences.
 *                             Must be freed with kim_identity_free().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the user's preferred client identity.
 * \sa kim_preferences_set_client_identity()
 */
kim_error kim_preferences_get_client_identity (kim_preferences  in_preferences,
                                                 kim_identity    *out_client_identity);

/*!
 * \param io_preferences               a preferences object to modify.
 * \param in_remember_client_identity  a boolean value indicating whether or not to remember the last 
 *                                     client identity for which a credential was acquired.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Set whether or not to remember the last client identity the user acquired a credential for.
 * \sa kim_preferences_get_remember_client_identity()
 */
kim_error kim_preferences_set_remember_client_identity (kim_preferences io_preferences,
                                                          kim_boolean     in_remember_client_identity);

/*!
 * \param in_preferences                a preferences object.
 * \param out_remember_client_identity  on exit, a boolean value indicating whether or \a in_preferences will 
 *                                      remember the last client identity for which a credential was acquired.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get whether or not to remember the last client identity the user acquired a credential for.
 * \sa kim_preferences_set_remember_client_identity()
 */
kim_error kim_preferences_get_remember_client_identity (kim_preferences  in_preferences,
                                                          kim_boolean     *out_remember_client_identity);

/*!
 * \param io_preferences       a preferences object to modify.
 * \param in_minimum_lifetime  a minimum lifetime indicating how small a lifetime the
 *                             GUI tools should allow the user to specify for credentials.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Set the minimum credential lifetime for GUI credential lifetime controls.
 * \sa kim_preferences_get_minimum_lifetime()
 */
kim_error kim_preferences_set_minimum_lifetime (kim_preferences io_preferences,
                                                  kim_lifetime    in_minimum_lifetime);

/*!
 * \param in_preferences        a preferences object.
 * \param out_minimum_lifetime  on exit, the minimum lifetime that GUI tools will 
 *                              allow the user to specify for credentials.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the minimum credential lifetime for GUI credential lifetime controls.
 * \sa kim_preferences_set_minimum_lifetime()
 */
kim_error kim_preferences_get_minimum_lifetime (kim_preferences  in_preferences,
                                                  kim_lifetime    *out_minimum_lifetime);

/*!
 * \param io_preferences       a preferences object to modify.
 * \param in_maximum_lifetime  a maximum lifetime indicating how large a lifetime the
 *                             GUI tools should allow the user to specify for credentials.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Set the maximum credential lifetime for GUI credential lifetime controls.
 * \sa kim_preferences_get_maximum_lifetime()
 */
kim_error kim_preferences_set_maximum_lifetime (kim_preferences io_preferences,
                                                  kim_lifetime    in_maximum_lifetime);

/*!
 * \param in_preferences        a preferences object.
 * \param out_maximum_lifetime  on exit, the maximum lifetime that GUI tools will 
 *                              allow the user to specify for credentials.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the maximum credential lifetime for GUI credential lifetime controls.
 * \sa kim_preferences_set_maximum_lifetime()
 */
kim_error kim_preferences_get_maximum_lifetime (kim_preferences  in_preferences,
                                                  kim_lifetime    *out_maximum_lifetime);

/*!
 * \param io_preferences               a preferences object to modify.
 * \param in_minimum_renewal_lifetime  a minimum lifetime indicating how small a lifetime the
 *                                     GUI tools should allow the user to specify for 
 *                                     credential renewal.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Set the minimum credential renewal lifetime for GUI credential lifetime controls.
 * \sa kim_preferences_get_minimum_renewal_lifetime()
 */
kim_error kim_preferences_set_minimum_renewal_lifetime (kim_preferences io_preferences,
                                                          kim_lifetime    in_minimum_renewal_lifetime);

/*!
 * \param in_preferences                a preferences object.
 * \param out_minimum_renewal_lifetime  on exit, the minimum lifetime that GUI tools will 
 *                                      allow the user to specify for credential renewal.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the minimum credential renewal lifetime for GUI credential lifetime controls.
 * \sa kim_preferences_set_minimum_renewal_lifetime()
 */
kim_error kim_preferences_get_minimum_renewal_lifetime (kim_preferences  in_preferences,
                                                          kim_lifetime    *out_minimum_renewal_lifetime);

/*!
 * \param io_preferences               a preferences object to modify.
 * \param in_maximum_renewal_lifetime  a maximum lifetime indicating how large a lifetime the
 *                                     GUI tools should allow the user to specify for 
 *                                     credential renewal.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Set the maximum credential renewal lifetime for GUI credential lifetime controls.
 * \sa kim_preferences_get_minimum_renewal_lifetime()
 */
kim_error kim_preferences_set_maximum_renewal_lifetime (kim_preferences io_preferences,
                                                          kim_lifetime    in_maximum_renewal_lifetime);

/*!
 * \param in_preferences                a preferences object.
 * \param out_maximum_renewal_lifetime  on exit, the maximum lifetime that GUI tools will 
 *                                      allow the user to specify for credential renewal.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the maximum credential renewal lifetime for GUI credential lifetime controls.
 * \sa kim_preferences_set_minimum_renewal_lifetime()
 */
kim_error kim_preferences_get_maximum_renewal_lifetime (kim_preferences  in_preferences,
                                                          kim_lifetime    *out_maximum_renewal_lifetime);

/*!
 * \param in_preferences           a preferences object.
 * \param out_number_of_identities on exit, the number of identities in \a in_preferences.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the number of favorite identities in a preferences object.
 */
kim_error kim_preferences_get_number_of_favorite_identities (kim_preferences  in_preferences,
                                                             kim_count       *out_number_of_identities);

/*!
 * \param in_preferences     a preferences object.
 * \param in_index           a index into the identities list (starting at 0).
 * \param out_identity       on exit, the identity at \a in_index in \a in_preferences.
 *                           Must be freed with kim_string_free().
 * \param out_options        on exit, the options associated with identity at \a in_index 
 *                           in \a in_favorite_identities.  May be KIM_OPTIONS_DEFAULT.
 *                           Pass NULL if you do not want the options associated with the identity.
 *                           Must be freed with kim_options_free().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the Nth favorite identity in a preferences object.
 */
kim_error kim_preferences_get_favorite_identity_at_index (kim_preferences  in_preferences,
                                                          kim_count        in_index,
                                                          kim_identity    *out_identity,
                                                          kim_options     *out_options);

/*!
 * \param io_preferences   a preferences object.
 * \param in_identity      an identity to add to \a io_preferences.
 * \param in_options       options which will be associated with that identity.
 *                         Use KIM_OPTIONS_DEFAULT if the identity should use
 *                         the user's default options.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Add a favorite identity to a preferences object.
 */
kim_error kim_preferences_add_favorite_identity (kim_preferences io_preferences,
                                                 kim_identity    in_identity,
                                                 kim_options     in_options);

/*!
 * \param io_preferences    a preferences object.
 * \param in_identity       an identity to remove from \a io_preferences.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Remove a favorite identity from a preferences object.
 */
kim_error kim_preferences_remove_favorite_identity (kim_preferences io_preferences,
                                                    kim_identity    in_identity);

/*!
 * \param io_preferences    a preferences object.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Remove all favorite identities in a preferences object.
 */
kim_error kim_preferences_remove_all_favorite_identities (kim_preferences io_preferences);

/*!
 * \param in_preferences a preferences object.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Synchronize a preferences object with the user's preferences, writing pending changes
 * and reading any changes applied by other processes.
 */
kim_error kim_preferences_synchronize (kim_preferences in_preferences);

/*!
 * \param io_preferences the preferences object to be freed.  Set to NULL on exit.
 * \brief Free memory associated with a preferences object.
 */
void kim_preferences_free (kim_preferences *io_preferences);

/*!@}*/

#ifdef __cplusplus
}
#endif

#endif /* KIM_PREFERENCES_H */

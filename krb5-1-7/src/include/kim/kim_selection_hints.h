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

#ifndef KIM_SELECTION_HINTS_H
#define KIM_SELECTION_HINTS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <kim/kim_types.h>
    
/*!
 * \page kim_selection_hints_overview KIM Selection Hints Overview
 *
 * \section kim_selection_hints_introduction Introduction
 *
 * Most users belong to multiple organizations and thus need
 * to authenticate to multiple Kerberos realms.  Traditionally Kerberos sites 
 * solved this problem by setting up a cross-realm relationship, which allowed 
 * the user to use TGT credentials for their client identity in one realm 
 * to obtain credentials in another realm via cross-realm authentication.  As a 
 * result users could acquire credentials for a single client identity and use 
 * them everywhere.
 *
 * Setting up cross-realm requires that realms share a secret, so sites must 
 * coordinate with one another to set up a cross-realm relationship.  In 
 * addition, sites must set up authorization policies for users from other  
 * realms.  As Kerberos becomes increasingly wide-spread, many realms will 
 * not have cross-realm relationships, and users will need to   
 * manually obtain credentials for their client identity at each realm
 * (eg: "user@BANK.COM", "user@UNIVERSITY.EDU", etc).  As a result, users 
 * will often have multiple credentials caches, one for each client identity.
 *
 * Unfortunately this presents a problem for applications which need to obtain
 * service credentials.  Which client identity should they use?  
 * Rather than having each application to manually search the cache collection,
 * KIM provides a selection hints API for choosing the best client identity.  
 * This API is intended to simplify the process of choosing credentials 
 * and provide consistent behavior across all applications.
 *
 * Searching the cache collection for credentials may be expensive if there
 * are a large number of caches.  If credentials for the client identity 
 * are expired or not present, KIM may also wish to prompt the user for
 * new credentials for the appropriate client identity.  As a result, 
 * applications might want to remember which client identity worked in
 * the past and always request credentials using that identity.  
 * 
 *
 * \section kim_selection_hints_creating Creating KIM Selection Hints
 * 
 * A KIM selection hints object consists of an application identifier and one or 
 * more pieces of information about the service the client application will be 
 * contacting.  The application identifier is used by user preferences 
 * to control how applications share cache entries.  It is important to be
 * consistent about what application identifier you provide.  Java-style  
 * identifiers are recommended to avoid collisions.
 *
 * \section kim_selection_hints_searching Selection Hint Search Behavior
 *
 * When using selection hints to search for an appropriate client identity, 
 * KIM uses a consistent hint search order.  This allows applications to specify 
 * potentially contradictory information without preventing KIM from locating a 
 * single ccache.  In addition the selection hint search order may change, 
 * especially if more hints are added.  
 *
 * As a result, callers are encouraged to provide all relevant search hints, 
 * even if only a subset of those search hints are necessary to get reasonable 
 * behavior in the current implementation.  Doing so will provide the most
 * user-friendly selection experience.
 *
 * Currently the search order looks like this:
 *
 * \li <B>Service Identity</B> The client identity which has obtained a service credential for this service identity.
 * \li <B>Server</B> A client identity which has obtained a service credential for this server.
 * \li <B>Service Realm</B> A client identity which has obtained a service credential for this realm.
 * \li <B>Service</B> A client identity which has obtained a service credential for this service.
 * \li <B>Client Realm</B> A client identity in this realm.
 * \li <B>User</B> A client identity whose first component is this user string.
 *
 * For example, if you specify a service identity and a credential for 
 * that identity already exists in the ccache collection, KIM may use that 
 * ccache, even if your user and client realm entries in the selection hints would  
 * lead it to choose a different ccache.  If no credentials for the service identity
 * exist then KIM will fall back on the user and realm hints.
 *
 * \note Due to performance and information exposure concerns, currently all 
 * searching is done by examining the cache collection.  In the future the KIM 
 * may also make network requests as part of its search algorithm.  For example
 * it might check to see if the TGT credentials in each ccache can obtain
 * credentials for the service identity specified by the selection hints.
 *
 * \section kim_selection_hints_selecting Selecting an Identity Using Selection Hints
 *
 * Once you have provided search criteria for selecting an identity, use
 * #kim_selection_hints_get_identity() to obtain an identity object.  
 * You can then use #kim_identity_get_string() to obtain a krb5 principal
 * string for use with gss_import_name() and gss_acquire_cred().  Alternatively, 
 * you can use #kim_ccache_create_from_client_identity() to obtain a ccache  
 * containing credentials for the identity.
 *
 * \note #kim_selection_hints_get_identity() obtains an identity based on
 * the current state of the selection hints object.  If you change the 
 * selection hints object you must call #kim_selection_hints_get_identity()
 * again.
 *
 * \section kim_selection_hints_caching Selection Hint Caching Behavior
 * 
 * In addition to using selection hints to search for an appropriate client
 * identity, KIM can also use them to remember which client identity worked.  
 * KIM maintains a per-user cache mapping selection hints to identities so
 * that applications do not have to maintain their own caches or present 
 * user interface for selecting which cache to use.
 *
 * When #kim_selection_hints_get_identity() is called KIM looks up in the
 * cache and returns the identity which the selection hints map to.  If 
 * there is not a preexisting cache entry for the selection hints then 
 * #kim_selection_hints_get_identity() will search for an identity and
 * prompt the user if it cannot find an appropriate one. 
 * 
 * If the client identity returned by KIM authenticates and passes 
 * authorization checks, you should tell KIM to cache the identity by calling
 * #kim_selection_hints_remember_identity().  This will create a cache entry
 * for the mapping between your selection hints and the identity so that 
 * subsequent calls to #kim_selection_hints_get_identity() do not need to 
 * prompt the user. 
 *
 * If the client identity returned by KIM fails to authenticate or fails
 * authorization checks, you must call #kim_selection_hints_forget_identity() 
 * to remove any mapping that already exists.  After this function is called,
 * future calls to #kim_selection_hints_get_identity() will search for an 
 * identity again.  You may also wish to call this function if the user 
 * changes your application preferences such that the identity might be 
 * invalidated.
 * 
 * \note It is very important that you call #kim_selection_hints_forget_identity()
 * if your application fails to successfully establish a connection with the
 * server. Otherwise the user can get "stuck" using the same non-working 
 * identity if they chose the wrong one accidentally or if their identity 
 * information changes.  Because only your application understands the 
 * authorization checksof the protocol it uses, KIM cannot tell whether or not
 * the identity worked.
 * 
 * If you wish to search and prompt for an identity without using
 * the cached mappings, you can turn off the cached mapping lookups using 
 * #kim_selection_hints_set_remember_identity().  This is not recommended
 * for most applications since it will result in a lot of unnecessary
 * searching and prompting for identities.
 *
 * \note Because cache entries key off of selection hints, it is important
 * to always specify the same hints when contacting a particular
 * service.  Otherwise KIM will not always find the cache entries.
 *
 * \section kim_selection_hints_prompt Selection Hint Prompting Behavior
 * 
 * If valid credentials for identity in the selection hints cache are
 * unavailable or if no identity could be found using searching or caching
 * when #kim_selection_hints_get_identity() is called, KIM may present a 
 * GUI to ask the user to select an identity or acquire credentials for 
 * an identity.  
 *
 * \note Because of the caching behavior described above the user will 
 * only be prompted to choose an identity when setting up the application 
 * or when their identity stops working. 
 *
 * In order to let the user know why Kerberos needs their assistance, KIM  
 * displays the name of the application which requested the identity   
 * selection. Unfortunately, some platforms do not provide a runtime 
 * mechanism for determining the name of the calling process.  If your 
 * application runs on one of these platforms (or is cross-platform) 
 * you should provide a localized version of its name with 
 * the private function #kim_library_set_application_name().
 *
 * In many cases a single application may select different identities for 
 * different purposes.  For example an email application might use different 
 * identities to check mail for different accounts.  If your application 
 * has this property you may need to provide the user with a localized 
 * string describing how the identity will be used.  You can specify 
 * this string with #kim_selection_hints_get_explanation().  You can find 
 * out what string will be used with kim_selection_hints_set_explanation().
 *
 * Since the user may choose to acquire credentials when selection an
 * identity, KIM also provides #kim_selection_hints_set_options() to 
 * set what credential acquisition options are used.  
 * #kim_selection_hints_get_options() returns the options which will be used. 
 *
 * If you need to disable user interaction, use 
 * #kim_selection_hints_set_allow_user_interaction().  Use 
 * #kim_selection_hints_get_allow_user_interaction() to find out whether or
 * not user interaction is enabled.  User interaction is enabled by default.
 *
 * See \ref kim_selection_hints_reference for information on specific APIs.
 */

/*!
 * \defgroup kim_selection_hints_reference KIM Selection Hints Reference Documentation
 * @{
 */

/*! A client identity in this realm. 
 * See \ref kim_selection_hints_overview for more information */
#define kim_hint_key_client_realm     "kim_hint_key_client_realm"

/*! A client identity whose first component is this user string. 
 * See \ref kim_selection_hints_overview for more information */
#define kim_hint_key_user             "kim_hint_key_user"

/*! A client identity which has obtained a service credential for this realm.
 * See \ref kim_selection_hints_overview for more information */
#define kim_hint_key_service_realm    "kim_hint_key_service_realm"

/*! A client identity which has obtained a service credential for this service. 
 * See \ref kim_selection_hints_overview for more information */
#define kim_hint_key_service          "kim_hint_key_service"

/*! A client identity which has obtained a service credential for this server.
 * See \ref kim_selection_hints_overview for more information */
#define kim_hint_key_server           "kim_hint_key_server"

/*! The client identity which has obtained a service credential for this service identity. 
 * See \ref kim_selection_hints_overview for more information */
#define kim_hint_key_service_identity "kim_hint_key_service_identity"
    
/*!
 * \param out_selection_hints       on exit, a new selection hints object.  
 *                                  Must be freed with kim_selection_hints_free().
 * \param in_application_identifier an application identifier string.  Java-style identifiers are recommended 
 *                                  to avoid cache entry collisions (eg: "com.example.MyApplication")
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Create a new selection hints object.
 */
kim_error kim_selection_hints_create (kim_selection_hints *out_selection_hints,
                                        kim_string           in_application_identifier);

/*!
 * \param out_selection_hints on exit, a new selection hints object which is a copy of in_selection_hints.  
 *                            Must be freed with kim_selection_hints_free().
 * \param in_selection_hints  a selection hints object. 
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Copy a selection hints object.
 */
kim_error kim_selection_hints_copy (kim_selection_hints *out_selection_hints,
                                      kim_selection_hints  in_selection_hints);

/*!
 * \param io_selection_hints    a selection hints object to modify.
 * \param in_hint_key           A string representing the type of hint to set.
 * \param in_hint_string        A string representation of a hint for
 *                              \a in_hint_key to set in \a in_selection_hints.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Set the string value of a hint used for identity selection.
 * \sa kim_selection_hints_get_hint()
 */
kim_error kim_selection_hints_set_hint (kim_selection_hints io_selection_hints,
                                        kim_string          in_hint_key,
                                        kim_string          in_hint_string);

/*!
 * \param in_selection_hints    a selection hints object.
 * \param in_hint_key           A string representing the type of hint to 
 *                              obtain.
 * \param out_hint_string       On exit, a string representation of the hint 
 *                              \a in_hint_key in \a in_selection_hints.
 *                              If the hint is not set, sets the value pointed
 *                              to by \a out_hint_string to NULL;
 *                              Must be freed with kim_string_free().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the string value of a hint used for identity selection.
 * \sa kim_selection_hints_set_hint()
 */
kim_error kim_selection_hints_get_hint (kim_selection_hints  in_selection_hints,
                                        kim_string           in_hint_key,
                                        kim_string          *out_hint_string);

/*!
 * \param io_selection_hints  a selection hints object to modify.
 * \param in_explanation      a localized string describing why the caller needs the identity.
 * \note If the application only does one thing (the reason it needs an identity is obvious) 
 * then you may not need to call this function.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Set the strings used to prompt the user to select the identity.
 * \sa kim_selection_hints_get_explanation()
 */
kim_error kim_selection_hints_set_explanation (kim_selection_hints io_selection_hints,
                                                 kim_string          in_explanation);

/*!
 * \param in_selection_hints   a selection hints object.
 * \param out_explanation      on exit, the localized string specified in \a in_selection_hints
 *                             which describes why the caller needs the identity.  May be NULL.
 *                             If non-NULL, must be freed with kim_string_free().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the strings used to prompt the user to select the identity.
 * \sa kim_selection_hints_set_explanation()
 */
kim_error kim_selection_hints_get_explanation (kim_selection_hints  in_selection_hints,
                                                 kim_string          *out_explanation);


/*!
 * \param io_selection_hints  a selection hints object to modify.
 * \param in_options          options to control credential acquisition. 
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Set the options which will be used if credentials need to be acquired.
 * \sa kim_selection_hints_get_options()
 */
kim_error kim_selection_hints_set_options (kim_selection_hints io_selection_hints,
                                             kim_options         in_options);

/*!
 * \param in_selection_hints a selection hints object.
 * \param out_options        on exit, the options to control credential acquisition  
 *                           specified in \a in_selection_hints.  May be KIM_OPTIONS_DEFAULT.
 *                           If not, must be freed with kim_options_free().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the options which will be used if credentials need to be acquired.
 * \sa kim_selection_hints_set_options()
 */
kim_error kim_selection_hints_get_options (kim_selection_hints  in_selection_hints,
                                             kim_options         *out_options);

/*!
 * \param in_selection_hints        a selection hints object to modify
 * \param in_allow_user_interaction a boolean value specifying whether or not KIM should ask
 *                                  the user to select an identity for \a in_selection_hints.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \note This setting defaults to TRUE.
 * \brief Set whether or not KIM may interact with the user to select an identity.
 * \sa kim_selection_hints_get_allow_user_interaction
 */
kim_error kim_selection_hints_set_allow_user_interaction (kim_selection_hints in_selection_hints,
                                                            kim_boolean         in_allow_user_interaction);

/*!
 * \param in_selection_hints         a selection hints object to modify
 * \param out_allow_user_interaction on exit, a boolean value specifying whether or not KIM 
 *                                   should ask the user to select an identity for 
 *                                   \a in_selection_hints.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \note This setting defaults to TRUE.
 * \brief Get whether or not KIM may interact with the user to select an identity.
 * \sa kim_selection_hints_set_allow_user_interaction
 */
kim_error kim_selection_hints_get_allow_user_interaction (kim_selection_hints  in_selection_hints,
                                                            kim_boolean         *out_allow_user_interaction);

/*!
 * \param in_selection_hints    a selection hints object to modify
 * \param in_remember_identity  a boolean value specifying whether or not KIM should use a cached
 *                              mapping between \a in_selection_hints and a Kerberos identity.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \note This setting defaults to TRUE.
 * \brief Set whether or not KIM will use cached mappings for this selection hints object.
 * \sa kim_selection_hints_get_remember_identity
 */
kim_error kim_selection_hints_set_remember_identity (kim_selection_hints in_selection_hints,
                                                       kim_boolean         in_remember_identity);

/*!
 * \param in_selection_hints     a selection hints object to modify
 * \param out_remember_identity on exit, a boolean value specifying whether or not KIM will use a 
 *                               cached mapping between \a in_selection_hints and a Kerberos identity.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \note This setting defaults to TRUE.
 * \brief Get whether or not KIM will use cache mappings for this selection hints object.
 * \sa kim_selection_hints_set_remember_identity
 */
kim_error kim_selection_hints_get_remember_identity (kim_selection_hints  in_selection_hints,
                                                       kim_boolean         *out_remember_identity);

/*!
 * \param in_selection_hints the selection hints to add to the cache.
 * \param out_identity       the Kerberos identity \a in_selection_hints maps to.
 *                           Must be freed with kim_identity_free().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \note \a out_identity is the identity mapped to by the current state of \a in_selection_hints.
 * This function may prompt the user via a GUI to choose that identity.
 * Subsequent modifications to \a in_selection_hints will not change \a out_identity.
 * \brief Choose a client identity based on selection hints.
 */

kim_error kim_selection_hints_get_identity (kim_selection_hints in_selection_hints,
                                              kim_identity        *out_identity);

/*!
 * \param in_selection_hints the selection hints to add to the cache.
 * \param in_identity the Kerberos identity \a in_selection_hints maps to.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Add an entry for the selection hints to the selection hints cache, 
 * replacing any existing entry.
 */

kim_error kim_selection_hints_remember_identity (kim_selection_hints in_selection_hints,
                                                   kim_identity        in_identity);

/*!
 * \param in_selection_hints the selection hints to remove from the cache.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Remove an entry for the selection hints from the selection hints cache.
 */

kim_error kim_selection_hints_forget_identity (kim_selection_hints in_selection_hints);

/*!
 * \param io_selection_hints the selection hints object to be freed.  Set to NULL on exit.
 * \brief Free memory associated with a selection hints object.
 */

void kim_selection_hints_free (kim_selection_hints *io_selection_hints);

/*!@}*/

#ifdef __cplusplus
}
#endif

#endif /* KIM_SELECTION_HINTS_H */

/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
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

#ifndef KIM_CCACHE_H
#define KIM_CCACHE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <kim/kim_types.h>

/*!
 * \page kim_ccache_overview KIM CCache Overview
 *
 * \section kim_ccache_introduction Introduction
 *
 * Kerberos credentials are stored in "ccaches" (short for "credentials caches").
 * The set of all ccaches which the KIM can use is called the "cache collection".
 * Each ccache has a name and type which uniquely identify it in the cache
 * collection and a client identity.  The ccache's client identity is the
 * identity whose credentials are stored in the ccache.  This allows for easy
 * lookup of all the credentials for a given identity.
 *
 * KIM attempts to preserve a one-to-one relationship between client identities
 * and ccaches.  If the KIM is used to manipulate the cache collection, there
 * will be one ccache per identity.  However, because low-level APIs allow callers
 * to create multiple ccaches for the same client identity or a single ccache
 * containing credentials for different client identities, KIM handles those
 * situations.  In general when searching KIM will find the first ccache matching
 * the requested client identity.  It will not find credentials for the requested
 * client identity if they are in a ccache with a different client identity.
 *
 * The kim_ccache_t object is a reference to a ccache in the cache collection.
 * If other applications make changes to the the ccache pointed to by a KIM ccache
 * object, the object will immediately show those changes.  KIM performs locking
 * on the cache collection to prevent deadlocks and maintain a consistent behavior
 * when multiple applications attempt to modify the cache collection.
 *
 * \note KIM ccache APIs are intended for applications and system
 * tools which manage credentials for the user.  They are not a substitute for
 * krb5 and GSSAPI functions which obtain service credentials for the purpose
 * of authenticating a client to an application server.
 *
 * \section kim_credential_cache_collection Acquiring a CCache from the Cache Collection
 *
 * KIM provides a simple iterator API for iterating over the ccaches
 * in the cache collection.  First, call #kim_ccache_iterator_create() to obtain
 * an iterator for the cache collection.  Then loop calling
 * #kim_ccache_iterator_next() until either you find the ccache you are looking
 * for or the API returns a NULL ccache, indicating that there are no more
 * ccaches in the cache collection.  When you are done with the iterator, call
 * #kim_ccache_iterator_free().
 *
 * \note #kim_ccache_iterator_next() returns ccache objects which
 * must be freed with #kim_ccache_free() to avoid leaking memory.
 *
 * KIM also provides a convenient API #kim_ccache_create_from_client_identity()
 * which returns the ccache for a specific client identity, if any exists.
 * Typically callers of this API obtain the client identity using
 * #kim_selection_hints_get_identity().
 *
 *
 * \section kim_ccache_acquire_default Acquiring Credentials from the Default CCache
 *
 * #kim_ccache_create_from_default() returns the default ccache.
 * The default ccache is a legacy concept which was replaced by selection
 * hints.  Prior to the existence of selection hints, applications always
 * looked at the default ccache for credentials.  By setting the system default
 * ccache, users could manually control which credentials each application used.
 * As the number of ccaches and applications has grown, this mechanism has become
 * unusable.  You should avoid using this API whenever possible.
 *
 *
 * \section kim_ccache_acquire_new Acquiring New Credentials in a CCache
 *
 * KIM provides the #kim_ccache_create_new() API for acquiring new
 * credentials and storing them in a ccache.  Credentials can either be
 * obtained for a specific client identity or by specifying
 * #KIM_IDENTITY_ANY to allow the user to choose.  Typically
 * callers of this API obtain the client identity using
 * #kim_selection_hints_get_identity().  Depending on the kim_options
 * specified, #kim_ccache_create_new() may present a GUI or command line
 * prompt to obtain information from the user.
 *
 * #kim_ccache_create_new_if_needed()
 * searches the cache collection for a ccache for the client identity
 * and if no appropriate ccache is available, attempts to acquire
 * new credentials and store them in a new ccache.  Depending on the
 * kim_options specified, #kim_ccache_create_new_if_needed() may
 * present a GUI or command line prompt to obtain information from the
 * user. This function exists for convenience and to avoid code duplication.
 * It can be trivially implemented using
 * #kim_ccache_create_from_client_identity() and #kim_ccache_create_new().
 *
 * For legacy password-based Kerberos environments KIM also provides
 * #kim_ccache_create_new_with_password() and
 * #kim_ccache_create_new_if_needed_with_password().  You should not use these
 * functions unless you know that they will only be used in environments using
 * passwords.  Otherwise users without passwords may be prompted for them.
 *
 * KIM provides the #kim_ccache_create_from_keytab() to create credentials
 * using a keytab and store them in the cache collection. A keytab is an
 * on-disk copy of a client identity's secret key.  Typically sites use
 * keytabs for client identities that identify a machine or service and
 * protect the keytab with disk permissions.  Because a keytab is
 * sufficient to obtain credentials, keytabs will normally only be readable
 * by root, Administrator or some other privileged account.
 * Typically applications use credentials obtained from keytabs to obtain
 * credentials for batch processes.  These keytabs and credentials are usually
 * for a special identity used for the batch process rather than a user
 * identity.
 *
 *
 * \section kim_ccache_validate Validating Credentials in a CCache
 *
 * A credential with a start time in the future (ie: after the issue date)
 * is called a post-dated credential.  Because the KDC administrator may
 * wish to disable a identity, once the start time is reached, all post-dated
 * credentials must be validated before they can be used.  Otherwise an
 * attacker using a compromised account could acquire lots of post-dated
 * credentials to circumvent the acccount being disabled.
 *
 * KIM provides the #kim_ccache_validate() API to validate the TGT
 * credential in a ccache. Note that this API replaces any existing
 * credentials with the validated credential.
 *
 *
 * \section kim_ccache_renew Renewing Credentials in a CCache
 *
 * A renewable credential can be used to obtain a new identical credential
 * without resending secret information (such as a password) to the KDC.
 * A credential may only be renewed during its renewal lifetime and while
 * valid.
 *
 * KIM provides the #kim_ccache_renew() API to renew the TGT credential
 * in a ccache. Note that this API replaces any existing credentials with the
 * renewed credential.
 *
 *
 * \section kim_ccache_verify Verifying Credentials in a CCache
 *
 * When a program acquires TGT credentials for the purpose of authenticating
 * itself to the machine it is running on, it is insufficient for the machine
 * to assume that the caller is authorized just because it got credentials.
 * Instead, the credentials must be verified using a key the local machine.
 * The reason this is necessary is because an attacker can trick the
 * machine into obtaining credentials from any KDC, including malicious ones
 * with the same realm name as the local machine's realm.  This exploit is
 * called the Zanarotti attack.
 *
 * In order to avoid the Zanarotti attack, the local machine must authenticate
 * the process in the same way an application server would authenticate a client.
 * Like an application server, the local machine must have its own identity in
 * its realm and a keytab for that identity on its local disk.    However,
 * rather than forcing system daemons to use the network-oriented calls in the
 * krb5 and GSS APIs, KIM provides the #kim_ccache_verify() API to
 * verify credentials directly.
 *
 * The most common reason for using #kim_ccache_verify() is user login.
 * If the local machine wants to use Kerberos to verify the username and password
 * provided by the user, it must call #kim_ccache_verify() on the credentials
 * it obtains to make sure they are really from a KDC it trusts.  Another common
 * case is a server which is only using Kerberos internally.  For example an
 * LDAP or web server might use a username and password obtained over the network
 * to get Kerberos credentials.  In order to make sure they aren't being tricked
 * into talking to the wrong KDC, these servers must also call
 * #kim_ccache_verify().
 *
 * The Zanarotti attack is only a concern if the act of accessing the machine
 * gives the process special access.  Thus a managed cluster machine with
 * Kerberos-authenticated networked home directories does not need to call
 * #kim_ccache_verify().  Even though an attacker can log in as any user on
 * the cluster machine, the attacker can't actually access any of the user's data
 * or use any of their privileges because those are all authenticated via
 * Kerberized application servers (and thus require actually having credentials
 * for the real local realm).
 *
 * #kim_ccache_verify() provides an option to
 * return success even if the machine's host key is not present.  This option
 * exists for sites which have a mix of different machines, some of which are
 * vulnerable to the Zanarotti attack and some are not.  If this option is used,
 * it is the responsiblity of the machine's maintainer to obtain a keytab
 * for their machine if it needs one.
 *
 *
 * \section kim_ccache_properties Examining CCache Properties
 *
 * \li #kim_ccache_get_type() returns the type of the ccache.  Types include
 * "API" for CCAPI ccaches, "FILE" for file-based ccaches and "MEMORY" for
 * single-process in-memory ccaches.
 *
 * \li #kim_ccache_get_name() returns the name of the ccache.  A ccache's name
 * identifies the ccache uniquely among ccaches of the same type.  Note that
 * two ccaches with different types may have the same name.
 *
 * \li #kim_ccache_get_display_name() returns a display string which uniquely
 * identifies a ccache.  A ccache display name is of the form "<type>:<name>"
 * and can be displayed to the user or used as an argument to certain krb5
 * APIs, such as krb5_cc_resolve().
 *
 * \li #kim_ccache_get_client_identity()
 * returns the ccache's client identity.
 *
 * \li #kim_ccache_get_valid_credential()
 * returns the first valid TGT in the ccache for its client identity.
 * If there are no TGTs in the ccache, it returns the first
 * valid non-TGT credential for the ccache's client identity.
 * TGT credentials (ie: "ticket-granting tickets") are credentials for
 * the krbtgt service: a service identity of the form "krbtgt/<REALM>@<REALM>".
 * These credentials allow the entity named by the client identity to obtain
 * additional credentials without resending shared secrets (such as a password)
 * to the KDC. Kerberos uses TGTs to provide single sign-on authentication.
 *
 * \li #kim_ccache_get_start_time()
 * returns when the credential's in a ccache will become valid.
 * Credentials may be "post-dated" which means that their lifetime starts sometime
 * in the future.  Note that when a post-dated credential's start time is reached,
 * the credential must be validated.  See \ref kim_credential_validate for more information.
 *
 * \li #kim_ccache_get_expiration_time()
 * returns when the credential's in a ccache will expire.
 * Credentials are time limited by the lifetime of the credential.  While you can
 * request a credential of any lifetime, the KDC limits the credential lifetime
 * to a administrator-defined maximum.  Typically credential lifetime range from 10
 * to 21 hours.
 *
 * \li #kim_ccache_get_renewal_expiration_time()
 * returns when the credential's in a ccache will no longer be renewable.
 * Valid credentials may be renewed up until their renewal expiration time.
 * Renewing credentials acquires a fresh set of credentials with a full lifetime
 * without resending secrets to the KDC (such as a password).  If credentials are
 * not renewable, this function will return an error.
 *
 * \li #kim_ccache_get_options()
 * returns a kim_options object with the credential options of the credentials
 * in the ccache.  This function is intended to be used when adding
 * an identity with existing credentials to the favorite identities list.
 * By passing in the options returned by this call, future requests for the
 * favorite identity will use the same credential options.
 *
 * See \ref kim_ccache_reference and \ref kim_ccache_iterator_reference for
 * information on specific APIs.
 */


/*!
 * \defgroup kim_ccache_iterator_reference KIM CCache Iterator Reference Documentation
 * @{
 */

/*!
 * \param out_ccache_iterator on exit, a ccache iterator object for the cache collection.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get a ccache iterator to enumerate ccaches in the cache collection.
 */
kim_error kim_ccache_iterator_create (kim_ccache_iterator *out_ccache_iterator);

/*!
 * \param in_ccache_iterator a ccache iterator object.
 * \param out_ccache         on exit, the next ccache in the cache collection. If there are
 *                           no more ccaches in the cache collection this argument will be
 *                           set to NULL.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the next ccache in the cache collection.
 */
kim_error kim_ccache_iterator_next (kim_ccache_iterator  in_ccache_iterator,
                                    kim_ccache          *out_ccache);

/*!
 * \param io_ccache_iterator a ccache iterator object to be freed.  Set to NULL on exit.
 * \brief Free memory associated with a ccache iterator.
 */
void kim_ccache_iterator_free (kim_ccache_iterator *io_ccache_iterator);

/*!@}*/

/*!
 * \defgroup kim_ccache_reference KIM CCache Reference Documentation
 * @{
 */

/*!
 * \param out_ccache          on exit, a new cache object for a ccache containing a newly acquired
 *                            initial credential.  Must be freed with kim_ccache_free().
 * \param in_client_identity  a client identity to obtain a credential for.   Specify KIM_IDENTITY_ANY to
 *                            allow the user to choose.
 * \param in_options          options to control credential acquisition.
 * \note #kim_ccache_create_new() may
 * present a GUI or command line prompt to obtain information from the user.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Acquire a new initial credential and store it in a ccache.
 */
kim_error kim_ccache_create_new (kim_ccache          *out_ccache,
                                 kim_identity         in_client_identity,
                                 kim_options          in_options);

/*!
 * \param out_ccache          on exit, a new cache object for a ccache containing a newly acquired
 *                            initial credential.  Must be freed with kim_ccache_free().
 * \param in_client_identity  a client identity to obtain a credential for.   Specify KIM_IDENTITY_ANY to
 *                            allow the user to choose.
 * \param in_options          options to control credential acquisition.
 * \param in_password         a password to be used while obtaining credentials.
 * \note #kim_ccache_create_new_with_password() exists to support
 * legacy password-based Kerberos environments.  You should not use this
 * function unless you know that it will only be used in environments using passwords.
 * This function may also present a GUI or command line prompt to obtain
 * additional information needed to obtain credentials (eg: SecurID pin).
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Acquire a new initial credential and store it in a ccache
 * using the provided password..
 */
kim_error kim_ccache_create_new_with_password (kim_ccache   *out_ccache,
                                               kim_identity  in_client_identity,
                                               kim_options   in_options,
                                               kim_string    in_password);

/*!
 * \param out_ccache          on exit, a ccache object for a ccache containing a newly acquired
 *                            initial credential. Must be freed with kim_ccache_free().
 * \param in_client_identity  a client identity to obtain a credential for.
 * \param in_options          options to control credential acquisition (if a credential is acquired).
 * \note #kim_ccache_create_new_if_needed() may
 * present a GUI or command line prompt to obtain information from the user.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Find a ccache containing a valid initial credential in the cache collection, or if
 *        unavailable, acquire and store a new initial credential.
 */
kim_error kim_ccache_create_new_if_needed (kim_ccache   *out_ccache,
                                           kim_identity  in_client_identity,
                                           kim_options   in_options);

/*!
 * \param out_ccache          on exit, a ccache object for a ccache containing a newly acquired
 *                            initial credential. Must be freed with kim_ccache_free().
 * \param in_client_identity  a client identity to obtain a credential for.
 * \param in_options          options to control credential acquisition (if a credential is acquired).
 * \param in_password         a password to be used while obtaining credentials.
 * \note #kim_ccache_create_new_if_needed_with_password() exists to support
 * legacy password-based Kerberos environments.  You should not use this
 * function unless you know that it will only be used in environments using passwords.
 * This function may also present a GUI or command line prompt to obtain
 * additional information needed to obtain credentials (eg: SecurID pin).
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Find a ccache containing a valid initial credential in the cache collection, or if
 *        unavailable, acquire and store a new initial credential using the provided password.
 */
kim_error kim_ccache_create_new_if_needed_with_password (kim_ccache   *out_ccache,
                                                         kim_identity  in_client_identity,
                                                         kim_options   in_options,
                                                         kim_string    in_password);

/*!
 * \param out_ccache          on exit, a ccache object for a ccache containing a TGT
 *                            credential. Must be freed with kim_ccache_free().
 * \param in_client_identity  a client identity to find a ccache for.  If
 *                            \a in_client_identity is #KIM_IDENTITY_ANY, this
 *                            function returns the default ccache
 *                            (ie: is equivalent to #kim_ccache_create_from_default()).
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Find a ccache for a client identity in the cache collection.
 */
kim_error kim_ccache_create_from_client_identity (kim_ccache   *out_ccache,
                                                  kim_identity  in_client_identity);

/*!
 * \param out_ccache      on exit, a new ccache object containing an initial credential
 *                        for the client identity \a in_identity obtained using in_keytab.
 *                        Must be freed with kim_ccache_free().
 * \param in_identity     a client identity to obtain a credential for.  Specify NULL for
 *                        the first client identity in the keytab.
 * \param in_options      options to control credential acquisition.
 * \param in_keytab       a path to a keytab.  Specify NULL for the default keytab location.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Acquire a new initial credential from a keytab and store it in a ccache.
 */
kim_error kim_ccache_create_from_keytab (kim_ccache    *out_ccache,
                                         kim_identity   in_identity,
                                         kim_options    in_options,
                                         kim_string     in_keytab);

/*!
 * \param out_ccache on exit, a ccache object for the default ccache.
 *                   Must be freed with kim_ccache_free().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the default ccache.
 */
kim_error kim_ccache_create_from_default (kim_ccache *out_ccache);

/*!
 * \param out_ccache      on exit, a ccache object for the ccache identified by
 *                        \a in_display_name.  Must be freed with kim_ccache_free().
 * \param in_display_name a ccache display name string (ie: "TYPE:NAME").
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \note This API is used to obtain a kim_ccache for a ccache name entered by the user.
 * \brief Get a ccache for a ccache display name.
 */
kim_error kim_ccache_create_from_display_name (kim_ccache  *out_ccache,
                                               kim_string   in_display_name);

/*!
 * \param out_ccache  on exit, a ccache object for the ccache identified by
 *                    \a in_type and \a in_name.  Must be freed with kim_ccache_free().
 * \param in_type     a ccache type string.
 * \param in_name     a ccache name string.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \note This API is provided for backwards compatibilty with applications which are not
 *       KIM-aware and should be avoided whenever possible.
 * \brief Get a ccache for a ccache type and name.
 */
kim_error kim_ccache_create_from_type_and_name (kim_ccache  *out_ccache,
                                                kim_string   in_type,
                                                kim_string   in_name);

/*!
 * \param out_ccache      on exit, a new ccache object which is a copy of in_krb5_ccache.
 *                        Must be freed with kim_ccache_free().
 * \param in_krb5_context the krb5 context used to create \a in_krb5_ccache.
 * \param in_krb5_ccache  a krb5 ccache object.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get a ccache for a krb5 ccache.
 */
kim_error kim_ccache_create_from_krb5_ccache (kim_ccache  *out_ccache,
                                              krb5_context in_krb5_context,
                                              krb5_ccache  in_krb5_ccache);

/*!
 * \param out_ccache on exit, the new ccache object which is a copy of in_ccache.
 *                   Must be freed with kim_ccache_free().
 * \param in_ccache  a ccache object.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Copy a ccache.
 */
kim_error kim_ccache_copy (kim_ccache  *out_ccache,
                           kim_ccache   in_ccache);

/*!
 * \param in_ccache             a ccache object.
 * \param in_compare_to_ccache  a ccache object.
 * \param out_comparison        on exit, a comparison of \a in_ccache and
 *                              \a in_compare_to_ccache which determines whether
 *                              or not the two ccache objects refer to the same ccache.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Compare ccache objects.
 */
kim_error kim_ccache_compare (kim_ccache      in_ccache,
                              kim_ccache      in_compare_to_ccache,
                              kim_comparison *out_comparison);

/*!
 * \param in_ccache        a ccache object.
 * \param in_krb5_context  a krb5 context which will be used to create out_krb5_ccache.
 * \param out_krb5_ccache  on exit, a new krb5 ccache object which is a copy of in_ccache.
 *                         Must be freed with krb5_cc_close() or krb5_cc_destroy().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get a krb5 ccache for a ccache.
 */
kim_error kim_ccache_get_krb5_ccache (kim_ccache  in_ccache,
                                      krb5_context  in_krb5_context,
                                      krb5_ccache  *out_krb5_ccache);

/*!
 * \param in_ccache  a ccache object.
 * \param out_name   on exit, the name string of \a in_ccache.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the name of a ccache.
 */
kim_error kim_ccache_get_name (kim_ccache  in_ccache,
                               kim_string *out_name);

/*!
 * \param in_ccache  a ccache object.
 * \param out_type   on exit, the type string of \a in_ccache.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the type of a ccache.
 */
kim_error kim_ccache_get_type (kim_ccache  in_ccache,
                               kim_string *out_type);

/*!
 * \param in_ccache        a ccache object.
 * \param out_display_name on exit, the type and name of \a in_ccache in a format appropriate for
 *                         display to the user in command line programs.  (ie: "<type>:<name>")
 *                         Must be freed with kim_string_free().
 *                         Note: this string can also be passed to krb5_cc_resolve().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the type and name for a ccache in display format.
 */
kim_error kim_ccache_get_display_name (kim_ccache  in_ccache,
                                       kim_string *out_display_name);

/*!
 * \param in_ccache            a ccache object.
 * \param out_client_identity  on exit, an identity object containing the client identity of
 *                             \a in_ccache. Must be freed with kim_identity_free().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the client identity for a ccache.
 */
kim_error kim_ccache_get_client_identity (kim_ccache    in_ccache,
                                          kim_identity *out_client_identity);

/*!
 * \param in_ccache       a ccache object.
 * \param out_credential  on exit, the first valid credential in \a in_ccache.
 *                        Must be freed with kim_credential_free().  Set to NULL
 *                        if you only want return value, not the actual credential.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the first valid credential in a ccache.
 * \note This function prefers valid TGT credentials.  If there are only non-valid TGTs
 *       in the ccache, it will always return an error.  However, if there are no
 *       TGTs at all, it will return the first valid non-TGT credential. If you only want
 *       TGTs, use kim_credential_is_tgt() to verify that \a out_credential is a tgt.
 */
kim_error kim_ccache_get_valid_credential (kim_ccache      in_ccache,
                                           kim_credential *out_credential);

/*!
 * \param in_ccache     a ccache object.
 * \param out_state     on exit, the state of the credentials in \a in_ccache.
 *                      See #kim_credential_state_enum for the possible values
 *                      of \a out_state.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Check the state of the credentials in a ccache (valid, expired, postdated, etc).
 * \note This function prefers TGT credentials.  If there are any TGTs in the
 *       ccache, it will always return their state.  However, if there are no
 *       TGTs at all, it will return the state of the first non-TGT credential.
 */
kim_error kim_ccache_get_state (kim_ccache            in_ccache,
                                kim_credential_state *out_state);

/*!
 * \param in_ccache      a ccache object.
 * \param out_start_time on exit, the time when the credentials in \a in_ccache
 *                       become valid.  May be in the past or future.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the time when the credentials in the ccache become valid.
 */
kim_error kim_ccache_get_start_time (kim_ccache  in_ccache,
                                     kim_time   *out_start_time);

/*!
 * \param in_ccache           a ccache object.
 * \param out_expiration_time on exit, the time when the credentials in
 *                            \a in_ccache will expire.  May be in the past or future.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the time when the credentials in the ccache will expire.
 */
kim_error kim_ccache_get_expiration_time (kim_ccache  in_ccache,
                                          kim_time   *out_expiration_time);

/*!
 * \param in_ccache                   a ccache object.
 * \param out_renewal_expiration_time on exit, the time when the credentials in \a in_ccache
 *                                    will no longer be renewable. May be in the past or future.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the time when the credentials in the ccache will no longer be renewable.
 */
kim_error kim_ccache_get_renewal_expiration_time (kim_ccache  in_ccache,
                                                  kim_time   *out_renewal_expiration_time);

/*!
 * \param in_ccache      a ccache object.
 * \param out_options    on exit, an options object reflecting the ticket
 *                       options of the credentials in \a in_ccache.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get a kim_options object based on a ccache's credential attributes.
 */
kim_error kim_ccache_get_options (kim_ccache   in_ccache,
                                  kim_options *out_options);

/*!
 * \param io_ccache a ccache object which will be set to the default ccache.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \note This API is provided for backwards compatibilty with applications which are not
 *       KIM-aware and should be avoided whenever possible.
 * \brief Set a ccache to the default ccache.
 */
kim_error kim_ccache_set_default (kim_ccache io_ccache);

/*!
 * \param in_ccache              a ccache object containing the TGT credential to be verified.
 * \param in_service_identity    a service identity to look for in the keytab.  Specify
 *                               KIM_IDENTITY_ANY to use the default service identity
 *                               (usually host/<host's FQDN>@<host's local realm>).
 * \param in_keytab              a path to a keytab.  Specify NULL for the default keytab location.
 * \param in_fail_if_no_service_key whether or not the absence of a key for \a in_service_identity
 *                                  in the host's keytab will cause a failure.
 * \note specifying FALSE for \a in_fail_if_no_service_key may expose the calling program to
 * the Zanarotti attack if the host has no keytab installed.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Verify the TGT in a ccache.
 */
kim_error kim_ccache_verify (kim_ccache   in_ccache,
                             kim_identity in_service_identity,
                             kim_string   in_keytab,
                             kim_boolean  in_fail_if_no_service_key);

/*!
 * \param in_ccache  a ccache object containing a TGT to be renewed.
 * \param in_options initial credential options to be used if a new credential is obtained.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Renew the TGT in a ccache.
 */
kim_error kim_ccache_renew (kim_ccache  in_ccache,
                            kim_options in_options);

/*!
 * \param in_ccache  a ccache object containing a TGT to be validated.
 * \param in_options initial credential options.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Validate the TGT in a ccache.
 */
kim_error kim_ccache_validate (kim_ccache  in_ccache,
                               kim_options in_options);

/*!
 * \param io_ccache  a ccache object to be destroyed.  Set to NULL on exit.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Remove a ccache from the cache collection.
 * \note Frees memory associated with the ccache.  Do not call kim_ccache_free()
 *       after calling this function.
 */
kim_error kim_ccache_destroy (kim_ccache *io_ccache);

/*!
 * \param io_ccache a ccache object to be freed.  Set to NULL on exit.
 * \brief Free memory associated with a ccache.
 */
void kim_ccache_free (kim_ccache *io_ccache);

/*!@}*/

#ifdef __cplusplus
}
#endif

#endif /* KIM_CCACHE_H */

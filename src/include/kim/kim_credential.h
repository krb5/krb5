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

#ifndef KIM_CREDENTIAL_H
#define KIM_CREDENTIAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <kim/kim_types.h>
#include <krb5.h>

/*!
 * \addtogroup kim_types_reference
 * @{
 */

/*!
 * Possible credential states.  Credentials may be:
 * \li valid - The credential can be used.
 * \li expired - The credential's lifetime has been exceeded.
 * \li not_yet_valid - The credential is post dated and the time when
 *                     it becomes valid has not yet been reached.
 * \li needs_validation - The credential is post-dated and although
 *                        the time when it becomes valid has been reached
 *                        it has not yet been validated.
 * \li address_mismatch - The credential contains IP address(es) which do
 *                        not match the host's local address(es).
 */
enum kim_credential_state_enum {
    kim_credentials_state_valid            = 0,
    kim_credentials_state_expired          = 1,
    kim_credentials_state_not_yet_valid    = 2,
    kim_credentials_state_needs_validation = 3,
    kim_credentials_state_address_mismatch = 4
};

/*!
 * The state of a credential.  See #kim_credential_state_enum for
 * possible values.
 */
typedef int kim_credential_state;

/*! @} */

/*!
 * \page kim_credential_overview KIM Credential Overview
 *
 * \section kim_credential_introduction Introduction
 *
 * A Kerberos credential (also called a "Kerberos ticket") is a time-limited
 * token issued by a KDC which authenticates the entity named by the credential's
 * client identity to the service named by the credential's service identity.
 *
 * The kim_credential object contains a single Kerberos credential.  KIM credentials
 * objects are always copies of credentials, not references to credentials
 * stored in the cache collection.  Modifying credential objects in the ccache
 * collection will not change any existing KIM credential objects.
 *
 * KIM credential APIs are intended for applications and system
 * tools which manage credentials for the user.  They are not a substitute for
 * krb5 and GSSAPI functions which obtain service credentials for the purpose
 * of authenticating a client to an application server.
 *
 * \note Many of the APIs listed below have equivalent functions which
 * operate on ccaches.  In most cases applications will want to use the
 * ccache versions of these APIs since they automatically store any
 * newly created credentials.  See \ref kim_ccache_overview for more
 * information.
 *
 *
 * \section kim_credential_acquire_new Acquiring New Credentials
 *
 * KIM provides the #kim_credential_create_new() API for acquiring new
 * credentials.  Credentials can either be obtained for a specific
 * client identity or by specifying #KIM_IDENTITY_ANY to allow
 * the user to choose.  Typically callers of this API obtain the client
 * identity using #kim_selection_hints_get_identity().  Depending on the
 * kim_options specified, #kim_credential_create_new() may present a
 * GUI or command line prompt to obtain information from the user.
 *
 * For legacy password-based Kerberos environments KIM also provides
 * #kim_credential_create_new_with_password().  You should not use this
 * function unless you know that it will only be used in environments using
 * passwords.  Otherwise users without passwords may be prompted for them.
 *
 * KIM provides the #kim_credential_create_from_keytab() to create credentials
 * using a keytab. A keytab is an on-disk copy of a client identity's secret
 * key.  Typically sites use keytabs for client identities that identify a
 * machine or service and protect the keytab with disk permissions.  Because
 * a keytab is sufficient to obtain credentials, keytabs will normally only
 * be readable by root, Administrator or some other privileged account.
 * Typically applications use credentials obtained from keytabs to obtain
 * credentials for batch processes.  These keytabs and credentials are usually
 * for a special identity used for the batch process rather than a user
 * identity.
 *
 *
 * \section kim_credential_validate Validating Credentials
 *
 * A credential with a start time in the future (ie: after the issue date)
 * is called a post-dated credential.  Because the KDC administrator may
 * wish to disable a identity, once the start time is reached, all post-dated
 * credentials must be validated before they can be used.  Otherwise an
 * attacker using a compromised account could acquire lots of post-dated
 * credentials to circumvent the acccount being disabled.
 *
 * KIM provides the #kim_credential_validate() API to validate a credential.
 * Note that this API replaces the credential object with a new validated
 * credential object.  If you wish to store the new credential in the
 * ccache collection you must either call #kim_credential_store() on the
 * validated credential or use #kim_ccache_validate() instead.
 *
 *
 * \section kim_credential_renew Renewing Credentials
 *
 * A renewable credential can be used to obtain a new identical credential
 * without resending secret information (such as a password) to the KDC.
 * A credential may only be renewed during its renewal lifetime and while
 * valid.
 *
 * KIM provides the #kim_credential_renew() API to renew a credential.
 * Note that this API replaces the credential object with a new renewed
 * credential object.  If you wish to store the new credential in the
 * ccache collection you must either call #kim_credential_store() on the
 * renewed credential or use #kim_ccache_renew() instead.
 *
 *
 * \section kim_credential_storing Storing Credentials in the Cache Collection
 *
 * KIM credential objects may be stored in the ccache collection using
 * #kim_credential_store().  This function runs any KIM authentication
 * plugins on the credential and if the plugins return successfully, creates a
 * new ccache for the credential's client identity in the cache collection
 * and stores the credential in that ccache.  Any existing ccaches and credentials
 * for that client identity will be overwritten.   #kim_credential_store() may
 * optionally return a kim_ccache object for the new ccache if you need to perform
 * further operations on the new ccache.
 *
 * Most of the time if you plan to store the credentials you are manipulating, you
 * should use one of KIM ccache APIs.  These functions perform the same operations
 * except that they also call #kim_credential_store() any time the credential object
 * changes.  See \ref kim_ccache_overview for more information.
 *
 *
 * \section kim_credential_iterator Iterating over the Credentials in a CCache
 *
 * KIM provides a simple iterator API for iterating over the credentials
 * in a ccache.  First, call #kim_credential_iterator_create() to obtain
 * an iterator for a ccache.  Then loop calling #kim_credential_iterator_next()
 * until either you find the credential you are looking for or the API
 * returns a NULL credential, indicating that there are no more
 * credentials in the ccache.  When you are done with the iterator, call
 * #kim_credential_iterator_free().
 *
 * \note #kim_credential_iterator_next() returns credential objects which
 * must be freed with #kim_credential_free() to avoid leaking memory.
 *
 *
 * \section kim_credential_verify Verifying Credentials
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
 * krb5 and GSS APIs, KIM provides the #kim_credential_verify() API to
 * verify credentials directly.
 *
 * The most common reason for using #kim_credential_verify() is user login.
 * If the local machine wants to use Kerberos to verify the username and password
 * provided by the user, it must call #kim_credential_verify() on the credentials
 * it obtains to make sure they are really from a KDC it trusts.  Another common
 * case is a server which is only using Kerberos internally.  For example an
 * LDAP or web server might use a username and password obtained over the network
 * to get Kerberos credentials.  In order to make sure they aren't being tricked
 * into talking to the wrong KDC, these servers must also call
 * #kim_credential_verify().
 *
 * The Zanarotti attack is only a concern if the act of accessing the machine
 * gives the process special access.  Thus a managed cluster machine with
 * Kerberos-authenticated networked home directories does not need to call
 * #kim_credential_verify().  Even though an attacker can log in as any user on
 * the cluster machine, the attacker can't actually access any of the user's data
 * or use any of their privileges because those are all authenticated via
 * Kerberized application servers (and thus require actually having credentials
 * for the real local realm).
 *
 * #kim_credential_verify() provides an option to
 * return success even if the machine's host key is not present.  This option
 * exists for sites which have a mix of different machines, some of which are
 * vulnerable to the Zanarotti attack and some are not.  If this option is used,
 * it is the responsiblity of the machine's maintainer to obtain a keytab
 * for their machine if it needs one.
 *
 *
 * \section kim_credential_properties Examining Credential Properties
 *
 * \li #kim_credential_get_client_identity()
 *     returns the credential's client identity.
 *
 * \li #kim_credential_get_service_identity()
 *     returns the credential's service identity.
 *
 * \li #kim_credential_is_tgt()
 *     returns whether the credential is a TGT (ie: "ticket-granting ticket").  TGTs are
 *     credentials for the krbtgt service: a service identity of the form "krbtgt/<REALM>@<REALM>".
 *     These credentials allow the entity named by the client identity to obtain
 *     additional service credentials without resending shared secrets (such as a password)
 *     to the KDC. Kerberos uses TGTs to provide single sign-on authentication.
 *
 * \li #kim_credential_get_state()
 *     returns a #kim_credential_state containing the state of the credential.
 *     Possible values are:
 *     * kim_credentials_state_valid
 *     * kim_credentials_state_expired
 *     * kim_credentials_state_not_yet_valid
 *     * kim_credentials_state_needs_validation
 *     * kim_credentials_state_address_mismatch
 *
 * \li #kim_credential_get_start_time()
 *     returns when the credential will become valid.
 *     Credentials may be "post-dated" which means that their lifetime starts sometime
 *     in the future.  Note that when a post-dated credential's start time is reached,
 *     the credential must be validated.  See \ref kim_credential_validate for more information.
 *
 * \li #kim_credential_get_expiration_time()
 *     returns when the credential will expire.
 *     Credentials are time limited by the lifetime of the credential.  While you can
 *     request a credential of any lifetime, the KDC limits the credential lifetime
 *     to a administrator-defined maximum.  Typically credential lifetime range from 10
 *     to 21 hours.
 *
 * \li #kim_credential_get_renewal_expiration_time()
 *     returns when the credential will no longer be renewable.
 *     Valid credentials may be renewed up until their renewal expiration time.
 *     Renewing credentials acquires a fresh set of credentials with a full lifetime
 *     without resending secrets to the KDC (such as a password).  If credentials are
 *     not renewable, this function will return a renewal expiration time of 0.
 *
 * \li #kim_credential_get_options()
 *     returns a kim_options object with the credential options of the
 *     credential.  This function is intended to be used when adding
 *     an identity with existing credentials to the favorite identities list.
 *     By passing in the options returned by this call, future requests for the
 *     favorite identity will use the same credential options.
 *
 *
 * See \ref kim_credential_reference and \ref kim_credential_iterator_reference for
 * information on specific APIs.
 */

/*!
 * \defgroup kim_credential_iterator_reference KIM Credential Iterator Reference Documentation
 * @{
 */

/*!
 * \param out_credential_iterator on exit, a credential iterator object for \a in_ccache.
 *                                Must be freed with kim_credential_iterator_free().
 * \param in_ccache               a ccache object.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get a credential iterator to enumerate credentials in a ccache.
 */

kim_error kim_credential_iterator_create (kim_credential_iterator *out_credential_iterator,
                                          kim_ccache               in_ccache);

/*!
 * \param in_credential_iterator a credential iterator object.
 * \param out_credential         on exit, the next credential in the ccache iterated by
 *                               \a in_credential_iterator.   Must be freed with
 *                               kim_credential_free(). If there are no more credentials
 *                               this argument will be set to NULL.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the next credential in a ccache.
 */

kim_error kim_credential_iterator_next (kim_credential_iterator  in_credential_iterator,
                                        kim_credential          *out_credential);

/*!
 * \param io_credential_iterator a credential iterator object to be freed.  Set to NULL on exit.
 * \brief Free memory associated with a credential iterator.
 */
void kim_credential_iterator_free (kim_credential_iterator *io_credential_iterator);

/*!@}*/

/*!
 * \defgroup kim_credential_reference KIM Credential Reference Documentation
 * @{
 */

/*!
 * \param out_credential      on exit, a new credential object containing a newly acquired
 *                            initial credential.  Must be freed with kim_credential_free().
 * \param in_client_identity  a client identity to obtain a credential for.   Specify NULL to
 *                            allow the user to choose the identity
 * \param in_options          options to control credential acquisition.
 * \note #kim_credential_create_new() may
 * present a GUI or command line prompt to obtain information from the user.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Acquire a new initial credential.
 * \sa kim_ccache_create_new
 */
kim_error kim_credential_create_new (kim_credential *out_credential,
                                     kim_identity    in_client_identity,
                                     kim_options     in_options);

/*!
 * \param out_credential      on exit, a new credential object containing a newly acquired
 *                            initial credential.  Must be freed with kim_credential_free().
 * \param in_client_identity  a client identity to obtain a credential for.   Specify NULL to
 *                            allow the user to choose the identity
 * \param in_options          options to control credential acquisition.
 * \param in_password         a password to be used while obtaining the credential.
 * \note #kim_credential_create_new_with_password() exists to support
 * legacy password-based Kerberos environments.  You should not use this
 * function unless you know that it will only be used in environments using passwords.
 * This function may also present a GUI or command line prompt to obtain
 * additional information needed to obtain credentials (eg: SecurID pin).
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Acquire a new initial credential using the provided password.
 * \sa kim_ccache_create_new
 */
kim_error kim_credential_create_new_with_password (kim_credential *out_credential,
                                                   kim_identity    in_client_identity,
                                                   kim_options     in_options,
                                                   kim_string      in_password);

/*!
 * \param out_credential  on exit, a new credential object containing an initial credential
 *                        for \a in_identity obtained using \a in_keytab.
 *                        Must be freed with kim_credential_free().
 * \param in_identity     a client identity to obtain a credential for.  Specify NULL for
 *                        the first identity in the keytab.
 * \param in_options      options to control credential acquisition.
 * \param in_keytab       a path to a keytab.  Specify NULL for the default keytab location.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Acquire a new initial credential from a keytab.
 * \sa kim_ccache_create_from_keytab
 */
kim_error kim_credential_create_from_keytab (kim_credential *out_credential,
                                             kim_identity    in_identity,
                                             kim_options     in_options,
                                             kim_string      in_keytab);

/*!
 * \param out_credential  on exit, a new credential object which is a copy of \a in_krb5_creds.
 *                        Must be freed with kim_credential_free().
 * \param in_krb5_context the krb5 context used to create \a in_krb5_creds.
 * \param in_krb5_creds   a krb5 credential object.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Copy a credential from a krb5 credential object.
 */
kim_error kim_credential_create_from_krb5_creds (kim_credential *out_credential,
                                                 krb5_context      in_krb5_context,
                                                 krb5_creds       *in_krb5_creds);

/*!
 * \param out_credential  on exit, a new credential object which is a copy of \a in_credential.
 *                        Must be freed with kim_credential_free().
 * \param in_credential   a credential object.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Copy a credential object.
 */
kim_error kim_credential_copy (kim_credential *out_credential,
                               kim_credential  in_credential);

/*!
 * \param in_credential    a credential object.
 * \param in_krb5_context  a krb5 context which will be used to create \a out_krb5_creds.
 * \param out_krb5_creds   on exit, a new krb5 creds object which is a copy of \a in_credential.
 *                         Must be freed with krb5_free_creds().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get a krb5 credentials object for a credential object.
 */
kim_error kim_credential_get_krb5_creds (kim_credential   in_credential,
                                         krb5_context       in_krb5_context,
                                         krb5_creds       **out_krb5_creds);

/*!
 * \param in_credential        a credential object.
 * \param out_client_identity  on exit, an identity object containing the client identity of
 *                             \a in_credential. Must be freed with kim_identity_free().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the client identity of a credential object.
 */
kim_error kim_credential_get_client_identity (kim_credential  in_credential,
                                              kim_identity   *out_client_identity);

/*!
 * \param in_credential         a credential object.
 * \param out_service_identity  on exit, an identity object containing the service identity of
 *                              \a in_credential. Must be freed with kim_identity_free().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the service identity of a credential object.
 */
kim_error kim_credential_get_service_identity (kim_credential  in_credential,
                                               kim_identity   *out_service_identity);

/*!
 * \param in_credential a credential object.
 * \param out_is_tgt    on exit, whether or not the credential is a TGT.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Check if a credential is a ticket granting ticket.
 */
kim_error kim_credential_is_tgt (kim_credential  in_credential,
                                 kim_boolean     *out_is_tgt);

/*!
 * \param in_credential a credential object.
 * \param out_state     on exit, the state of the credential.  See #kim_credential_state_enum
 *                      for the possible values of \a out_state.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Check the state of a credential (valid, expired, postdated, etc).
 */
kim_error kim_credential_get_state (kim_credential        in_credential,
                                    kim_credential_state *out_state);

/*!
 * \param in_credential  a credential object.
 * \param out_start_time on exit, the time when \a in_credential becomes valid.
 *                       May be in the past or future.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the time when the credentials become valid.
 * \sa kim_ccache_get_start_time
 */
kim_error kim_credential_get_start_time (kim_credential  in_credential,
                                         kim_time       *out_start_time);

/*!
 * \param in_credential       a credential object.
 * \param out_expiration_time on exit, the time when \a in_credential will expire.
 *                            May be in the past or future.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the time when the credentials will expire.
 * \sa kim_ccache_get_expiration_time
 */
kim_error kim_credential_get_expiration_time (kim_credential  in_credential,
                                              kim_time       *out_expiration_time);

/*!
 * \param in_credential               a credential object.
 * \param out_renewal_expiration_time on exit, the time when \a in_credential will no longer
 *                                    be renewable. May be in the past or future.  If
 *                                    credentials are not renewable at all, returns 0.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the time when the credentials will no longer be renewable.
 * \sa kim_ccache_get_renewal_expiration_time
 */
kim_error kim_credential_get_renewal_expiration_time (kim_credential  in_credential,
                                                      kim_time       *out_renewal_expiration_time);

/*!
 * \param in_credential  a credential object.
 * \param out_options    on exit, an options object reflecting the ticket
 *                       options of \a in_credential.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get a kim_options object based on a credential's attributes.
 */
kim_error kim_credential_get_options (kim_credential  in_credential,
                                      kim_options    *out_options);

/*!
 * \param in_credential       a credential object.
 * \param in_client_identity  a client identity.
 * \param out_ccache          on exit, a ccache object containing \a in_credential with the client
 *                            identity \a in_client_identity.  Must be freed with kim_ccache_free().
 *                            Specify NULL if you don't want this return value.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Store a credential in a ccache in the cache collection.
 */
kim_error kim_credential_store (kim_credential  in_credential,
                                kim_identity    in_client_identity,
                                kim_ccache     *out_ccache);

/*!
 * \param in_credential          a TGT credential to be verified.
 * \param in_service_identity    a service identity to look for in the keytab.  Specify
 *                               KIM_IDENTITY_ANY to use the default service identity
 *                               (usually host/<host's FQDN>@<host's local realm>).
 * \param in_keytab              a path to a keytab.  Specify NULL for the default keytab location.
 * \param in_fail_if_no_service_key whether or not the absence of a key for \a in_service_identity
 *                                  in the host's keytab will cause a failure.
 * \note specifying FALSE for \a in_fail_if_no_service_key may expose the calling program to
 * the Zanarotti attack if the host has no keytab installed.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Verify a TGT credential.
 * \sa kim_ccache_verify
 */
kim_error kim_credential_verify (kim_credential in_credential,
                                 kim_identity   in_service_identity,
                                 kim_string     in_keytab,
                                 kim_boolean    in_fail_if_no_service_key);

/*!
 * \param io_credential  a TGT credential to be renewed.  On exit, the old credential
 *                       object will be freed and \a io_credential will be replaced
 *                       with a new renewed credential.  The new credential must be freed
 *                       with kim_credential_free().
 * \param in_options     initial credential options.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Renew a TGT credential.
 * \sa kim_ccache_renew
 */
kim_error kim_credential_renew (kim_credential *io_credential,
                                kim_options     in_options);

/*!
 * \param io_credential  a credential object to be validated. On exit, the old credential
 *                       object will be freed and \a io_credential will be replaced
 *                       with a new validated credential.  The new credential must be freed
 *                       with kim_credential_free().
 * \param in_options     initial credential options.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Validate a TGT credential.
 * \sa kim_ccache_validate
 */
kim_error kim_credential_validate (kim_credential *io_credential,
                                   kim_options     in_options);

/*!
 * \param io_credential the credential object to be freed.  Set to NULL on exit.
 * \brief Free memory associated with a credential object.
 */
void kim_credential_free (kim_credential *io_credential);

/*!@}*/


#ifdef __cplusplus
}
#endif

#endif /* KIM_CREDENTIAL_H */

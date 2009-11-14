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

#ifndef KIM_IDENTITY_H
#define KIM_IDENTITY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <kim/kim_types.h>
#include <krb5.h>
#include <gssapi/gssapi.h>

/*!
 * \ingroup kim_types_reference
 * Constant to specify any Kerberos identity is acceptable.
 */
#define KIM_IDENTITY_ANY ((kim_identity) NULL)

/*!
 * \page kim_identity_overview KIM Identity Overview
 *
 * \section kim_identity_introduction Introduction
 *
 * Identities in Kerberos are named by "principals".  These identies may be people (users)
 * or services (a server running on a host).  When Kerberos issues credentials which
 * authenticate one identity to another, the identity being authenticated is called
 * the "client identity" and the identity being authenticated to is called the
 * "service identity".
 *
 * Kerberos identities are made up of one or more components, as well as the Kerberos realm
 * the entity belongs to.  For client identities the first component is usually the client
 * username (eg: "jdoe").  For service identities the first component is the name of the
 * service (eg: "imap").
 *
 * Kerberos identities have both a binary (opaque) representation and also a string
 * representation.  The string representation consists of the components separated by '/'
 * followed by an '@' and then the realm.  For example, the identity "jdoe/admin@EXAMPLE.COM"
 * represents John Doe's administrator identity at the realm EXAMPLE.COM.  Note that
 * identity components may contain both '/' and '@' characters.  When building a
 * identity from its string representation these syntactic characters must be escaped
 * with '\'.
 *
 *
 * \section kim_identity_create_display Creating and Displaying Identities
 *
 * KIM Identities can be generated from components, their escaped string representation
 * or from a krb5_principal.  Once you have a KIM identity object, you can also get
 * the component, string or krb5_principal representations back out:
 *
 * \li #kim_identity_create_from_components() creates an identity object from a list of components.
 * \li #kim_identity_get_number_of_components() returns the number of components in an identity object.
 * \li #kim_identity_get_component_at_index() return a component of an identity object.
 * \li #kim_identity_get_realm() returns the identity's realm.
 *
 * \li #kim_identity_create_from_string() generates an identity object from an escaped string representation.
 * \li #kim_identity_get_string() returns the identity's escaped string representation.
 * \li #kim_identity_get_display_string() returns a non-escaped string for display to the user.
 * This string cannot be passed into #kim_identity_create_from_string().
 *
 * \li #kim_identity_create_from_krb5_principal() generates an identity object from a krb5_principal object.
 * \li #kim_identity_get_krb5_principal() returns a krb5_principal object for an identity object.
 *
 * \note If you need to know if two identity objects refer to the same entity, use #kim_identity_compare().
 *
 *
 * \section kim_identity_selection Choosing a Client Identity
 *
 * Unfortunately most of the time applications don't know what client identity to use.
 * Users may have identities for multiple Kerberos realms, as well as multiple identities
 * in a single realm (such as a user and administrator identity).
 *
 * To solve this problem, #kim_selection_hints_get_identity() takes information
 * from the application in the form of a selection hints object and returns the best
 * matching client identity, if one is available.  See \ref kim_selection_hints_overview
 * for more information.
 *
 *
 * \section kim_identity_password Changing a Identity's Password
 *
 * Many Kerberos sites use passwords for user accounts.  Because passwords may be
 * stolen or compromised, they must be frequently changed.  KIM provides APIs to
 * change the identity's password directly, and also handles changing the identity's
 * password when it has expired.
 *
 * #kim_identity_change_password() presents a user interface to obtain the old and
 * new passwords from the user.
 *
 * \note Not all identities have a password. Some sites use certificates (pkinit)
 * and in the future there may be other authentication mechanisms (eg: smart cards).
 *
 * See \ref kim_identity_reference for information on specific APIs.
 */

/*!
 * \defgroup kim_identity_reference KIM Identity Reference Documentation
 * @{
 */

/*!
 * \param out_identity  on exit, a new identity object. Must be freed with kim_identity_free().
 * \param in_string     a string representation of a Kerberos identity.
 *                      Special characters such as '/' and '@' must be escaped with '\'.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Create a identity from a string.
 */
kim_error kim_identity_create_from_string (kim_identity *out_identity,
                                           kim_string    in_string);

/*!
 * \param out_identity     on exit, a new identity object.  Must be freed with kim_identity_free().
 * \param in_realm         a string representation of a Kerberos realm.
 * \param in_1st_component a string representing the first component of the identity.
 * \param ...              zero or more strings of type kim_string_t representing additional components
 *                         of the identity followed by a terminating NULL.  Components will be assembled in
 *                         order (ie: the 4th argument to kim_identity_create_from_components() will be
 *                         the 2nd component of the identity).
 * \note The last argument must be a NULL or kim_identity_create_from_components() may crash.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Create a identity from a realm and component strings.
 */
kim_error kim_identity_create_from_components (kim_identity *out_identity,
                                               kim_string    in_realm,
                                               kim_string    in_1st_component,
                                               ...);

/*!
 * \param out_identity      on exit, a new identity object which is a copy of \a in_krb5_principal.
 *                          Must be freed with kim_identity_free().
 * \param in_krb5_context   the krb5 context used to create \a in_krb5_principal.
 * \param in_krb5_principal a krb5 principal object.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Create an identity object from a krb5_principal.
 */
kim_error kim_identity_create_from_krb5_principal (kim_identity *out_identity,
                                                   krb5_context    in_krb5_context,
                                                   krb5_principal  in_krb5_principal);

/*!
 * \param out_identity  on exit, a new identity object which is a copy of \a in_identity.
 *                      Must be freed with kim_identity_free().
 * \param in_identity  an identity object.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Copy an identity object.
 */
kim_error kim_identity_copy (kim_identity *out_identity,
                             kim_identity  in_identity);


/*!
 * \param in_identity             an identity object.
 * \param in_compare_to_identity  an identity object.
 * \param out_comparison          on exit, a comparison of \a in_identity and
 *                                \a in_compare_to_identity which determines whether
 *                                or not the two identities are equivalent and their
 *                                sort order (for display to the user) if they are not.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Compare identity objects for equivalency.
 */
kim_error kim_identity_compare (kim_identity    in_identity,
                                kim_identity    in_compare_to_identity,
                                kim_comparison *out_comparison);
/*!
 * \param in_identity  an identity object.
 * \param out_string   on exit, a string representation of \a in_identity.
 *                     Must be freed with kim_string_free().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the string representation of a identity.
 * \note  Special characters such as '@' and '/' will be escaped with '\'.
 */
kim_error kim_identity_get_string (kim_identity   in_identity,
                                   kim_string    *out_string);


/*!
 * \param in_identity        an identity object.
 * \param out_display_string on exit, a string representation of \a in_identity appropriate for
 *                           display to the user.  Must be freed with kim_string_free().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get a human-readable string representation of an identity.
 * \note Special characters such as '/' and '@' are \em not escaped with '\'.  As a result the
 *        string returned from this function cannot be used with kim_identity_create_from_string()
 *        because it does not uniquely specify a principal.
 *        The result of this function should \em only be used to display to the user.
 */
kim_error kim_identity_get_display_string (kim_identity   in_identity,
                                           kim_string    *out_display_string);

/*!
 * \param in_identity     an identity object.
 * \param out_realm_string on exit, a string representation of \a in_identity's realm.
 *                         Must be freed with kim_string_free().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the realm string of an identity.
 */
kim_error kim_identity_get_realm (kim_identity  in_identity,
                                  kim_string   *out_realm_string);

/*!
 * \param in_identity             an identity object.
 * \param out_number_of_components on exit the number of components in \a in_identity.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the number of components of an identity.
 */
kim_error kim_identity_get_number_of_components (kim_identity  in_identity,
                                                 kim_count    *out_number_of_components);

/*!
 * \param in_identity          an identity object.
 * \param in_index             the index of the desired component.  Component indexes start at 0.
 * \param out_component_string on exit, a string representation of the component in \a in_identity
 *                             specified by \a in_index.  Must be freed with kim_string_free().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the Nth component of an identity.
 */
kim_error kim_identity_get_component_at_index (kim_identity  in_identity,
                                               kim_count     in_index,
                                               kim_string   *out_component_string);

/*!
 * \param in_identity      an identity object.
 * \param out_components   on exit, a string of the non-realm components of \a in_identity
 *                         separated by '/' characters.  Must be freed with kim_string_free().
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get a display string of the non-realm components of an identity.
 */
kim_error kim_identity_get_components_string (kim_identity  in_identity,
                                              kim_string   *out_components);

/*!
 * \param in_identity        an identity object.
 * \param in_krb5_context    a krb5 context object.
 * \param out_krb5_principal on exit, a krb5_principal representation of \a in_identity
 *                           allocated with \a in_krb5_context. Must be freed with
 *                           krb5_free_principal() using \a in_krb5_context.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Get the krb5_principal representation of an identity.
 */
kim_error kim_identity_get_krb5_principal (kim_identity  in_identity,
                                           krb5_context    in_krb5_context,
                                           krb5_principal *out_krb5_principal);

/*!
 * \param in_identity  an identity object whose password will be changed.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Change the password for an identity.
 * \note kim_identity_change_password() will acquire a temporary credential to change
 * the password.
 */
kim_error kim_identity_change_password (kim_identity  in_identity);

/*!
 * \param io_identity the identity object to be freed.  Set to NULL on exit.
 * \brief Free memory associated with an identity.
 */
void kim_identity_free (kim_identity *io_identity);

/*!@}*/

#ifdef __cplusplus
}
#endif

#endif /* KIM_IDENTITY_H */

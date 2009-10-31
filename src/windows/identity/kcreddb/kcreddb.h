/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* $Id$ */

#ifndef __KHIMAIRA_KCREDDB_H__
#define __KHIMAIRA_KCREDDB_H__

#include<khdefs.h>
#include<time.h>


/*! \defgroup kcdb NetIDMgr Credentials Database */
/*@{*/

/*! \brief Maximum length in characters of short description

    The length includes the terminating \a NULL character.
    */
#define KCDB_MAXCCH_SHORT_DESC  256

/*! \brief Maximum length in bytes of short description

    The length includes the terminating \a NULL character.
    */
#define KCDB_MAXCB_SHORT_DESC   (sizeof(wchar_t) * KCDB_MAXCCH_SHORT_DESC)

/*! \brief Maximum length in characters of long description

    The length includes the terminating \a NULL character.
    */
#define KCDB_MAXCCH_LONG_DESC   8192

/*! \brief Maximum length in characters of long description

    The length includes the terminating \a NULL character.
    */
#define KCDB_MAXCB_LONG_DESC    (sizeof(wchar_t) * KCDB_MAXCCH_LONG_DESC)

/*! \brief Maximum length in characters of name

    The length includes the terminating \a NULL character.
    */
#define KCDB_MAXCCH_NAME        256

/*! \brief Maximum length in bytes of short description

    The length includes the terminating \a NULL character.
    */
#define KCDB_MAXCB_NAME         (sizeof(wchar_t) * KCDB_MAXCCH_NAME)

/*! \brief Automatically determine the number of bytes required

    Can be used in most places where a count of bytes is required.
    For many objects, the number of bytes that are required can be
    determined through context and may be ommited.  In such cases you
    can use the \a KCDB_CBSIZE_AUTO value to specify that the function
    is to determine the size automatically.

    \note Not all functions that take a count of bytes support the \a
        KCDB_CBSIZE_AUTO value.
*/
#define KCDB_CBSIZE_AUTO ((khm_size) -1)

/*!
\defgroup kcdb_ident Identities

Functions, macros etc. for manipulating identities.
*/

/*@{*/

/*! \brief The maximum number of characters (including terminator) that can
           be specified as an identity name */
#define KCDB_IDENT_MAXCCH_NAME 256

/*! \brief The maximum number of bytes that can be specified as an identity
           name */
#define KCDB_IDENT_MAXCB_NAME (sizeof(wchar_t) * KCDB_IDENT_MAXCCH_NAME)

/*! \brief Valid characters in an identity name */
#define KCDB_IDENT_VALID_CHARS L"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._@-/"

/*!
\name Flags for identities */
/*@{*/

/*! \brief Create the identity if it doesn't already exist.
    \note  Only to be used with kcdb_identity_create() */
#define KCDB_IDENT_FLAG_CREATE      0x10000000L

/*! \brief Has configuration information

    Indicates that the identity has persistent configuration
    information associated with it.
 */
#define KCDB_IDENT_FLAG_CONFIG      0x00800000L

/*! \brief Marks the identity as active.

    An active identity is one that is in active use within NetIDMgr.

    \note This flag is readonly and cannot be specified when creating
        or modifying an identity. Once an identity is deleted, it will
        no longer have this flag. */
#define KCDB_IDENT_FLAG_ACTIVE      0x02000000L


/*! \brief The identity has custom attributes assigned
 */
#define KCDB_IDENT_FLAG_ATTRIBS     0x08000000L

/*! \brief This is the default identity.

    At most one identity will have this flag set at any given time.
    To set or reset the flag, use kcdb_identity_set_default() */
#define KCDB_IDENT_FLAG_DEFAULT     0x00000001L

/*! \brief This identity can be searched.

    The meaning of this flag is left to be interpreted by individual
    plugins. */
#define KCDB_IDENT_FLAG_SEARCHABLE  0x00000002L

/*! \brief Hidden identity.

    The identity will not show up in the identity list window.  Once
    the hidden is switched off, the identity (and all associated
    credentials) will re-appear in the window */
#define KCDB_IDENT_FLAG_HIDDEN      0x00000004L

/*! \brief Invalid identity

    For one reason or another, this identity is invalid.  This flag
    can be set by an identity provider to indicate that this identity
    does not correspond to an actual identity because an external
    entity (such as a KDC) has denied it's existence.

    The absence of this flag does not imply that the identity is
    valid.  The ::KCDB_IDENT_FLAG_VALID bit must be set for that to be
    the case.  If neither flag is set, then the status of the identity
    is not known.
*/
#define KCDB_IDENT_FLAG_INVALID     0x00000008L

/*! \brief Valid identity

    The identity has been validated through an external entity, or
    it's validity implied through the existence of credentials for the
    identity.

    The absence of this flag does not imply that the identity is
    invalid.  The ::KCDB_IDENT_FLAG_INVALID bit must be set for that
    to be the case.  If neither flag is set, then the status of the
    identity is not known.
 */
#define KCDB_IDENT_FLAG_VALID       0x00000010L

/*! \brief Expired identity

    This identity has expired and can not be actively used to obtain
    credentials.  This determination is made based on the input of
    some external entity.  This flag may only be set by an identity
    provider.
*/
#define KCDB_IDENT_FLAG_EXPIRED     0x00000020L

/*! \brief Empty identity

    The identity does not have actual credentials associated with it.
 */
#define KCDB_IDENT_FLAG_EMPTY       0x00000040L

/*! \brief Renewable identity

    The initial credentials associated with this identity are
    renewable.  Thus making the whole identity renewable.
 */
#define KCDB_IDENT_FLAG_RENEWABLE   0x00000080L

/*! \brief Required user interaction

    The identity is in a state which requires user interaction to
    activate.  Currently, the identity may not be in a state where it
    can be used to obtain credentials.

    A typical example of this is when the primary password for an
    identity has expired.
 */
#define KCDB_IDENT_FLAG_INTERACT    0x00000100L

/*! \brief Has expired credentials

    The identity has expired credentials associated with it.
 */
#define KCDB_IDENT_FLAG_CRED_EXP    0x00000200L

/*! \brief Has renewable credentials

    The identity has renewable credentials associated with it.  If the
    initial credentials of the identity are renewable, then identity
    is renewable.  Hence the ::KCDB_IDENT_FLAG_RENEWABLE should also
    be set.
 */
#define KCDB_IDENT_FLAG_CRED_RENEW  0x00000400L

/*! \brief Sticky identity

    Sticky identities are identities that are always visible in the
    credentials display even if no credentials are associated with it.
 */
#define KCDB_IDENT_FLAG_STICKY      0x00000800L

/*! \brief Unknown state

    The validity of the identity cannot be determined.  This usually
    means that an authority could not be contacted.  This flag is to
    be treated as transient.  If ::KCDB_IDENT_FLAG_INVALID or
    ::KCDB_IDENT_FLAG_VALID is set for the identity, this flag is to
    be ignored.
 */
#define KCDB_IDENT_FLAG_UNKNOWN     0x00001000L

/*! \brief Read/write flags mask.

    A bitmask that correspond to all the read/write flags in the mask.
*/
#define KCDB_IDENT_FLAGMASK_RDWR    0x00001fffL

/*@}*/

/*! \name Identity Provider Data Structures
@{*/

/*! \brief Name transfer structure

    Used when the KCDB is communicating with the identity provider to
    exchange string names of identities.  See individual ::KMSG_IDENT
    message subtypes for the usage of this structure.
 */
typedef struct tag_kcdb_ident_name_xfer {
    const wchar_t * name_src;   /*!< An identity name.  Does not
                                     exceed KCDB_IDENT_MAXCCH_NAME
                                     characters including terminating
                                     NULL. */
    const wchar_t * name_alt;   /*!< An identity name.  Does not
                                     exceed KCDB_IDENT_MAXCCH_NAME
                                     characters including terminating
                                     NULL. */
    wchar_t *       name_dest;  /*!< Pointer to a buffer that is to
                                     receive a response string.  The
                                     size of the buffer in bytes is
                                     specified in \a cb_name_dest. */
    khm_size        cb_name_dest; /*!< Size of buffer pointed to by \a
                                     name_dest in bytes. */
    khm_int32       result;     /*!< Receives a result value, which is
                                     usually an error code defined in
                                     kherror.h, though it is not
                                     always. */
} kcdb_ident_name_xfer;

typedef struct tag_kcdb_ident_info {
    khm_handle      identity;
    khm_int32       fields;

    FILETIME        expiration;
} kcdb_ident_info;

/*@}*/

/*! \name Identity provider interface functions

    These functions encapsulate safe calls to the current identity
    provider.  While these functions are exported, applications should
    not call these functions directly.  They are provided for use by
    the NetIDMgr core application.
@{*/

/*! \brief Validate an identity name

    The name that is provided will be passed through sets of
    validations.  One set, which doesn't depend on the identity
    provider checks whether the length of the identity name and
    whether there are any invalid characters in the identity name.  If
    the name passes those tests, then the name is passed down to the
    identity provider's name validation handler.

    \retval KHM_ERROR_SUCCESS The name is valid
    \retval KHM_ERROR_TOO_LONG Too many characters in name
    \retval KHM_ERROR_INVALID_NAME There were invalid characters in the name.
    \retval KHM_ERROR_NO_PROVIDER There is no identity provider;
        however the name passed the length and character tests.
    \retval KHM_ERROR_NOT_IMPLEMENTED The identity provider doesn't
        implement a name validation handler; however the name passed
        the length and character tests.

    \see ::KMSG_IDENT_VALIDATE_NAME
 */
KHMEXP khm_int32 KHMAPI
kcdb_identpro_validate_name(const wchar_t * name);

/*! \brief Validate an identity

    The identity itself needs to be validated.  This may involve
    communicating with an external entity.

    \see ::KMSG_IDENT_VALIDATE_IDENTITY
 */
KHMEXP khm_int32 KHMAPI
kcdb_identpro_validate_identity(khm_handle identity);

/*! \brief Canonicalize the name


    \see ::KMSG_IDENT_CANON_NAME
*/
KHMEXP khm_int32 KHMAPI
kcdb_identpro_canon_name(const wchar_t * name_in,
                         wchar_t * name_out,
                         khm_size * cb_name_out);

/*! \brief Compare two identity names

    \see ::KMSG_IDENT_COMPARE_NAME
*/
KHMEXP khm_int32 KHMAPI
kcdb_identpro_compare_name(const wchar_t * name1,
                           const wchar_t * name2);

/*! \brief Set the specified identity as the default

    \see ::KMSG_IDENT_SET_DEFAULT
*/
KHMEXP khm_int32 KHMAPI
kcdb_identpro_set_default(khm_handle identity);

/*! \brief Set the specified identity as searchable

    \see ::KMSG_IDENT_SET_SEARCHABLE
*/
KHMEXP khm_int32 KHMAPI
kcdb_identpro_set_searchable(khm_handle identity,
                             khm_boolean searchable);

/*! \brief Update the specified identity

    \see ::KMSG_IDENT_UPDATE
*/
KHMEXP khm_int32 KHMAPI
kcdb_identpro_update(khm_handle identity);

/*! \brief Obtain the UI callback

    \a rock is actually a pointer to a ::khui_ident_new_creds_cb which
    is to receive the callback.

    \see ::KMSG_IDENT_GET_UI_CALLBACK
 */
KHMEXP khm_int32 KHMAPI
kcdb_identpro_get_ui_cb(void * rock);

/*! \brief Notify an identity provider of the creation of a new identity

    \see ::KMSG_IDENT_NOTIFY_CREATE
*/
KHMEXP khm_int32 KHMAPI
kcdb_identpro_notify_create(khm_handle identity);

/*@}*/

/*! \brief Check if the given name is a valid identity name

    \return TRUE or FALSE to the question, is this valid?
*/
KHMEXP khm_boolean KHMAPI
kcdb_identity_is_valid_name(const wchar_t * name);

/*! \brief Create or open an identity.

    If the KCDB_IDENT_FLAG_CREATE flag is specified in the flags
    parameter a new identity will be created if one does not already
    exist with the given name.  If an identity by that name already
    exists, then the existing identity will be opened. The result
    parameter will receive a held reference to the opened identity.
    Use kcdb_identity_release() to release the handle.

    \param[in] name Name of identity to create
    \param[in] flags If KCDB_IDENT_FLAG_CREATE is specified, then the
        identity will be created if it doesn't already exist.
        Additional flags can be set here which will be assigned to the
        identity if it is created.  Additional flags have no effect if
        an existing identity is opened.
    \param[out] result If the call is successful, this receives a held
        reference to the identity.  The caller should call
        kcdb_identity_release() to release the identity once it is no
        longer needed.
    */
KHMEXP khm_int32 KHMAPI
kcdb_identity_create(const wchar_t *name,
                     khm_int32 flags,
                     khm_handle * result);

/*! \brief Mark an identity for deletion.

    The identity will be marked for deletion.  The
    KCDB_IDENT_FLAG_ACTIVE will no longer be present for this
    identity.  Once all references to the identity are released, it
    will be removed from memory.  All associated credentials will also
    be removed. */
KHMEXP khm_int32 KHMAPI
kcdb_identity_delete(khm_handle id);

/*! \brief Set or unset the specified flags in the specified identity.

    Only flags that are in KCDB_IDENT_FLAGMASK_RDWR can be specifed in
    the \a flags parameter or the \a mask parameter.  The flags set in
    the \a mask parameter of the identity will be set to the
    corresponding values in the \a flags parameter.

    If ::KCDB_IDENT_FLAG_INVALID is set using this function, then the
    ::KCDB_IDENT_FLAG_VALID will be automatically reset, and vice
    versa.  Resetting either bit does not undo this change, and will
    leave the identity's validity unspecified.  Setting either of
    ::KCDB_IDENT_FLAG_INVALID or ::KCDB_IDENT_FLAG_VALID will
    automatically reset ::KCDB_IDENT_FLAG_UNKNOWN.

    Note that setting or resetting certain flags have other semantic
    side-effects:

    - ::KCDB_IDENT_FLAG_DEFAULT : Setting this is equivalent to
      calling kcdb_identity_set_default() with \a id.  Resetting this
      is equivalent to calling kcdb_identity_set_default() with NULL.

    - ::KCDB_IDENT_FLAG_SEARCHABLE : Setting this will result in the
      identity provider getting notified of the change. If the
      identity provider indicates that searchable flag should not be
      set or reset on the identity, then kcdb_identity_set_flags()
      will return an error.

    \note kcdb_identity_set_flags() is not atomic.  Even if the
    function returns a failure code, some flags in the identity may
    have been set.  When calling kcdb_identity_set_flags() always
    check the flags in the identity using kcdb_identity_get_flags() to
    check which flags have been set and which have failed.
*/
KHMEXP khm_int32 KHMAPI
kcdb_identity_set_flags(khm_handle id,
                        khm_int32 flags,
                        khm_int32 mask);

/*! \brief Return all the flags for the identity

    The returned flags may include internal flags.
*/
KHMEXP khm_int32 KHMAPI
kcdb_identity_get_flags(khm_handle id,
                        khm_int32 * flags);

/*! \brief Return the name of the identity

    \param[out] buffer Buffer to copy the identity name into.  The
        maximum size of an identity name is \a KCDB_IDENT_MAXCB_NAME.
        If \a buffer is \a NULL, then the required size of the buffer
        is returned in \a pcbsize.

    \param[in,out] pcbsize Size of buffer in bytes. */
KHMEXP khm_int32 KHMAPI
kcdb_identity_get_name(khm_handle id,
                       wchar_t * buffer,
                       khm_size * pcbsize);

/*! \brief Set the specified identity as the default.

    Specifying NULL effectively makes none of the identities the
    default.

    \see kcdb_identity_set_flags()
*/
KHMEXP khm_int32 KHMAPI
kcdb_identity_set_default(khm_handle id);

/*! \brief Mark the specified identity as the default.

    This API is reserved for use by identity providers as a means of
    specifying which identity is default.  The difference between
    kcdb_identity_set_default() and kcdb_identity_set_default_int() is
    in semantics.

    - kcdb_identity_set_default() is used to request the KCDB to
      designate the specified identity as the default.  When
      processing the request, the KCDB invokes the identity provider
      to do the necessary work to make the identity the default.

    - kcdb_identity_set_default_int() is used by the identity provider
      to notify the KCDB that the specified identity is the default.
      This does not result in the invocation of any other semantics to
      make the identity the default other than releasing the previous
      defualt identity and making the specified one the default.
 */
KHMEXP khm_int32 KHMAPI
kcdb_identity_set_default_int(khm_handle id);

/*! \brief Get the default identity

    Obtain a held handle to the default identity if there is one.  The
    handle must be freed using kcdb_identity_release().

    If there is no default identity, then the handle pointed to by \a
    pvid is set to \a NULL and the function returns
    KHM_ERROR_NOT_FOUND. */
KHMEXP khm_int32 KHMAPI
kcdb_identity_get_default(khm_handle * pvid);

/*! \brief Get the configuration space for the identity.

    If the configuration space for the identity does not exist and the
    flags parameter does not specify ::KHM_FLAG_CREATE, then the
    function will return a failure code as specified in
    ::khc_open_space().  Depending on whether or not a configuration
    space was found, the ::KCDB_IDENT_FLAG_CONFIG flag will be set or
    reset for the identity.

    \param[in] id Identity for which the configuraiton space is requested

    \param[in] flags Flags used when calling khc_open_space().  If \a
        flags specifies KHM_FLAG_CREATE, then the configuration space
        is created.

    \param[out] result The resulting handle.  If the call is
        successful, this receives a handle to the configuration space.
        Use khc_close_space() to close the handle.
*/
KHMEXP khm_int32 KHMAPI
kcdb_identity_get_config(khm_handle id,
                         khm_int32 flags,
                         khm_handle * result);

/*! \brief Hold a reference to an identity.

    A reference to an identity (a handle) is only valid while it is
    held.  \note Once the handle is released, it can not be
    revalidated by calling kcdb_identity_hold().  Doing so would lead
    to unpredictable consequences. */
KHMEXP khm_int32 KHMAPI
kcdb_identity_hold(khm_handle id);

/*! \brief Release a reference to an identity.
    \see kcdb_identity_hold() */
KHMEXP khm_int32 KHMAPI
kcdb_identity_release(khm_handle id);

/*! \brief Set the identity provider subscription

    If there was a previous subscription, that subscription will be
    automatically deleted.

    \param[in] sub New identity provider subscription
*/
KHMEXP khm_int32 KHMAPI
kcdb_identity_set_provider(khm_handle sub);

/*! \brief Set the primary credentials type

    The primary credentials type is designated by the identity
    provider.  As such, this function should only be called by an
    identity provider.
 */
KHMEXP khm_int32 KHMAPI
kcdb_identity_set_type(khm_int32 cred_type);

/*! \brief Retrieve the identity provider subscription

    \param[out] sub Receives the current identity provider
        subscription.  Set to NULL if only the existence of an
        identity provider needs to be checked.

    \retval KHM_ERROR_SUCCESS An identity provider exists.  If \a sub
        was not NULL, the subscription has been copied there.

    \retval KHM_ERROR_NOT_FOUND There is currently no registered
        identity provider.  If \a sub was not NULL, the handle it
        points to has been set to NULL.
*/
KHMEXP khm_int32 KHMAPI
kcdb_identity_get_provider(khm_handle * sub);

/*! \brief Retrieve the identity provider credentials type

    This is the credentials type that the identity provider has
    designated as the primary credentials type.
 */
KHMEXP khm_int32 KHMAPI
kcdb_identity_get_type(khm_int32 * ptype);

/*! \brief Returns TRUE if the two identities are equal

    Also returns TRUE if both identities are NULL.
 */
KHMEXP khm_boolean KHMAPI
kcdb_identity_is_equal(khm_handle identity1,
                       khm_handle identity2);

/*! \brief Set an attribute in an identity by attribute id

    \param[in] buffer A pointer to a buffer containing the data to
        assign to the attribute.  Setting \a buffer to NULL has the
        effect of removing any data that is already assigned to the
        attribute.  If \a buffer is non-NULL, then \a cbbuf should
        specify the number of bytes in \a buffer.

    \param[in] cbbuf Number of bytes of data in \a buffer.  The
        individual data type handlers may copy in less than this many
        bytes in to the credential.
*/
KHMEXP khm_int32 KHMAPI
kcdb_identity_set_attr(khm_handle identity,
                       khm_int32 attr_id,
                       void * buffer,
                       khm_size cbbuf);

/*! \brief Set an attribute in an identity by name

    The attribute name has to be a KCDB registered attribute or
    property.

    \param[in] cbbuf Number of bytes of data in \a buffer.  The
        individual data type handlers may copy in less than this many
        bytes in to the credential.
*/
KHMEXP khm_int32 KHMAPI
kcdb_identity_set_attrib(khm_handle identity,
                         const wchar_t * attr_name,
                         void * buffer,
                         khm_size cbbuf);

/*! \brief Get an attribute from an identity by attribute id.

    \param[in] buffer The buffer that is to receive the attribute
        value.  Set this to NULL if only the required buffer size is
        to be returned.

    \param[in,out] cbbuf The number of bytes available in \a buffer.
        If \a buffer is not sufficient, returns KHM_ERROR_TOO_LONG and
        sets this to the required buffer size.

    \param[out] attr_type Receives the data type of the attribute.
        Set this to NULL if the type is not required.

    \note Set both \a buffer and \a cbbuf to NULL if only the
        existence of the attribute is to be checked.  If the attribute
        exists in this identity then the function will return
        KHM_ERROR_SUCCESS, otherwise it returns KHM_ERROR_NOT_FOUND.
*/
KHMEXP khm_int32 KHMAPI
kcdb_identity_get_attr(khm_handle identity,
                       khm_int32 attr_id,
                       khm_int32 * attr_type,
                       void * buffer,
                       khm_size * pcbbuf);

/*! \brief Get an attribute from an identity by name.

    \param[in] buffer The buffer that is to receive the attribute
        value.  Set this to NULL if only the required buffer size is
        to be returned.

    \param[in,out] cbbuf The number of bytes available in \a buffer.
        If \a buffer is not sufficient, returns KHM_ERROR_TOO_LONG and
        sets this to the required buffer size.

    \note Set both \a buffer and \a cbbuf to NULL if only the
        existence of the attribute is to be checked.  If the attribute
        exists in this identity then the function will return
        KHM_ERROR_SUCCESS, otherwise it returns KHM_ERROR_NOT_FOUND.
*/
KHMEXP khm_int32 KHMAPI
kcdb_identity_get_attrib(khm_handle identity,
                         const wchar_t * attr_name,
                         khm_int32 * attr_type,
                         void * buffer,
                         khm_size * pcbbuf);

/*! \brief Get the string representation of an identity attribute.

    A shortcut function which generates the string representation of
    an identity attribute directly.

    \param[in] identity A handle to an identity

    \param[in] attr_id The attribute to retrieve

    \param[out] buffer A pointer to a string buffer which receives the
        string form of the attribute.  Set this to NULL if you only
        want to determine the size of the required buffer.

    \param[in,out] pcbbuf A pointer to a #khm_int32 that, on entry,
        holds the size of the buffer pointed to by \a buffer, and on
        exit, receives the actual number of bytes that were copied.

    \param[in] flags Flags for the string conversion. Can be set to
        one of KCDB_TS_LONG or KCDB_TS_SHORT.  The default is
        KCDB_TS_LONG.

    \retval KHM_ERROR_SUCCESS Success
    \retval KHM_ERROR_NOT_FOUND The given attribute was either invalid
        or was not defined for this identity
    \retval KHM_ERROR_INVALID_PARAM One or more parameters were invalid
    \retval KHM_ERROR_TOO_LONG Either \a buffer was NULL or the
        supplied buffer was insufficient
*/
KHMEXP khm_int32 KHMAPI
kcdb_identity_get_attr_string(khm_handle identity,
                              khm_int32 attr_id,
                              wchar_t * buffer,
                              khm_size * pcbbuf,
                              khm_int32 flags);

/*! \brief Get the string representation of an identity attribute by name.

    A shortcut function which generates the string representation of
    an identity attribute directly.

    \param[in] identity A handle to an identity

    \param[in] attrib The name of the attribute to retrieve

    \param[out] buffer A pointer to a string buffer which receives the
        string form of the attribute.  Set this to NULL if you only
        want to determine the size of the required buffer.

    \param[in,out] pcbbuf A pointer to a #khm_int32 that, on entry,
        holds the size of the buffer pointed to by \a buffer, and on
        exit, receives the actual number of bytes that were copied.

    \param[in] flags Flags for the string conversion. Can be set to
        one of KCDB_TS_LONG or KCDB_TS_SHORT.  The default is
        KCDB_TS_LONG.

    \see kcdb_identity_get_attr_string()
*/
KHMEXP khm_int32 KHMAPI
kcdb_identity_get_attrib_string(khm_handle identity,
                                const wchar_t * attr_name,
                                wchar_t * buffer,
                                khm_size * pcbbuf,
                                khm_int32 flags);

/*! \brief Enumerate identities

    Enumerates all the active identities that match the criteria
    specified using \a and_flags and \a eq_flags.  The condition is
    applied to all active identities as follows:

    \code
    (identity->flags & and_flags) == (eq_flags & and_flags)
    \endcode

    Essentially, if a flag is set in \a and_flags, then that flag in
    the identity should equal the setting in \a eq_flags.

    \param[in] and_flags See above

    \param[in] eq_flags See above

    \param[out] name_buf Buffer to receive the list of identity names.
        Can be NULL if only the required size of the buffer or the
        number of matching identities is required.  The list is
        returned as a multi string.

    \param[in,out] pcb_buf Number of bytes in buffer pointed to by \a
        name_buf on entry.  On exit, will receive the number of bytes
        copied.  Can be NULL only if \a name_buf is also NULL.  If \a
        name_buf is NULL or if \a pcb_buf indicates that the buffer is
        insufficient, this will receive the number of bytes required
        and the return value of the function will be
        KHM_ERROR_TOO_LONG

    \param[out] pn_idents Receives the number of identities that match
        the given criteria.

    \retval KHM_ERROR_SUCCESS If \a name_buf was valid, the buffer now
        contains a multi string of identities that matched.  If \a
        pn_idents was valid, it contains the number of identities
        matched.

    \retval KHM_ERROR_TOO_LONG No buffer was supplied or the supplied
        buffer was insufficient.  If \a pn_idents was valid, it
        contains the number of identities.

    \retval KHM_ERROR_INVALID_PARAM None of the parameters \a name_buf,
        \a pcb_buf and \a pn_idents were supplied, or \a pcb_buf was
        NULL when \a name_buf was not.

    \note Calling this function to obtain the required size of the
        buffer and then calling it with a that sized buffer is not
        guaranteed to work since the list of identities may change
        between the two calls.
  */
KHMEXP khm_int32 KHMAPI
kcdb_identity_enum(khm_int32 and_flags,
                   khm_int32 eq_flags,
                   wchar_t * name_buf,
                   khm_size * pcb_buf,
                   khm_size * pn_idents);

/*! \brief Refresh identity attributes based on root credential set

    Several flags in an identity are dependent on the credentials that
    are associated with it in the root credential set.  In addition,
    other flags in an identity depend on external factors that need to
    be verfied once in a while.  This API goes through the root
    credential set as well as consulting the identity provider to
    update an identity.

    \see kcdb_identity_refresh()
 */
KHMEXP khm_int32 KHMAPI
kcdb_identity_refresh(khm_handle vid);

/*! \brief Refresh all identities

    Equivalent to calling kcdb_identity_refresh() for all active
    identities.

    \see kcdb_identityt_refresh()
 */
KHMEXP khm_int32 KHMAPI
kcdb_identity_refresh_all(void);

/* KSMG_KCDB_IDENT notifications are structured as follows:
   type=KMSG_KCDB
   subtype=KMSG_KCDB_IDENT
   uparam=one of KCDB_OP_*
   blob=handle to identity in question */

/*@}*/


/*********************************************************************/


/*!
\defgroup kcdb_creds Credential sets and individual credentials

@{
*/


/*! \brief Credentials process function

    This function is called for each credential in a credential set
    when supplied to kcdb_credset_apply().  It should return
    KHM_ERROR_SUCCESS to continue the operation, or any other value to
    terminate the processing.

    \see kcdb_credset_apply()
*/
typedef khm_int32
(KHMAPI *kcdb_cred_apply_func)(khm_handle cred,
                               void * rock);

/*! \brief Credentials filter function.

    Should return non-zero if the credential passed as \a cred is to
    be "accepted".  The precise consequence of a non-zero return value
    is determined by the individual function that this call back is
    passed into.

    This function should not call any other function which may modify
    \a cred.

    \see kcdb_credset_collect_filtered()
    \see kcdb_credset_extract_filtered()
*/
typedef khm_int32
(KHMAPI *kcdb_cred_filter_func)(khm_handle cred,
                                khm_int32 flags,
                                void * rock);

/*! \brief Credentials compare function.

    Asserts a weak ordering on the credentials that are passed in as
    \a cred1 and \a cred2.  It should return:

    - a negative value if \a cred1 < \a cred2
    - zero if \a cred1 == \a cred2
    - a postive value if \a cred1 > \a cred2
    \see kcdb_credset_sort()
    \see ::kcdb_credtype
*/
typedef khm_int32
(KHMAPI *kcdb_cred_comp_func)(khm_handle cred1,
                              khm_handle cred2,
                              void * rock);

/*! \defgroup kcdb_credset Credential sets */
/*@{*/

/*! \brief Create a credential set.

    Credential sets are temporary containers for credentials.  These
    can be used by plug-ins to store credentials while they are being
    enumerated from an external source.  Once all the credentials have
    been collected into the credential set, the plug-in may call
    kcdb_credset_collect() to collect the credentials into the root
    credential store.

    The user interface will only display credentials that are in the
    root credential store.  No notifications are generated for changes
    to a non-root credential set.

    Use kcdb_credset_delete() to delete the credential set once it is
    created.

    \see kcdb_credset_delete()
    \see kcdb_credset_collect()
*/
KHMEXP khm_int32 KHMAPI
kcdb_credset_create(khm_handle * result);

/** \brief Delete a credential set

    \see kcdb_credset_create()
*/
KHMEXP khm_int32 KHMAPI
kcdb_credset_delete(khm_handle credset);

/** \brief Collect credentials from a credential set to another credential set.

    Collecting a subset of credentials from credential set \a cs_src
    into credential set \a cs_dest involves the following steps:

    - Select all credentials from \a cs_src that matches the \a
      identity and \a type specified in the function call and add them
      to the \a cs_dest credential set if they are not there already.
      Note that if neither credential set is not the root credential
      store, then the credentials will be added by reference, while if
      it is the root credential store, the credentials will be
      duplicated, and the copies will be added to \a cs_dest.

    - If a selected credential in \a cs_src already exists in \a
      cs_dest, then update the credential in \a cs_dest with the
      credential fields in \a cs_src.  In other words, once a
      credential is found to exist in both \a cs_src and \a cs_dest,
      all the non-null fields from the credential in \a cs_src will be
      copied to the credential in \a cs_dest.  Fields which are null
      (undefined) in \a cs_src and are non-null in \a cs_dest will be
      left unmodified in \a cs_dest.

      One notable exception is the credentials' flags.  All flags in
      \a cs_src which are not included in
      ::KCDB_CRED_FLAGMASK_ADDITIVE will be copied to the
      corresponding bits in the flags of \a cs_dest.  However, flags
      that are included in ::KCDB_CRED_FLAGMASK_ADDITIVE will be added
      to the corresponding bits in \a cs_dest.

      (See notes below)

    - Remove all credentials from \a cs_dest that match the \a
      identity and \a type that do not appear in \a cs_src. (see notes
      below)

    For performance reasons, plugins should use kcdb_credset_collect()
    to update the root credentials store instead of adding and
    removing individual credentials from the root store.

    Only credentials that are associated with active identities are
    affected by kcdb_credset_collect().

    \param[in] cs_dest A handle to the destination credential set.  If
        this is \a NULL, then it is assumed to refer to the root
        credential store.

    \param[in] cs_src A handle to the source credential set.  If this
        is NULL, then it is assumed to refer to the root credential
        store.

    \param[in] identity A handle to an identity.  Setting this to NULL
        collects all identities in the credential set.

    \param[in] type A credentials type.  Setting this to
        KCDB_CREDTYPE_ALL collects all credential types in the set.

    \param[out] delta A bit mask that indicates the modifications that
        were made to \a cs_dest as a result of the collect operation.
        This is a combination of KCDB_DELTA_* values.  This parameter
        can be \a NULL if the value is not required.

    \warning If \a identity and \a type is set to a wildcard, all
        credentials in the root store that are not in this credentials
        set will be deleted.

    \note Two credentials \a A and \a B are considered equal if:
        - They refer to the same identity
        - Both have the same credential type
        - Both have the same name

    \note This is the only supported way of modifying the root
        credential store.

    \note \a cs_src and \a cs_dest can not refer to the same
        credentials set.

    \note The destination credential set cannot be sealed.
*/
KHMEXP khm_int32 KHMAPI
kcdb_credset_collect(khm_handle cs_dest,
                     khm_handle cs_src,
                     khm_handle identity,
                     khm_int32 type,
                     khm_int32 * delta);

/*! \brief Credentials were added
    \see kcdb_credset_collect() */
#define KCDB_DELTA_ADD      1

/*! \brief Credentials were deleted
    \see kcdb_credset_collect() */
#define KCDB_DELTA_DEL      2

/*! \brief Credentials were modified
    \see kcdb_credset_collect() */
#define KCDB_DELTA_MODIFY   4

/*! \brief Indicates that the credential to be filtered is from the root store.

    \see kcdb_credset_collect_filtered()
*/
#define KCDB_CREDCOLL_FILTER_ROOT   1

/*! \brief Indicates that the credential to be filtered is from the source
        credential set

    \see kcdb_credset_collect_filtered() */
#define KCDB_CREDCOLL_FILTER_SRC    2

/*! \brief Indicates that the credential to be filtered is from the destination
        credential set

    \see kcdb_credset_collect_filtered() */
#define KCDB_CREDCOLL_FILTER_DEST   4

/*! \brief Collect credentials from one credential set to another using a filter.

    Similar to kcdb_credset_collect() except instead of selecting
    credentials by matching against an identity and/or type, a filter
    function is called.  If the filter function returns non-zero for a
    credential, that credential is selected.

    Credentials in the source and destination credential sets are
    passed into the filter function.  Depending on whether the
    credential is in the source credential set or destination
    credential set, the \a flag parameter may have either \a
    KCDB_CREDCOLL_FILTER_SRC or \a KCDB_CREDCOLL_FILTER_DEST bits set.
    Also, if either one of the credential sets is the root credential
    store, then additionally \a KCDB_CREDCOLL_FILTER_ROOT would also
    be set.

    See the kcdb_credset_collect() documentation for explanations of
    the \a cs_src, \a cs_dest and \a delta parameters which perform
    identical functions.

    \param[in] filter The filter of type ::kcdb_cred_filter_func
    \param[in] rock A custom argument to be passed to the filter function.

    \see kcdb_credset_collect()
*/
KHMEXP khm_int32 KHMAPI
kcdb_credset_collect_filtered(khm_handle cs_dest,
                              khm_handle cs_src,
                              kcdb_cred_filter_func filter,
                              void * rock,
                              khm_int32 * delta);

/*! \brief Flush all credentials from a credential set

    Deletes all the crednetials from the credential set.

    \param[in] credset A handle to a credential set.  Cannot be NULL.

    \note The credential set cannot be sealed
*/
KHMEXP khm_int32 KHMAPI
kcdb_credset_flush(khm_handle credset);

/*! \brief Extract credentials from one credential set to another

    Credentials from the source credential set are selected based on
    the \a identity and \a type arguements.  If a credential is
    matched, then it is added to the \a destcredset.

    If the \a sourcecredset is the root credential set, the added
    credentials are copies of the actual credentials in the root
    credential set.  Otherwise the credentials are references to the
    original credentials in the \a sourcecredset .

    \param[in] destcredset Destination credential set.  Must be valid.

    \param[in] sourcecredset The source credential set.  If set to
        NULL, extracts from the root credential set.

    \param[in] identity The identity to match in the source credential
        set.  If set to NULL, matches all identities.

    \param[in] type The credential type to match in the source credential set.
        If set to KCDB_CREDTYPE_INVALID, matches all types.

    \note This function does not check for duplicate credentials.

    \note The destination credential set cannot be sealed.
*/
KHMEXP khm_int32 KHMAPI
kcdb_credset_extract(khm_handle destcredset,
                     khm_handle sourcecredset,
                     khm_handle identity,
                     khm_int32 type);

/*! \brief Extract credentials from one credential set to another using a filter.

    Similar to kcdb_credset_extract() except a filter function is used
    to determine which credentials should be selected.

    \param[in] rock A custom argument to be passed in to the filter function.

    \note The destination credential set cannot be sealed.
*/
KHMEXP khm_int32 KHMAPI
kcdb_credset_extract_filtered(khm_handle destcredset,
                              khm_handle sourcecredset,
                              kcdb_cred_filter_func filter,
                              void * rock);

/*! \brief Retrieve a held reference to a credential in a credential set based on index.

    \param[in] idx The index of the credential to retrieve.  This is a
        zero based index which goes from 0 ... (size of credset - 1).

    \param[out] cred The held reference to a credential.  Call
        kcdb_cred_release() to release the credential.

    \retval KHM_ERROR_SUCCESS Success. \a cred has a held reference to the credential.
    \retval KHM_ERROR_OUT_OF_BOUNDS The index specified in \a idx is out of bounds.
    \retval KHM_ERROR_DELETED The credential at index \a idx has been marked as deleted.

    \see kcdb_cred_release()
*/
KHMEXP khm_int32 KHMAPI
kcdb_credset_get_cred(khm_handle credset,
                      khm_int32 idx,
                      khm_handle * cred);

/*! \brief Search a credential set for a specific credential

    The credential set indicated by \a credset is searched for a
    credential that satisfies the predicate function \a f.  Each
    credential starting at \a idx_start is passed into the predicate
    function until it returns a non-zero value.  At this point, that
    credential is passed in to the \a cred parameter, and the index of
    the credential is passed into the \a idx parameter.

    \param[in] credset The credential set to search on.  Specify NULL
        if you want to search teh root credential set.

    \param[in] idx_start The index at which to start the search after.
        The first credential passed to the predicate function will be
        at \a idx_start + 1.  Specify -1 to start from the beginning
        of the credential set.

    \param[in] f The predicate function.  The \a flags parameter of
        the predicate function will always receive 0.

    \param[in] rock An opaque parameter to be passed to the predicate
        function \a f.

    \param[out] cred A held reference to the credential that satisfied
        the predicate function or NULL if no such credential was
        found.  Note that if a valid credential is returned, the
        calling function must release the credential using
        kcdb_cred_release().

    \param[out] idx The index of the credential passed in \a cred.
        Specify NULL if the index is not required.

    \retval KHM_ERROR_SUCCESS A credential that satisfied the
        predicate function was found and was assigned to \a cred.

    \retval KHM_ERROR_NOT_FOUND No credential was found that matched
        the predicate function.

    \note When querying credential sets that are shared between
        threads, it is possible that another thread modifies the
        credential set between successive calls to
        kcdb_credset_find_filtered().  Therefore a continued sequences of
        searches are not guaranteed to exhastively cover the
        credential set nor to not return duplicate matches.  Duplicate
        matches are possible if the order of the credentials in the
        set was changed.
*/
KHMEXP khm_int32 KHMAPI
kcdb_credset_find_filtered(khm_handle credset,
                           khm_int32 idx_start,
                           kcdb_cred_filter_func f,
                           void * rock,
                           khm_handle * cred,
                           khm_int32 * idx);

/*! \brief Find matching credential

    Searches a credential set for a credential that matches the
    specified credential.  For a credential to be a match, it must
    have the same identity, credential type and name.

    \param[in] credset Credential set to search

    \param[in] cred_src Credetial to search on

    \param[out] cred_dest receieves the matching credential if the
        search is successful.  If a handle is returend, the
        kcdb_cred_release() must be used to release the handle.  If
        the matching credential is not required, you can pass in NULL.

    \retval KHM_ERROR_SUCCESS The search was successful.  A credential
        was assigned to \a cred_dest

    \retval KHM_ERROR_NOT_FOUND A matching credential was not found.
 */
KHMEXP khm_int32 KHMAPI
kcdb_credset_find_cred(khm_handle credset,
                       khm_handle cred_src,
                       khm_handle *cred_dest);


/*! \brief Delete a credential from a credential set.

    The credential at index \a idx will be deleted.  All the
    credentials that are at indices \a idx + 1 and above will be moved
    down to fill the gap and the size of the credential set will
    decrease by one.

    Use kcdb_credset_del_cred_ref() to delete a credential by
    reference.  Using kcdb_credset_del_cred() is faster than
    kcdb_credset_del_cred_ref().

    If you call kcdb_credset_del_cred() or kcdb_credset_del_cred_ref()
    from within kcdb_credset_apply(), the credential will only be
    marked as deleted.  They will not be removed.  This means that the
    size of the credential set will not decrease.  To purge the
    deleted credentials from the set, call kcdb_credset_purge() after
    kcdb_credset_apply() completes.

    \note The credential set cannot be sealed.

    \see kcdb_credset_del_cred_ref()
*/
KHMEXP khm_int32 KHMAPI
kcdb_credset_del_cred(khm_handle credset,
                      khm_int32 idx);

/*! \brief Delete a credential from a credential set by reference.

    See kcdb_credset_del_cred() for description of what happens when a
    credential is deleted from a credential set.

    \note The credential set cannot be sealed.

    \see kcdb_credset_del_cred()
*/
KHMEXP khm_int32 KHMAPI
kcdb_credset_del_cred_ref(khm_handle credset,
                          khm_handle cred);

/*! \brief Add a credential to a credential set.

    The credential is added by reference.  In other words, no copy of
    the credential is made.

    \param[in] idx Index of the new credential.  This must be a value
        in the range 0..(previous size of credential set) or -1.  If
        -1 is specifed, then the credential is appended at the end of
        the set.

    \note The credential set cannot be sealed.
*/
KHMEXP khm_int32 KHMAPI
kcdb_credset_add_cred(khm_handle credset,
                      khm_handle cred,
                      khm_int32 idx);

/*! \brief Get the number of credentials in a credential set.

    Credentials in a credential set may be volatile.  When
    kcdb_credeset_get_size() is called, the credential set is
    compacted to only include credentials that are active at the time.
    However, when you are iterating through the credential set, it
    might be the case that some credentials would get marked as
    deleted.  These credentials will remain in the credential set
    until the credential set is discarded or another call to
    kcdb_credset_get_size() or kdcb_credset_purge() is made.

    If the credential set is sealed, then it will not be compacted and
    will include deleted credentials as well.

    \see kcdb_credset_purge()
    \see kcdb_credset_get_cred()
*/
KHMEXP khm_int32 KHMAPI
kcdb_credset_get_size(khm_handle credset,
                      khm_size * size);

/*! \brief Removes credentials that have been marked as deleted from a credential set.

    See description of \a kcdb_credset_purge() for a description of
    what happens when credntials that are contained in a credential
    set are deleted by an external entity.

    \note The credential set cannot be sealed.

    \see kcdb_credset_get_size()
    \see kcdb_credset_get_cred()
*/
KHMEXP khm_int32 KHMAPI
kcdb_credset_purge(khm_handle credset);

/*! \brief Applies a function to all the credentials in a credentials set

    The given function is called for each credential in a credential
    set.  With each iteration, the function is called with a handle to
    the credential and the user defined parameter \a rock.  If the
    function returns anything other than KHM_ERROR_SUCCESS, the
    processing stops.

    \param[in] credset The credential set to apply the function to, or
        NULL if you want to apply this to the root credential set.

    \param[in] f Function to call for each credential

    \param[in] rock An opaque parameter which is to be passed to 'f'
        as the second argument.

    \retval KHM_ERROR_SUCCESS All the credentials were processed.

    \retval KHM_ERROR_EXIT The supplied function signalled the
        processing to be aborted.

    \retval KHM_ERROR_INVALID_PARAM One or more parameters were invalid.
*/
KHMEXP khm_int32 KHMAPI
kcdb_credset_apply(khm_handle credset,
                   kcdb_cred_apply_func f,
                   void * rock);

/*! \brief Sort the contents of a credential set.

    \param[in] rock A custom argument to be passed in to the \a comp function.

    \note The credential set cannot be sealed.

    \see kcdb_cred_comp_generic()
*/
KHMEXP khm_int32 KHMAPI
kcdb_credset_sort(khm_handle credset,
                  kcdb_cred_comp_func comp,
                  void * rock);

/*! \brief Seal a credential set

    Sealing a credential set makes it read-only.  To unseal a
    credential set, call kcdb_credset_unseal().

    Sealing is an additive operation.  kcdb_credset_seal() can be
    called muliple times.  However, for every call to
    kcdb_credset_seal() a call to kcdb_credset_unseal() must be made
    to undo the seal.  The credential set will become unsealed when
    all the seals are released.

    Once sealed, the credential set will not allow any operation that
    might change its contents.  However, a selaed credential set can
    still be delted.

    \see kcdb_credset_unseal()
 */
KHMEXP khm_int32 KHMAPI
kcdb_credset_seal(khm_handle credset);

/*! \brief Unseal a credential set

    Undoes what kcdb_credset_seal() did.  This does not guarantee that
    the credential set is unsealed since there may be other seals.

    \see kcdb_credset_seal()
 */
KHMEXP khm_int32 KHMAPI
kcdb_credset_unseal(khm_handle credset);

/*! \brief Defines a sort criterion for kcdb_cred_comp_generic()

    \see kcdb_cred_comp_generic()
*/
typedef struct tag_kcdb_cred_comp_field {
    khm_int32 attrib; /*!< a valid attribute ID */
    khm_int32 order; /*!< one of KCDB_CRED_COMP_INCREASING or
                       KCDB_CRED_COMP_DECREASING.  Optionally,
                       KCDB_CRED_COMP_INITIAL_FIRST may be combined
                       with either. */
} kcdb_cred_comp_field;

/*! \brief Defines the sort order for a field in ::kcdb_cred_comp_field

    Sorts lexicographically ascending by string representation of field.
*/
#define KCDB_CRED_COMP_INCREASING 0

/*! \brief Defines the sort order for a field in ::kcdb_cred_comp_field

    Sorts lexicographically descending by string representation of
    field.
 */
#define KCDB_CRED_COMP_DECREASING 1

/*! \brief Defines the sort order for a field in ::kcdb_cred_comp_field

    Any credentials which have the ::KCDB_CRED_FLAG_INITIAL will be
    grouped above any that don't.

    If that does not apply, then credentials from the primary
    credentials type will be sorted before others.
*/
#define KCDB_CRED_COMP_INITIAL_FIRST 2

/*! \brief Defines the sort criteria for kcdb_cred_comp_generic()

    \see kcdb_cred_comp_generic()
*/
typedef struct tag_kcdb_cred_comp_order {
    khm_int32 nFields;
    kcdb_cred_comp_field * fields;
} kcdb_cred_comp_order;

/*! \brief A generic compare function for comparing credentials.

    This function can be passed as a parameter to kcdb_credset_sort().

    The \a rock parameter to this function should be a pointer to a
    ::kcdb_cred_comp_order object.  The \a fields member of the
    ::kcdb_cred_comp_order object should point to an array of
    ::kcdb_cred_comp_field objects, each of which specifies the sort
    order in decreasing order of priority.  The number of
    ::kcdb_cred_comp_field objects in the array should correspond to
    the \a nFields member in the ::kcdb_cred_comp_order object.

    The array of ::kcdb_cred_comp_field objects define the sort
    criteria, in order.  The \a attrib member should be a valid
    attribute ID, while the \a order member determines whether the
    sort order is increasing or decreasing.  The exact meaning or
    increasing or decreasing depends on the data type of the
    attribute.

    \param[in] rock a pointer to a ::kcdb_cred_comp_order object
*/
KHMEXP khm_int32 KHMAPI
kcdb_cred_comp_generic(khm_handle cred1,
                       khm_handle cred2,
                       void * rock);

/*@}*/

/*! \defgroup kcdb_cred Credentials */
/*@{*/

/*! \brief Maximum number of characters in a credential name */
#define KCDB_CRED_MAXCCH_NAME 256

/*! \brief Maximum number of bytes in a credential name */
#define KCDB_CRED_MAXCB_NAME (sizeof(wchar_t) * KCDB_CRED_MAXCCH_NAME)

/*! \brief Marked as deleted */
#define KCDB_CRED_FLAG_DELETED     0x00000008

/*! \brief Renewable */
#define KCDB_CRED_FLAG_RENEWABLE   0x00000010

/*! \brief Initial

    Initial credentials form the basis of an identity.  Some
    properties of an initial credential, such as being renewable, are
    directly inherited by the identity.  An identity is also
    automatically considered valid if it contains a valid initial
    credential.
 */
#define KCDB_CRED_FLAG_INITIAL     0x00000020

/*! \brief Expired

    The credential's lifetime has ended.
 */
#define KCDB_CRED_FLAG_EXPIRED     0x00000040

/*! \brief Invalid

    The credential can no longer serve its intended function.  This
    may be because it is expired and is not renewable, or its
    renewable time period has also expired, or for some other reason.
 */
#define KCDB_CRED_FLAG_INVALID     0x00000080

/*! \brief Credential is selected

    Indicates that the credential is selected.  Note that using this
    flag may be subject to race conditions.
 */
#define KCDB_CRED_FLAG_SELECTED    0x00000100

/*! \brief Bitmask indicating all known credential flags
 */
#define KCDB_CRED_FLAGMASK_ALL     0x0000ffff

/*! \brief External flags

    These are flags that are provided by the credentials providers.
    The other flags are internal to KCDB and should not be modified.
 */
#define KCDB_CRED_FLAGMASK_EXT     (KCDB_CRED_FLAG_INITIAL | KCDB_CRED_FLAG_EXPIRED | KCDB_CRED_FLAG_INVALID | KCDB_CRED_FLAG_RENEWABLE)

/*! \brief Bitmask indicating dditive flags

    Additive flags are special flags which are added to exiting
    credentials based on new credentials when doing a collect
    operation.  See details on kcdb_credset_collect()

    \see kcdb_credset_collect()
*/
#define KCDB_CRED_FLAGMASK_ADDITIVE KCDB_CRED_FLAG_SELECTED

/*! \brief Generic credentials request

    This data structure is used as the format for a generic
    credentials reqeust for a ::KMSG_KCDB_REQUEST message.  A plugin
    typically publishes this message so that a credentials provider
    may handle it and in response, obtain the specified credential.

    While the \a identity, \a type and \a name members of the
    structure are all optional, typically one would specify all three
    or at least two for a credential provider to be able to provide
    the credential unambigously.

    Credential providers do not need to respond to ::KMSG_KCDB_REQUEST
    messages.  However, if they do, they should make sure that they
    are the only credential provider that is responding by setting the
    \a semaphore member to a non-zero value.  The \a semaphore is set
    to zero when a request is initially sent out.  When incrementing
    the semaphore, the plugin should use a thread safe mechanism to
    ensure that there are no race conditions that would allow more
    than one provider to respond to the message.
 */
typedef struct tag_kcdb_cred_request {
    khm_handle identity;        /*!< Identity of the credential.  Set
                                  to NULL if not specified. */
    khm_int32  type;            /*!< Type of the credential.  Set to
                                  KCDB_CREDTYPE_INVALID if not
                                  specified.  */
    wchar_t *  name;            /*!< Name of the credential.  Set to
                                  NULL if not specified.  */

    khm_handle dest_credset;    /*!< If non-NULL, instructs whoever is
                                  handling the request that the
                                  credential thus obtained be placed
                                  in this credential set in addition
                                  to whereever it may place newly
                                  acquired credentials.  Note that
                                  while this can be NULL if the new
                                  credential does not need to be
                                  placed in a credential set, it can
                                  not equal the root credential
                                  set.  */

    void *     vparam;        /*!< An unspecified
                                  parameter. Specific credential types
                                  may specify how this field is to be
                                  used. */

    long       semaphore;       /*!< Incremented by one when this
                                  request is answered.  Only one
                                  credential provider is allowed to
                                  answer a ::KMSG_KCDB_REQUEST
                                  message.  Initially, when the
                                  message is sent out, this member
                                  should be set to zero. */
} kcdb_cred_request;

/*! \brief Create a new credential

    \param[in] name Name of credential.  \a name cannot be NULL and cannot
        exceed \a KCDB_CRED_MAXCCH_NAME unicode characters including the
        \a NULL terminator.
    \param[in] identity A reference to an identity.
    \param[in] cred_type A credentials type identifier for the credential.
    \param[out] result Gets a held reference to the newly created credential.
        Call kcdb_cred_release() or kcdb_cred_delete() to release the
        reference.
    \see kcdb_cred_release()
*/
KHMEXP khm_int32 KHMAPI
kcdb_cred_create(const wchar_t *   name,
                 khm_handle  identity,
                 khm_int32   cred_type,
                 khm_handle * result);

/*! \brief Duplicate an existing credential.

    \param[out] newcred A held reference to the new credential if the call
        succeeds.
*/
KHMEXP khm_int32 KHMAPI
kcdb_cred_dup(khm_handle cred,
              khm_handle * newcred);

/*! \brief Updates one credential using field values from another

    All fields that exist in \a vsrc will get copied to \a vdest and will
    overwrite any values that are already there in \a vdest.  However any
    values that exist in \a vdest taht do not exist in \a vsrc will not be
    modified.

    \retval KHM_ERROR_SUCCESS vdest was successfully updated
    \retval KHM_ERROR_EQUIVALENT all fields in vsrc were present and equivalent in vdest
*/
KHMEXP khm_int32 KHMAPI
kcdb_cred_update(khm_handle vdest,
                 khm_handle vsrc);

/*! \brief Set an attribute in a credential by name



    \param[in] cbbuf Number of bytes of data in \a buffer.  The
        individual data type handlers may copy in less than this many
        bytes in to the credential.  For some data types where the
        size of the buffer is fixed or can be determined from its
        contents, you can specify ::KCDB_CBSIZE_AUTO for this
        parameter.
*/
KHMEXP khm_int32 KHMAPI
kcdb_cred_set_attrib(khm_handle cred,
                     const wchar_t * name,
                     void * buffer,
                     khm_size cbbuf);

/*! \brief Set an attribute in a credential by attribute id

    \param[in] buffer A pointer to a buffer containing the data to
        assign to the attribute.  Setting this to NULL has the effect
        of removing any data that is already assigned to the
        attribute.  If \a buffer is non-NULL, then \a cbbuf should
        specify the number of bytes in \a buffer.

    \param[in] cbbuf Number of bytes of data in \a buffer.  The
        individual data type handlers may copy in less than this many
        bytes in to the credential.
*/
KHMEXP khm_int32 KHMAPI
kcdb_cred_set_attr(khm_handle cred,
                   khm_int32 attr_id,
                   void * buffer,
                   khm_size cbbuf);

/*! \brief Get an attribute from a credential by name.

    \param[in] buffer The buffer that is to receive the attribute
        value.  Set this to NULL if only the required buffer size is
        to be returned.

    \param[in,out] cbbuf The number of bytes available in \a buffer.
        If \a buffer is not sufficient, returns KHM_ERROR_TOO_LONG and
        sets this to the required buffer size.

    \note Set both \a buffer and \a cbbuf to NULL if only the
        existence of the attribute is to be checked.  If the attribute
        exists in this credential then the function will return
        KHM_ERROR_SUCCESS, otherwise it returns KHM_ERROR_NOT_FOUND.
*/
KHMEXP khm_int32 KHMAPI
kcdb_cred_get_attrib(khm_handle cred,
                     const wchar_t * name,
                     khm_int32 * attr_type,
                     void * buffer,
                     khm_size * cbbuf);

/*! \brief Get an attribute from a credential by attribute id.

    \param[in] buffer The buffer that is to receive the attribute
        value.  Set this to NULL if only the required buffer size is
        to be returned.

    \param[in,out] cbbuf The number of bytes available in \a buffer.
        If \a buffer is not sufficient, returns KHM_ERROR_TOO_LONG and
        sets this to the required buffer size.

    \param[out] attr_type Receives the data type of the attribute.
        Set this to NULL if the type is not required.

    \note Set both \a buffer and \a cbbuf to NULL if only the
        existence of the attribute is to be checked.  If the attribute
        exists in this credential then the function will return
        KHM_ERROR_SUCCESS, otherwise it returns KHM_ERROR_NOT_FOUND.
*/
KHMEXP khm_int32 KHMAPI
kcdb_cred_get_attr(khm_handle cred,
                   khm_int32 attr_id,
                   khm_int32 * attr_type,
                   void * buffer,
                   khm_size * cbbuf);

/*! \brief Get the name of a credential.

    \param[in] buffer The buffer that is to receive the credential
        name.  Set this to NULL if only the required buffer size is to
        be returned.

    \param[in,out] cbbuf The number of bytes available in \a buffer.
        If \a buffer is not sufficient, returns KHM_ERROR_TOO_LONG and
        sets this to the required buffer size.
*/
KHMEXP khm_int32 KHMAPI
kcdb_cred_get_name(khm_handle cred,
                   wchar_t * buffer,
                   khm_size * cbbuf);

/*! \brief Get the string representation of a credential attribute.

    A shortcut function which generates the string representation of a
    credential attribute directly.

    \param[in] vcred A handle to a credential

    \param[in] attr_id The attribute to retrieve

    \param[out] buffer A pointer to a string buffer which receives the
        string form of the attribute.  Set this to NULL if you only
        want to determine the size of the required buffer.

    \param[in,out] pcbbuf A pointer to a #khm_int32 that, on entry,
        holds the size of the buffer pointed to by \a buffer, and on
        exit, receives the actual number of bytes that were copied.

    \param[in] flags Flags for the string conversion. Can be set to
        one of KCDB_TS_LONG or KCDB_TS_SHORT.  The default is
        KCDB_TS_LONG.

    \retval KHM_ERROR_SUCCESS Success
    \retval KHM_ERROR_NOT_FOUND The given attribute was either invalid
        or was not defined for this credential
    \retval KHM_ERROR_INVALID_PARAM One or more parameters were invalid
    \retval KHM_ERROR_TOO_LONG Either \a buffer was NULL or the
        supplied buffer was insufficient
*/
KHMEXP khm_int32 KHMAPI
kcdb_cred_get_attr_string(khm_handle vcred,
                          khm_int32 attr_id,
                          wchar_t * buffer,
                          khm_size * pcbbuf,
                          khm_int32 flags);

/*! \brief Get the string representation of a credential attribute by name.

    A shortcut function which generates the string representation of a
    credential attribute directly.

    \param[in] vcred A handle to a credential

    \param[in] attrib The name of the attribute to retrieve

    \param[out] buffer A pointer to a string buffer which receives the
        string form of the attribute.  Set this to NULL if you only
        want to determine the size of the required buffer.

    \param[in,out] pcbbuf A pointer to a #khm_int32 that, on entry,
        holds the size of the buffer pointed to by \a buffer, and on
        exit, receives the actual number of bytes that were copied.

    \param[in] flags Flags for the string conversion. Can be set to
        one of KCDB_TS_LONG or KCDB_TS_SHORT.  The default is
        KCDB_TS_LONG.

    \see kcdb_cred_get_attr_string()
*/
KHMEXP khm_int32 KHMAPI
kcdb_cred_get_attrib_string(khm_handle cred,
                            const wchar_t * name,
                            wchar_t * buffer,
                            khm_size * cbbuf,
                            khm_int32 flags) ;


/*! \brief Get a held reference to the identity associated with a credential

    Use kcdb_identity_release() to release the reference that is
    returned.

    \see kcdb_identity_relase()
*/
KHMEXP khm_int32 KHMAPI
kcdb_cred_get_identity(khm_handle cred,
                       khm_handle * identity);

/*! \brief Set the identity of a credential

    While it is ill-advised to change the identity of a credential
    that has been placed in one or more credential sets, there can be
    legitimate reasons for doing so.  Only change the identity of a
    credential that is not placed in a credential set or placed in a
    credential set that is only used by a single entity.
*/
KHMEXP khm_int32 KHMAPI
kcdb_cred_set_identity(khm_handle vcred,
                       khm_handle id);

/*! \brief Get the serial number for the credential.

    Each credential gets assigned a serial number at the time it is
    created.  This will stay with the credential for its lifetime.

    \param[out] pserial Receives the serial number. Cannot be NULL.
*/
KHMEXP khm_int32 KHMAPI
kcdb_cred_get_serial(khm_handle cred,
                     khm_ui_8 * pserial);

/*! \brief Get the type of the credential.

    The returned type is a credential type. Doh.

    \param[out] type Receives the type.  Cannot be NULL.
*/
KHMEXP khm_int32 KHMAPI
kcdb_cred_get_type(khm_handle cred,
                   khm_int32 * type);

/*! \brief Retrieve flags from a credential

    The flags returned will be place in the location pointed to by \a
    flags.  Note that the specified credential must be an active
    credential for the operation to succeed.  This means the
    ::KCDB_CRED_FLAG_DELETED will never be retured by this function.
 */
KHMEXP khm_int32 KHMAPI
kcdb_cred_get_flags(khm_handle cred,
                    khm_int32 * flags);

/*! \brief Set the flags of a credential

    The flags specified in the \a mask parameter will be set to the
    values specified in the \a flags parameter.  The flags that are
    not included in \a mask will not be modified.

    This function can not be used to set the ::KCDB_CRED_FLAG_DELETED
    flag.  If this bit is specified in either \a flags or \a mask, it
    will be ignored.

    \see ::KCDB_CRED_FLAGMASK_ALL
 */
KHMEXP khm_int32 KHMAPI
kcdb_cred_set_flags(khm_handle cred,
                    khm_int32 flags,
                    khm_int32 mask);

/*! \brief Hold a reference to a credential.

    Use kcdb_cred_release() to release the reference.

    \see kcdb_cred_release()
*/
KHMEXP khm_int32 KHMAPI
kcdb_cred_hold(khm_handle cred);

/*! \brief Release a held reference to a credential.
*/
KHMEXP khm_int32 KHMAPI
kcdb_cred_release(khm_handle cred);

/*! \brief Delete a credential.

    The credential will be marked for deletion and will continue to
    exist until all held references are released.  If the credential
    is bound to a credential set or the root credential store, it will
    be removed from the respective container.
*/
KHMEXP khm_int32 KHMAPI
kcdb_cred_delete(khm_handle cred);

/*! \brief Compare an attribute of two credentials by name.

    \return The return value is dependent on the type of the attribute
    and indicate a weak ordering of the attribute values of the two
    credentials.  If one or both credentials do not contain the
    attribute, the return value is 0, which signifies that no ordering
    can be determined.
*/
KHMEXP khm_int32 KHMAPI
kcdb_creds_comp_attrib(khm_handle cred1,
                       khm_handle cred2,
                       const wchar_t * name);

/*! \brief Compare an attribute of two credentials by attribute id.

    \return The return value is dependent on the type of the attribute
    and indicate a weak ordering of the attribute values of the two
    credentials.  If one or both credentials do not contain the
    attribute, the return value is 0, which signifies that no ordering
    can be determined.
*/
KHMEXP khm_int32 KHMAPI
kcdb_creds_comp_attr(khm_handle cred1,
                     khm_handle cred2,
                     khm_int32 attr_id);

/*! \brief Compare two credentials for equivalence

    \return Non-zero if the two credentials are equal.  Zero otherwise.
    \note Two credentials are considered equal if all the following hold:
        - Both refer to the same identity.
        - Both have the same name.
        - Both have the same type.
*/
KHMEXP khm_int32 KHMAPI
kcdb_creds_is_equal(khm_handle cred1,
                    khm_handle cred2);

/*@}*/
/*@}*/

/********************************************************************/

/*! \defgroup kcdb_type Credential attribute types

@{*/

/*! \brief Convert a field to a string

    Provides a string representation of a field in a credential.  The
    data buffer can be assumed to be valid.

    On entry, \a s_buf can be NULL if only the required size of the
    buffer is to be returned.  \a pcb_s_buf should be non-NULL and
    should point to a valid variable of type ::khm_size that will, on
    entry, contain the size of the buffer pointed to by \a s_buf if \a
    s_buf is not \a NULL, and on exit will contain the number of bytes
    consumed in \a s_buf, or the required size of the buffer if \a
    s_buf was NULL or the size of the buffer was insufficient.

    The implementation should verify the parameters that are passed in
    to the function.

    The data pointed to by \a data should not be modified in any way.

    \param[in] data Valid pointer to a block of data

    \param[in] cb_data Number of bytes in data block pointed to by \a
        data

    \param[out] s_buf Buffer to receive the string representation of
        data.  If the data type flags has KCDB_TYPE_FLAG_CB_AUTO, then
        this parameter could be set to KCDB_CBSIZE_AUTO.  In this
        case, the function should compute the size of the input buffer
        assuming that the input buffer is valid.

    \param[in,out] pcb_s_buf On entry, contains the size of the buffer
        pointed to by \a s_buf, and on exit, contains the number of
        bytes used by the string representation of the data including
        the NULL terminator

    \param[in] flags Flags for formatting the string

    \retval KHM_ERROR_SUCCESS The string representation of the data
        field was successfully copied to \a s_buf and the size of the
        buffer used was copied to \a pcb_s_buf.

    \retval KHM_ERROR_INVALID_PARAM One or more parameters were invalid

    \retval KHM_ERROR_TOO_LONG Either \a s_buf was \a NULL or the size
        indicated by \a pcb_s_buf was too small to contain the string
        representation of the value.  The required size of the buffer
        is in \a pcb_s_buf.

    \note This documents the expected behavior of this prototype function

    \see ::kcdb_type
 */
typedef khm_int32
(KHMAPI *kcdb_dtf_toString)(const void *     data,
                            khm_size         cb_data,
                            wchar_t *        s_buf,
                            khm_size *       pcb_s_buf,
                            khm_int32        flags);

/*! \brief Verifies whetehr the given buffer contains valid data

    The function should examine the buffer and the size of the buffer
    and determine whether or not the buffer contains valid data for
    this data type.

    The data field pointed to by \a data should not be modified in any
    way.

    \param[in] data A pointer to a data buffer

    \param[in] cb_data The number of bytes in the data buffer. If the
        data type flags has KCDB_TYPE_FLAG_CB_AUTO, then this
        parameter could be set to KCDB_CBSIZE_AUTO.  In this case, the
        function should compute the size of the input buffer assuming
        that the input buffer is valid.

    \return TRUE if the data is valid, FALSE otherwise.

    \note This documents the expected behavior of this prototype function

    \see ::kcdb_type
*/
typedef khm_boolean
(KHMAPI *kcdb_dtf_isValid)(const void *     data,
                           khm_size         cb_data);

/*! \brief Compare two fields

    Compare the two data fields and return a value indicating their
    relative ordering.  The return value follows the same
    specification as strcmp().

    Both data buffers that are passed in can be assumed to be valid.

    None of the data buffers should be modified in any way.

    \param[in] data_l Valid pointer to first data buffer

    \param[in] cb_data_l Number of bytes in \a data_l. If the data
        type flags has KCDB_TYPE_FLAG_CB_AUTO, then this parameter
        could be set to KCDB_CBSIZE_AUTO.  In this case, the function
        should compute the size of the input buffer assuming that the
        input buffer is valid.

    \param[in] data_r Valid pointer to second data buffer

    \param[in] cb_data_r Number of bytes in \a data_r. If the data
        type flags has KCDB_TYPE_FLAG_CB_AUTO, then this parameter
        could be set to KCDB_CBSIZE_AUTO.  In this case, the function
        should compute the size of the input buffer assuming that the
        input buffer is valid.

    \return The return value should be
        - Less than zero if \a data_l &lt; \a data_r
        - Equal to zero if \a data_l == \a data_r or if this data type can not be compared
        - Greater than zero if \a data_l &gt; \a data_r

    \note This documents the expected behavior of this prototype function

    \see ::kcdb_type
*/
typedef khm_int32
(KHMAPI *kcdb_dtf_comp)(const void *     data_l,
                        khm_size         cb_data_l,
                        const void *     data_r,
                        khm_size         cb_data_r);

/*! \brief Duplicate a data field

    Duplicates a data field.  The buffer pointed to by \a data_src
    contains a valid field.  The function should copy the field with
    appropriate adjustments to \a data_dst.

    The \a data_dst parameter can be NULL if only the required size of
    the buffer is needed.  In this case, teh function should set \a
    pcb_data_dst to the number of bytes required and then return
    KHM_ERROR_TOO_LONG.

    \param[in] data_src Pointer to a valid data buffer

    \param[in] cb_data_src Number of bytes in \a data_src. If the data
        type flags has KCDB_TYPE_FLAG_CB_AUTO, then this parameter
        could be set to KCDB_CBSIZE_AUTO.  In this case, the function
        should compute the size of the input buffer assuming that the
        input buffer is valid.

    \param[out] data_dst Poitner to destination buffer.  Could be NULL
       if only the required size of the destination buffer is to be
       returned.

    \param[in,out] pcb_data_dst On entry specifies the number of bytes
        in \a data_dst, and on exit should contain the number of bytes
        copied.

    \retval KHM_ERROR_SUCCESS The data was successfully copied.  The
        number of bytes copied is in \a pcb_data_dst

    \retval KHM_ERROR_INVALID_PARAM One or more parameters is incorrect.

    \retval KHM_ERROR_TOO_LONG Either \a data_dst was NULL or the size
        of the buffer was insufficient.  The required size is in \a
        pcb_data_dst

    \note This documents the expected behavior of this prototype function

    \see ::kcdb_type
 */
typedef khm_int32
(KHMAPI *kcdb_dtf_dup)(const void * data_src,
                       khm_size cb_data_src,
                       void * data_dst,
                       khm_size * pcb_data_dst);

/*! \brief A data type descriptor.

    Handles basic operation for a specific data type.

    \see \ref cred_data_types
*/
typedef struct tag_kcdb_type {
    wchar_t *   name;
    khm_int32   id;
    khm_int32   flags;

    khm_size    cb_min;
    khm_size    cb_max;

    kcdb_dtf_toString    toString;
        /*!< Provides a string representation for a value.  */

    kcdb_dtf_isValid     isValid;
        /*!< Returns true of the value is valid for this data type */

    kcdb_dtf_comp        comp;
        /*!< Compare two values and return \a strcmp style return value */

    kcdb_dtf_dup         dup;
        /*!< Duplicate a value into a secondary buffer */
} kcdb_type;

/*! \name Flags for kcdb_type::toString
@{*/
/*! \brief Specify that the short form of the string representation should be returned.

    Flags for #kcdb_type::toString.  The flag specifies how long the
    string representation should be.  The specific length of a short
    or long description is not restricted and it is up to the
    implementation to choose how to interpret the flags.

    Usually, KCDB_TS_SHORT is specified when the amount of space that
    is available to display the string is very restricted.  It may be
    the case that the string is truncated to facilitate displaying in
    a constrainted space.
*/
#define KCDB_TS_SHORT   1

/*! \brief Specify that the long form of the string representation should be returned

    Flags for #kcdb_type::toString.  The flag specifies how long the
    string representation should be.  The specific length of a short
    or long description is not restricted and it is up to the
    implementation to choose how to interpret the flags.

*/
#define KCDB_TS_LONG    0
/*@}*/

/*! \brief The maximum number of bytes allowed for a value of any type */
#define KCDB_TYPE_MAXCB 16384

/*! \name Flags for kcdb_type
@{*/

/*! \brief The type supports KCDB_CBSIZE_AUTO.

    Used for types where the size of the object can be determined
    through context or by the object content.  Such as for objects
    that have a fixed size or unicode strings that have a terminator.

    This implies that ALL the object manipulation callbacks that are
    defined in this type definition support the KCDB_CBSIZE_AUTO
    value.
*/
#define KCDB_TYPE_FLAG_CB_AUTO      16

/*! \brief The \a cb_min member is valid.

    The \a cb_min member defines the minimum number of bytes that an
    object of this type will consume.

    \note If this flag is used in conjunction with \a
    KCDB_TYPE_FLAG_CB_MAX then, \a cb_min must be less than or equal
    to \a cb_max.
*/
#define KCDB_TYPE_FLAG_CB_MIN       128

/*! \brief The \a cb_max member is valid.

    The \a cb_max member defines the maximum number of bytes that an
    object of this type will consume.

    \note If this flag is used in conjunction with \a
        KCDB_TYPE_FLAG_CB_MIN then, \a cb_min must be less than or
        equal to \a cb_max. */
#define KCDB_TYPE_FLAG_CB_MAX       256

/*! \brief Denotes that objects of this type have a fixed size.

    If this flags is specified, then the type definition must also
    specify cb_min and cb_max, which must both be the same value.

    \note Implies \a KCDB_TYPE_FLAG_CB_AUTO, \a KCDB_TYPE_FLAG_CB_MIN
        and \a KCDB_TYPE_FLAG_CB_MAX. Pay special attention to the
        implication of \a KCDB_TYPE_FLAG_AUTO.
*/
#define KCDB_TYPE_FLAG_CB_FIXED (KCDB_TYPE_FLAG_CB_AUTO|KCDB_TYPE_FLAG_CB_MIN|KCDB_TYPE_FLAG_CB_MAX)

/*@}*/

KHMEXP khm_int32 KHMAPI
kcdb_type_get_id(const wchar_t *name, khm_int32 * id);

/*! \brief Return the type descriptor for a given type id

    \param[out] info Receives a held reference to a type descriptor.
        Use kcdb_type_release_info() to release the handle.  If the \a
        info parameter is NULL, the function returns KHM_ERROR_SUCCESS
        if \a id is a valid type id, and returns KHM_ERROR_NOT_FOUND
        otherwise.

    \see kcdb_type_release_info()
*/
KHMEXP khm_int32 KHMAPI
kcdb_type_get_info(khm_int32 id, kcdb_type ** info);

/*! \brief Release a reference to a type info structure

    Releases the reference to the type information obtained with a
    prior call to kcdb_type_get_info().
 */
KHMEXP khm_int32 KHMAPI
kcdb_type_release_info(kcdb_type * info);

/*! \brief Get the name of a type

    Retrieves the non-localized name of the specified type.
 */
KHMEXP khm_int32 KHMAPI
kcdb_type_get_name(khm_int32 id,
                   wchar_t * buffer,
                   khm_size * cbbuf);

/*! \brief Register a credentials attribute type

    The credentials type record pointed to by \a type defines a new
    credential attribute type.  The \a id member of \a type may be set
    to KCDB_TYPE_INVALID to indicate that an attribute ID is to be
    generated automatically.

    \param[in] type The type descriptor
    \param[out] new_id Receives the identifier for the credential attribute type.
*/
KHMEXP khm_int32 KHMAPI
kcdb_type_register(const kcdb_type * type,
                   khm_int32 * new_id);

/*! \brief Unregister a credential attribute type

    Removes the registration for the specified credentials attribute
    type.
*/
KHMEXP khm_int32 KHMAPI
kcdb_type_unregister(khm_int32 id);

KHMEXP khm_int32 KHMAPI
kcdb_type_get_next_free(khm_int32 * id);

/*! \name Conversion functions
@{*/
/*! \brief Convert a time_t value to FILETIME
*/
KHMEXP void KHMAPI
TimetToFileTime( time_t t, LPFILETIME pft );

/*! \brief Convert a time_t interval to a FILETIME interval
*/
KHMEXP void KHMAPI
TimetToFileTimeInterval(time_t t, LPFILETIME pft);

/*! \brief Convert a FILETIME interval to seconds
*/
KHMEXP long KHMAPI
FtIntervalToSeconds(LPFILETIME pft);

/*! \brief Convert a FILETIME interval to milliseconds
*/
KHMEXP long KHMAPI
FtIntervalToMilliseconds(LPFILETIME pft);

/*! \brief Compare two FILETIME values

    The return value is similar to the return value of strcmp(), based
    on the comparison of the two FILETIME values.
 */
KHMEXP long KHMAPI
FtCompare(LPFILETIME pft1, LPFILETIME pft2);

/*! \brief Convert a FILETIME to a 64 bit int
*/
KHMEXP khm_int64 KHMAPI FtToInt(LPFILETIME pft);

/*! \brief Convert a 64 bit int to a FILETIME
*/
KHMEXP FILETIME KHMAPI IntToFt(khm_int64 i);

/*! \brief Calculate the difference between two FILETIMEs

    Returns the value of ft1 - ft2
 */
KHMEXP FILETIME KHMAPI FtSub(LPFILETIME ft1, LPFILETIME ft2);

/*! \brief Calculate the sum of two FILETIMEs

    Return the value of ft1 + ft2
 */
KHMEXP FILETIME KHMAPI FtAdd(LPFILETIME ft1, LPFILETIME ft2);

/*! \brief Convert a FILETIME inverval to a string
*/
KHMEXP khm_int32 KHMAPI
FtIntervalToString(LPFILETIME data,
                   wchar_t * buffer,
                   khm_size * cb_buf);

/*! \brief Parse a string representing an interval into a FILETIME interval

    The string is a localized string which should look like the
    following:

    \code
    [number unit] [number unit]...
    \endcode

    where \a number is an integer while \a unit is a localized
    (possibly abbreviated) unit specification.  The value of the
    described interval is calculated as the sum of each \a number in
    \a units.  For example :

    \code
    1 hour 36 minutes
    \endcode

    would result in an interval specification that's equivalent to 1
    hour and 36 minutes.  Of course there is no restriction on the
    order in which the \a number \a unit specifications are given and
    the same unit may be repeated multiple times.

    \retval KHM_ERROR_INVALID_PARAM The given string was invalid or had
        a token that could not be parsed.  It can also mean that \a
        pft was NULL or \a str was NULL.

    \retval KHM_ERROR_SUCCESS The string was successfully parsed and
        the result was placed in \a pft.
*/
KHMEXP khm_int32 KHMAPI
IntervalStringToFt(FILETIME * pft, wchar_t * str);

/*! \brief Return number of milliseconds till next representation change

   Returns the number of milliseconds that must elapse away from the
   interval specified in pft \a for the representation of pft to change
   from whatever it is right now.

   Returns 0 if the representation is not expected to change.
*/
KHMEXP long KHMAPI
FtIntervalMsToRepChange(LPFILETIME pft);

/*! \brief Convert a safe ANSI string to a Unicode string

    The resulting string is guaranteed to be NULL terminated and
    within the size limit set by \a cbwstr.

    If the whole string cannot be converted, \a wstr is set to an
    empty string.

    \return the number of characters converted.  This is always either
        the length of the string \a astr or 0.
*/
KHMEXP int KHMAPI
AnsiStrToUnicode( wchar_t * wstr, size_t cbwstr, const char * astr);

/*! \brief Convert a Unicode string to ANSI

    The resulting string is guaranteed to be NULL terminated and
    within the size limit set by \a cbdest.

    \return the number of characters converted.  This is always either
        the length of the string \a src or 0.
*/
KHMEXP int KHMAPI
UnicodeStrToAnsi( char * dest, size_t cbdest, const wchar_t * src);
/*@}*/

/*! \name Standard type identifiers and names
@{*/

/*! Maximum identifier number */
#define KCDB_TYPE_MAX_ID 255

/*! \brief Invalid type

    Used by functions that return a type identifier to indicate that
    the returned type identifier is invalid.  Also used to indicate
    that a type identifier is not available */
#define KCDB_TYPE_INVALID (-1)

/*! \brief All types

    Used by filters to indicate that all types are allowed.
*/
#define KCDB_TYPE_ALL       KCDB_TYPE_INVALID

/*! \brief Void

    No data.  This is not an actual data type.
 */
#define KCDB_TYPE_VOID      0

/*! \brief String

    NULL terminated Unicode string.  The byte count for a string
    attribute always includes the terminating NULL.
 */
#define KCDB_TYPE_STRING    1

/*! \brief Data

    A date/time represented in FILETIME format.
 */
#define KCDB_TYPE_DATE      2

/*! \brief Interval

    An interval of time represented as the difference between two
    FILETIME values.
 */
#define KCDB_TYPE_INTERVAL  3

/*! \brief 32-bit integer

    A 32-bit signed integer.
 */
#define KCDB_TYPE_INT32     4

/*! \brief 64-bit integer

    A 64-bit integer.
 */
#define KCDB_TYPE_INT64     5

/*! \brief Raw data

    A raw data buffer.
 */
#define KCDB_TYPE_DATA      6

#define KCDB_TYPENAME_VOID      L"Void"
#define KCDB_TYPENAME_STRING    L"String"
#define KCDB_TYPENAME_DATE      L"Date"
#define KCDB_TYPENAME_INTERVAL  L"Interval"
#define KCDB_TYPENAME_INT32     L"Int32"
#define KCDB_TYPENAME_INT64     L"Int64"
#define KCDB_TYPENAME_DATA      L"Data"
/*@}*/
/*@}*/

/********************************************************************/

/*! \defgroup kcdb_credattr Credential attributes */
/*@{*/

/*! \brief Prototype callback function for computed data types.

    If the flags for a particular attribute specifies that the value
    is computed, then a callback function should be specified.  The
    callback function will be called with a handle to a credential
    along with the attribute ID for the requested attribute.  The
    function should place the computed value in \a buffer.  The size
    of the buffer in bytes is specifed in \a cbsize.  However, if \a
    buffer is \a NULL, then the required buffer size should be placed
    in \a cbsize.
 */
typedef khm_int32
(KHMAPI *kcdb_attrib_compute_cb)(khm_handle cred,
                                 khm_int32 id,
                                 void * buffer,
                                 khm_size * cbsize);

/*! \brief Credential attribute descriptor

    \see kcdb_attrib_register()
*/
typedef struct tag_kcdb_attrib {
    wchar_t * name;             /*!< Name.  (Not localized,
                                  required) */
    khm_int32 id;               /*!< Identifier.  When registering,
                                  this can be set to
                                  ::KCDB_ATTR_INVALID if a unique
                                  identifier is to be generated. */
    khm_int32 alt_id;           /*!< Alternate identifier.  If the \a
                                  flags specify
                                  ::KCDB_ATTR_FLAG_ALTVIEW, then this
                                  field should specify the identifier
                                  of the canonical attribute from
                                  which this attribute is derived. */
    khm_int32 flags;            /*!< Flags. Combination of \ref
                                  kcdb_credattr_flags "attribute
                                  flags" */

    khm_int32 type;             /*!< Type of the attribute.  Must be valid. */

    wchar_t * short_desc;       /*!< Short description. (Localized,
                                  optional) */

    wchar_t * long_desc;        /*!< Long description. (Localized,
                                  optional) */

    kcdb_attrib_compute_cb compute_cb;
                                /*!< Callback.  Required if \a flags
                                  specify ::KCDB_ATTR_FLAG_COMPUTED. */

    khm_size compute_min_cbsize;
                                /*!< Minimum number of bytes required
                                  to store this attribute.  Required
                                  if ::KCDB_ATTR_FLAG_COMPUTED is
                                  specified.*/
    khm_size compute_max_cbsize;
                                /*!< Maximum number of bytes required
                                  to store this attribute.  Required
                                  if ::KCDB_ATTR_FLAG_COMPUTED is
                                  specified.*/
} kcdb_attrib;

/*! \brief Retrieve the ID of a named attribute */
KHMEXP khm_int32 KHMAPI
kcdb_attrib_get_id(const wchar_t *name,
                   khm_int32 * id);

/*! \brief Register an attribute

    \param[out] new_id Receives the ID of the newly registered
        attribute.  If the \a id member of the ::kcdb_attrib object is
        set to KCDB_ATTR_INVALID, then a unique ID is generated. */
KHMEXP khm_int32 KHMAPI
kcdb_attrib_register(const kcdb_attrib * attrib,
                     khm_int32 * new_id);

/*! \brief Retrieve the attribute descriptor for an attribute

    The descriptor that is returned must be released through a call to
    kcdb_attrib_release_info()

    If only the validity of the attribute identifier needs to be
    checked, you can pass in NULL for \a attrib.  In this case, if the
    identifier is valid, then the funciton will return
    KHM_ERROR_SUCCESS, otherwise it will return KHM_ERROR_NOT_FOUND.

    \see kcdb_attrib_release_info()
    */
KHMEXP khm_int32 KHMAPI
kcdb_attrib_get_info(khm_int32 id,
                     kcdb_attrib ** attrib);

/*! \brief Release an attribute descriptor

    \see kcdb_attrib_get_info()
    */
KHMEXP khm_int32 KHMAPI
kcdb_attrib_release_info(kcdb_attrib * attrib);

/*! \brief Unregister an attribute

    Once an attribute ID has been unregistered, it may be reclaimed by
    a subsequent call to kcdb_attrib_register().
*/
KHMEXP khm_int32 KHMAPI
kcdb_attrib_unregister(khm_int32 id);

/*! \brief Retrieve the description of an attribute

    \param[in] flags Specify \a KCDB_TS_SHORT to retrieve the short description. */
KHMEXP khm_int32 KHMAPI
kcdb_attrib_describe(khm_int32 id,
                     wchar_t * buffer,
                     khm_size * cbsize,
                     khm_int32 flags);

/*! \brief Count attributes

    Counts the number of attributes that match the given criteria.
    The criteria is specified against the flags of the attribute.  An
    attribute is a match if its flags satisfy the condition below:

    \code
    (attrib.flags & and_flags) == (eq_flags & and_flags)
    \endcode

    The number of attributes that match are returned in \a pcount.
 */
KHMEXP khm_int32 KHMAPI
kcdb_attrib_get_count(khm_int32 and_flags,
                      khm_int32 eq_flags,
                      khm_size * pcount);

/*! \brief List attribute identifiers

    Lists the identifiers of the attributes that match the given
    criteria.  The criteria is specified against the flags of the
    attribute.  An attribute is a match if the following condition is
    satisfied:

    \code
    (attrib.flags & and_flags) == (eq_flags & and_flags)
    \endcode

    The list of attributes found are copied to the \a khm_int32 array
    specified in \a plist.  The number of elements available in the
    buffer \a plist is specified in \a pcsize.  On exit, \a pcsize
    will hold the actual number of attribute identifiers copied to the
    array.

    \param[in] and_flags See above
    \param[in] eq_flags See above
    \param[in] plist A khm_int32 array
    \param[in,out] pcsize On entry, holds the number of elements
        available in the array pointed to by \a plist.  On exit, holds
        the number of elements copied to the array.

    \retval KHM_ERROR_SUCCESS The list of attribute identifiers have
        been copied.
    \retval KHM_ERROR_TOO_LONG The list was too long to fit in the
        supplied buffer.  As many elements as possible have been
        copied to the \a plist array and the required number of
        elements has been written to \a pcsize.

    \note The \a pcsize parameter specifies the number of khm_int32
        elements in the array and not the number of bytes in the
        array.  This is different from the usual size parameters used
        in the NetIDMgr API.
 */
KHMEXP khm_int32 KHMAPI
kcdb_attrib_get_ids(khm_int32 and_flags,
                    khm_int32 eq_flags,
                    khm_int32 * plist,
                    khm_size * pcsize);

/*! \defgroup kcdb_credattr_flags Attribute flags */
/*@{*/
/*! \brief The attribute is required */
#define KCDB_ATTR_FLAG_REQUIRED 0x00000008

/*! \brief The attribute is computed.

    If this flag is set, the \a compute_cb, \a compute_min_cbsize and
    \a compute_max_cbsize members of the ::kcdb_attrib attribute
    descriptor must be assigned valid values.
*/
#define KCDB_ATTR_FLAG_COMPUTED 0x00000010

/*! \brief System attribute.

    This cannot be specified for a custom attribute.  Implies that the
    value of the attribute is given by the credentials database
    itself.
*/
#define KCDB_ATTR_FLAG_SYSTEM   0x00000020

/*! \brief Hidden

    The attribute is not meant to be displayed to the user.  Setting
    this flag prevents this attribute from being listed in the list of
    available data fields in the UI.
*/
#define KCDB_ATTR_FLAG_HIDDEN   0x00000040

/*! \brief Property

    The attribute is a property.  The main difference between regular
    attributes and properties are that properties are not allocated
    off the credentials record.  Hence, a property can not be used as
    a credentials field.  Other objects such as identities can hold
    property sets.  A property set can hold both regular attributes as
    well as properties.
*/
#define KCDB_ATTR_FLAG_PROPERTY 0x00000080

/*! \brief Volatile

    A volatile property is one whose value changes often, such as
    ::KCDB_ATTR_TIMELEFT.  Some controls will make use of additional
    logic to deal with such values, or not display them at all.
 */
#define KCDB_ATTR_FLAG_VOLATILE 0x00000100

/*! \brief Alternate view

    The attribute is actually an alternate representation of another
    attribute.  The Canonical attribute name is specified in \a
    alt_id.

    Sometimes a certain attribute may need to be represented in
    different ways.  You can register multiple attributes for each
    view.  However, you should also provide a canonical attribute for
    whenever the canonical set of attributes of the credential is
    required.
 */
#define KCDB_ATTR_FLAG_ALTVIEW  0x00000200

/*! \brief Transient attribute

    A transient attribute is one whose absence is meaningful.  When
    updating one record using another, if a transient attribute is
    absent in the source but present in the destination, then the
    attribute is removed from the destination.
*/
#define KCDB_ATTR_FLAG_TRANSIENT 0x00000400

/*@}*/

/*! \defgroup kcdb_credattr_idnames Standard attribute IDs and names */
/*@{*/

/*! \name Attribute related constants */
/*@{*/
/*! \brief Maximum valid attribute ID */
#define KCDB_ATTR_MAX_ID        255

/*! \brief Minimum valid property ID */
#define KCDB_ATTR_MIN_PROP_ID   4096

/*! \brief Maximum number of properties */
#define KCDB_ATTR_MAX_PROPS     128

/*! \brief Maximum valid property ID */
#define KCDB_ATTR_MAX_PROP_ID (KCDB_ATTR_MIN_PROP_ID + KCDB_ATTR_MAX_PROPS - 1)

/*! \brief Invalid ID */
#define KCDB_ATTR_INVALID   (-1)

/*! \brief First custom attribute ID */
#define KCDB_ATTRID_USER        20

/*@}*/

/*!\name Attribute identifiers  */
/*@{*/
/*! \brief Name of the credential

    - \b Type: STRING
    - \b Flags: REQUIRED, COMPUTED, SYSTEM
 */
#define KCDB_ATTR_NAME          0

/*! \brief The identity handle for the credential

    - \b Type: INT64
    - \b Flags: REQUIRED, COMPUTED, SYSTEM, HIDDEN

    \note The handle returned in by specifying this attribute to
        kcdb_cred_get_attr() or kcdb_cred_get_attrib() is not held.
        While the identity is implicitly held for the duration that
        the credential is held, it is not recommended to obtain a
        handle to the identity using this method.  Use
        kcdb_cred_get_identity() instead.
*/
#define KCDB_ATTR_ID            1

/*! \brief The name of the identity

    - \b Type: STRING
    - \b Flags: REQUIRED, COMPUTED, SYSTEM
 */
#define KCDB_ATTR_ID_NAME       2

/*! \brief The type of the credential

    - \b Type: INT32
    - \b Flags: REQUIRED, COMPUTED, SYSTEM, HIDDEN
*/
#define KCDB_ATTR_TYPE          3

/*! \brief Type name for the credential

    - \b Type: STRING
    - \b Flags: REQUIRED, COMPUTED, SYSTEM
*/
#define KCDB_ATTR_TYPE_NAME     4

/*! \brief Name of the parent credential

    - \b Type: STRING
    - \b Flags: SYSTEM
*/
#define KCDB_ATTR_PARENT_NAME   5

/*! \brief Issed on

    - \b Type: DATE
    - \b Flags: SYSTEM
*/
#define KCDB_ATTR_ISSUE         6

/*! \brief Expires on

    - \b Type: DATE
    - \b Flags: SYSTEM
*/
#define KCDB_ATTR_EXPIRE        7

/*! \brief Renewable period expires on

    - \b Type: DATE
    - \b Flags: SYSTEM
*/
#define KCDB_ATTR_RENEW_EXPIRE  8

/*! \brief Time left till expiration

    - \b Type: INTERVAL
    - \b Flags: SYSTEM, COMPUTED, VOLATILE
*/
#define KCDB_ATTR_TIMELEFT      9

#define KCDB_ATTR_RENEW_TIMELEFT 10

/*! \brief Location of the credential

    - \b Type: STRING
    - \b Flags: SYSTEM
*/
#define KCDB_ATTR_LOCATION      11

/*! \brief Lifetime of the credential

    - \b Type: INTERVAL
    - \b Flags: SYSTEM
*/
#define KCDB_ATTR_LIFETIME      12

#define KCDB_ATTR_RENEW_LIFETIME 13

/*! \brief Flags for the credential

    - \b Type: INT32
    - \b Flags: REQUIRED, COMPUTED, SYSTEM, HIDDEN
 */
#define KCDB_ATTR_FLAGS         14

/*@}*/

/*!\name Attribute names */
/*@{ */

#define KCDB_ATTRNAME_NAME          L"Name"
#define KCDB_ATTRNAME_ID            L"Identity"
#define KCDB_ATTRNAME_ID_NAME       L"IdentityName"
#define KCDB_ATTRNAME_TYPE          L"TypeId"
#define KCDB_ATTRNAME_TYPE_NAME     L"TypeName"
#define KCDB_ATTRNAME_FLAGS         L"Flags"

#define KCDB_ATTRNAME_PARENT_NAME   L"Parent"
#define KCDB_ATTRNAME_ISSUE         L"Issued"
#define KCDB_ATTRNAME_EXPIRE        L"Expires"
#define KCDB_ATTRNAME_RENEW_EXPIRE  L"RenewExpires"
#define KCDB_ATTRNAME_TIMELEFT      L"TimeLeft"
#define KCDB_ATTRNAME_RENEW_TIMELEFT L"RenewTimeLeft"
#define KCDB_ATTRNAME_LOCATION      L"Location"
#define KCDB_ATTRNAME_LIFETIME      L"Lifetime"
#define KCDB_ATTRNAME_RENEW_LIFETIME L"RenewLifetime"

/*@}*/

/*@}*/

/*@}*/

/*****************************************************************************/

/*! \defgroup kcdb_credtype Credential types */
/*@{*/

/*! \brief Credential type descriptor */
typedef struct tag_kcdb_credtype {
    wchar_t * name;     /*!< name (less than KCDB_MAXCB_NAME bytes) */
    khm_int32 id;
    wchar_t * short_desc;       /*!< short localized description (less
                                  than KCDB_MAXCB_SHORT_DESC bytes) */
    wchar_t * long_desc;        /*!< long localized descriptionn (less
                                  than KCDB_MAXCB_LONG_DESC bytes) */
    khm_handle sub;             /*!< Subscription for credentials type
                                  hander.  This should be a valid
                                  subscription constructed through a
                                  call to kmq_create_subscription()
                                  and must handle KMSG_CRED messages
                                  that are marked as being sent to
                                  type specific subscriptions.

                                  The subscription will be
                                  automatically deleted with a call to
                                  kmq_delete_subscription() when the
                                  credentials type is unregistered.*/

    kcdb_cred_comp_func is_equal; /*!< Used as an additional clause
                                  when comparing two credentials for
                                  equality.  The function this is
                                  actually a comparison function, it
                                  should return zero if the two
                                  credentials are equal and non-zero
                                  if they are not.  The addtional \a
                                  rock parameter is always zero.

                                  It can be assumed that the identity,
                                  name and credentials type have
                                  already been found to be equal among
                                  the credentials and the credential
                                  type is the type that is being
                                  registered.*/

#ifdef _WIN32
    HICON icon;
#endif
} kcdb_credtype;

/*! \brief Maximum value of a credential type identifier

    Credential type identifiers are assigned serially unless the
    process registering the credential type sets a specific identity.
    The maximum identifier number places a hard limit to the number of
    credential types that can be registered at one time, which is
    KCDB_CREDTYPE_MAX_ID + 1.
 */
#define KCDB_CREDTYPE_MAX_ID 31

/*! \brief Specify all credential types

    This value is used by functions which filter credentials based on
    credential types.  Specifying this value tells the filter to
    accept all credential types.
 */
#define KCDB_CREDTYPE_ALL (-1)

/*! \brief Automatically determine a credential type identifier

    Used with kcdb_credtype_register() to specify that the credential
    type identifier should be automatically determined to avoid
    collisions.
 */
#define KCDB_CREDTYPE_AUTO (-2)

/*! \brief An invalid credential type

    Even though any non positive credential type ID is invalid
    anywhere where a specific credential type ID is required, this
    value is provided for explicit indication that the credential type
    is invalid.  Also it makes code more readable to have a constant
    that shouts out INVALID.

*/
#define KCDB_CREDTYPE_INVALID (-3)

/*! \brief Macro predicate for testing whether a credtype is valid

    Returns TRUE if the given credtype is valid.  This is a safe
    macro.
*/
#define KCDB_CREDTYPE_IS_VALID(t) ((t) >= 0)

/*! \brief Register a credentials type.

    The information given in the \a type parameter is used to register
    a new credential type.  Note that the \a name member of the \a
    type should be unique among all credential types.

    You can specify ::KCDB_CREDTYPE_AUTO as the \a id member of \a
    type to let kcdb_credtype_register() determine a suitable
    credential type identifier.  You can subsequently call
    kcdb_credtype_get_id() to retrieve the generated id or pass a
    valid pointer to a khm_int32 type variable as \a new_id.

    \param[in] type Credential type descriptor

    \param[out] new_id The credential type identifier that this type
        was registered as.

    \retval KHM_ERROR_SUCCESS The credential type was successfully registered.

    \retval KHM_ERROR_INVALID_PARAM One or more of the parameters were invalid

    \retval KHM_ERROR_TOO_LONG One or more of the string fields in \a
        type exceeded the character limit for that field.

    \retval KHM_ERROR_NO_RESOURCES When autogenerating credential type
        identifiers, this value indicates that the maximum number of
        credential types have been registered.  No more registrations
        can be accepted unless some credentials type is unregisred.

    \retval KHM_ERROR_DUPLICATE The \a name or \a id that was
        specified is already in use.
*/
KHMEXP khm_int32 KHMAPI
kcdb_credtype_register(const kcdb_credtype * type,
                       khm_int32 * new_id);

/*! \brief Return a held reference to a \a kcdb_credtype object describing the credential type.

    The reference points to a static internal object of type \a
    kcdb_credtype.  Use the kcdb_credtype_release_info() function to
    release the reference.

    Also, the structure passed in as the \a type argument to
    kcdb_credtype_register() is not valid as a credential type
    descriptor.  Use kcdb_credtype_get_info() to obtain the actual
    credential type descriptor.

    \param[in] id Credentials type identifier.

    \param[out] type Receives the credentials descriptor handle.  If
        \a type is NULL, then no handle is returned.  However, the
        function will still return \a KHM_ERROR_SUCCESS if the \a id
        parameter passed in is a valid credentials type identifier.

    \see kcdb_credtype_release_info()
    \see kcdb_credtype_register()
*/
KHMEXP khm_int32 KHMAPI
kcdb_credtype_get_info(khm_int32 id,
                       kcdb_credtype ** type);

/*! \brief Release a reference to a \a kcdb_credtype object

    Undoes the hold obtained on a \a kcdb_credtype object from a
    previous call to kcdb_credtype_get_info().

    \see kcdb_credtype_get_info()
 */
KHMEXP khm_int32 KHMAPI
kcdb_credtype_release_info(kcdb_credtype * type);

/*! \brief Unregister a credentials type

    Undoes the registration performed by kcdb_credtype_register().

    This should only be done when the credentials provider is being
    unloaded.
 */
KHMEXP khm_int32 KHMAPI
kcdb_credtype_unregister(khm_int32 id);

/*! \brief Retrieve the name of a credentials type

    Given a credentials type identifier, retrieves the name.  The name
    is not localized and serves as a persistent identifier of the
    credentials type.

    \param[out] buf The buffer to receive the name.  Could be \a NULL
        if only the length of the buffer is required.

    \param[in,out] cbbuf On entry, specifies the size of the buffer
        pointed to by \a buf if \a buf is not NULL.  On exit, contains
        the number of bytes copied to \a buf or the required size of
        the buffer.

    \retval KHM_ERROR_SUCCESS The call succeeded.

    \retval KHM_ERROR_TOO_LONG Either \a buf was NULL or the supplied
        buffer was not large enough.  The required size is in \a cbbuf.

    \retval KHM_ERROR_INVALID_PARAM Invalid parameter.
 */
KHMEXP khm_int32 KHMAPI
kcdb_credtype_get_name(khm_int32 id,
                       wchar_t * buf,
                       khm_size * cbbuf);

/*! \brief Retrieve the type specific subscription for a type

    Given a credentials type, this function returns the credentials
    type specific subcription.  It may return NULL if the subscription
    is not available.
 */
KHMEXP khm_handle KHMAPI
kcdb_credtype_get_sub(khm_int32 id);

/*! \brief Get the description of a credentials type

   Unlike the name of a credential type, the description is localized.

   \param[in] id Credentials type identifier

   \param[out] buf Receives the description.  Can bet set to NULL if
       only the size of the buffer is required.

   \param[in,out] cbbuf On entry, specifies the size of the buffer
       pointed to by \a buf.  On exit, specifies the required size of
       the buffer or the number of bytes copied, depending on whether
       the call succeeded or not.

   \param[in] flags Specify ::KCDB_TS_SHORT if the short version of
       the description is desired if there is more than one.

   \retval KHM_ERROR_SUCCESS The call succeeded
   \retval KHM_ERROR_TOO_LONG Either \a buf was NULL or the supplied buffer was insufficient.  The required size is specified in \a cbbuf.
   \retval KHM_ERROR_INVALID_PARAM One or more parameters were invalid.
 */
KHMEXP khm_int32 KHMAPI
kcdb_credtype_describe(khm_int32 id,
                       wchar_t * buf,
                       khm_size * cbbuf,
                       khm_int32 flags);

/*! \brief Look up the identifier of a credentials type by name

    Given a name, looks up the identifier.

    \param[in] name Name of the credentials type
    \param[out] id Receives the identifier if the call succeeds

 */
KHMEXP khm_int32 KHMAPI
kcdb_credtype_get_id(const wchar_t * name,
                     khm_int32 * id);

/*@}*/

/*********************************************************************/

/*! \defgroup kcdb_buf Generic access to buffer

    Currently, credentials and identities both hold record data types.
    This set of API's allow an application to access fields in the
    records using a single interface.  Note that credentials only
    accept regular attributes while identities can hold both
    attributes and properties.

    Handles to credentials and identities are implicitly also handles
    to records.  Thus they can be directly used as such.
*/
/*@{*/

/*! \brief Get an attribute from a record by attribute id.

    \param[in] buffer The buffer that is to receive the attribute
        value.  Set this to NULL if only the required buffer size is
        to be returned.

    \param[in,out] cbbuf The number of bytes available in \a buffer.
        If \a buffer is not sufficient, returns KHM_ERROR_TOO_LONG and
        sets this to the required buffer size.

    \param[out] attr_type Receives the data type of the attribute.
        Set this to NULL if the type is not required.

    \note Set both \a buffer and \a cbbuf to NULL if only the
        existence of the attribute is to be checked.  If the attribute
        exists in this record then the function will return
        KHM_ERROR_SUCCESS, otherwise it returns KHM_ERROR_NOT_FOUND.
*/
KHMEXP khm_int32 KHMAPI
kcdb_buf_get_attr(khm_handle  record,
                  khm_int32   attr_id,
                  khm_int32 * attr_type,
                  void *      buffer,
                  khm_size *  pcb_buf);

/*! \brief Get an attribute from a record by name.

    \param[in] buffer The buffer that is to receive the attribute
        value.  Set this to NULL if only the required buffer size is
        to be returned.

    \param[in,out] cbbuf The number of bytes available in \a buffer.
        If \a buffer is not sufficient, returns KHM_ERROR_TOO_LONG and
        sets this to the required buffer size.

    \note Set both \a buffer and \a cbbuf to NULL if only the
        existence of the attribute is to be checked.  If the attribute
        exists in this record then the function will return
        KHM_ERROR_SUCCESS, otherwise it returns KHM_ERROR_NOT_FOUND.
*/
KHMEXP khm_int32 KHMAPI
kcdb_buf_get_attrib(khm_handle  record,
                    const wchar_t *   attr_name,
                    khm_int32 * attr_type,
                    void *      buffer,
                    khm_size *  pcb_buf);

/*! \brief Get the string representation of a record attribute.

    A shortcut function which generates the string representation of a
    record attribute directly.

    \param[in] record A handle to a record

    \param[in] attr_id The attribute to retrieve

    \param[out] buffer A pointer to a string buffer which receives the
        string form of the attribute.  Set this to NULL if you only
        want to determine the size of the required buffer.

    \param[in,out] pcbbuf A pointer to a #khm_int32 that, on entry,
        holds the size of the buffer pointed to by \a buffer, and on
        exit, receives the actual number of bytes that were copied.

    \param[in] flags Flags for the string conversion. Can be set to
        one of KCDB_TS_LONG or KCDB_TS_SHORT.  The default is
        KCDB_TS_LONG.

    \retval KHM_ERROR_SUCCESS Success
    \retval KHM_ERROR_NOT_FOUND The given attribute was either invalid
        or was not defined for this record
    \retval KHM_ERROR_INVALID_PARAM One or more parameters were invalid
    \retval KHM_ERROR_TOO_LONG Either \a buffer was NULL or the
        supplied buffer was insufficient
*/
KHMEXP khm_int32 KHMAPI
kcdb_buf_get_attr_string(khm_handle  record,
                         khm_int32   attr_id,
                         wchar_t *   buffer,
                         khm_size *  pcbbuf,
                         khm_int32  flags);

/*! \brief Get the string representation of a record attribute by name.

    A shortcut function which generates the string representation of a
    record attribute directly.

    \param[in] record A handle to a record

    \param[in] attrib The name of the attribute to retrieve

    \param[out] buffer A pointer to a string buffer which receives the
        string form of the attribute.  Set this to NULL if you only
        want to determine the size of the required buffer.

    \param[in,out] pcbbuf A pointer to a #khm_int32 that, on entry,
        holds the size of the buffer pointed to by \a buffer, and on
        exit, receives the actual number of bytes that were copied.

    \param[in] flags Flags for the string conversion. Can be set to
        one of KCDB_TS_LONG or KCDB_TS_SHORT.  The default is
        KCDB_TS_LONG.

    \see kcdb_cred_get_attr_string()
*/
KHMEXP khm_int32 KHMAPI
kcdb_buf_get_attrib_string(khm_handle  record,
                           const wchar_t *   attr_name,
                           wchar_t *   buffer,
                           khm_size *  pcbbuf,
                           khm_int32   flags);

/*! \brief Set an attribute in a record by attribute id

    \param[in] cbbuf Number of bytes of data in \a buffer.  The
        individual data type handlers may copy in less than this many
        bytes in to the record.
*/
KHMEXP khm_int32 KHMAPI
kcdb_buf_set_attr(khm_handle  record,
                  khm_int32   attr_id,
                  void *      buffer,
                  khm_size    cbbuf);

/*! \brief Set an attribute in a record by name

    \param[in] cbbuf Number of bytes of data in \a buffer.  The
        individual data type handlers may copy in less than this many
        bytes in to the record.
*/
KHMEXP khm_int32 KHMAPI
kcdb_buf_set_attrib(khm_handle  record,
                    const wchar_t *   attr_name,
                    void *      buffer,
                    khm_size    cbbuf);

KHMEXP khm_int32 KHMAPI
kcdb_buf_hold(khm_handle  record);

KHMEXP khm_int32 KHMAPI
kcdb_buf_release(khm_handle record);

/*@}*/

/********************************************************************/

/* Notification operation constants */

#define KCDB_OP_INSERT      1
#define KCDB_OP_DELETE      2
#define KCDB_OP_MODIFY      3
#define KCDB_OP_ACTIVATE    4
#define KCDB_OP_DEACTIVATE  5
#define KCDB_OP_HIDE        6
#define KCDB_OP_UNHIDE      7
#define KCDB_OP_SETSEARCH   8
#define KCDB_OP_UNSETSEARCH 9
#define KCDB_OP_NEW_DEFAULT 10
#define KCDB_OP_DELCONFIG   11

/*@}*/

#endif

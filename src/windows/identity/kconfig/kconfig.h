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

#ifndef __KHIMAIRA_KCONFIG_H
#define __KHIMAIRA_KCONFIG_H

#include<khdefs.h>
#include<mstring.h>

/*! \defgroup kconf NetIDMgr Configuration Provider */
/*@{*/

/*! \brief Configuration schema descriptor record

    The schema descriptor is a convenient way to provide a default set
    of configuration options for a part of an application.  It
    describes the configuration spaces and the values and subspaces
    contained in each space.

    \see kconf_load_schema()
*/
typedef struct tag_kconf_schema {
    wchar_t *   name;       /*!< name of the object being described.
                                Optional for KC_ENDSPACE type object,
                                but required for everything else.
                                Names can be upto KCONF_MAXCCH_NAME
                                characters in length. */
    khm_int32   type;       /*!< type of the object.  Can be one of
                                KC_SPACE, KC_ENDSPACE, KC_INT32,
                                KC_INT64, KC_STRING or KC_BINARY */
    khm_ui_8    value;      /*!< the value of the object.  It is not
                                used for KC_SPACE and KC_ENDSPACE
                                typed objects.  For a KC_STRING, this
                                contains a pointer to the string
                                value.  The string should not be
                                longer than KCONF_MAXCCH_STRING
                                characters. KC_INT32 and KC_INT64
                                objects store the value directly in
                                this field, while KC_BINARY objects do
                                not support defining a default value
                                here. */
    wchar_t *   description;/*!< a friendly description of the value
                                or configuration space. */
} kconf_schema;

/*! \name Configuration data types
  @{*/
/*! \brief Not a known type */
#define KC_NONE         0

/*! \brief When used as ::kconf_schema \a type, defines the start of a configuration space.

    There should be a subsequent KC_ENDSPACE record in the schema
    which defines the end of this configuration space.

    \a name specifies the name of the configuration space.  Optionally
    use \a description to provide a description.*/
#define KC_SPACE        1

/*! \brief Ends a configuration space started with KC_SPACE */
#define KC_ENDSPACE     2

/*! \brief A 32 bit integer

    Specifies a configuration parameter named \a name which is of this
    type.  Use \a description to provide an optional description of
    the value.

    \a value specifies a default value for this parameter in the lower
    32 bits.
*/
#define KC_INT32        3

/*! \brief A 64 bit integer

    Specifies a configuration parameter named \a name which is of this
    type.  Use \a description to provide an optional description of
    the value.

    \a value specifies a default value for this parameter.
*/
#define KC_INT64        4

/*! \brief A unicode string

    Specifies a configuration parameter named \a name which is of this
    type.  Use \a description to provide an optional description of
    the value.

    \a value specifies a default value for this parameter which should
    be a pointer to a NULL terminated unicode string of no more than
    ::KCONF_MAXCCH_STRING characters.
*/
#define KC_STRING       5

/*! \brief An unparsed binary stream

    Specifies a configuration parameter named \a name which is of this
    type.  Use \a description to provide an optional description of
    the value.

    Default values are not supported for binary streams.  \a value is
    ignored.
*/
#define KC_BINARY       6
/*@}*/

/*! \brief This is the root configuration space */
#define KCONF_FLAG_ROOT          0x00000001

/*! \brief Indicates the configuration store which stores user-specific information */
#define KCONF_FLAG_USER          0x00000002

/*! \brief Indicates the configuration store which stores machine-specific information */
#define KCONF_FLAG_MACHINE       0x00000004

/*! \brief Indicates the configuration store which stores the schema */
#define KCONF_FLAG_SCHEMA        0x00000008

/*! \brief Indicates that the last component of the given configuration path is to be considered to be a configuration value */
#define KCONF_FLAG_TRAILINGVALUE 0x00000020

/*! \brief Only write values back there is a change

    Any write operations using the handle with check if the value
    being written is different from the value being read from the
    handle.  It will only be written if the value is different.

    \note Note that the value being read from a handle takes schema and
    shadowed configuration handles into consideration while the value
    being written is only written to the topmost layer of
    configuration that can be written to.

    \note Note also that this flag does not affect binary values.
 */
#define KCONF_FLAG_WRITEIFMOD    0x00000040

/*! \brief Use case-insensitive comparison for KCONF_FLAG_WRITEIFMOD

    When used in combination with \a KCONF_FLAG_WRITEIFMOD , the
    string comparison used when determining whether the string read
    from the configuration handle is the same as the string being
    written will be case insensitive.  If this flag is not set, the
    comparison will be case sensitive.
 */
#define KCONF_FLAG_IFMODCI     0x00000080

/*! \brief Do not parse the configuration space name

    If set, disables the parsing of the configuration space for
    subspaces.  The space name is taken verbatim to be a configuration
    space name.  This can be used when there can be forward slashes or
    backslahes in the name which are not escaped.

    By default, the configuration space name,

    \code
    L"foo\\bar"
    \endcode

    is taken to mean the configuration space \a bar which is a
    subspace of \a foo.  If ::KCONF_FLAG_NOPARSENAME is set, then this
    is taken to mean configuration space \a foo\\bar.
 */
#define KCONF_FLAG_NOPARSENAME   0x00000040

/*! \brief Maximum number of allowed characters (including terminating NULL) in a name

    \note This is a hard limit in Windows, since we are mapping
        configuration spaces to registry keys.
*/
#define KCONF_MAXCCH_NAME 256

/*! \brief Maximum number of allowed bytes (including terminating NULL) in a name */
#define KCONF_MAXCB_NAME (KCONF_MAXCCH_NAME * sizeof(wchar_t))

/*! \brief Maximum level of nesting for configuration spaces
 */
#define KCONF_MAX_DEPTH 16

/*! \brief Maximum number of allowed characters (including terminating NULL) in a configuration path */
#define KCONF_MAXCCH_PATH (KCONF_MAXCCH_NAME * KCONF_MAX_DEPTH)

/*! \brief Maximum number of allowed bytes (including terminating NULL) in a configuration path */
#define KCONF_MAXCB_PATH (KCONF_MAXCCH_PATH * sizeof(wchar_t))

/*! \brief Maximum number of allowed characters (including terminating NULL) in a string */
#define KCONF_MAXCCH_STRING KHM_MAXCCH_STRING

/*! \brief Maximum number of allowed bytes (including terminating NULL) in a string */
#define KCONF_MAXCB_STRING (KCONF_MAXCCH_STRING * sizeof(wchar_t))

/*! \brief Open a configuration space

    Opens the configuration space specified by \a cspace.  By default,
    the opened space includes user,machine and schema configuration
    stores.  However, you can specify a subset of these.

    If the configuration space does not exist and the \a flags specify
    KHM_FLAG_CREATE, then the configuration space is created.  The
    stores that are affected by the create operation depend on \a
    flags.  If the \a flags only specifies ::KCONF_FLAG_MACHINE, then
    the configuration space is created in the machine store.  If \a
    flags specifies any combination of stores including \a
    ::KCONF_FLAG_USER, then the configuration space is created in the
    user store.  Note that ::KCONF_FLAG_SCHEMA is readonly.

    Once opened, use khc_close_space() to close the configuration
    space.

    \param[in] parent The parent configuration space.  The path
        specified in \a cspace is relative to the parent.  Set this to
        NULL to indicate the root configuration space.

    \param[in] cspace The configuration path.  This can be up to
        ::KCONF_MAXCCH_PATH characters in length.  Use backslashes to
        specify hiearchy.  Set this to NULL to reopen the parent
        configuration space.

    \param[in] flags Flags.  This can be a combination of KCONF_FLAG_*
        constants and KHM_FLAG_CREATE.  If none of ::KCONF_FLAG_USER,
        ::KCONF_FLAG_MACHINE or ::KCONF_FLAG_SCHEMA is specified, then
        it defaults to all three.

    \param[out] result Pointer to a handle which receives the handle
        to the opened configuration space if the call succeeds.

    \note You can re-open a configuration space with different flags
        such as ::KCONF_FLAG_MACHINE by specifying NULL for \a cspace
        and settings \a flags to the required flags.

*/
KHMEXP khm_int32 KHMAPI
khc_open_space(khm_handle parent, const wchar_t * cspace, khm_int32 flags,
               khm_handle * result);

/*! \brief Set the shadow space for a configuration handle

    The handle specified by \a lower becomes a shadow for the handle
    specified by \a upper.  Any configuration value that is queried in
    \a upper that does not exist in \a upper will be queried in \a
    lower.

    If \a upper already had a shadow handle, that handle will be
    replaced by \a lower.  The handle \a lower still needs to be
    closed by a call to khc_close_space().  However, closing \a lower
    will not affect \a upper which will still treat the configuration
    space pointed to by \a lower to be it's shadow.

    Shadows are specific to handles and not configuration spaces.
    Shadowing a configuration space using one handle does not affect
    any other handles which may be obtained for the same configuration
    space.

    Specify NULL for \a lower to remove any prior shadow.
 */
KHMEXP khm_int32 KHMAPI
khc_shadow_space(khm_handle upper, khm_handle lower);

/*! \brief Close a handle opened with khc_open_space()
*/
KHMEXP khm_int32 KHMAPI
khc_close_space(khm_handle conf);

/*! \brief Read a string value from a configuration space

    The \a value_name parameter specifies the value to read from the
    configuration space.  This can be either a value name or a value
    path consisting of a series nested configuration space names
    followed by the value name all separated by backslashes or forward
    slashes.

    For example: If \a conf is a handle to the configuration space \c
    'A/B/C', then the value name \c 'D/E/v' refers to the value named
    \c 'v' in the configuration space \c 'A/B/C/D/E'.

    The specific configuration store that is used to access the value
    depends on the flags that were specified in the call to
    khc_open_space().  The precedence of configuration stores are as
    follows:

    - If KCONF_FLAG_USER was specified, then the user configuration
      space.

    - Otherwise, if KCONF_FLAG_MACHINE was specified, then the machine
      configuration space.

    - Otherwise, if KCONF_FLAG_SCHEMA was specified, the the schema
      store.

    Note that not specifying any of the configuration store specifiers
    in the call to khc_open_space() is equivalent to specifying all
    three.

    If the value is not found in the configuration space and any
    shadowed configuration spaces, the function returns \a
    KHM_ERROR_NOT_FOUND.  In this case, the buffer is left unmodified.

    \param[in] buf Buffer to copy the string to.  Specify NULL to just
        retrieve the number of required bytes.

    \param[in,out] bufsize On entry, specifies the number of bytes of
        space available at the location specified by \a buf.  On exit
        specifies the number of bytes actually copied or the size of
        the required buffer if \a buf is NULL or insufficient.

    \retval KHM_ERROR_NOT_READY The configuration provider has not started
    \retval KHM_ERROR_INVALID_PARAM One or more of the supplied parameters are not valid
    \retval KHM_ERROR_TYPE_MISMATCH The specified value is not a string
    \retval KHM_ERROR_TOO_LONG \a buf was NULL or the size of the buffer was insufficient.  The required size is in bufsize.
    \retval KHM_ERROR_SUCCESS Success.  The number of bytes copied is in bufsize.
    \retval KHM_ERROR_NOT_FOUND The value was not found.

    \see khc_open_space()
*/
KHMEXP khm_int32 KHMAPI
khc_read_string(khm_handle conf,
                const wchar_t * value_name,
                wchar_t * buf,
                khm_size * bufsize);

/*! \brief Read a multi-string value from a configuration space

    The \a value_name parameter specifies the value to read from the
    configuration space.  This can be either a value name or a value
    path consisting of a series nested configuration space names
    followed by the value name all separated by backslashes or forward
    slashes.

    For example: If \a conf is a handle to the configuration space \c
    'A/B/C', then the value name \c 'D/E/v' refers to the value named
    \c 'v' in the configuration space \c 'A/B/C/D/E'.

    The specific configuration store that is used to access the value
    depends on the flags that were specified in the call to
    khc_open_space().  The precedence of configuration stores are as
    follows:

    - If KCONF_FLAG_USER was specified, then the user configuration
      space.

    - Otherwise, if KCONF_FLAG_MACHINE was specified, then the machine
      configuration space.

    - Otherwise, if KCONF_FLAG_SCHEMA was specified, the the schema
      store.

    A multi-string is a pseudo data type.  The value in the
    configuration store should contain a CSV string.  Each comma
    separated value in the CSV string is considered to be a separate
    value.  Empty values are not allowed. The buffer pointed to by \a
    buf will receive these values in the form of a series of NULL
    terminated strings terminated by an empty string (or equivalently,
    the last string will be terminated by a double NULL).

    Note that not specifying any of the configuration store specifiers
    in the call to khc_open_space() is equivalent to specifying all
    three.

    If the value is not found in the configuration space and any
    shadowed configuration spaces, the function returns \a
    KHM_ERROR_NOT_FOUND.  In this case, the buffer is left unmodified.

    \param[in] buf Buffer to copy the multi-string to.  Specify NULL
        to just retrieve the number of required bytes.

    \param[in,out] bufsize On entry, specifies the number of bytes of
        space available at the location specified by \a buf.  On exit
        specifies the number of bytes actually copied or the size of
        the required buffer if \a buf is NULL or insufficient.

    \retval KHM_ERROR_NOT_READY The configuration provider has not started
    \retval KHM_ERROR_INVALID_PARAM One or more of the supplied parameters are not valid
    \retval KHM_ERROR_TYPE_MISMATCH The specified value is not a string
    \retval KHM_ERROR_TOO_LONG \a buf was NULL or the size of the buffer was insufficient.  The required size is in bufsize.
    \retval KHM_ERROR_SUCCESS Success.  The number of bytes copied is in bufsize.
    \retval KHM_ERROR_NOT_FOUND The value was not found.

    \see khc_open_space()
*/
KHMEXP khm_int32 KHMAPI
khc_read_multi_string(khm_handle conf,
                      const wchar_t * value_name,
                      wchar_t * buf,
                      khm_size * bufsize);

/*! \brief Read a 32 bit integer value from a configuration space

    The \a value_name parameter specifies the value to read from the
    configuration space.  This can be either a value name or a value
    path consisting of a series nested configuration space names
    followed by the value name all separated by backslashes or forward
    slashes.

    For example: If \a conf is a handle to the configuration space \c
    'A/B/C', then the value name \c 'D/E/v' refers to the value named
    \c 'v' in the configuration space \c 'A/B/C/D/E'.

    The specific configuration store that is used to access the value
    depends on the flags that were specified in the call to
    khc_open_space().  The precedence of configuration stores are as
    follows:

    - If KCONF_FLAG_USER was specified, then the user configuration
      space.

    - Otherwise, if KCONF_FLAG_MACHINE was specified, then the machine
      configuration space.

    - Otherwise, if KCONF_FLAG_SCHEMA was specified, the the schema
      store.

    Note that not specifying any of the configuration store specifiers
    in the call to khc_open_space() is equivalent to specifying all
    three.

    If the value is not found in the configuration space and any
    shadowed configuration spaces, the function returns \a
    KHM_ERROR_NOT_FOUND.  In this case, the buffer is left unmodified.

    \param[in] conf Handle to a configuration space
    \param[in] value The value to query
    \param[out] buf The buffer to receive the value

    \retval KHM_ERROR_NOT_READY The configuration provider has not started.
    \retval KHM_ERROR_SUCCESS Success.  The value that was read was placed in \a buf
    \retval KHM_ERROR_NOT_FOUND The specified value was not found
    \retval KHM_ERROR_INVALID_PARAM One or more parameters were invalid
    \retval KHM_ERROR_TYPE_MISMATCH The specified value was found but was not of the correct type.
    \see khc_open_space()
*/
KHMEXP khm_int32 KHMAPI
khc_read_int32(khm_handle conf,
               const wchar_t * value_name,
               khm_int32 * buf);

/*! \brief Read a 64 bit integer value from a configuration space

    The \a value_name parameter specifies the value to read from the
    configuration space.  This can be either a value name or a value
    path consisting of a series nested configuration space names
    followed by the value name all separated by backslashes or forward
    slashes.

    For example: If \a conf is a handle to the configuration space \c
    'A/B/C', then the value name \c 'D/E/v' refers to the value named
    \c 'v' in the configuration space \c 'A/B/C/D/E'.

    The specific configuration store that is used to access the value
    depends on the flags that were specified in the call to
    khc_open_space().  The precedence of configuration stores are as
    follows:

    - If KCONF_FLAG_USER was specified, then the user configuration
      space.

    - Otherwise, if KCONF_FLAG_MACHINE was specified, then the machine
      configuration space.

    - Otherwise, if KCONF_FLAG_SCHEMA was specified, the the schema
      store.

    Note that not specifying any of the configuration store specifiers
    in the call to khc_open_space() is equivalent to specifying all
    three.

    If the value is not found in the configuration space and any
    shadowed configuration spaces, the function returns \a
    KHM_ERROR_NOT_FOUND.  In this case, the buffer is left unmodified.

    \param[in] conf Handle to a configuration space
    \param[in] value_name The value to query
    \param[out] buf The buffer to receive the value

    \retval KHM_ERROR_NOT_READY The configuration provider has not started
    \retval KHM_ERROR_SUCCESS Success.  The value that was read was placed in \a buf
    \retval KHM_ERROR_NOT_FOUND The specified value was not found
    \retval KHM_ERROR_INVALID_PARAM One or more parameters were invalid
    \retval KHM_ERROR_TYPE_MISMATCH The specified value was found but was not the correct data type.

    \see khc_open_space()
*/
KHMEXP khm_int32 KHMAPI
khc_read_int64(khm_handle conf,
               const wchar_t * value_name,
               khm_int64 * buf);

/*! \brief Read a binary value from a configuration space

    The \a value_name parameter specifies the value to read from the
    configuration space.  This can be either a value name or a value
    path consisting of a series nested configuration space names
    followed by the value name all separated by backslashes or forward
    slashes.

    For example: If \a conf is a handle to the configuration space \c
    'A/B/C', then the value name \c 'D/E/v' refers to the value named
    \c 'v' in the configuration space \c 'A/B/C/D/E'.

    The specific configuration store that is used to access the value
    depends on the flags that were specified in the call to
    khc_open_space().  The precedence of configuration stores are as
    follows:

    - If KCONF_FLAG_USER was specified, then the user configuration
      space.

    - Otherwise, if KCONF_FLAG_MACHINE was specified, then the machine
      configuration space.

    Note that not specifying any of the configuration store specifiers
    in the call to khc_open_space() is equivalent to specifying all
    three. Also note that the schema store (KCONF_FLAG_SCHEMA) does
    not support binary values.

    If the value is not found in the configuration space and any
    shadowed configuration spaces, the function returns \a
    KHM_ERROR_NOT_FOUND.  In this case, the buffer is left unmodified.

    \param[in] buf Buffer to copy the string to.  Specify NULL to just
        retrieve the number of required bytes.

    \param[in,out] bufsize On entry, specifies the number of bytes of
        space available at the location specified by \a buf.  On exit
        specifies the number of bytes actually copied or the size of
        the required buffer if \a buf is NULL or insufficient.

    \retval KHM_ERROR_SUCCESS Success. The data was copied to \a buf.  The number of bytes copied is stored in \a bufsize
    \retval KHM_ERROR_NOT_FOUND The specified value was not found
    \retval KHM_ERROR_INVALID_PARAM One or more parameters were invalid.

    \see khc_open_space()
*/
KHMEXP khm_int32 KHMAPI
khc_read_binary(khm_handle conf,
                const wchar_t * value_name,
                void * buf,
                khm_size * bufsize);

/*! \brief Write a string value to a configuration space

    The \a value_name parameter specifies the value to write to the
    configuration space.  This can be either a value name or a value
    path consisting of a series nested configuration space names
    followed by the value name all separated by backslashes or forward
    slashes.

    For example: If \a conf is a handle to the configuration space \c
    'A/B/C', then the value name \c 'D/E/v' refers to the value named
    \c 'v' in the configuration space \c 'A/B/C/D/E'.

    The specific configuration store that is used to write the value
    depends on the flags that were specified in the call to
    khc_open_space().  The precedence of configuration stores are as
    follows:

    - If \a KCONF_FLAG_USER was specified, then the user configuration
      space.

    - Otherwise, if \a KCONF_FLAG_MACHINE was specified, then the
      machine configuration space.

    Note that not specifying any of the configuration store specifiers
    in the call to khc_open_space() is equivalent to specifying all
    three.  Also note that the schema store (KCONF_FLAG_SCHEMA) is
    readonly.

    If the \a KCONF_FLAG_WRITEIFMOD flag is specified in the call to
    khc_open_space() for obtaining the configuration handle, the
    specified string will only be written if it is different from the
    value being read from the handle.

    If the \a KCONF_FLAG_IFMODCI flag is specified along with the \a
    KCONF_FLAG_WRITEIFMOD flag, then the string comparison used will
    be case insensitive.

    \param[in] conf Handle to a configuration space
    \param[in] value_name Name of value to write
    \param[in] buf A NULL terminated unicode string not exceeding KCONF_MAXCCH_STRING in characters including terminating NULL

    \see khc_open_space()
*/
KHMEXP khm_int32 KHMAPI
khc_write_string(khm_handle conf,
                 const wchar_t * value_name,
                 wchar_t * buf);

/*! \brief Write a multi-string value to a configuration space

    The \a value_name parameter specifies the value to write to the
    configuration space.  This can be either a value name or a value
    path consisting of a series nested configuration space names
    followed by the value name all separated by backslashes or forward
    slashes.

    For example: If \a conf is a handle to the configuration space \c
    'A/B/C', then the value name \c 'D/E/v' refers to the value named
    \c 'v' in the configuration space \c 'A/B/C/D/E'.

    The specific configuration store that is used to write the value
    depends on the flags that were specified in the call to
    khc_open_space().  The precedence of configuration stores are as
    follows:

    A multi-string is a pseudo data type.  The buffer pointed to by \a
    buf should contain a sequence of NULL terminated strings
    terminated by an empty string (or equivalently, the last string
    should terminate with a double NULL).  This will be stored in the
    value as a CSV string.

    - If KCONF_FLAG_USER was specified, then the user configuration
      space.

    - Otherwise, if KCONF_FLAG_MACHINE was specified, then the machine
      configuration space.

    Note that not specifying any of the configuration store specifiers
    in the call to khc_open_space() is equivalent to specifying all
    three.  Also note that the schema store (KCONF_FLAG_SCHEMA) is
    readonly.

    If the \a KCONF_FLAG_WRITEIFMOD flag is specified in the call to
    khc_open_space() for obtaining the configuration handle, the
    specified string will only be written if it is different from the
    value being read from the handle.

    If the \a KCONF_FLAG_IFMODCI flag is specified along with the \a
    KCONF_FLAG_WRITEIFMOD flag, then the string comparison used will
    be case insensitive.

    \see khc_open_space()
*/
KHMEXP khm_int32 KHMAPI
khc_write_multi_string(khm_handle conf,
                       const wchar_t * value_name,
                       wchar_t * buf);

/*! \brief Write a 32 bit integer value to a configuration space

    The \a value_name parameter specifies the value to write to the
    configuration space.  This can be either a value name or a value
    path consisting of a series nested configuration space names
    followed by the value name all separated by backslashes or forward
    slashes.

    For example: If \a conf is a handle to the configuration space \c
    'A/B/C', then the value name \c 'D/E/v' refers to the value named
    \c 'v' in the configuration space \c 'A/B/C/D/E'.

    The specific configuration store that is used to write the value
    depends on the flags that were specified in the call to
    khc_open_space().  The precedence of configuration stores are as
    follows:

    - If KCONF_FLAG_USER was specified, then the user configuration
      space.

    - Otherwise, if KCONF_FLAG_MACHINE was specified, then the machine
      configuration space.

    Note that not specifying any of the configuration store specifiers
    in the call to khc_open_space() is equivalent to specifying all
    three.  Also note that the schema store (KCONF_FLAG_SCHEMA) is
    readonly.

    If the \a KCONF_FLAG_WRITEIFMOD flag is specified in the call to
    khc_open_space() for obtaining the configuration handle, the
    specified string will only be written if it is different from the
    value being read from the handle.

    \see khc_open_space()
*/
KHMEXP khm_int32 KHMAPI
khc_write_int32(khm_handle conf,
                const wchar_t * value_name,
                khm_int32 buf);

/*! \brief Write a 64 bit integer value to a configuration space

    The \a value_name parameter specifies the value to write to the
    configuration space.  This can be either a value name or a value
    path consisting of a series nested configuration space names
    followed by the value name all separated by backslashes or forward
    slashes.

    For example: If \a conf is a handle to the configuration space \c
    'A/B/C', then the value name \c 'D/E/v' refers to the value named
    \c 'v' in the configuration space \c 'A/B/C/D/E'.

    The specific configuration store that is used to write the value
    depends on the flags that were specified in the call to
    khc_open_space().  The precedence of configuration stores are as
    follows:

    - If KCONF_FLAG_USER was specified, then the user configuration
      space.

    - Otherwise, if KCONF_FLAG_MACHINE was specified, then the machine
      configuration space.

    Note that not specifying any of the configuration store specifiers
    in the call to khc_open_space() is equivalent to specifying all
    three.  Also note that the schema store (KCONF_FLAG_SCHEMA) is
    readonly.

    If the \a KCONF_FLAG_WRITEIFMOD flag is specified in the call to
    khc_open_space() for obtaining the configuration handle, the
    specified string will only be written if it is different from the
    value being read from the handle.

    \see khc_open_space()
*/
KHMEXP khm_int32 KHMAPI
khc_write_int64(khm_handle conf,
                const wchar_t * value_name,
                khm_int64 buf);

/*! \brief Write a binary value to a configuration space

    The \a value_name parameter specifies the value to write to the
    configuration space.  This can be either a value name or a value
    path consisting of a series nested configuration space names
    followed by the value name all separated by backslashes or forward
    slashes.

    For example: If \a conf is a handle to the configuration space \c
    'A/B/C', then the value name \c 'D/E/v' refers to the value named
    \c 'v' in the configuration space \c 'A/B/C/D/E'.

    The specific configuration store that is used to write the value
    depends on the flags that were specified in the call to
    khc_open_space().  The precedence of configuration stores are as
    follows:

    - If KCONF_FLAG_USER was specified, then the user configuration
      space.

    - Otherwise, if KCONF_FLAG_MACHINE was specified, then the machine
      configuration space.

    Note that not specifying any of the configuration store specifiers
    in the call to khc_open_space() is equivalent to specifying all
    three.  Also note that the schema store (KCONF_FLAG_SCHEMA) is
    readonly.

    \see khc_open_space()
*/
KHMEXP khm_int32 KHMAPI
khc_write_binary(khm_handle conf,
                 const wchar_t * value_name,
                 void * buf,
                 khm_size bufsize);

/*! \brief Get the type of a value in a configuration space

    \return The return value is the type of the specified value, or
        KC_NONE if the value does not exist.
 */
KHMEXP khm_int32 KHMAPI
khc_get_type(khm_handle conf, const wchar_t * value_name);

/*! \brief Check which configuration stores contain a specific value.

    Each value in a configuration space can be contained in zero or
    more configuration stores.  Use this function to determine which
    configuration stores contain the specific value.

    The returned bitmask always indicates a subset of the
    configuration stores that were specified when opening the
    configuration space corresponding to \a conf.

    If the specified handle is shadowed (see khc_shadow_space()) and
    the value is not found in any of the visible stores for the
    topmost handle, each of the shadowed handles will be tried in turn
    until the value is found.  The return value will correspond to the
    handle where the value is first found.

    \return A combination of ::KCONF_FLAG_MACHINE, ::KCONF_FLAG_USER
        and ::KCONF_FLAG_SCHEMA indicating which stores contain the
        value.
 */
KHMEXP khm_int32 KHMAPI
khc_value_exists(khm_handle conf, const wchar_t * value);

/*! \brief Remove a value from a configuration space

    Removes a value from one or more configuration stores.

    A value can exist in multiple configuration stores.  Only the
    values that are stored in writable stores can be removed.  When
    the function searches for values to remove, it will only look in
    configuration stores that are specified in the handle.  In
    addition, the configuration stores affected can be further
    narrowed by specifying them in the \a flags parameter.  If \a
    flags is zero, then all the stores visible to the handle are
    searched.  If \a flags specifies ::KCONF_FLAG_USER or
    ::KCONF_FLAG_MACHINE or both, then only the specified stores are
    searched, provided that the stores are visible to the handle.

    This function only operates on the topmost configuration space
    visible to the handle.  If the configuration handle is shadowed,
    the shadowed configuration spaces are unaffected by the removal.

    \param[in] conf Handle to configuration space to remove value from

    \param[in] value_name Value to remove

    \param[in] flags Specifies which configuration stores will be
        affected by the removal.  See above.

    \retval KHM_ERROR_SUCCESS The value was removed from all the
        specified configuration stores.

    \retval KHM_ERROR_NOT_FOUND The value was not found.

    \retval KHM_ERROR_UNKNOWN An unknown error occurred while trying
        to remove the value.

    \retval KHM_ERROR_PARTIAL The value was successfully removed from
        one or more stores, but the operation failed on one or more
        other stores.
 */
KHMEXP khm_int32 KHMAPI
khc_remove_value(khm_handle conf, const wchar_t * value_name, khm_int32 flags);

/*! \brief Get the name of a configuration space

    \param[in] conf Handle to a configuration space

    \param[out] buf The buffer to receive the name.  Set to NULL if
        only the size of the buffer is required.

    \param[in,out] bufsize On entry, holds the size of the buffer
        pointed to by \a buf.  On exit, holds the number of bytes
        copied into the buffer including the NULL terminator.
 */
KHMEXP khm_int32 KHMAPI
khc_get_config_space_name(khm_handle conf,
                          wchar_t * buf,
                          khm_size * bufsize);

/*! \brief Get a handle to the parent space

    \param[in] conf Handle to a configuration space

    \param[out] parent Handle to the parent configuration space if the
        call succeeds.  Receives NULL otherwise.  The returned handle
        must be closed using khc_close_space()
 */
KHMEXP khm_int32 KHMAPI
khc_get_config_space_parent(khm_handle conf,
                            khm_handle * parent);

/*! \brief Load a configuration schema into the specified configuration space

    \param[in] conf Handle to a configuration space or NULL to use the
        root configuration space.

    \param[in] schema The schema to load.  The schema is assumed to be
        well formed.

    \see khc_unload_schema()
 */
KHMEXP khm_int32 KHMAPI
khc_load_schema(khm_handle conf,
                const kconf_schema * schema);

/*! \brief Unload a schema from a configuration space
 */
KHMEXP khm_int32 KHMAPI
khc_unload_schema(khm_handle conf,
                  const kconf_schema * schema);

/*! \brief Enumerate the subspaces of a configuration space

    Prepares a configuration space for enumeration and returns the
    child spaces in no particular order.

    \param[in] conf The configuration space to enumerate child spaces

    \param[in] prev The previous configuration space returned by
        khc_enum_subspaces() or NULL if this is the first call.  If
        this is not NULL, then the handle passed in \a prev will be
        freed.

    \param[out] next If \a prev was NULL, receives the first sub space
        found in \a conf.  You must \b either call
        khc_enum_subspaces() again with the returned handle or call
        khc_close_space() to free the returned handle if no more
        subspaces are required.  \a next can point to the same handle
        specified in \a prev.

    \retval KHM_ERROR_SUCCESS The call succeeded.  There is a valid
        handle to a configuration space in \a first_subspace.

    \retval KHM_ERROR_INVALID_PARAM Either \a conf or \a prev was not a
        valid configuration space handle or \a first_subspace is NULL.
        Note that \a prev can be NULL.

    \retval KHM_ERROR_NOT_FOUND There were no subspaces in the
        configuration space pointed to by \a conf.

    \note The configuration spaces that are enumerated directly belong
        to the configuration space given by \a conf.  This function
        does not enumerate subspaces of shadowed configuration spaces
        (see khc_shadow_space()).  Even if \a conf was obtained on a
        restricted domain (i.e. you specified one or more
        configuration stores when you openend the handle and didn't
        include all the configuration stores. See khc_open_space()),
        the subspaces that are returned are the union of all
        configuration spaces in all the configuration stores.  This is
        not a bug.  This is a feature.  In NetIDMgr, a configuartion
        space exists if some configuration store defines it (or it was
        created with a call to khc_open_space() even if no
        configuration store defines it yet).  This is the tradeoff you
        make when using a layered configuration system.

	However, the returned handle has the same domain restrictions
	as \a conf.
 */
KHMEXP khm_int32 KHMAPI
khc_enum_subspaces(khm_handle conf,
                   khm_handle prev,
                   khm_handle * next);

/*! \brief Remove a configuration space

    The configuration space will be marked for removal.  Once all the
    handles for the space have been released, it will be deleted.  The
    configuration stores that will be affected are the write enabled
    configuration stores for the handle.
 */
KHMEXP khm_int32 KHMAPI
khc_remove_space(khm_handle conf);
/*@}*/

#endif

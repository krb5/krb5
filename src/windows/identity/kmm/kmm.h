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

#ifndef __KHIMAIRA_KMM_H
#define __KHIMAIRA_KMM_H

#include<khdefs.h>
#include<kmq.h>

/*! \defgroup kmm NetIDMgr Module Manager
@{*/

/*! \brief A handle to a module.
*/
typedef khm_handle kmm_module;

/*! \brief A handle to a plugin.
 */
typedef khm_handle kmm_plugin;

/*! \name Limits
  @{*/

/*! \brief Maximum number of characters in a name in KMM including the terminating NULL */
#define KMM_MAXCCH_NAME 256

/*! \brief Maximum number of bytes in a name in KMM including the terminating NULL */
#define KMM_MAXCB_NAME (sizeof(wchar_t) * KMM_MAXCCH_NAME)

/*! \brief Maximum number of characters in a description in KMM including the terminating NULL */
#define KMM_MAXCCH_DESC 512

/*! \brief Maximum number of bytes in a description in KMM including the terminating NULL */
#define KMM_MAXCB_DESC (sizeof(wchar_t) * KMM_MAXCCH_NAME)

/*! \brief Maximum number of characters in a vendor string in KMM including the terminating NULL */
#define KMM_MAXCCH_VENDOR 256

/*! \brief Maximum number of bytes in a vendor string in KMM including the terminating NULL */
#define KMM_MAXCB_VENDOR (sizeof(wchar_t) * KMM_MAXCCH_VENDOR)

/*! \brief Maximum number of characters in a support URI in KMM including the terminating NULL */
#define KMM_MAXCCH_SUPPORT 256

/*! \brief Maximum number of bytes in a vendor string in KMM including the terminating NULL */
#define KMM_MAXCB_SUPPORT (sizeof(wchar_t) * KMM_MAXCCH_SUPPORT)

/*! \brief Maximum number of dependencies per plugin
*/
#define KMM_MAX_DEPENDENCIES    8

/*! \brief Maximum number of dependants per plugin
 */
#define KMM_MAX_DEPENDANTS      32

/*! \brief Maximum number of characters a dependency string including trailing double NULL */
#define KMM_MAXCCH_DEPS (KMM_MAXCCH_NAME * KMM_MAX_DEPENDENCIES + 1)

/*! \brief Maximum number of bytes in a dependency string including trailing double NULL */
#define KMM_MAXCB_DEPS (sizeof(wchar_t) * KMM_MAXCCH_DEPS)
/*@}*/ /* Limits */

/*! \brief Plugin registration

    \see ::khm_cred_provider
*/
typedef struct tag_kmm_plugin_reg {
    wchar_t *   name;           /*!< Name of the plugin.  Maximum of
                                     KMM_MAXCCH_NAME characters
                                     including the terminating
                                     NULL. Required. */

    wchar_t *   module;         /*!< Name of module that owns the
                                     plugin. Maximum of
                                     KMM_MAXCCH_NAME characters
                                     including terminating NULL.
                                     Required. */

    khm_int32   type;           /*!< Type plugin type.  One of
                                     KHM_PITYPE_*. Required. */
    khm_int32   flags;          /*!< Unused. Set to 0 */
    kmq_callback_t msg_proc;    /*!< Message processor.  Required. */
    wchar_t *   dependencies;   /*!< Dependencies.  Note that this is
                                     a multi string.  (you can use the
                                     KHC multi string functions to
                                     manipulate multi strings or to
                                     convert a comma separated list of
                                     dependencies to a multi string).
                                     Each string in the multi string
                                     is a name of a plugin that this
                                     plugin depends on.  Optional (set
                                     to NULL if this plugin has no
                                     dependencies). Maximum of
                                     KMM_MAXCCH_DEPS characters
                                     including terminating double
                                     NULL.*/

    wchar_t *   description;    /*!< Description of the plugin.
                                     Maximum of KMM_MAXCCH_DESC
                                     characters including the
                                     terminating
                                     NULL. Localized. Optional (set to
                                     NULL if not provided) */
#ifdef _WIN32
    HICON       icon;           /*!< Icon used to represent the
                                     plugin. Optional. (set to NULL if
                                     not provided) */
#endif
} kmm_plugin_reg;

/*! \brief Plugin information
*/
typedef struct tag_kmm_plugin_info {
    kmm_plugin_reg reg;         /*!< Registration info */

    khm_int32   state;          /*!< Current status of the plugin.
                                  One of ::_kmm_plugin_states */

    khm_int32   failure_count;  /*!< Number of recorded failures in
				     the plugin */
    FILETIME    failure_time;   /*!< Time of first recorded failure */
    khm_int32   failure_reason; /*!< The reason for the first recorded
				     failure */

    kmm_plugin  h_plugin;       /*!< Handle to plugin */

    khm_int32   flags;          /*!< Flags for the plugin. Currently
                                  this can only specify
                                  ::KMM_PLUGIN_FLAG_DISABLED. */
} kmm_plugin_info;

/*! \brief The plugin is disabled

    This flag will be set in the \a flags field of the
    ::kmm_plugin_info structure for a plugin that has been marked as
    disabled.  If the plugin is currently running, but marked as
    disabled for future sessions, then this bit will be set in \a
    flags , but the \a state of the plugin will indicate that the
    plugin is running.
 */
#define KMM_PLUGIN_FLAG_DISABLED    0x00000400

/*! \name Plugin types
@{*/
/*! \brief A credentials provider

    \see \ref pi_pt_cred for more information.
 */
#define KHM_PITYPE_CRED     1

/*! \brief A identity provider

    \see \ref pi_pt_cred for more information
 */
#define KHM_PITYPE_IDENT    2

/*! \brief A configuration provider

    \see \ref pi_pt_conf for more information.
 */
#define KHM_PITYPE_CONFIG   3

/*! \brief Undefined plugin type

    The plugin doesn't provide any credential type.
 */
#define KHM_PITYPE_MISC     4

/*@}*/

/*! \brief Plugin states */
enum _kmm_plugin_states {
    KMM_PLUGIN_STATE_FAIL_INIT = -6,    /*!< Failed to initialize */
    KMM_PLUGIN_STATE_FAIL_UNKNOWN = -5, /*!< Failed due to unknown
                                          reasons */
    KMM_PLUGIN_STATE_FAIL_MAX_FAILURE = -4, /*!< The plugin has
                                          reached the maximum number
                                          of failures and cannot be
                                          initialized until the
                                          failure count is reset */
    KMM_PLUGIN_STATE_FAIL_NOT_REGISTERED = -3, /*!< Failed because the
                                          plugin was not registered
                                          and automatic registration
                                          failed. */
    KMM_PLUGIN_STATE_FAIL_DISABLED = -2,/*!< Failed because plugin was
                                          disabled by the user. */
    KMM_PLUGIN_STATE_FAIL_LOAD = -1,    /*!< The plugin failed to load
                                          due to some unknown
                                          reason. */
    KMM_PLUGIN_STATE_NONE = 0,          /*!< Unknown state */
    KMM_PLUGIN_STATE_PLACEHOLDER,       /*!< Placeholder.  The plugin
                                          hasn't been provided by
                                          anyone yet, but the plugin
                                          record has been created to
                                          keep track of
                                          dependencies. */
    KMM_PLUGIN_STATE_REG,               /*!< The plugin is registered
                                          but not initialized */
    KMM_PLUGIN_STATE_PREINIT,           /*!< The plugin is in the
                                          process of being
                                          initialized */
    KMM_PLUGIN_STATE_HOLD,              /*!< On hold.  One or more
                                          dependencies of this plugin
                                          has not been resolved */
    KMM_PLUGIN_STATE_INIT,              /*!< The plugin was initialized */
    KMM_PLUGIN_STATE_RUNNING,           /*!< The plugin is running */
    KMM_PLUGIN_STATE_EXITED             /*!< The plugin has been stopped. */
};

/*! \brief Module registration */
typedef struct tag_kmm_module_reg {
    wchar_t *   name;               /*!< Identifier for the module */
    wchar_t *   path;               /*!< Full pathname to module
				         binary */

    wchar_t *   description;        /*!< Description of module */

    wchar_t *   vendor;             /*!< Vendor/copyright string */

    wchar_t *   support;            /*!< Support URL/contact */

    khm_int32   n_plugins;          /*!< Number of plugins that are
				         active */
    kmm_plugin_reg * plugin_reg_info;  /*!< Array of kmm_plugin_reg
				         records for each active
				         plugin */
} kmm_module_reg;

/*! \brief Module information record */
typedef struct tag_kmm_module_info {
    kmm_module_reg reg;             /*!< Registration info */

    khm_ui_4    language;           /*!< Currently loaded langugage */

    khm_int32   state;              /*!< Current status of the
				         module */

    khm_version file_version;       /*!< File version for the
				         module */
    khm_version product_version;    /*!< Product version for the
				         module */

    khm_int32   failure_count;      /*!< Number of times the module
				         has failed to load */
    FILETIME    failure_time;       /*!< Time of first recorded
				         failure */
    khm_int32   failure_reason;     /*!< Reason for first failure.
				         One of the module status
				         values */

    kmm_module  h_module;           /*!< Handle to the module. */
} kmm_module_info;

/*! \brief Module states
*/
enum KMM_MODULE_STATES {
    KMM_MODULE_STATE_FAIL_INCOMPAT=-12, /*!< The library containing
                                          the module was not
                                          compatible with this version
                                          of NetIDMgr. */
    KMM_MODULE_STATE_FAIL_INV_MODULE=-11, /*!< The library containing
                                            the module was invalid. */
    KMM_MODULE_STATE_FAIL_UNKNOWN=-10,   /*!< Module could not be
                                          loaded due to unknown
                                          reasons. */
    KMM_MODULE_STATE_FAIL_MAX_FAILURE=-9,/*!< The module has failed
                                          too many times already.  Not
                                          attempting to restart it
                                          again */
    KMM_MODULE_STATE_FAIL_DUPLICATE=-8, /*!< An attempt was made to
                                          load the same module
                                          twice. */
    KMM_MODULE_STATE_FAIL_NOT_REGISTERED=-7, /*!< The module is not
                                          found among the registered
                                          module list */
    KMM_MODULE_STATE_FAIL_NO_PLUGINS=-6,/*!< The module provided no
                                          plugins, or all the plugins
                                          that are provided are
                                          disabled */
    KMM_MODULE_STATE_FAIL_DISABLED=-5,  /*!< Module is disabled and
                                          cannot be loaded */
    KMM_MODULE_STATE_FAIL_LOAD=-4,      /*!< The module failed to
                                          initialize */
    KMM_MODULE_STATE_FAIL_INVALID=-3,   /*!< The module was invalid.
                                          Typically caused by the
                                          required entrypoints not
                                          being present */
    KMM_MODULE_STATE_FAIL_SIGNATURE=-2, /*!< The module failed to load
                                          due to an unverifiable
                                          signature */
    KMM_MODULE_STATE_FAIL_NOT_FOUND=-1, /*!< The module was not
                                          found */
    KMM_MODULE_STATE_NONE=0,            /*!< Unknown state. The handle
                                          is possibly invalid */
    KMM_MODULE_STATE_PREINIT,           /*!< The module is being
                                          loaded. init_module() hasn't
                                          been called yet */
    KMM_MODULE_STATE_INIT,              /*!< In init_module() */
    KMM_MODULE_STATE_INITPLUG,          /*!< Initializing plugins */
    KMM_MODULE_STATE_RUNNING,           /*!< Running */
    KMM_MODULE_STATE_EXITPLUG,          /*!< Currently exiting plugins */
    KMM_MODULE_STATE_EXIT,              /*!< Currently exiting */
    KMM_MODULE_STATE_EXITED             /*!< Exited */
};

/*! \brief Start the Module Manager

    \note Only called by the NetIDMgr core.
*/
KHMEXP void KHMAPI
kmm_init(void);

/*! \brief Stop the Module Manager

    \note Only called by the NetIDMgr core.
*/
KHMEXP void KHMAPI
kmm_exit(void);

/*! \brief Return the plugin handle for the current plugin

    The returned handle represents the plugin which owns the current
    thread.  The returned handle must be released by calling
    kmm_release_plugin().  Returns NULL if the current thread is not
    owned by any plugin.
 */
KHMEXP kmm_plugin KHMAPI
kmm_this_plugin(void);

/*! \brief Return the module handle for the current module

    The returned handle represents the module which owns the current
    thread.  The returned handle must be released by calling
    kmm_release_module()
*/
KHMEXP kmm_module KHMAPI
kmm_this_module(void);

/*! \name Flags for kmm_load_module()
@{*/
/*!\brief Load synchronously

    If this flag is set, then the function waits for the module to be
    loaded.  The default is to load the module asynchronously.

    When loading a module asynchronously, the kmm_load_module()
    function returns KHM_ERROR_SUCCESS and exits without waiting for
    the module to load.  If \a result is not NULL, it will receive a
    valid handle to the module.

    When loading a module synchronously, kmm_load_module() will wait
    for the module to completely load.  If it fails to load properly,
    it will return an error code and set \a result to NULL.
*/
#define KMM_LM_FLAG_SYNC    1

/*! \brief Do not load

    Indicates that the module shouldn't actually be loaded.  If the
    specified module name identifies a module that has already been
    loaded, then the function returns a held handle to the existing
    module (use kmm_release_module() to free the handle).  Otherwise,
    the function returns KHM_ERROR_NOT_FOUND.
*/
#define KMM_LM_FLAG_NOLOAD  2
/*@}*/

/*! \brief Load a module

    The \a modulename parameter specifies a module to load.  Depending
    on the configuration, not all of the plugins that are provided by
    the module may be loaded.  If no plugins are successfully loaded,
    the module will be immediately unloaded.

    If the module is currently loaded or is being loaded, then a valid
    handle to the existing module is returned.

    When called with KMM_LM_FLAG_SYNC, the function does not return
    until the module and the associated plugins are all initialized,
    or an error occurs.

    If the KMM_LM_FLAG_NOLOAD flag is set, then a handle to an
    existing instance of the module will be returned.  If the module
    hasn't been loaded yet, then no handle is returned and the
    function returns KHM_ERROR_NOT_FOUND.

    See the associated NetIDMgr Module Manager documentation on the
    sequence of events associated with loading a module.

    \param[in] modulename Name of the module.  The module should have
        been registered under this name prior to the call.
    \param[in] flags Combination of KMM_LM_FLAG_*
    \param[out] result Receives a handle to the loaded module.  If the
        result is not required, set this to NULL. If \a result is not
        NULL, and km_load_module() returns KHM_ERROR_SUCCESS, then
        kmm_release_module() must be called to release the handle to
        the module.  Otherwise, \a result receives NULL.  If a handle
        is returned, it will be valid regardless of whether the module
        fails to load or not.  You can use kmm_get_module_state() to
        query the progress of the loading process.  See
        ::KMM_LM_FLAG_SYNC.

    \retval KHM_ERROR_SUCCESS The call succeeded.  If \a
        KMM_LM_FLAG_SYNC was specified, this means that the module was
        successfully loaded.  Otherwise, it only means that the module
        has been queued up for loading.  Use kmm_get_module_state() to
        determine if it was successfully loaded.  If \a result is not
        NULL, a valid handle is returned.
    \retval KHM_ERROR_EXISTS The module is already loaded or has been
        already queued for loading.  If \a result is not NULL, a valid
        handle to the existing module instance is returned.
    \retval KHM_ERROR_NOT_FOUND If called with KMM_LM_FLAG_NOLOAD,
        indicates that the module has not been loaded.  Otherwise only
        returned when called with KMM_LM_FLAG_SYNC.  The module image
        was not found.  No handle is returned.
    \retval KHM_ERROR_INVALID_SIGNATURE Only returned when called with
        KMM_LM_FLAG_SYNC.  The module was signed with an invalid
        certificate.  No handle is returned.
    \retval KHM_ERROR_UNKNOWN Only returned when called with
        KMM_LM_FLAG_SYNC.  Some other error has occured.  No handle is
        returned.

    \see \ref pi_fw_pm_load
    \see ::KMM_LM_FLAG_SYNC, ::KMM_LM_FLAG_NOLOAD
*/
KHMEXP khm_int32   KHMAPI
kmm_load_module(wchar_t * modname, khm_int32 flags, kmm_module * result);

/*! \brief Hold a handle to a module

    Use kmm_release_module() to release the hold.
*/
KHMEXP khm_int32   KHMAPI
kmm_hold_module(kmm_module module);

/*! \brief Release a handle to a module

    Release a held referece to a module that was returned in a call to
    kmm_load_module().
*/
KHMEXP khm_int32   KHMAPI
kmm_release_module(kmm_module m);

/*! \brief Query the state of a module

    When loading a module asynchronously you can query the state of
    the loading process using this.  The return value is a status
    indicator.

    \return The return value is one of the ::KMM_MODULE_STATES
        enumerations.
*/
KHMEXP khm_int32   KHMAPI
kmm_get_module_state(kmm_module m);

/*! \brief Unload a module

    See the associated NetIDMgr Module Manager documentation on the
    sequence of events associated with unloading a module.

    \see \ref pi_fw_pm_unload
*/
KHMEXP khm_int32   KHMAPI
kmm_unload_module(kmm_module module);

/*! \brief Loads the default modules as specified in the configuration

    The configuration can specify the default set of modules to load.
    This function dispatches the necessary message for loading these
    modules and reutnrs.
*/
KHMEXP khm_int32   KHMAPI
kmm_load_default_modules(void);

/*! \brief Checks whether there are any pending loads

    Returns TRUE if there are modules still waiting to be loaded.
*/
KHMEXP khm_boolean  KHMAPI
kmm_load_pending(void);

#ifdef _WIN32

/*! \brief Returns the Windows module handle from a handle to a NetIDMgr module.
    Although it is possible to obtain the Windows module handle and
    use it to call Windows API functions, it is not recommended to do
    so.  This is because that might cause the state of the module to
    change in ways which are inconsistent from the internal data
    structures that kmm maintains.
 */
KHMEXP HMODULE     KHMAPI
kmm_get_hmodule(kmm_module m);
#endif

/*! \brief Hold a plugin

    Obtains a hold on a plugin.  The plugin handle will remain valid
    until the hold is released with a call to kmm_release_plugin().
    No guarantees are made on the handle once the handle is released.
 */
KHMEXP khm_int32   KHMAPI
kmm_hold_plugin(kmm_plugin p);

/*! \brief Release a plugin

    Releases a hold on a plugin obtained through a call to
    kmm_hold_plugin().  The plugin handle should no longer be
    considered valied once this is called.
 */
KHMEXP khm_int32   KHMAPI
kmm_release_plugin(kmm_plugin p);

/*! \brief Provide a plugin

    This function must be called for each plugin that the module
    provides.

    Note that this function returns immediately and does not
    initialize the plugin.  All plugins that are provided by a
    module will be initialized once the init_module() function
    returns.  If the plugin has dependencies, it will be kept in a
    held state until the plugins that it depends on are successfully
    initialized.  If the dependencies are not resolved (the dependent
    plugins are not loaded), then plugin will not be initialized.

    If the plugin is not registered and \a plugin contains enough
    information to perform the registration, then it will be
    automatically registered.  However, if the plugin is not
    registered and cannot be registered using the provided
    information, the plugin will not be initialized properly.  Note
    that automatic registration will always register the plugin in the
    user configuration store.

    The \a name and \a msg_proc members of \a plugin are required to
    have valid values.  The \a icon member may optionally be
    specified.  The other fields can be specified if the plugin should
    be automatically registered, however, the \a module field will be
    ignored and will be determined by the \a module handle.

    \param[in] module Handle to this module that is providing the plugin.
    \param[in] plugin A plugin descriptor.

    \retval KHM_ERROR_SUCCESS Succeeded.
    \retval KHM_ERROR_INVALID_OPERATION The function was not called
        during init_module()
    \retval KHM_ERROR_INVALID_PARAM One or more parameters were invalid
    \retval KHM_ERROR_DUPLICATE The plugin was already provided

    \note This can only be called when handing init_module()
*/
KHMEXP khm_int32   KHMAPI
kmm_provide_plugin(kmm_module module, kmm_plugin_reg * plugin);

/*! \brief Query the state of a plugin.

    \return One of ::_kmm_plugin_states
*/
KHMEXP khm_int32   KHMAPI
kmm_get_plugin_state(wchar_t * plugin);

/*! \defgroup kmm_reg Registration

    The functions for managing plugin and module registration.  These
    functions are also available as static linked libraries for use by
    external applications which must register or unregister plugins or
    modules.
@{*/

/*! \brief Obtain the configuration space for a named plugin

    Note that the named plugin does not have to actually exist.
    Configuration spaces for plugins are based solely on the plugin
    name and hence can be accessed regardless of whether the specific
    plugin is loaded or not.

    \param[in] flags Controls the options for opening the
        configuration space.  If KHM_FLAG_CREATE is specified, then
        the configuration space for the plugin named \a plugin wil be
        created if it doesn't already exist.  The \a flags parameter
        is directly passed into a call to khc_open_space().

    \param[in] plugin Name of the plugin.  The name can not contain
        slashes.

    \param[out] result Receives a configuration space handle.  The
        calling application should free the handle using
        khc_close_space().

    \see khc_open_space()
    \see khc_close_space()
 */
KHMEXP khm_int32   KHMAPI
kmm_get_plugin_config(wchar_t * plugin, khm_int32 flags, khm_handle * result);

/*! \brief Obtain the configuration space for a named module

    The named module does not have to actually exist.  Configuration
    spaces for modules are based on the basename of the module
    (including the extension).

    \param[in] module Name of the module.

    \param[in] flags The flags used to call khc_open_space().  You can
        use this to specify a particular configuration store if
        needed.

    \param[out] result Receives the handle to a configuration space if
        successful.  Call khc_close_space() to close the handle.

    \see khc_open_space()
    \see khc_close_space()
*/
KHMEXP khm_int32   KHMAPI
kmm_get_module_config(wchar_t * module, khm_int32 flags, khm_handle * result);

/*! \brief Retrieve a handle to the configuration space for plugins

    The configuration space for plugins is a container which holds the
    configuration subspaces for all the plugins.  This is the config
    space which must be used to load a configuration space for a
    plugin.

    \param[in] flags The flags to pass in to the call to
        khc_open_space().  The flags can be used to select a specific
        configuration store if needed.

    \param[out] result Receives a handle to the configuration
        space. Call khc_close_space() to close the handle

    \see khc_open_space()
    \see khc_close_space()
 */
KHMEXP khm_int32   KHMAPI
kmm_get_plugins_config(khm_int32 flags, khm_handle * result);

/*! \brief Retrieve the handle to the configuration space for modules

    The configuration space for modules is a container which hold the
    configuration subspaces for all the modules.  Each module
    registration ends up in this subspace.

    \param[in] flags The flags to pass in to the call to
        khc_open_space().  The flags can be used to select a specific
        configuration store if needed.

    \param[out] result Receives a handle to the configuration space.
        Call khc_close_space() to close the handle.

    \see khc_open_space()
    \see khc_close_space()
 */
KHMEXP khm_int32   KHMAPI
kmm_get_modules_config(khm_int32 flags, khm_handle * result);

/*! \brief Return information about a loaded module

    The retrieves a block of information about a module.  Refer to
    ::kmm_module_info for information about the format of the returned
    data.

    Note that the size of the required buffer is actually greater than
    the size of the ::kmm_module_info structure and accomodates the
    ::kmm_plugin_info structures and strings required to complete the
    information block.

    Call the function with \a buffer set to NULL and \a cb_buffer
    pointing at a khm_size variable to obtain the required size of the
    buffer.

    \param[in] module_name Name of a module
    \param[in] flags Flags indicating which types of information to
        return
    \param[out] buffer Points to a buffer that recieves information.
        Set this to NULL if only the size of the buffer is required.
    \param[in,out] On entry, contains the size of the buffer pointed
        to by \a buffer if \a buffer is not NULL. On exit, contains
        the required size of the buffer or the number of actual bytes
        copied.

    \retval KHM_ERROR_SUCCESS The requested information was copied
    \retval KHM_ERROR_INVALID_PARAM One of the parameters was invalid
    \retval KHM_ERROR_TOO_LONG The buffer was not large enough or was
        NULL.  The number of bytes requied is in \a cb_buffer.
    \retval KHM_ERROR_NOT_FOUND The specified module is not a
        registered module.
 */
KHMEXP khm_int32   KHMAPI
kmm_get_module_info(wchar_t *  module_name, khm_int32 flags,
                    kmm_module_info * buffer, khm_size * cb_buffer);

/*! \brief Get information about a module

    Similar to kmm_get_module_info(), but uses a module handle instead
    of a name, and uses internal buffers for providing string fields.

    The information that is returned should be freed using a call to
    kmm_release_module_info_i().

    \see kmm_release_module_info_i()
 */
KHMEXP khm_int32   KHMAPI
kmm_get_module_info_i(kmm_module module, kmm_module_info * info);

/*! \brief Release module information

    Releases the information returned by a previous call to
    kmm_get_module_info_i().  The contents of the ::kmm_module_info
    structure should not have been modified in any way between calling
    kmm_get_module_info_i() and kmm_release_module_info_i().
 */
KHMEXP khm_int32   KHMAPI
kmm_release_module_info_i(kmm_module_info * info);

/*! \brief Obtain information about a plugin

    Retrieve a block of information about a plugin.  See
    ::kmm_plugin_info for details about what information can be
    returned.  Note that some fields may not be available if the
    module is not loaded.

    Note that the size of the required buffer is greater than the size
    of the ::kmm_plugin_info structure and accounts for strings as
    well.  Call kmm_get_plugin_info() with \a buffer set to NULL and
    \a cb_buffer set to point to a variable of type \a khm_size to
    obtain the required size of the structure.

    \param[in] plugin_name Name of the plugin
    \param[out] buffer The buffer to receive the plugin information.
        Set to \a NULL if only the size of the buffer is required.
    \param[in,out] cb_buffer On entry, points to variable that
        specifies the size of the buffer pointed to by \a buffer is \a
        buffer is not \a NULL.  On exit, holds the number of bytes
        copied or the required size of the buffer.

    \retval KHM_ERROR_SUCCESS The requested information was
        successfully copied to the \a buffer
    \retval KHM_ERROR_TOO_LONG The buffer was either \a NULL or
        insufficient to hold the requested information.  The required
        size of the buffer was stored in \a cb_buffer
    \retval KHM_ERROR_INVALID_PARAM One or more parameters were
        invlaid.
    \retval KHM_ERROR_NOT_FOUND The specified plugin was not found
        among the registered plugins.
*/
KHMEXP khm_int32   KHMAPI
kmm_get_plugin_info(wchar_t * plugin_name,
                    kmm_plugin_info * buffer,
                    khm_size * cb_buffer);

/*! \brief Obtain information about a plugin using a plugin handle

    Similar to kmm_get_plugin_info() but uses a plugin handle instead
    of a plugin name.  If the call is successful, the \a info
    structure will be filled with information about the plugin.  The
    returned info should not be modified in any way and may contain
    pointers to internal buffers.

    The returned information must be released with a call to
    kmm_release_plugin_info_i().
 */
KHMEXP khm_int32   KHMAPI
kmm_get_plugin_info_i(kmm_plugin p, kmm_plugin_info * info);

/*! \brief Release plugin information returned by kmm_get_plugin_info_i

    The information returned by kmm_get_plugin_info_i() should not be
    modified in any way before calling kmm_release_plugin_info_i().
    Once the call completes, the contents of \a info will be
    initialized to zero.
 */
KHMEXP khm_int32   KHMAPI
kmm_release_plugin_info_i(kmm_plugin_info * info);

/*! \brief Enumerates plugins

    Enumerates through known plugins.  This list may not include
    plugins which were not loaded by NetIDMgr in this session.

    If the call is successful, a handle to the next plugin in the list
    will be placed in \a p_next.  The returned handle must be freed
    with a call to kmm_release_plugin().

    If the \a p parameter is set to NULL, then the first plugin handle
    will be placed in \a p_next.  The handles will not be returned in
    any specific order.  In addition, the enumeration may not include
    all known plugins if the list of plugins changes during
    enumeration.
 */
KHMEXP khm_int32   KHMAPI
kmm_get_next_plugin(kmm_plugin p, kmm_plugin * p_next);

/*! \brief Enables or disables a plugin

    This function currently does not take effect immediately.  However
    it marks the plugin as enabled or disabled so that the next time
    NetIDMgr starts, the module manager will act accordingly.

    \param[in] p Handle to the plugin

    \param[in] enable If non-zero, the plugin will be marked as
        enabled.  Otherwise the plugin will be marked as disabled.
 */
KHMEXP khm_int32   KHMAPI
kmm_enable_plugin(kmm_plugin p, khm_boolean enable);

/*! \brief Register a plugin

    The \a plugin member defines the plugin to be registered.  The \a
    msg_proc and \a icon members of the structure are ignored.

    At the time kmm_register_plugin() is called, the module specified
    by \a module member of the \a plugin parameter must have been already
    registered.  Otherwise the function call fails.

    If the plugin has already been registered, then all the fields in
    the plugin registration will be updated to be in sync with the
    information provided in the \a plugin parameter.  The failure
    counts and associated statistics will not be reset when the
    configuration information is updated.

    If the plugin has not been registered, the a new registration
    entry is created in the configuration space indicated by the \a
    config_flags parameter.  In addition, the plugin will be added to
    the list of plugins associated with the owning module.

    Note that the module that owns the plugin must be registered in
    the same configuration store as the plugin.

    \param[in] plugin Registration info for the plugin.  The \a
        msg_proc and \a icon members are ignored.  All other fields
        are required.  The \a description member should be localized
        to the system locale when registering a plugin in the machine
        configuration store and should be localized to the user locale
        when registering a plugin in the user configuration store.
    \param[in] config_flags Flags for the configuration provider.
        These flags are used verbatim to call khc_open_space(), hence
        they may be used to pick whether or not the registration is
        per machine or per user.

    \see kmm_register_module()
 */
KHMEXP khm_int32   KHMAPI
kmm_register_plugin(kmm_plugin_reg * plugin, khm_int32 config_flags);

/*! \brief Register a module

    The \a module parameter specifies the parameters for the module
    registration.

    The \a plugin_info member should point to an array of
    ::kmm_plugin_info structures unless the \a n_plugins member is
    zero, in which case \a plugin_info can be \a NULL.  Plugins can be
    registered separately using kmm_register_plugin().

    \param[in] module Information about the module.  The name and path
        fields are required. The \a plugin_info field can only be \a
        NULL if \a n_plugins is zero.

    \param[in] config_flags Flags used to call khc_open_space().  This
        can be used to choose the configuration store in which the
        module registration will be performed.
  */
KHMEXP khm_int32   KHMAPI
kmm_register_module(kmm_module_reg * module, khm_int32 config_flags);

/*! \brief Unregister a plugin

    Registration information associated with the plugin will be
    removed.  In addtion, the plugin will be removed from the list of
    plugins provided by the owner module.

    \param[in] plugin Names the plugin to be removed
    \param[in] config_flags Flags used to call khc_open_space(). Can
        be used to choose the configuraiton store that is affected by
        the call.

    \note kmm_unregister_plugin() has no effect on whether the plugin
        is loaded or not.  The caller must make sure that the plugin
        is unloaded and the associated module is either also unloaded
        or in a state where the plugin can be unregistered.
 */
KHMEXP khm_int32   KHMAPI
kmm_unregister_plugin(wchar_t * plugin, khm_int32 config_flags);

/*! \brief Unregister a module

    Registration information associated with the module as well as all
    the plugins provided by the module will be removed from the
    configuration store.

    \param[in] module Names the module to be removed

    \param[in] config_flags Flags used to call khc_open_space().  Can
        be used to choose the configuration store affected by the
        call.

    \note kmm_unregister_module() has no effect on the loaded state of
        the module.  The caller should make sure that the module is
        unloaded and in a state where it can be unregistered.
 */
KHMEXP khm_int32   KHMAPI
kmm_unregister_module(wchar_t * module, khm_int32 config_flags);

/*@}*/ /* kmm_reg */

/*! \defgroup kmm_loc Internationalization support

    See \ref pi_localization for more information about
    internationalization.

@{*/

/*! \brief Locale descriptor record

    See kmm_set_locale()
*/
typedef struct tag_kmm_module_locale {
    khm_ui_4    language; /*!< A language ID.  On Windows, you can use the
                            MAKELANGID macro to generate this value. */
    wchar_t *   filename; /*!< The filename corresponding to this language.
                            Use NULL to indicate that resources for this
                            language are to be found in the main module. */
    khm_int32   flags;    /*!< Flags.  Combination of KMM_MLOC_FLAG_* */
} kmm_module_locale;

#define LOCALE_DEF(language_id, filename, flags) {language_id, filename, flags}

/*! \brief Default (fallback) locale
*/
#define KMM_MLOC_FLAG_DEFAULT 1


/*! \brief Sets the locale for a loaded module.

    The given locale records are searched in the given order until a
    locale that matches the current user locale is found.  If no
    locales match, then the first locale with the
    ::KMM_MLOC_FLAG_DEFAULT flag set will be loaded.  If no locales
    have that flag set, then the first locale is loaded.

    You can obtain a handle to the loaded library using
    kmm_get_resource_hmodule().  This function does not return until a
    matched library is loaded.

    Note that the ::kmm_module_locale structure only specifies a
    module name for the resource module.  This resource module must
    exist in the same directory as the \a module.

    \param[in] module The module handle
    \param[in] locales An array of ::kmm_module_locale objects
    \param[in] n_locales The number of objects in the array pointed to by \a locales

    \retval KHM_ERROR_SUCCESS Succeeded.
    \retval KHM_ERROR_NOT_FOUND A matching locale resource library was not found.
    \retval KHM_ERROR_INVALID_OPERATION The function was called on a module which is currently not being initalized.

    \see \ref pi_localization
    \see kmm_get_resource_hmodule()

    \note This can only be called when handing init_module()
*/
KHMEXP khm_int32   KHMAPI
kmm_set_locale_info(kmm_module module,
                    kmm_module_locale * locales,
                    khm_int32 n_locales);

#ifdef _WIN32

/*! \brief Return the Windows module handle of the resource library of a NetIDMgr module.

    NetIDMgr allows the specification of an alternate resource library
    that will be used to load localized resources from.  This function
    returns a handle to this library.

    While you can use the convenience macros to access resources in a
    localization library using the module handle, it is recommended,
    for performance reasons, to use this function to obtain the handle
    to the resource library and then use that handle in calls to
    LoadString, LoadImage etc. directly.
*/
KHMEXP HMODULE     KHMAPI
kmm_get_resource_hmodule(kmm_module m);

/*! \name Convenience Macros
@{*/
/*! \brief Convenience macro for using calling LoadAccelerators using a module handle

    \param[in] module A handle to a loaded module.  The corresponding resource
        module will be located through a call to kmm_get_resource_hmodule()
*/
#define kmm_LoadAccelerators(module, lpTableName) \
    (LoadAccelerators(kmm_get_resource_hmodule(module), lpTableName))

/*! \brief Convenience macro for using calling LoadBitmap using a module handle

    \param[in] module A handle to a loaded module.  The corresponding resource
        module will be located through a call to kmm_get_resource_hmodule()
*/
#define kmm_LoadBitmap(module, lpBitmapName) \
    (LoadBitmap(kmm_get_resource_hmodule(module), lpBitmapName))

/*! \brief Convenience macro for using calling LoadImage using a module handle

    \param[in] module A handle to a loaded module.  The corresponding resource
        module will be located through a call to kmm_get_resource_hmodule()
*/
#define kmm_LoadImage(module, lpszName, uType, cxDesired, cyDesired, fuLoad) \
    (LoadImage(kmm_get_resource_hmodule(module), lpszName, uType, cxDesired, cyDesired, fuLoad))

/*! \brief Convenience macro for using calling LoadCursor using a module handle

    \param[in] module A handle to a loaded module.  The corresponding resource
        module will be located through a call to kmm_get_resource_hmodule()
*/
#define kmm_LoadCursor(module, lpCursorName) \
    (LoadCursor(kmm_get_resource_hmodule(module), lpCursorName))

/*! \brief Convenience macro for using calling LoadIcon using a module handle

    \param[in] module A handle to a loaded module.  The corresponding resource
        module will be located through a call to kmm_get_resource_hmodule()
*/
#define kmm_LoadIcon(module, lpIconName) \
    (LoadIcon(kmm_get_resource_hmodule(module), lpIconName))

/*! \brief Convenience macro for using calling LoadMenu using a module handle

    \param[in] module A handle to a loaded module.  The corresponding resource
        module will be located through a call to kmm_get_resource_hmodule()
*/
#define kmm_LoadMenu(module, lpMenuName) \
    (LoadMenu(kmm_get_resource_hmodule(module), lpMenuName))

/*! \brief Convenience macro for using calling LoadString using a module handle

    \param[in] module A handle to a loaded module.  The corresponding resource
        module will be located through a call to kmm_get_resource_hmodule()
*/
#define kmm_LoadString(module, uID, lpBuffer, nBufferMax) \
    (LoadString(kmm_get_resource_hmodule(module), uID, lpBuffer, nBufferMax))
/*@}*/ /* Convenience Macros */
#endif
/*@}*/ /* group kmm_loc */
/*@}*/ /* group kmm */
#endif

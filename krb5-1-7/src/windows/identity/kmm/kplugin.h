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

#ifndef __KHIMAIRA_KPLUGIN_H
#define __KHIMAIRA_KPLUGIN_H

#include<kmm.h>
#include<kherror.h>

/*! \addtogroup kmm
@{*/
/*! \defgroup kplugin NetIDMgr Plugin Callbacks

See the following related documentation pages for more information 
about NetIDMgr plugins.

These are prototypes of functions that must be implemented by a NetIDMgr
plugin.

- \ref plugins
@{*/

/*! \brief Initialize the module

    This is the first callback function to be called in a module.
    Perform all the required intialization when this is called.  As
    mentioned in \ref plugins, you should not attempt to call any
    NetIDMgr API function from DLLMain or other initialization code
    other than this one.

    You should use this call back to register the plugins that will be
    implemented in this module and to notify the plugin manager of any
    resource libraries that this module will use.

    Call:
    - kmm_set_locale() : to set the notify the plugin manager of the
      locale specifc resource libraries that are used by this module.
    - kmm_provide_plugin() : to register each plugin that is
      implemented in this module.

    This function is called in the context of the current user, from
    the plug-in manager thread.  This same thread is used by the
    plug-in manager to load and initialize all the modules for a
    session.

    The name of the callback must be init_module().  The calling
    convention is KHMAPI, which is currently __stdcall.

    If this function does not register any plugins, the plugin manager
    will immediately call exit_module() and unload the module even if
    the init_module() function completes successfully.

    \return Return the following values to indicate whether the module
        successfully initialized or not.
        - KHM_ERROR_SUCCESS : Succeeded. The module manager will call
            init_plugin() for each of the registered plugins for the
            module.
        - any other error code: Signals that the module did not
            successfully initialize.  The plugin manager will
            immediately call exit_module() and then unload the module.

    \note This callback is required.
*/
KHMEXP_EXP khm_int32 KHMAPI init_module(kmm_module h_module);

/*! \brief Type for init_module() */
typedef khm_int32 (KHMAPI *init_module_t)(kmm_module);

#if defined(_WIN64)
#define EXP_INIT_MODULE "init_module"
#elif defined(_WIN32)
#define EXP_INIT_MODULE "_init_module@4"
#else
#error  EXP_INIT_MODULE not defined for platform
#endif

/*! \brief Plugin procedure

    This is the message processor for a plugin.  See \ref pi_fw_pnm_p
    for more information.

    Essentially, this is a message subscriber for KMQ messages.
*/
KHMEXP_EXP khm_int32 KHMAPI _plugin_proc(khm_int32 msg_type, khm_int32 msg_subtype, khm_ui_4 uparam, void * vparam);

/*! \brief Type for init_plugin() */
typedef kmq_callback_t _plugin_proc_t;

/*! \brief Exit a module

    This is the last callback function that the NetIDMgr module
    manager calls before unloading the module.  When this function is
    called, all of the plugins for the module have already been
    stopped.  However, any localization libraries that were loaded as
    a result of init_module() calling kmm_set_locale_info() will still
    be loaded.  These localization libraries will be unloaded
    immediately after this callback returns.

    Use this callback to perform any required cleanup tasks.  However,
    it is advisable that each plugin perform its own cleanup tasks,
    since each plugin may be stopped independently of others.

    \return The return value of this function is ignored.

    \note This callback is not required.
*/
KHMEXP_EXP khm_int32 KHMAPI exit_module(kmm_module h_module);

/*! \brief Type for exit_module() */
typedef khm_int32 (KHMAPI *exit_module_t)(kmm_module);

#if defined(_WIN64)
#define EXP_EXIT_MODULE "exit_module"
#elif defined(_WIN32)
#define EXP_EXIT_MODULE "_exit_module@4"
#else
#error  EXP_EXIT_MODULE not defined for platform
#endif

/*@}*/
/*@}*/

#endif

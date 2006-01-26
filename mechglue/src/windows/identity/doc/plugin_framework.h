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

/*!
\page pi_framework Plugin Framework

\section pi_fw_pnm Plugins and Modules

\subsection pi_fw_pnm_p Plugins

A NetIDMgr plugin is a package that implements a defined API that will
perform credentials management or related tasks on behalf of NetIDMgr.
The core NetIDMgr codebase does not interact directly with Kerberos of
AFS or any other external entity directly.  Instead, plugins are used
to abstract out this task.

Each plugin has a name.  The name should be unique among the loaded
plugins, or the plugin will fail to load.

The method in which NetIDMgr communicates with a plugin depends on the
plugin type.  For more information on each plugin type, please refer
to \ref pi_pt.

Most plugin types rely on a message processor for communication.
During plugin registration, the module specifies the message processor
for the plugin, which acts as the only point of contact between the
NetIDMgr core and the plugin.  Some other plugins require exporting
specific functions.

\subsection pi_fw_pnw_m Modules

One or more plugins can be bundled together into a module.  A module
is essentially a dynamically loadable library which contain a specific
set of callbacks.  Currently, the only two required callbacks for a
module are :

- init_module(), and
- exit_module()

\section pi_fw_pm Plugin/Module Manager

The plugin manager maintains a separate thread for loading and
registering modules.  When a module is successfully loaded and it
registers one or more plugins, a new thread is created for each
plugin.  Plugin specific initialization and other callback functions
are called from within this new thread.  This is to prevent one plugin
from "hanging" other plugins and the main NetIDMgr UI threads.

Read more :
- \ref pi_structure

\subsection pi_fw_pm_load Load sequence

When kmm_load_module() is called, the following sequence of events
happen.

- The standard system search path is used to locate the binary.

- The binary is loaded into the address space of NetIDMgr along with
  any dependencies not already loaded.

- If the NetIDMgr core binary is signed, then the signature is checked
  against the system and user certificate stores.  If this fails, the
  module is unloaded. See \ref pi_fw_pm_unload.

- init_module() for the loaded module is called.  If this function
  returns an error or if no plugins are registered, then the module is
  unloaded. See \ref pi_fw_pm_unload.

- During processing of init_module(), if any localized resource
  libraries are specified using kmm_set_locale_info(), then one of the
  localized libraries will be loaded. See \ref pi_localization

- During processing of init_module(), the module registers all the
  plugins that it is implementing by calling kmm_register_plugin() for
  each.

- Once init_module() returns, each plugin is initialized.  The method
  by which a plugin is initialized depends on the plugin type.  The
  initialization code for the plugin may indicate that it didn't
  initialize properly, in which case the plugin is immediately
  unregistered.  No further calls are made to the plugin.

- If no plugin is successfully loaded, the module is unloaded. See
  \ref pi_fw_pm_unload.

- During normal operation, any registered plugins for a module can be
  unloaded explicitly, or the plugin itself may signal that it should
  be unloaded.  If at anytime, all the plugins for the module are
  unloaded, then the module itself is also unloaded.

\subsection pi_fw_pm_unload Unload sequence

- For each of the plugins that are registered for a module, the exit
  code is invoked.  The method by which this happens depends on the
  plugin type.  The plugin is not given a chance to object to the
  decision to unload. Each plugin is responsible for performing
  cleanup tasks, freeing resources and unsubscribing from any message
  classes that it has subscribed to.

- exit_module() is called for the module.

- If any localized resource libraries were loaded for the module, they
  are unloaded.

- The module is unloaded.

 */

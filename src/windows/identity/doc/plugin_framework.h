/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
 * Copyright (c) 2007 Secure Endpoints Inc.
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
\page pi_framework Plug-in Framework

\section pi_fw_pnm Plug-ins and Modules

\subsection pi_fw_pnm_p Plug-ins

A Network Identity Manager plug-in is a package that implements a defined API that will
perform credentials management or related tasks on behalf of Network Identity Manager.
The core Network Identity Manager codebase does not interact directly with Kerberos v5 or
AFS or any other external entity directly.  Instead, plug-ins are used.

Each plug-in has a name.  The name should be unique among the loaded
plug-ins, or the plug-in will fail to load.

The method in which Network Identity Manager communicates with a plug-in depends on the
plug-in type.  For more information on each plug-in type, please refer
to \ref pi_pt.

Most plug-in types rely on a message processor for communication.
During plug-in registration, the module specifies the message processor
for the plug-in, which acts as the only point of contact between the
Network Identity Manager core and the plug-in.  Some other plug-ins require exporting
specific functions.

\subsection pi_fw_pnw_m Modules

One or more plug-ins can be bundled together into a module.  A module
is a dynamically loadable library which exports a specific
set of callbacks.  Currently, the only two required callbacks for a
module are :

- init_module(), and
- exit_module()

\section pi_fw_pm Plug-in/Module Manager

The plug-in manager maintains a separate thread for loading and
registering modules.  When a module is successfully loaded and it
registers one or more plug-ins, a new thread is created for each
plug-in.  Plug-in specific initialization and other callback functions
are called from within this new thread.  This is to prevent one plug-in
from "hanging" other plug-ins and the main Network Identity Manager 
user interface threads.

Read more :
- \ref pi_structure

\subsection pi_fw_pm_load Load sequence

When kmm_load_module() is called, the following sequence of events
occur:

- The standard system search path is used to locate the binary.

- The binary is loaded into the address space of Network Identity Manager along with
  any dependencies not already loaded.

- If the Network Identity Manager core binary is signed, then the signature is checked
  against the system and user certificate stores.  If this fails, the
  module is unloaded. See \ref pi_fw_pm_unload.

- init_module() for the loaded module is called.  If this function
  returns an error or if no plug-ins are registered, then the module is
  unloaded. See \ref pi_fw_pm_unload.

- During processing of init_module(), if any localized resource
  libraries are specified using kmm_set_locale_info(), then one of the
  localized libraries will be loaded. See \ref pi_localization

- During processing of init_module(), the module registers all the
  plug-ins that it is implementing by calling kmm_register_plug-in() for
  each.

- Once init_module() returns, each plug-in is initialized.  The method
  by which a plug-in is initialized depends on the plug-in type.  The
  initialization code for the plug-in may indicate that it didn't
  initialize properly, in which case the plug-in is immediately
  unregistered.  No further calls are made to the plug-in.

- If no plug-in is successfully loaded, the module is unloaded. See
  \ref pi_fw_pm_unload.

- During normal operation, any registered plug-ins for a module can be
  unloaded explicitly, or the plug-in itself may signal that it should
  be unloaded.  If at anytime, all the plug-ins for the module are
  unloaded, then the module itself is also unloaded unless the NoUnload
  registry value is set in the module key.

\subsection pi_fw_pm_unload Unload sequence

- For each of the plug-ins that are registered for a module, the exit
  code is invoked.  The method by which this happens depends on the
  plug-in type.  The plug-in is not given a chance to object to the
  decision to unload. Each plug-in is responsible for performing
  cleanup tasks, freeing resources and unsubscribing from any message
  classes that it has subscribed to.

- exit_module() is called for the module.

- If any localized resource libraries were loaded for the module, they
  are unloaded.

- The module is unloaded.

 */

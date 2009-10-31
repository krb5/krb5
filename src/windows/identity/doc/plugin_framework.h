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

\section pi_fw_pnm Introduction to Plug-ins, Modules and Messages

\subsection pi_fw_pnm_p Plug-ins

A plug-in is a package that implements a defined API that will perform
credentials management or related tasks on behalf of Network Identity
Manager.

The Network Identity Manager architecture is message based.  The core
of each plug-in is a message handler.  The plug-in integrates with the
application by subscribing to, and handling specific types of
messages.

The plug-in message handler runs in its own thread and receive
asynchronous messages.  There are exceptions, such as when one plug-in
requires another plug-in to handle a specific message before it can
handle the message.  In addition, during certain operations that
require user interaction, each plug-in can delegate code that will run
in the main application thread (the user interface thread) to process
window messages.

\subsection pi_fw_pnw_m Modules

One or more plug-ins can be bundled together into a module.  A module
is a dynamically loadable library which exports a specific set of
callbacks.  Currently, the only two required callbacks for a module
are :

- init_module(), and
- exit_module()

For more information about how a module is structured, see \ref
pi_structure .

\subsection pi_fw_pnm_msg Messages and Message Queues

An integral part of this framework is the messaging system.  Most of
the communication between the Network Identity Manager application and
plug-ins is conducted through passing messages.

A message has a type and subtype and is denoted in this documentation
as \< \e message_type, \e message_subtype\>.  For example, when a
plug-in is loaded, the first message it receives is \< ::KMSG_SYSTEM,
::KMSG_SYSTEM_INIT \>.

Each thread in the application, specially threads that were created
for individual plug-in messages handlers, has an associated message
queue that stores and manages all the messages that have been sent to
subscribers in that thread.

The most common recipient of a message is a message callback function
(see ::kmq_callback_t ). The message handler for a plug-in is one such
example. A message callback function receives the message type,
subtype and two optional parameters for the message.

Any acceptable recipient can subscribe to broadcast messages of any
type.  Once subscribed, whenever a message of that type is broadcast,
the message will get queued on the corresponding message queue.  Then,
one of the dispatch functions can dispatch the message to the correct
callback function. (see ::kmq_dispatch).

Next \subpage pi_fw_pm ...

*/

/*!

\page pi_fw_pm Module Manager

The Module Manager is tasked with loading and unloading modules as
well as managing the plug-in message processing.

When a module is successfully loaded, it registers one or more
plug-ins.  The Module Manager creates a new thread for each of these
plug-ins.  Then the initialization message to the plug-in is sent and
the message dispatch loop is started in this new thread.  Having each
plug-in in a separate thread prevents one plug-in from "hanging" other
plug-ins and the user interface.

\note For compatibility with future versions of Network Identity
Manager, a plug-in should not depend on the fact that it is running in
its own thread.

Read more :
- \ref pi_structure

\section pi_fw_pm_load Module Load Sequence

When kmm_load_module() is called to load a specific module, the
following sequence of events occur:

<ul>

 <li>
  The registration information for the module is located on the
  registry key \c
  \\Software\\MIT\\NetIDMgr\\PluginManager\\Modules\\[ModuleName]. \see
  \ref config
 </li>

 <li> The module will not be loaded if one of the following conditions are
  true:

  <ul>
   <li>
    The \c Disabled value is defined and non-zero.
   </li>

   <li>
    The \c FailureCount value is defined and exceeds the maximum
    failure count.  By default, the maximum failure count is three,
    although it can be set by adding the registry value \c
    ModuleMaxFailureCount in registry key \c
    Software\\MIT\\NetIDMgr\\PluginManager\\Modules .
   </li>
  </ul>
 </li>

 <li>
  The \c ImagePath value from the registration information is used to
  locate the module binary.  If it is not an absolute path, then the
  binary is located using the standard system search path starting
  from the directory in which Network Identity Manager binaries are
  located.
 </li>

 <li>
  The binary is loaded into the address space of Network Identity
  Manager along with any dependencies not already loaded.
 </li>

 <li>
  If the Network Identity Manager core binary is signed, then the
  signature is checked against the system and user certificate stores.
  If this fails, the module is unloaded. See \ref pi_fw_pm_unload.
 </li>

 <li>
  The init_module() entry point for the loaded module is called.  If
  this function returns an error or if no plug-ins are registered,
  then the module is immediately unloaded. See \ref pi_fw_pm_unload.

  <ul>
   <li>
    During processing of init_module(), if any localized resource
    libraries are specified using kmm_set_locale_info(), then one of the
    localized libraries will be loaded. See \ref pi_localization
   </li>

   <li>
    During processing of init_module(), the module registers all the
    plug-ins that it is implementing by calling kmm_provide_plugin()
    for each.
   </li>
  </ul>
 </li>

 <li>
  Once init_module() returns, each plug-in is initialized.  The method
  by which a plug-in is initialized depends on the plug-in type.  The
  initialization code for the plug-in may indicate that it didn't
  initialize properly, in which case the plug-in is immediately
  unregistered.  No further calls are made to the plug-in.
 </li>

 <li>
  If no plug-in is successfully loaded, the module is unloaded. See
  \ref pi_fw_pm_unload.
 </li>
</ul>

  During normal operation, any registered plug-ins for a module can be
  unloaded explicitly, or the plug-in itself may signal that it should
  be unloaded.  If at anytime, all the plug-ins for the module are
  unloaded, then the module itself is also unloaded unless the \c
  NoUnload registry value is set in the module key.

\section pi_fw_pm_unload Unload sequence

<ul>
 <li>
  For each of the plug-ins that are registered for a module, the exit
  code is invoked.  The method by which this happens depends on the
  plug-in type.  The plug-in is not given a chance to veto the
  decision to unload. Each plug-in is responsible for performing
  cleanup tasks, freeing resources and unsubscribing from any message
  classes that it has subscribed to.
 </li>

 <li>
  Once all the plug-ins have been unloaded, the exit_module() entry
  point is called for the module.
 </li>

 <li>
  If any localized resource libraries were loaded for the module, they
  are unloaded.
 </li>

 <li>
  The module is unloaded.
 </li>
</ul>

The following diagram illustrates the relationship between modules and
plug-ins as implemented in the Kerberos 5 plug-in distributed with
Network Identity Manager.

\image html modules_plugins_krb5.png

 */

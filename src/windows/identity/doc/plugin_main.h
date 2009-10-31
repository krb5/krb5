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

\page plug-ins Network Identity Manager Modules and Plug-ins

  The Network Identity Manager application does not include any
  ability to manage any specific type of credential.  Instead it
  exposes a framework on which plug-ins can be implemented to manage
  credentials.

  Plug-ins and localization are handled by the Network Identity
  Manager Module Manager API.

  The following sections describe plug-ins in detail:

  - \subpage pi_framework
  - \subpage pi_pt
  - \subpage pi_structure
  - \subpage pi_localization
*/

/*! \page pi_pt Plug-in Types

The types of plug-ins that are currently supported by Network Identity
Manager are :

\section pi_pt_cred Credential Provider

A credential provider plug-in essentially acts as an interface between
Network Identity Manager and some entity which defines the credentials
for the purpose of managing those credentials.

There can be more than one credential provider in a module.

\subsection pi_pt_cred_comm Communication

Communication between Network Identity Manager and a credential
provider occurs through a message processor.  When registering a
credential provider, the module initialization code in init_module()
specifies ::KHM_PITYPE_CRED as the \a type member and sets \a msg_proc
member to a valid message processor in the ::khm_plugin record.

\subsection pi_pt_cred_init Initialization

Once init_module() has completed, the module manager sends a
<::KMSG_SYSTEM,::KMSG_SYSTEM_INIT> message to the message processor.

For credential provider plug-ins, <::KMSG_SYSTEM,::KMSG_SYSTEM_INIT> is
guaranteed to be the first message it receives.

The callback function should return KHM_ERROR_SUCCESS if it
initializes properly or some other value otherwise.  If the return
value signals an error, then the plug-in is assumed to have failed
initialization and is immediately unloaded.

The message processor is automatically subscribed to the following
message types:
- ::KMSG_SYSTEM
- ::KMSG_KCDB

Although a plug-in can use the <::KMSG_SYSTEM,::KMSG_SYSTEM_INIT>
message enumerate existing credentials in the system, it should not
obtain new credentials.  This is because other plug-ins that may depend
on the new credential messages may not be loaded at this time. See the
section on \ref cred_msgs for more information.

\subsection pi_pt_cred_exit Uninitialization

When the plug-in is to be removed, the module manager sends a
<::KMSG_SYSTEM,::KMSG_SYSTEM_EXIT> to the message processor.  The
plug-in must perform any necessary shutdown operations, free up
resources and unsubscribe from any messages that it has subscribed to.

This message is guaranteed to be the last message received by a
credentials manager plug-in if the plug-in unsubsribes from all
additional message classes that it subsribed to.

The message types that the message processor is automatically
subscribed to (See \ref pi_pt_cred_init) do not have to be
unsubscribed from as they are automatically removed.

\subsection pi_pt_cred_other Other Notes

Since credential managers may receive privileged information, the
signature requirements for credential managers are specially strict.

*/

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

/*! \page cred_msgs Handling credentials provider messages

A credentials provider plug-in receives a number of messages during the
course of execution.  This section describes the appropriate ways of
handling these messages.

  - \ref pi_credmsg_system
  - \ref pi_credmsg_cred
    - \ref pi_credmsg_list
    - \ref pi_credmsg_credacq
    - \ref pi_credmsg_destroy
    - \ref pi_credmsg_import
    - \ref pi_credmsg_prop

\section pi_credmsg_system System mesages

There are only two system messages that a credentials provider needs
to handle.  Both of these are explained elsewhere as they deal with
initialization and uninitialization of the plug-in.  See the following
two sections for details on handling these messages.

- <::KMSG_SYSTEM,::KMSG_SYSTEM_INIT> \ref pi_pt_cred_init
- <::KMSG_SYSTEM,::KMSG_SYSTEM_EXIT> \ref pi_pt_cred_exit

\section pi_credmsg_cred Credential messages

\subsection pi_credmsg_list Listing Credentials

When the Network Identity Manager application needs to refresh the
list of credentials that credentials providers are aware of, it sends
out a <::KMSG_CRED, ::KMSG_CRED_REFRESH> message.

Each credentials provider is expected to populate a credential set
with the credentials that it is aware of and call
kcdb_credset_collect() or kcdb_credset_collect_filtered() to merge the
credentials into the root credentials set.

In addition to responding to <::KMSG_CRED, ::KMSG_CRED_REFRESH>, each
credentials provider is expected to list and merge their credentials
during the following events:

- When the plug-in is initialized, during <::KMSG_SYSTEM, ::KMSG_SYSTEM_INIT>

- When the plug-in obtains new credentials during the new credentials
  acquisition sequence and whenever the plug-in becomes aware of new
  credentials.

\subsection pi_credmsg_credacq Credential Acquisition Message Sequence

The aquisition of new or renewed credentials is conducted via a
sequence of messages.  Details of handling this sequence is explained
in the section \ref cred_acq .

\subsection pi_credmsg_destroy Destroying Credentials

When a request is received to destroy credentials, Network Identity
Manager sends out a <::KMSG_CRED, ::KMSG_CRED_DESTROY_CRED> message.
The \c vparam member of the message will point to a
::khui_action_context structure that describes which credentials are
being destroyed.  The plug-in is expected to destroy any credentials
that were provided by the plug-in which are included in the user
interface context.

\see \ref khui_context_using

\subsection pi_credmsg_import Importing Credentials

The import action is typically used to request that plug-ins import
any relevant credentials from the Windows LSA cache.  This typically
only applies to plug-ins that provide Kerberos credentials and is not
discussed in detail.

\subsection pi_credmsg_prop Property Pages

Credentials providers are also expected to participate in the user
interface when the user makes a request to view the properties of a
credential or identity.

  - <::KMSG_CRED, ::KMSG_CRED_PP_BEGIN>
  - <::KMSG_CRED, ::KMSG_CRED_PP_PRECREATE>
  - <::KMSG_CRED, ::KMSG_CRED_PP_END>
  - <::KMSG_CRED, ::KMSG_CRED_PP_DESTROY>

Details about handling this sequence of messages is discussed in \ref
cred_prop_pages .

\subsection pi_credmsg_addrchange Address Change Notification

When the Network Identity Manager detects that that IP address of the
machine has changed, it will issue a <::KMSG_CRED,
::KMSG_CRED_ADDR_CHANGE>.  Handling this notification is optional and
is only necessary for credentials providers which are affected by IP
address changes.  This is just a notification and the plug-in is not
expected to take any special action.

*/

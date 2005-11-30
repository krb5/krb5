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

/*! \page cred_acq Managed credential acquisition

    Credential providers and the identity provider must participate in
    managed credential acquisition in order to respond to the user's
    requests to obtain new credentials for an identity or to obtain
    new credentials for an existing identity.

    There are two major processes that result in managed credential
    acuqisition.  One is the acquisition of initial credentials, while
    the other is the acquisition of new crednetials.  Both processes
    acquire new credentials (or replace existing credentials with new
    ones). The difference between the two processes lie in the way the
    new credentials are obtained.  Initial credentials are obtained
    using user supplied username and password while new credentials
    are obtained using other existing credentials.

    \section cred_acq_init Initial Credentials

    When a user initiates the process of initial credential
    acquisition, NetIDMgr broadcasts a
    <::KMSG_CRED,::KMSG_CRED_INITIAL_CREDS> message.  Credential
    providers which need to participate in the initial credential
    acquisition should respond to this message as detailed in 
    \ref cred_acq_handle.

    \section cred_acq_new New Credentials

    When a user initiates the process of obtaining new credentials
    based on existing credentials, NetIDMgr broadcasts a
    <::KMSG_CRED,::KMSG_CRED_NEW_CREDS> message.  Credential providers
    which need to participate in the initial credential acquisition
    should respond to this message as detailed in \ref cred_acq_handle.

    The following pages provide detailed information:

    - \subpage cred_acq_new_resp
    - \subpage cred_acq_dlgproc
 */

/*! \page cred_acq_new_resp Handling new credentials acquisition

    The process of acquiring new credentials whether they are initial
    credentials or not, happen as follows :

    - NetIDMgr creates a ::khui_new_creds object and a credentials
      acquisition window.

    - <::KMSG_CRED,::KMSG_CRED_INITIAL_CREDS> or
      <::KMSG_CRED,::KMSG_CRED_NEW_CREDS> is sent to all the
      credentials providers.

    - The credential providers create the panels (where appropriate)
      for customizing their respective credential types.  The type,
      panel and any dependency information is populated into a
      ::khui_new_creds_by_type structure and added to the
      ::khui_new_creds structure.

    - <::KMSG_CRED, ::KMSG_CRED_DIALOG_PRESTART> is sent to all the
      credentials providers.  Credentials providers should use this
      message to finialize initialization in preparation of showing
      the credentials acquisition window, such as by initializing the
      controls of the individual panels.

    - <::KMSG_CRED, ::KMSG_CRED_DIALOG_START> is sent to all the
      credentials providers.

    - The dialog for obtaining credentials is displayed.
      Notifications between the main dialog and the individual panels
      are done through ::KHUI_WM_NC_NOTIFY messages to the dialog
      procedures.

    - Once the dialog completes, NetIDMgr sends
      <::KMSG_CRED,::KMSG_CRED_DIALOG_END> message to all the
      credentials providers.  The UI portion ends here.  The
      individual dialog controls are destroyed as a result of the main
      credentials acquisition window being destroyed.

    - NetIDMgr posts <::KMSG_CRED,::KMSG_CRED_DIALOG_PROCESS> message
      to all the credentials providers.  Each provider should check if
      the user cancelled the dialog or indicated that the new
      credentials should be obtained and act accordingly.  The
      credentials provider is responsible for removing the
      ::khui_new_creds_by_type structre from the ::khui_new_creds
      structure and freeing up any resources it allocated earlier in
      preparation for obtaining new credentials.

    \section cred_acq_handle Responding to credential acquisition messages

    The credential acquisition messages are
    <::KMSG_CRED,::KMSG_CRED_INITIAL_CREDS> and <::KMSG_CRED,
    ::KMSG_CRED_NEW_CREDS>.  They are structured as follows :

    - \b type : ::KMSG_CRED
    - \b subtype: ::KMSG_CRED_INITIAL_CREDS or ::KMSG_CRED_NEW_CREDS
    - \b uparam : 0 (unused)
    - \b vparam : a pointer to a ::khui_new_creds structure.

    The \a vparam parameter of the message, as shown above, is a
    pointer to a ::khui_new_creds structure.  You can use the \a
    subtype field of this structure to determine whether this is an
    initial credentials acquisition or a new credentials acquisition
    at any point.

    In response to this message, a credentials provider is expected to
    provide a configuration panel which the user can use to customize
    how the credentials of this type are to be obtained.  The panel is
    described by the ::khui_new_cred_panel structure.

    \subsection cred_acq_panel_spec Specifying the credentials type panel

    The credentials type panel is used by the user to customize how
    credentials of the specified type are to be obtained.  The
    ::khui_new_cred_panel structure that describes the panel can be
    used to specify a number of parameters that guide how the panel is
    to be displayed in the new credentials acquisition dialog.

    The \a name field defines a localized string that will be
    displayed in the tab control that houses the panel.  Optionally,
    an icon can be specified in the \a icon field which will appear
    alongside the name.  A tooltip may be provided in the \a tooltip
    field which will be displayed when the user hovers the mouse over
    the tab.

    In order to assert that the tab appears at a specific position in
    the list of tabs, you can specify a positive number in the \a
    ordinal field.  Zero does not count as a valid ordinal.  The
    panels with positive ordinals are arranged first in increasing
    order of ordinal (conflicts are resolved by sorting along the \a
    name).  Then the panels without a positive ordianl are arranged
    behind these in increasing order of \a name.

    The \a hwnd_panel field is used to specify the handle to the
    dialog or window of the panel.  The parent of this window should
    be set to the \a hwnd parameter of the ::khui_new_creds structure
    which is passed in to the message handler.

    Following is a code snippet which suggests how this could be done:

    \code
       // Message handling code for KMSG_CRED_NEW_CREDS or
       // KMSG_CRED_INIT_CREDS
       ...
       khui_new_creds * c;
       khui_new_creds_by_type * t;

       c = (khui_new_creds *) vparam;
       t = PMALLOC(sizeof(*t));
       ZeroMemory(t, sizeof(*t));

       t->type = my_cred_type;

       // set look and feel params
       t->ordinal = 3; // third in line
       t->name = L"My panel name";
       t->icon = LoadIcon(my_hInstance, MAKEINTRESOURCE(IDI_PANEL_ICON));
       t->tooltip = L"Configure credentials of my type";

       t->hwnd_panel = CreateDialog(
           my_hInstance, 
	   MAKEINTRESOURCE(IDD_MY_PANEL),
	   c->hwnd,
	   my_dialog_proc);

       if(KHM_FAILED(khui_cw_add_type(c,t))) {
           // handle error
       }
    \endcode

    It is important to note that the ::khui_new_creds_by_type pointer
    that is passed into khui_cw_add_type() points to an allocated
    block of memory which should remain in memory until
    <::KMSG_CRED,::KMSG_CRED_DIALOG_PROCESS> message is received.

    For information on how the dialog procedure should be written, see
    \ref cred_acq_dlgproc .
 
*/

/*! \page cred_acq_dlgproc Writing the dialog procedure for a cred type panel

    
*/

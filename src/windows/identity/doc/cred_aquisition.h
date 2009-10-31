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

/*! \page cred_acq Managed credential acquisition

    Credential providers and identity providers must participate in
    managed credential acquisition in order to respond to the user's
    requests to obtain new credentials for an identity or to renew
    credentials for an existing identity.

    There are two major processes that result in managed credential
    acuqisition.  One is the acquisition of credentials, while the
    other is credential renewal.  During a renewal, existing
    credentials are used to obtain new credentials which expire later
    than the existing credential.  Typically, the identity provider
    performs the task of obtaining renewed initial credentials while
    the other credential providers obtain new credentials based on
    these initial credentials.

    \section cred_acq_new New Credentials

    When a user initiates the process of initial credential
    acquisition, Network Identity Manager broadcasts a
    <::KMSG_CRED,::KMSG_CRED_NEW_CREDS> message.  Credential providers
    which need to participate in the credential acquisition should
    respond to this message as detailed in \ref cred_acq_handle.

    \section cred_acq_renew Renew Credentials

    Network Identity Manager broadcasts a
    <::KMSG_CRED,::KMSG_CRED_RENEW_CREDS> message to initiate the
    process of renewing credentials.  This may be triggered
    automatically or by a user action.  Credential providers which
    need to participate in the renewal should respond to this message
    as detailed in \ref cred_acq_handle.

    The following pages provide detailed information:

    - \subpage cred_acq_new_resp
    - \subpage cred_acq_dlgproc
 */

/*! \page cred_acq_new_resp Handling new credentials acquisition

    The process of acquiring credentials happens as follows:

    - Network Identity Manager creates a ::khui_new_creds object and a
      credentials acquisition window.

    - <::KMSG_CRED,::KMSG_CRED_RENEW_CREDS> or
      <::KMSG_CRED,::KMSG_CRED_NEW_CREDS> is sent to all the
      credentials providers.

    - The credential providers create the panels (where appropriate)
      for customizing their respective credential types.  The type,
      panel and any dependency information is populated into a
      ::khui_new_creds_by_type structure and added to the
      ::khui_new_creds structure. (See khui_cw_add_type()).

    - <::KMSG_CRED, ::KMSG_CRED_DIALOG_PRESTART> is sent to all the
      credentials providers.

    - <::KMSG_CRED, ::KMSG_CRED_DIALOG_START> is sent to all the
      credentials providers.

    - The dialog for obtaining credentials is displayed.
      Notifications between the main dialog and the individual panels
      are done through ::KHUI_WM_NC_NOTIFY messages to the dialog
      procedures.

    - Once the dialog processing is done, a ::WMNC_DIALOG_PREPROCESS
      message is sent to the dialog procedure.

    - Network Identity Manager posts
      <::KMSG_CRED,::KMSG_CRED_DIALOG_PROCESS> message to all the
      credentials providers.  Each provider should check if the user
      cancelled the dialog or indicated that the new credentials
      should be obtained and act accordingly.  The \c result field of
      the ::khui_new_creds structure will be set to either
      ::KHUI_NC_RESULT_PROCESS or ::KHUI_NC_RESULT_CANCEL to indicate
      whether the user wishes to acquire credentials or cancel the
      operation.

    - Once all the plug-ins have processed the <::KMSG_CRED,
      ::KMSG_CRED_DIALOG_PROCESS> message, the application checks
      whether the new credentials dialog should continue processing,
      or whether the dialog should be closed.  If the dialog should
      continue processing, then the dialog returns to the state it was
      in prior to the ::WMNC_DIALOG_PREPROCESS message was sent.  If
      the dialog should be closed, then a <::KMSG_CRED,
      ::KMSG_CRED_END> message is sent.

    - A <::KMSG_CRED, ::KMSG_CRED_END> message signals the end of the
      credentials acquisition process.  Each credentials provider is
      responsible for removing the ::khui_new_creds_by_type structre
      from the ::khui_new_creds structure and freeing up any resources
      it allocated earlier in preparation for obtaining new
      credentials.

    \section cred_acq_handle Responding to credential acquisition messages

    \subsection cred_acq_handle_init <::KMSG_CRED,::KMSG_CRED_NEW_CREDS> and <::KMSG_CRED,::KMSG_CRED_RENEW_CREDS> Messages

    The credential acquisition messages are
    <::KMSG_CRED,::KMSG_CRED_NEW_CREDS> and <::KMSG_CRED,
    ::KMSG_CRED_RENEW_CREDS>.  They are structured as follows:

    - \b type : ::KMSG_CRED
    - \b subtype: ::KMSG_CRED_NEW_CREDS or ::KMSG_CRED_RENEW_CREDS
    - \b uparam : 0 (unused)
    - \b vparam : a pointer to a ::khui_new_creds structure.

    The \a vparam parameter of the message, as shown above, is a
    pointer to a ::khui_new_creds structure.  You can use the \a
    subtype field of this structure to determine whether this is a new
    credentials acquisition or a renewal.

    In response to this message, a credentials provider is expected to
    provide a configuration panel which the user can use to customize
    how the credentials of this type are to be obtained.  The panel is
    described by the ::khui_new_creds_by_type structure.

    \subsubsection cred_acq_panel_spec Specifying the credentials type panel

    The credentials type panel is used by the user to customize how
    credentials of the specified type are to be obtained.  The
    ::khui_new_creds_by_type structure that describes the panel can be
    used to specify a number of parameters that guide how the panel is
    to be displayed in the new credentials acquisition dialog.

    The \a name field defines a localized string that will be
    displayed in the tab control that houses the panel.  If it is \a
    NULL, then the name of the credentials type is used.  Optionally,
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

    Currently, the credentials provider must specify a dialog template
    that will be used to create the embedded dialog for configuring
    new credentials for the type.  This is done by setting the
    khui_new_creds_by_type::h_module, khui_new_creds_by_type::dlg_proc
    and khui_new_creds_by_type::dlg_template fields.

    Following is example code which suggests how this could be done:

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

       // specify the dialog template to use
       t->h_module = my_hInstance;
       t->dlg_proc = my_dialog_procedure;
       t->dlg_template = MAKEINTRESOURCE(IDD_NEW_CREDS);

       if(KHM_FAILED(khui_cw_add_type(c,t))) {
           // handle error
       }
    \endcode

    It is important to note that the ::khui_new_creds_by_type pointer
    that is passed into khui_cw_add_type() points to an allocated
    block of memory which should remain in memory until
    <::KMSG_CRED,::KMSG_CRED_END> message is received.

    For information on how the dialog procedure should be written, see
    \ref cred_acq_dlgproc .

*/

/*! \page cred_acq_dlgproc Writing the dialog procedure for a cred type panel

    Once each credentials provider has had a chance to add a
    credentials type panel for the new credentials dialog, the
    application will attempt to create all the dialog panels.  It will
    use the dialog template and the dialog procedure specified in the
    \c dlg_proc and \c dlg_template members of the
    ::khui_new_creds_by_type structure.

    The credentials type panel will be an ordinary dialog that is
    created as a child of the new credentials window.  Therefore, the
    dialog template should have the WS_CHILD style and the
    WS_EX_CONTROLPARENT extended style set so that the main dialog
    procedure can correctly navigate the child dialog.

    \section cred_acq_dlgmsg Handling Messages

    \subsection cred_acq_dlg_WM_INITDIALOG WM_INITDIALOG

    When the application creates a credentials type panel dialog, it
    passes a pointer to the ::khui_new_creds structure as the \c
    LPARAM parameter.  This can be used to query for the credentials
    type panel for the plug-in, as follows:

    \code

    // Handler for WM_INITDIALOG:
    // HWND hwnd, WPARAM wParam and LPARAM lParam

    khui_new_creds *         nc = NULL;
    khui_new_creds_by_type * nct = NULL;

    // We can define and use a structure like the following to
    // maintain the data that will be used to drive the dialog user
    // interface and to store credentials type settings:
    struct nc_dialog_data *  d = NULL;

    nc = (khui_new_creds *) lParam;

    // Now we can use nc to query for our credentials type structure
    khui_cw_find_type(nc, credtype_id, &nct);

    assert(nct);

    // The dialog data structure should live until we receive
    // WM_DESTROY.
    d = malloc(sizeof(*d));
    ZeroMemory(d, sizeof(*d));

    d->nc = nc;
    d->nct = nct;

    // Store it as our user data for the dialog.
    SetWindowLongPtr(hwnd, DWLP_USER, (LPARAM) d);

    // The aux member of the khui_new_creds_by_type structure is
    // reserved for use by the credentials provider.  We can use it to
    // store our dialog data.  This way, the dialog procedure and the
    // plug-in thread can both access it and use it to store
    // credential options for use when obtaining credentials.  The
    // dialog and the dialog data exist until KMSG_CRED_END is sent.
    nct->aux = (LPARAM) d;

    // We should return FALSE here to indicate that we don't want to
    // set keyboard focus to this dialog yet.  The application will
    // attempt to create all the credentials type panels as well as
    // the other child dialogs used for the new credentials opeartion.
    return FALSE;

    \endcode

    \subsection cred_acq_dlg_WM_NC_NOTIFY WM_NC_NOTIFY

    ::WM_NC_NOTIFY is a special window message that Network Identity
    Manager uses to communicate with credentials type panels.  The
    messages are listed in the ::khui_wm_nc_notifications enumeration.
    The format of the message is as follows:

    - uMsg : KHUI_WM_NC_NOTIFY
    - HIWORD(wParam) : one of ::khui_wm_nc_notifications
    - LPARAM : pointer to the ::khui_new_creds structure (except where noted)

    The ::WM_NC_NOTIFY notifications that a credentials provider is
    expected to handle are the following:

    - ::WMNC_IDENTITY_CHANGE

    \copydoc WMNC_IDENTITY_CHANGE

    - ::WMNC_DIALOG_MOVE

    \copydoc WMNC_DIALOG_MOVE

    - ::WMNC_UPDATE_CREDTEXT

    \copydoc WMNC_UPDATE_CREDTEXT

    - ::WMNC_CREDTEXT_LINK

    \copydoc WMNC_CREDTEXT_LINK

    - ::WMNC_DIALOG_PREPROCESS

    \copydoc WMNC_DIALOG_PREPROCESS

    \section cred_acq_other Other notes

*/

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

#ifndef __KHIMAIRA_KHNEWCRED_H
#define __KHIMAIRA_KHNEWCRED_H

/********************************************************************
  New credentials windows
*********************************************************************/

/*! \addtogroup khui
@{ */

/*! \defgroup khui_cred Credentials acquisition 

    Declarations associated with credentials acquisition.

@{ */

/*! \brief Window message sent to credentials type panels

    This message is sent to the child windows.

    The format of the message is :
    - uMsg : KHUI_WM_NC_NOTIFY
    - HIWORD(wParam) : one of ::khui_wm_nc_notifications
    - LPARAM : pointer to the ::khui_new_creds structure (except where noted)
*/
#define KHUI_WM_NC_NOTIFY (WM_APP + 0x101)

/*! \brief The first control ID that may be used by an identity provider */
#define KHUI_CW_ID_MIN 8016

/*! \brief The maximum number of controls that may be created by an identity provider*/
#define KHUI_CW_MAX_CTRLS 8

/*! \brief The maximum control ID that may be used by an identity provider */
#define KHUI_CW_ID_MAX (KHUI_CW_ID_MIN + KHUI_CW_MAX_CTRLS - 1)


/*! \brief Credentials dialog notifications

    These notifications will be sent to the individual dialog
    procedures of the credential type panels or to the new credentials
    window as a ::KHUI_WM_NC_NOTIFY message.
*/
enum khui_wm_nc_notifications {
    WMNC_DIALOG_EXPAND = 1, 
    /*!< The dialog is switching from basic to advanced mode or vice
      versa.

      In expanded mode, all credentials type panels are visible as
      opposed to the compressed mode where they are not visible.  The
      message is not sent to credentials type panels.

      Only sent to the new credentials window.
    */

    WMNC_DIALOG_SETUP,
    /*!< Sent to the new creds window to notify it that the dialog
      should create all the type configuration panels.
        
      Until this message is issued, none of the credentials type
      panels exist.  The credentials type panels will receive
      WM_INITDIALOG etc as per the normal dialog creation process.

      Only sent to the new credentials window.
    */

    WMNC_DIALOG_ACTIVATE,
    /*!< Sent to the new creds window to notify it that the dialog
      should do final initialization work and activate.

      Only sent to the new credentials window.
    */

    WMNC_DIALOG_MOVE,
    /*!< The new credentials window has moved.

      This message is sent to all the credentials type panels when the
      new credentials window is being moved.  It will be sent
      continuously if the user is dragging the window.  Plug-ins
      rarely need to know their position on the screen.  However, if
      there are any other windows that were created by the plug-in,
      such as floating controls or tooltips, they may need to be
      repositioned in response to this message.

      Sent to all the credentials type panels.
     */

    WMNC_DIALOG_SWITCH_PANEL,
    /*!< Sent to the new creds window to cause it to switch to the
      panel identified by LOWORD(wParam).

      Does nothing if the specified panel is already the current
      panel.  If the dialog is in compact mode and making the
      specified panel visible requires switching to expanded mode, the
      dialog will do so.

      Only sent to the new credentials window.
    */

    WMNC_UPDATE_CREDTEXT,
    /*!< Update the credentials text associated with a panel.

      During the new credentials operation, each plug-in is expected
      to maintain a textual representation of the credentials that the
      plug-in expects to obtain for the selected identity.  It can,
      alternatively, be used to indicate the state of the credentials
      type in respect to the selected identity (for example, whether
      the credentials type is disabled for the identity and why).

      This text is not visible when the new credentials window is in
      basic mode, but it is visible when the window is in advanced
      mode.  The following image shows the expanded new credentials
      window including the credentials text from a several plug-ins:

      \image html new_creds_expanded.png

      Once this message is received, each plug-in should construct its
      credentials text string and store it in the \c credtext member
      of its ::khui_new_creds_by_type structure as shown in the sample
      code below:

      \code
      // Handler for window message WM_NC_NOTIFY with
      // HWND hwnd, WPARAM wParam and LPARAM lParam

      // This structure holds the dialog data for the panel.  We
      // assume it has 'nc' and 'nct' fields that point to the
      // khui_new_creds and khui_new_creds_by_type structures
      // respectively.

      ...
      struct nc_dialog_data * d;
      ...

      // Retrieve the data structure from the dialog user data.
      d = (struct nc_dialog_data *) GetWindowLongPtr(hwnd, DWLP_USER);

      switch (HIWORD(wParam)) {
      case WMNC_UPDATE_CREDTEXT:
        {
          wchar_t buffer[KHUI_MAXCCH_LONG_DESC];
          size_t cb_size;

          // we are being requested to update the credentials text. We
          // already allocated a buffer when we created the nct
          // structure.  So we can just set the text here.

          // The credentials text should reflect the credentials that
          // will be obtained when the new credentials operation
          // completes.

          assert(d && d->nc && d->nct);

          if (d->nct->credtext) {
              free(d->nct->credtext);
              d->nct->credtext = NULL;
          }

          // We only display something if there is a selected identity
          if (d->nc->n_identities > 0) {
            StringCbPrintf(buffer, sizeof(buffer),
                           L"<p>My Credentials<tab>: %s</p>",
                           get_credential_name(d));
            StringCbLength(buffer, sizeof(buffer), &cb_size);
            cb_size += sizeof(wchar_t); // account for the terminating NULL

            d->nct->credtext = malloc(cb_size);
            if (d->nct->credtext) {
               StringCbCopy(d->nct->credtext, cb_size, buffer);
            }
          }

          break;
        }

      ... // Handler other notifications
      }
      \endcode

      The text that is specified as the credentials text is formatted
      hypertext.  For more information about support for formatting
      and hypertext and handling hyperlinks, see \ref khui_htwnd.

      \note When this message is sent to the new credentials window,
      the application will send the ::WMNC_UPDATE_CREDTEXT message to
      all the credential type panels and update the credential text
      window. */

    WMNC_CREDTEXT_LINK,
    /*!< A hyperlink was activated.

      Sent to a panel dialog procedure when a user clicks an embedded
      link in the credentials text that belongs to that panel.  The \a
      lParam parameter of the message is a pointer to a
      ::khui_htwnd_link structure describing the link.

      \see \ref khui_htwnd

      \note The \a lParam parameter does not point to a
      ::khui_new_creds structure for this message.
    */

    WMNC_IDENTITY_CHANGE,
    /*!< The primary identity has changed.

      The ::khui_new_creds structure contains a list of identities to
      which the current operation should be applied.  In its current
      implementation, only the first identity in this list is used.
      Therefore, the list will contain at most one identity.  It is
      possible for the list to be empty (for example, if the user
      hasn't selected an identity yet).

      When handling this notification, the plug-in should check the \c
      n_identities member of the ::khui_new_creds structure to see
      whether there are any identities selected.  This value would be
      either zero or one.  If it is non-zero, then a handle to the
      selected identity will be in \c khui_new_creds::identities[0].

      Plug-ins typically use this notfication to load identity
      specific settings when a new identity is selected.

      This notification is sent to all the credentials type panels.
     */

    WMNC_CLEAR_PROMPTS,
    /*!< Sent to the new creds window to clear any custom prompts.

      Only sent to the new credentials window.
     */

    WMNC_SET_PROMPTS,
    /*!< Sent to the new creds window to set custom prompts.

      Only sent to the new credentials window. */
    
    WMNC_DIALOG_PREPROCESS,
    /*!< The credentials acquisition process is about to start.

      Sent to all the credentials type panels to notify them that the
      credentials acquisition process will start.  Once all plug-ins
      have handled the notification, the application will start
      sending out <::KMSG_CRED, ::KMSG_CRED_PROCESS> messages to the
      credentials providers which are participating in the new
      credentials operation.
    */

    WMNC_DIALOG_PROCESS,
    /*!< This notification is no longer used. */
#pragma deprecated(WMNC_DIALOG_PROCESS)

    WMNC_DIALOG_PROCESS_COMPLETE,
    /*!< Sent to the new creds window to indicate that the all the
      threads have completed processing.*/

    WMNC_TYPE_STATE,
    /*!< Sent to the new creds window as notification that a
      particular credentials type has changed state from enabled to
      disabled or vice versa.  The LPARAM member of the message
      specifies the credentials type identifier for the changed
      type */

    WMNC_ADD_CONTROL_ROW,
    /*!< Add a row of controls to a new cred dialog.  This is an
      internal message. */

    WMNC_UPDATE_LAYOUT,
    /*!< Update the layout of a dialog or window.  This is an internal
      message. */
};

/*! \brief Plugins can use WMNC_NOTIFY message codes from here on up

    \see ::KHUI_WM_NC_NOTIFY
 */
#define WMNC_USER 2048

/*! \brief Notifications to the identity provider

    These notifications are sent through to the identity provider's UI
    callback that was obtained using a ::KMSG_IDENT_GET_UI_CB message.

    The callback routine is called from the context of the UI thread
    and is expected to not make any blocking calls.  One of the
    following commands will be passed in as the \a cmd parameter to
    the callback.
 */
enum khui_wm_nc_ident_notify {
    WMNC_IDENT_INIT,            
    /*!< Initialize an identity selector for a new credentials
         dialog. The \a lParam parameter contains a handle to the
         dialog window which will contain the identity selector
         controls.  The identity provider may make use of the \a
         ident_aux field of the ::khui_new_creds structure to hold any
         data pertaining to the credentials acquisition dialog.*/

    WMNC_IDENT_WMSG,
    /*!< Windows message.  Presumably sent from one of the controls
         that was created by the identity provider.  The callback is
         expected to return TRUE if it processed the message or FALSE
         if it did not.  The \a uMsg, \a wParam and \a lParam
         parameters are set to the values passed in by Windows. */

    WMNC_IDENT_EXIT,
    /*!< Terminate a credentials acquisition dialog. Sent just before
      the dialog is terminated. */

    WMNC_IDENT_PREPROCESS,
    /*!< The identity is about to be fetched from the \a
       ::khui_new_creds structure.  The callback is expected to ensure
       that the primary identity listed in that structure is
       consistent with the user selection. */
};

/*! \name Standard credtext link IDs
@{*/

/*! \brief Switch the panel
    
    The \a id attribute of the link specifies the ordinal of the panel
    to switch to.
*/
#define CTLINKID_SWITCH_PANEL L"SwitchPanel"

/*@}*/

/*forward dcl*/
struct tag_khui_new_creds_by_type;
typedef struct tag_khui_new_creds_by_type khui_new_creds_by_type;
struct tag_khui_new_creds_prompt;
typedef struct tag_khui_new_creds_prompt khui_new_creds_prompt;
struct tag_khui_new_creds;
typedef struct tag_khui_new_creds khui_new_creds;

typedef LRESULT
(KHMAPI *khui_ident_new_creds_cb)(khui_new_creds * nc,
                                  UINT cmd,
                                  HWND hwnd,
                                  UINT uMsg,
                                  WPARAM wParam,
                                  LPARAM lParam);

/*! \brief New credentials acquisition blob

    A pointer to an object of this type is passed in along with the
    credentials acquisition messages.

    \see \ref cred_acq for more information
*/
typedef struct tag_khui_new_creds {
    khm_int32   magic;          /*!< Internal use */

    khm_int32   subtype;        /*!< Subtype of the request that is
                                  being handled through this object.
                                  One of ::KMSG_CRED_NEW_CREDS,
                                  ::KMSG_CRED_RENEW_CREDS or
                                  ::KMSG_CRED_PASSWORD */

    CRITICAL_SECTION cs;        /*!< Internal use */

    khm_boolean set_default;    /*!< After a successfull credentials
                                  acquisition, set the primary
                                  identity as the default. */

    khm_handle  *identities;    /*!< The list of identities associated
                                  with this request.  The first
                                  identity in this list (\a
                                  identities[0]) is the primary
                                  identity. */

    khm_size    n_identities;   /*!< Number of identities in the list
                                  \a identities */

    khm_size    nc_identities;  /*!< Internal use */

    khui_action_context ctx;    /*!< An action context specifying the
                                  context in which the credentials
                                  acquisition operation was
                                  launced. */

    khm_int32   mode;           /*!< The mode of the user interface.
                                  One of ::KHUI_NC_MODE_MINI or
                                  ::KHUI_NC_MODE_EXPANDED. */

    HWND        hwnd;           /*!< Handle to the new credentials
                                  window. */

    struct tag_khui_new_creds_by_type **types;
                                /*!< Internal use */
    khm_handle  *type_subs;     /*!< Internal use */
    khm_size    n_types;        /*!< Internal use */
    khm_size    nc_types;       /*!< Internal use */

    khm_int32   result;     /*!< One of ::KHUI_NC_RESULT_CANCEL or
                                ::KHUI_NC_RESULT_PROCESS indicating
                                the result of the dialog with the
                                user */

    khm_int32   response;   /*!< Response.  See individual message
                                documentation for info on what to do
                                with this field */

    wchar_t     *password;  /*!< Not used. */

    /* UI stuff */

    wchar_t     *banner;        /*!< Internal use */
    wchar_t     *pname;         /*!< Internal use */
    khm_size    n_prompts;      /*!< Internal use */
    khm_size    nc_prompts;     /*!< Internal use */
    struct tag_khui_new_creds_prompt ** prompts; /*!< Internal use */

    khui_ident_new_creds_cb ident_cb; /*!< Internal use */

    wchar_t     *window_title;  /*!< Internal use */

    LPARAM      ident_aux;      /*!< Auxilliary field which is
                                  reserved for use by the identity
                                  provider during the course of
                                  conducting this dialog. */

} khui_new_creds;

#define KHUI_NC_MAGIC 0x84270427

/*!\name Result values for khui_new_creds_t::result
  @{*/
#define KHUI_NC_RESULT_PROCESS    0
#define KHUI_NC_RESULT_CANCEL       1
/*@}*/

/*!\name Mode values for khui_new_creds_t::mode
  @{*/
#define KHUI_NC_MODE_MINI       0
#define KHUI_NC_MODE_EXPANDED   1
/*@}*/

/*!\name Response values for khui_new_creds_t::response
  @{*/
/*!\brief No known response */
#define KHUI_NC_RESPONSE_NONE     0

/*!\brief It is okay to exit the dialog now 

    This is the default, which is why it has a value of zero.  In
    order to prevent the dialog from exiting, set the
    KHUI_NC_RESPONSE_NOEXIT response bit. */
#define KHUI_NC_RESPONSE_EXIT     0

/*!\brief It is NOT okay to exit the dialog now

    Used to indicate that further user-interaction is necessary to
    process the dialog.  Usually this is accompanied by setting
    necessary custom prompts and notifications so the user knows why
    the dialog is prompting for more information.
 */
#define KHUI_NC_RESPONSE_NOEXIT    0x00000002

/*!\brief The dialog was processed successfully

    Since this is the default response, the value is zero.  Use one of
    KHUI_NC_RESPONSE_FAILED or KHUI_NC_RESPONSE_PENDING to indicate an
    error or pending status.
 */
#define KHUI_NC_RESPONSE_SUCCESS  0

/*!\brief The processing of the dialog failed

    Self explanatory.  More information about the failure should have
    been reported using the khlog API, however, this response value
    indicates to other credential types that depend on this credential
    type that whatever it was that this credential type was supposed
    to do didn't happen.
*/
#define KHUI_NC_RESPONSE_FAILED    0x00000008

/*!\brief Further interaction required

    Set along with KHUI_NC_RESPONSE_NOEXIT although it is not
    required.  Setting this bit will automatically add the
    KHUI_NC_RESPONSE_NOEXIT.

    If this bit is set, all dependent plugins will be set on hold
    until another round of processing clears the pending bit.
 */
#define KHUI_NC_RESPONSE_PENDING   0x00000010

/*! \brief Completed

    This is automatically set if the plugin sets a response which does
    not indicate either KHUI_NC_RESPONSE_NOEXIT or
    KHUI_NC_RESPONSE_PENDING, which is considered to mean that the
    plugin is completed processing.

    This flag cannot be explicitly specified in a response.
 */
#define KHUI_NC_RESPONSE_COMPLETED 0x00000020

/*! \brief Processing

    This is an internal flag set while the credentials acquisition
    process is executing.
 */
#define KHUI_NC_RESPONSE_PROCESSING 0x00010000

#define KHUI_NCMASK_RESPONSE (KHUI_NC_RESPONSE_EXIT|KHUI_NC_RESPONSE_NOEXIT)
#define KHUI_NCMASK_RESULT  (KHUI_NC_RESPONSE_SUCCESS|KHUI_NC_RESPONSE_FAILED|KHUI_NC_RESPONSE_PENDING)
/*@}*/

/*!\brief Maximum number of dependencies for a credentials type */
#define KHUI_MAX_TYPE_DEPS 8

/*!\brief Maximum number of credential types for a new creds window */
#define KHUI_MAX_NCTYPES 16

/*!\brief Maximum number of characters in a password

  Length includes the termininating NULL
*/
#define KHUI_MAXCCH_PASSWORD 512

/*! \brief Maximum number of bytes in a password

  Includes terminating NULL
*/
#define KHUI_MAXCB_PASSWORD (KHUI_MAXCCH_PASSWORD * sizeof(wchar_t))

/*! \brief Maximum number of characters in a custom banner

    Length includes terminating NULL
*/
#define KHUI_MAXCCH_BANNER 256


/*! \brief Maximum number of bytes in a custom banner

    Length includes terminating NULL
*/
#define KHUI_MAXCB_BANNER (KHUI_MAXCCH_BANNER * sizeof(wchar_t))

/*! \brief Maximum number of characters in a panel name

    Length includes terminating NULL
*/
#define KHUI_MAXCCH_PNAME 256

/*! \brief Maximum number of bytes in a panel name

    Length includes terminating NULL
*/
#define KHUI_MAXCB_PNAME (KHUI_MAXCCH_PNAME * sizeof(wchar_t))

/*! \brief A descriptor of a panel in the new credentials acquisition tab

    When processing certain credentials messages such as
    ::KMSG_CRED_PASSWORD, ::KMSG_CRED_NEW_CREDS,
    ::KMSG_CRED_RENEW_CREDS, a pointer to a ::khui_new_creds structure
    will be passed in to the message handler.  If the handler of the
    message needs to add one or more credentials types as participants
    of the operation, the handler will need to call khui_cw_add_type()
    and specify a ::khui_new_creds_by_type structure.

    Note that the memory address passed in to the call to
    khui_cw_add_type() will not be copied.  Therefore, the block of
    memory should remain as-is for the lifetime of the
    ::khui_new_creds structure or until it is removed with a call to
    khui_cw_del_type().

    Some of the credentials messages that require specifying a
    ::khui_new_creds_by_type structure require providing a
    user-interface.  In these cases, the fields marked for providing a
    UI may be required to hold valid values.  If the message does not
    require providing a UI, these fields will be ignored.
*/
typedef struct tag_khui_new_creds_by_type {
    khui_new_creds * nc;        /*!< Internal use.  Do not set */
    khm_int32   flags;          /*!< Internal use.  Do not set */

    khm_int32   type;           /*!< The identifier of the credentials
                                  type.  This is a credentials type
                                  identifier allocated with a call to
                                  kcdb_credtype_register(). */

    khm_int32   type_deps[KHUI_MAX_TYPE_DEPS];
                                /*!< credentials types that this
                                    credential type depends on.  Each
                                    element defines a credentials type
                                    identifier that this type depends
                                    on for this operation.  The number
                                    of valid values in this array
                                    should be specified in the \a
                                    n_type_deps field. */

    khm_size    n_type_deps;    /*!< Number of dependencies listed
                                  above.  Should be between 0 and
                                  ::KHUI_MAX_TYPE_DEPS.  Specify 0 if
                                  there are no dependencies. */

    khm_size    ordinal;        /*!< The requested ordinal.  The UI
                                  would attempt to place this panel at
                                  the reqested order in the list of
                                  panels.  Set to -1 if the order does
                                  not matter.  Once the dialog is
                                  activated this field will be updated
                                  to reflect the actual ordinal of the
                                  panel. */

    wchar_t    *name;           /*!< Name of the panel (localized,
                                  optional).  If NULL, the localized
                                  name of the credentials type is
                                  used. Only used if providing a
                                  user-interface. */

    HICON       icon;           /*!< Icon for the panel (optional).
                                  Only used if providing a
                                  user-interface. */

    wchar_t    *tooltip;        /*!< Tooltip for the panel (localized,
                                  optional).  If NULL, no tooltip will
                                  be assigned for the panel.  Only
                                  used if providing a
                                  user-interface.  */

    HMODULE     h_module;       /*!< Handle to the module containing
                                  the dialog resource.  Only used if
                                  providing a user-interface. */

    LPWSTR      dlg_template;   /*!< The dialog resource.  Only used
                                  if providing a user-interface. */
    DLGPROC     dlg_proc;       /*!< The dialog procedure. Only used
                                  if providing a user-interface. */

    HWND        hwnd_panel;     /*!< The dialog window.  Once the
                                  dialog panel is created, a handle to
                                  the panel will be assigned here.
                                  Note that the handle is assigned
                                  after a successful call to
                                  CreateDialogParam and hence would
                                  not be available when handling the
                                  WM_INITDIALOG message from the
                                  dialog procedure.  Only used of
                                  providing a user-interface. */

    HWND        hwnd_tc;        /*!< Internal use. Do not set */

    wchar_t    *credtext;       /*!< A brief description of the
                                  current state of this cred
                                  type. (localized, optional).  Only
                                  used if providing a
                                  user-interface. If this field is
                                  non-NULL, then it should point to a
                                  NULL terminated string that does not
                                  exceed ::KHUI_MAXCCH_LONG_DESC
                                  characters in length including the
                                  terminating NULL.

                                  \see \ref khui_htwnd for information
                                  on how to format the string for this
                                  field.
                                */

    LPARAM      aux;            /*!< auxilliary field.  For use by the
                                  plug-in. */
} khui_new_creds_by_type;

/*!\name Flags for khui_new_creds_by_type

    Note that KHUI_NC_RESPONSE_SUCCESS, KHUI_NC_RESPONSE_FAILED,
    KHUI_NC_RESPONSE_PENDING are also stored in the flags. 

@{*/
#define KHUI_NCT_FLAG_PROCESSED 1024
#define KHUI_NCT_FLAG_DISABLED  2048
/*@}*/

/*! \brief Width of a new creds dialog panel in dialog units*/
#define NCDLG_WIDTH     300
/*! \brief Height of a new creds dialog panel in dialog units*/
#define NCDLG_HEIGHT    166

/*! \brief A custom prompt */
typedef struct tag_khui_new_creds_prompt {
    khm_size    index;          /*!< Set to the zero based index
                                  of this prompt. */

    khm_int32   type;           /*!< one of KHUI_NCPROMPT_TYPE_* */
    wchar_t *   prompt;         /*!< prompt string. Cannot exceed
                                  KHUI_MAXCCH_PROMPT */
    wchar_t *   def;            /*!< default value. Cannot exceed
                                  KHUI_MAXCCH_PROMPT_VALUE */
    wchar_t *   value;          /*!< On completion, this is set to the
                                  value that the user entered. Will
                                  not exceed
                                  KHUI_MAXCCH_PROMPT_VALUE */

    khm_int32   flags;          /*!< Combination of
                                  KHUI_NCPROMPT_FLAG_* */

    HWND        hwnd_static;    /* internal use */
    HWND        hwnd_edit;      /* internal use */
} khui_new_creds_prompt;

/*! \brief The prompt input is hidden

    The input is hidden for prompts which accept passwords.  The
    control which represents the input will display an asterisk or a
    small circle corresponding to each character typed in, but will
    not show the actual character.
 */
#define KHUI_NCPROMPT_FLAG_HIDDEN   1

/*! \brief Internal use */
#define KHUI_NCPROMPT_FLAG_STOCK    2

/*! \brief Maximum number of characters in a prompt

    Refers to the prompt text that accompanies an input control.  THe
    length includes the terminating NULL.
 */
#define KHUI_MAXCCH_PROMPT 256

/*! \brief Maximum number of bytes in a prompt

    Refers to the prompt text that accompanies an input control.  THe
    length includes the terminating NULL.
 */
#define KHUI_MAXCB_PROMPT (KHUI_MAXCCH_PROMPT * sizeof(wchar_t))

/*! \brief Maximum number of characters that can be entered in an input control

    Refers to the input control of a prompt.  The length includes the
    terminating NULL.
 */
#define KHUI_MAXCCH_PROMPT_VALUE 256

/*! \brief Maximum number of bytes that can be entered in an input control

    Refers to the input control of a prompt.  The length includes the
    terminating NULL.
 */
#define KHUI_MAXCB_PROMPT_VALUE (KHUI_MAXCCH_PROMPT_VALUE * sizeof(wchar_t))

/* from krb5.h.  Redefining here because we don't want to depend on
   krb5.h for all credential types */

/*! \brief A password control */
#define KHUI_NCPROMPT_TYPE_PASSWORD             1

/*! \brief New password control

    Used when changing the password
 */
#define KHUI_NCPROMPT_TYPE_NEW_PASSWORD         2

/*! \brief New password again control

    Used when changing the password
 */
#define KHUI_NCPROMPT_TYPE_NEW_PASSWORD_AGAIN   3

/*! \brief Preauthentication (reserved) */
#define KHUI_NCPROMPT_TYPE_PREAUTH              4

/*! \brief Control sizes */
typedef enum tag_khui_control_size {
    KHUI_CTRLSIZE_SMALL,
    /*!< A small control fits in about 1/5 the width of the new
      credentials panel */
    KHUI_CTRLSIZE_HALF,
    /*!< Half size controls fit in 1/2 the width of the new
      credentials panel */
    KHUI_CTRLSIZE_FULL,
    /*!< Takes up the whole width of the crednetials panel */
} khui_control_size;

/*! \brief Internal use */
typedef struct tag_khui_control_row {
    HWND label;
    HWND input;
    khui_control_size size;
} khui_control_row;

/*! \brief Create a ::khui_new_creds object

    Creates and initializes a ::khui_new_creds object.  The created
    object must be destroyed using the khui_cw_destroy_cred_blob()
    function.

    \note Plugins should not call this function directly.  The
         necessary ::khui_new_creds objects will be created by
         NetIDMgr.

    \see khui_cw_destroy_cred_blob()
 */
KHMEXP khm_int32 KHMAPI 
khui_cw_create_cred_blob(khui_new_creds ** c);

/*! \brief Destroy a ::khui_new_creds object

    Destroys a ::khui_new_creds object that was fomerly created using
    a call to khui_cw_create_cred_blob().

    \note Plugins should not call this function directly.  The
         necessary ::khui_new_creds objects will be created by
         NetIDMgr.

    \see khui_cw_create_cred_blob()
*/
KHMEXP khm_int32 KHMAPI 
khui_cw_destroy_cred_blob(khui_new_creds *c);

/*! \brief Lock the new_creds object

    When a plugin is accessing the fields of a ::khui_new_creds
    object, it must first obtain a lock on the object so that other
    threads will not modify the fields at the same time.  Locking the
    object ensures that the fields of the object will be consistent.

    Use khui_cw_unlock_nc() to undo the lock obtained through a call
    to khui_cw_lock_nc().

    It is not necessary to lock a new credentials object when
    modifying it using the NetIDMgr API.
 */
KHMEXP khm_int32 KHMAPI 
khui_cw_lock_nc(khui_new_creds * c);

/*! \brief Unlock a new_creds object

    \see khui_cw_lock_nc()
 */
KHMEXP khm_int32 KHMAPI 
khui_cw_unlock_nc(khui_new_creds * c);

/*! \brief Add a new panel to a new credentials acquisition window 

    See the description of ::khui_new_cred_panel for information on
    how to populate it to describe a credentials type panel.

    Note that the structure pointed to by \a t is added by reference.
    The memory pointed to by \a t is not copied.  Hence, the block of
    memory and any other blocks pointed to by the
    ::khui_new_creds_by_type structure located there should remain
    intact for the lifetime of the ::khui_new_creds structure pointed
    to by \a c or until the credentials type panel is removed from the
    ::khui_new_creds structure with a call to khui_cw_del_type().

    Generally, a plug-in that calls this function should allocate a
    block of memory to contain the ::khui_new_creds_by_type structure,
    fill it in and then pass in the address in a call to
    khui_cw_add_type() while handling a ::KMSG_CRED_PASSWORD,
    ::KMSG_CRED_NEW_CREDS or ::KMSG_CRED_RENEW_CREDS message.  Then
    the plug-in should remove the reference with a call to
    khui_cw_del_type() while processing ::KMSG_CRED_END.

    \see khui_cw_del_type()
    \see \ref cred_acq_panel_spec
    \see ::khui_new_cred_panel
    \see ::khui_new_creds
*/
KHMEXP khm_int32 KHMAPI 
khui_cw_add_type(khui_new_creds * c, 
                 khui_new_creds_by_type * t);

/*! \brief Remove a panel from a new credentials acquisition window

    \see khui_cw_add_type()
 */
KHMEXP khm_int32 KHMAPI 
khui_cw_del_type(khui_new_creds * c, 
                 khm_int32 type);

/*! \brief Find the panel belonging to a particular credentials type

    This panel would have been added to the new credentials window
    using khui_cw_add_type().

    \see khui_cw_add_type()
 */
KHMEXP khm_int32 KHMAPI 
khui_cw_find_type(khui_new_creds * c, 
                  khm_int32 type, 
                  khui_new_creds_by_type **t);

/*! \brief Enable/disable a particular credentials type

    Enables or disables the panel associated with a particular
    credentials type.  Does not preclude the credentials type from
    participating in the new credentials acquisition.  However, the
    user will be prevented from interacting with the specific panel.
 */
KHMEXP khm_int32 KHMAPI 
khui_cw_enable_type(khui_new_creds * c,
                    khm_int32 type,
                    khm_boolean enable);

/*! \brief Set the primary identity in a new credentials acuisition

    The primary identity dictates many of the defaults and the
    semantics associated with the credentials acquision process.
    Setting the primary identity also triggers the
    ::WMNC_IDENTITY_CHANGE notification which will be sent to all the
    credentials type panels.

    Has no effect if the primary identity is already the same as the
    one specified in \a id.  Specify NULL for \a id if the current
    primary identity is to be cleared.

    If the primary identity is changed, then all the additional
    identities associated with the new credentials acquisition dialog
    will also be discarded.
 */
KHMEXP khm_int32 KHMAPI 
khui_cw_set_primary_id(khui_new_creds * c, 
                       khm_handle id);

/*! \brief Add an additional identity to the new credentials acquisition

    Individual plugins are free to decide how to handle additional
    identities.  Generally, they would attempt to obtain credentials
    for the primary and additional identities, but would not consider
    it an error if an additional identity failed to obtain
    credentials.

    Calling this function with \a id of NULL does nothing.
*/
KHMEXP khm_int32 KHMAPI 
khui_cw_add_identity(khui_new_creds * c, 
                     khm_handle id);

/*! \brief Clear all custom prompts

    Removes all the custom prompts from the new credentials dialog.
 */
KHMEXP khm_int32 KHMAPI 
khui_cw_clear_prompts(khui_new_creds * c);

/*! \brief Synchronize custom prompt values

    It is important to synchronize the values before accessing their
    values.  The controls associated with custom prompts update the
    values in the ::khui_new_creds object periodically.  However, the
    values may lose sync intermittently.
 */
KHMEXP khm_int32 KHMAPI 
khui_cw_sync_prompt_values(khui_new_creds * c);

/*! \brief Begin custom prompting

    Begins the process of defining custom prompts.  Implicity removes
    all the custom prompts that are currently being displayed.  The \a
    banner and \a name will be displayed in separate controls above
    the set of new custom prompts.

    The controls associated with the prompts will not actually be
    created until all the prompts have been added using
    khui_cw_add_prompt().  The number of promtps that can be added
    will be exactly \a n_prompts.
 */
KHMEXP khm_int32 KHMAPI 
khui_cw_begin_custom_prompts(khui_new_creds * c, 
                             khm_size n_prompts, 
                             wchar_t * banner, 
                             wchar_t * name);

/*! \brief Add a custom prompt

    After khui_cw_begin_custom_prompts() is called, the plugin should
    call khui_cw_add_prompt() to add the actual prompts.  The number
    of prompts that can be added is the \a n_prompts value specified
    in the earlier call to \a khui_cw_begin_custom_prompts().

    Once \a n_prompts prompts have been added, the new prompts will
    automatically be created and shown in the user interface.
    However, if less than that prompts are added, nothing is displayed
    to the user.

    \param[in] c Pointer to ::khui_new_creds structure

    \param[in] type Type of prompt.  One of
        ::KHUI_NCPROMPT_TYPE_PREAUTH, ::KHUI_NCPROMPT_TYPE_PASSWORD,
        ::KHUI_NCPROMPT_TYPE_NEW_PASSWORD,
        ::KHUI_NCPROMPT_TYPE_NEW_PASSWORD_AGAIN

    \param[in] prompt Text of the prompt.  Constrained by
        ::KHUI_MAXCCH_PROMPT. (Localized, required)

    \param[in] def Default value.  (optional).  Constrained by
        ::KHUI_MAXCCH_PROMPT_VALUE.  Set to NULL if not provided.

    \param[in] flags Flags.  Combination of
        ::KHUI_NCPROMPT_FLAG_HIDDEN
 */
KHMEXP khm_int32 KHMAPI 
khui_cw_add_prompt(khui_new_creds * c, 
                   khm_int32 type, 
                   wchar_t * prompt, 
                   wchar_t * def, 
                   khm_int32 flags);

/*! \brief Retrieve a custom prompt

    Retrieves an individual prompt.  The \a idx parameter is a
    zero-based index of the prompt to retrieve.  The ordering is the
    same as the order in which khui_cw_add_prompt() was called.
 */
KHMEXP khm_int32 KHMAPI 
khui_cw_get_prompt(khui_new_creds * c, 
                   khm_size idx, 
                   khui_new_creds_prompt ** prompt);

/*! \brief Get the number of custom prompts

    Retrieves the number of custom prompts currently displayed.  If
    this function is called between calling
    khui_cw_begin_custom_prompts() and adding all the prompts, the
    number returned will be the number of prompts that is expected to
    be registered (i.e. the \a n_prompts parameter passed to
    khui_cw_begin_custom_prompts()).
 */
KHMEXP khm_int32 KHMAPI 
khui_cw_get_prompt_count(khui_new_creds * c,
                         khm_size * np);


/*! \brief Get the value of a custom prompt

    Retrieve the value of a specific prompt.  The value is the string
    that was typed into the input control associated with a custom
    prompt.  The \a idx parameter is the zero-based index of the
    prompt from which to retrieve the value from.  The ordering is the
    same as the order in which khui_cw_add_prompt() was called.

    It is important to call khui_cw_sync_prompt_values() before
    starting to call khui_cw_get_prompt_value() so that the values
    returned are up-to-date.
 */
KHMEXP khm_int32 KHMAPI 
khui_cw_get_prompt_value(khui_new_creds * c, 
                         khm_size idx, 
                         wchar_t * buf, 
                         khm_size *cbbuf);

/*! \brief Set the response for a plugin

    When handling ::KMSG_CRED_DIALOG_PROCESS from within the plugin
    thread, it is important to set the response by calling this
    function.  The response can be used to signal whether the plugin
    successfully obtained credentials or whether further interaction
    is required, or the credentials acquisition failed.

    The response is a combination of :
    - ::KHUI_NC_RESPONSE_PENDING
    - ::KHUI_NC_RESPONSE_FAILED
    - ::KHUI_NC_RESPONSE_PENDING
    - ::KHUI_NC_RESPONSE_SUCCESS
    - ::KHUI_NC_RESPONSE_NOEXIT
    - ::KHUI_NC_RESPONSE_EXIT
 */
KHMEXP khm_int32 KHMAPI 
khui_cw_set_response(khui_new_creds * c,
                     khm_int32 type,
                     khm_int32 response);

/*! \brief Check whether a specified credential type panel succeeded

    This is called during the processing of ::KMSG_CRED_DIALOG_PROCESS
    to determine whether a specified credential type succeeded in
    obtaining credentials.  The credential type that is being queried
    should have also been listed as a dependency when adding the
    current credentials type, otherwise the type queried may not have
    been invoked yet.

    \return TRUE iff the queried type has reported that it successfully
        completed the credentials acquision operation.
 */
KHMEXP khm_boolean KHMAPI 
khui_cw_type_succeeded(khui_new_creds * c,
                       khm_int32 type);

/*! \brief Add a row of controls to the identity specifier area

    Only for use by identity provider callbacks that wish to add an
    identity selector control.  A row of controls consist of a label
    control and some input control.

    When the ::WMNC_IDENT_INIT message is sent to the identity
    provider, it receives a handle to the dialog panel in the \a
    lParam parameter which should be the parent window of both the
    windows specified here.  The control ID for any controls created
    must fall within the ::KHUI_CW_ID_MIN and ::KHUI_CW_ID_MAX range.

    Both controls will be resized to fit in the row.

    If \a long_label is TRUE then the size of the label will be larger
    than normal and will accomodate more text.
 */
KHMEXP khm_int32 KHMAPI
khui_cw_add_control_row(khui_new_creds * c,
                        HWND label,
                        HWND input,
                        khui_control_size size);

/*!@}*/ /* Credentials acquisition */
/*!@}*/

#endif

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

#ifndef __KHIMAIRA_KHALERTS_H
#define __KHIMAIRA_KHALERTS_H

/*********************************************************************
  Alerter and error reporting
**********************************************************************/

/*! \addtogroup khui
@{ */

/*!\defgroup khui_alert Alerter and Error Reporting
@{*/

struct tag_khui_alert;
typedef struct tag_khui_alert khui_alert;

#define KHUI_MAX_ALERT_COMMANDS  4

/*! \brief Maximum number of characters in title including terminating NULL
 */
#define KHUI_MAXCCH_TITLE 256

/*! \brief Maximum number of bytes in title including terminating NULL
 */
#define KHUI_MAXCB_TITLE (KHUI_MAXCCH_TITLE * sizeof(wchar_t))

/*! \brief Maximum number of characters in message including terminating NULL
 */
#define KHUI_MAXCCH_MESSAGE 1024

/*! \brief Maximum number of bytes in message including terminating NULL
 */
#define KHUI_MAXCB_MESSAGE (KHUI_MAXCCH_MESSAGE * sizeof(wchar_t))

/*! \brief Maxumum number of characters in a suggestion including terminating NULL */
#define KHUI_MAXCCH_SUGGESTION 1024

/*! \brief Maximum number of bytes in a suggestion, including terminating NULL */
#define KHUI_MAXCB_SUGGESTION (KHUI_MAXCCH_SUGGESTION * sizeof(wchar_t))

/*! \brief Flags for an alert */
enum khui_alert_flags {
    KHUI_ALERT_FLAG_FREE_STRUCT     =0x00000001, 
    /*!< Internal. Free the structure once the alert is done. */

    KHUI_ALERT_FLAG_FREE_TITLE      =0x00000002,
    /*!< Internal. Free the \a title field when the alert is done.*/

    KHUI_ALERT_FLAG_FREE_MESSAGE    =0x00000004,
    /*!< Internal. Free the \a message field when the alert is done. */

    KHUI_ALERT_FLAG_FREE_SUGGEST    =0x00000008,
    /*!< Internal. Free the \a suggest field when the alert is done */

    KHUI_ALERT_FLAG_DEFACTION       =0x00000010,
    /*!< If the message is displayed as a balloon prompt, then perform
      the default action when it is clicked.  The default action is
      the first action added to the alert.  Cannot be used if there
      are no actions or if ::KHUI_ALERT_FLAG_REQUEST_WINDOW is
      specified.*/

    KHUI_ALERT_FLAG_DISPATCH_CMD    =0x00000020,
    /*!< If the message has commands, when the user clicks on one of
      the command buttons, the corresponding command will be
      immediately dispatched as if khui_action_trigger() is called
      with a NULL UI context.  Otherwise, the selected command will be
      stored in the alert and can be retrieved via a call to
      khui_alert_get_response(). */

    KHUI_ALERT_FLAG_VALID_TARGET    =0x00010000,
    /*!< Internal. There is a valid target for the alert */

    KHUI_ALERT_FLAG_VALID_ERROR     =0x00020000,
    /*!< Internal. There is a valid error context associated with the alert */

    KHUI_ALERT_FLAG_DISPLAY_WINDOW  =0x01000000,
    /*!< The alert has been displayed in a window */

    KHUI_ALERT_FLAG_DISPLAY_BALLOON =0x02000000,
    /*!< The alert has been displayed in a ballon */

    KHUI_ALERT_FLAG_REQUEST_WINDOW  =0x04000000,
    /*!< The alert should be displayed in a window */

    KHUI_ALERT_FLAG_REQUEST_BALLOON =0x08000000,
    /*!< The alert should be displayed in a balloon */

    KHUI_ALERT_FLAG_MODAL           =0x10000000,
    /*!< Internal. Modal alert.  Do not set direclty. */

    KHUI_ALERT_FLAGMASK_RDWR        =0x0C000030,
    /*!< Bit mask of flags that can be set by khui_alert_set_flags() */
};

/*! \brief Alert types

    These types can be set with khui_alert_set_type() to indicate
    which type of alert this is.  The types defined here are
    identified by the Network Identity Manager and will receive
    special handling whereever appropriate.

    The type is a hint to the application and will not guarantee a
    particular behavior.
 */
typedef enum tag_khui_alert_types {
    KHUI_ALERTTYPE_NONE = 0,    /*!< No specific alert type */
    KHUI_ALERTTYPE_PLUGIN,      /*!< Plug-in or module load related
                                  alert */
    KHUI_ALERTTYPE_EXPIRE,      /*!< Credential or identity expiration
                                  warning */
    KHUI_ALERTTYPE_RENEWFAIL,   /*!< Failed to renew credentials */
    KHUI_ALERTTYPE_ACQUIREFAIL, /*!< Failed to acquire credentials */
    KHUI_ALERTTYPE_CHPW,        /*!< Failed to change password */
} khui_alert_type;

/*! \brief Create an empty alert object

    The returned result is a held pointer to a ::khui_alert object.
    Use khui_alert_release() to release the object.
 */
KHMEXP khm_int32 KHMAPI 
khui_alert_create_empty(khui_alert ** result);

/*! \brief Create a simple alert object

    The returned result is a held pointer to a ::khui_alert object.
    Use khui_alert_release() to release the object.

    \param[in] title The title of the alert. (Required, Localized)
        Limited by ::KHUI_MAXCCH_TITLE.

    \param[in] message The message.  (Required. Localized).  Limited
        by ::KHUI_MAXCCH_MESSAGE.

    \param[in] severity One of ::tag_kherr_severity

    \param[out] result Receives a held pointer to a ::khui_alert
        object upon successful completion.
 */
KHMEXP khm_int32 KHMAPI 
khui_alert_create_simple(const wchar_t * title, 
                         const wchar_t * message, 
                         khm_int32 severity, 
                         khui_alert ** result);

/*! \brief Set the title of an alert object

    The title is limited by ::KHUI_MAXCCH_TITLE.
 */
KHMEXP khm_int32 KHMAPI 
khui_alert_set_title(khui_alert * alert, 
                     const wchar_t * title);

/*! \brief Set the message of an alert object

    The message is limited by ::KHUI_MAXCCH_MESSAGE.
 */
KHMEXP khm_int32 KHMAPI 
khui_alert_set_message(khui_alert * alert, 
                       const wchar_t * message);

/*! \brief Set the suggestion of an alert object 

    The suggestion is limited by ::KHUI_MAXCCH_SUGGESTION
 */
KHMEXP khm_int32 KHMAPI 
khui_alert_set_suggestion(khui_alert * alert,
                          const wchar_t * suggestion);

/*! \brief Set the severity of the alert object

    The severity value is one of ::tag_kherr_severity
 */
KHMEXP khm_int32 KHMAPI 
khui_alert_set_severity(khui_alert * alert, 
                        khm_int32 severity);

/*! \brief Sets the flags of the alert

    The flags are as defined in ::khui_alert_flags.  The bits that are
    on in \a mask will be set to the corresponding values in \a flags.
    Only the bits specified in ::KHUI_ALERT_FLAGMASK_RDWR can be
    specified in \a mask.
 */
KHMEXP khm_int32 KHMAPI
khui_alert_set_flags(khui_alert * alert, khm_int32 mask, khm_int32 flags);

/*! \brief Clear all the commands from an alert object

    \see khui_alert_add_command()
 */
KHMEXP khm_int32 KHMAPI 
khui_alert_clear_commands(khui_alert * alert);

/*! \brief Add a command to an alert object

    The command ID should be a valid registered action.
 */
KHMEXP khm_int32 KHMAPI 
khui_alert_add_command(khui_alert * alert, 
                       khm_int32 command_id);

/*! \brief Set the type of alert
 */
KHMEXP khm_int32 KHMAPI
khui_alert_set_type(khui_alert * alert,
                    khui_alert_type type);

/*! \brief Set the action context for the alert */
KHMEXP khm_int32 KHMAPI
khui_alert_set_ctx(khui_alert * alert,
                   khui_scope scope,
                   khm_handle identity,
                   khm_int32 cred_type,
                   khm_handle cred);

/*! \brief Get the response code from an alert

    Once an alert has been displayed to the user, the user may choose
    a command from the list of commands provided in the alert (see
    khui_alert_add_command() ).  This function can retrieve the
    selected command from the alert.

    \return The selected command or \a 0 if no commands were selected.
 */
KHMEXP khm_int32 KHMAPI
khui_alert_get_response(khui_alert * alert);


/*! \brief Display an alert

    The alert must have a valid \a severity, \a title and a \a message
    to be displayed.  Otherwise the function immediately returns with
    a failure code.

    The method used to display the alert is as follows:

    - A balloon alert will be shown if one of the following is true: 
      - The NetIDMgr application is minimized or in the background.  
      - ::KHUI_ALERT_FLAG_REQUEST_BALLOON is specified in \a flags.  
    - Otherwise an alert window will be shown.

    If the message, title of the alert is too long to fit in a balloon
    prompt, there's a suggestion or if there are custom commands then
    a placeholder balloon prompt will be shown which when clicked on,
    shows the actual alert in an alert window.  

    An exception is when ::KHUI_ALERT_FLAG_DEFACTION is specified in
    flags.  In this case instead of a placeholder balloon prompt, one
    will be shown with the actual title and message (truncated if
    necessary).  Clicking on the balloon will cause the first command
    in the command list to be performed.

    The placeholder balloon prompt will have a title derived from the
    first 63 characters of the \a title field in the alert and a
    message notifying the user that they should click the balloon
    prompt for more information.

    To this end, it is beneficial to limit the length of the title to
    63 characters (64 counting the terminating NULL).  This limit is
    enforced on Windows.  Also, try to make the title descriptive.

    User interaction with the alert will be as follows:

    - If the alert contains no commands, then the alert will be
      displayed to the user as described above.  A 'close' button will
      be added to the alert if the alert is being displayed in a
      window.

    - If the alert contains commands, has the
      ::KHUI_ALERT_FLAG_DEFACTION flag set and is displayed in a
      balloon and the user clicks on it, the first command in the
      command list will be executed.

    - If the alert contains commands and does not have the
      ::KHUI_ALERT_FLAG_DEFACTION and has the
      ::KHUI_ALERT_FLAG_DISPATCH_CMD flag set, then when the user
      selects one of the command buttons, the corresponding command
      will immediately be dispatched. (see
      ::KHUI_ALERT_FLAG_DISPATCH_CMD).

    - If the alert contains command and have neither
      ::KHUI_ALERT_FLAG_DEFACTION nor ::KHUI_ALERT_FLAG_DISPATCH_CMD,
      then when the user selects one of the command buttons, the
      selected command will be stored along with the alert.  It can be
      retrieved via a call to khui_alert_get_response().

 */
KHMEXP khm_int32 KHMAPI 
khui_alert_show(khui_alert * alert);

/*! \brief Display a modal alert

    Similar to khui_alert_show(), but shows a modal alert dialog.  The
    function does not return until the user has closed the alert.

    This function always opens an alert window (never shows a
    balloon).

 */
KHMEXP khm_int32 KHMAPI
khui_alert_show_modal(khui_alert * alert);

/*! \brief Queue an alert

    Instead of displaying the alert immediately, the alert is queued
    and the status bar updated to notify the user that there is a
    pending alert.  Once the user activates the pending alert, it will
    be displayed as if khui_alert_show() was called.
 */
KHMEXP khm_int32 KHMAPI
khui_alert_queue(khui_alert * alert);

/*! \brief Display a simple alert

    \see khui_alert_show()
 */
KHMEXP khm_int32 KHMAPI 
khui_alert_show_simple(const wchar_t * title, 
                       const wchar_t * message, 
                       khm_int32 severity);

/*! \brief Obtain a hold on the alert

    An alert structure is only considered valid for the duration that
    there is a hold on it.

    Use khui_alert_release() to release the hold.
 */
KHMEXP khm_int32 KHMAPI 
khui_alert_hold(khui_alert * alert);

/*! \brief Release the hold on the alert

    Holds obtained on an alert using any of the functions that either
    return a held pointer to an alert or implicitly obtains a hold on
    it need to be undone through a call to khui_alert_release().
 */
KHMEXP khm_int32 KHMAPI 
khui_alert_release(khui_alert * alert);

/*! \brief Lock an alert 

    Locking an alert disallows any other thread from accessing the
    alert at the same time.  NetIDMgr keeps a global list of all alert
    objects and the user interface may access any of them at various
    points in time.  Locking the alert allows a thread to modify an
    alert without causing another thread to be exposed to an
    inconsistent state.

    Once a thread obtains a lock on the alert, it must call
    khui_alert_unlock() to unlock it.  Otherwise no other thread will
    be able to access the alert.

    \note Currently the alert lock is global.  Locking one alert
        disallows access to all other alerts as well.

    \note Calling khui_alert_lock() is only necessary if you are
        accessing the ::khui_alert structure directly.  Calling any of
        the khui_alert_* functions to modify the alert does not
        require obtaining a lock, as they perform synchronization
        internally.
*/
KHMEXP void KHMAPI 
khui_alert_lock(khui_alert * alert);

/*! \brief Unlock an alert 

    \see khui_alert_lock()
*/
KHMEXP void KHMAPI 
khui_alert_unlock(khui_alert * alert);

/*!@}*/
/*!@}*/

#endif

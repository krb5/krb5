/*
 * Copyright (c) 2004 Massachusetts Institute of Technology
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

#define KHUI_MAX_ALERT_COMMANDS  4

/*! \brief An alert

    Describes an alert message that will be shown to the user in a
    variety of ways depending on the state of the NetIDMgr
    application.
 */
typedef struct tag_khui_alert {
    khm_int32           magic;  /*!< Magic number. Always set to
                                  KHUI_ALERT_MAGIC */

    khm_int32           severity; /*!< The severity of the alert.  One
                                    of KHERR_ERROR, KHERR_WARNING or
                                    KHERR_INFO.  The default is
                                    KHERR_INFO.  Do not set directly.
                                    Use khui_alert_set_severity(). */

    khm_int32           alert_commands[KHUI_MAX_ALERT_COMMANDS];
                                /*!< The command buttons associated
                                  with the alert.  Use
                                  khui_alert_add_command() to add a
                                  command.  The buttons will appear in
                                  the order in which they were added.
                                  The first button will be the
                                  default.  Each command should be a
                                  known action identifier. */
    khm_int32           n_alert_commands;

    wchar_t *           title;  /*!< The title of the alert.  Subject
                                  to ::KHUI_MAXCCH_TITLE.  Use
                                  khui_alert_set_title() to set.  Do
                                  not modify directly. */

    wchar_t *           message; /*!< The main message of the alert.
                                   Subject to ::KHUI_MAXCCH_MESSAGE.
                                   Use khui_alert_set_message() to
                                   set.  Do not modify direcly. */

    wchar_t *           suggestion; /*!< A suggestion.  Appears below
                                      the message text. Use
                                      khui_alert_set_suggestion() to
                                      set.  Do not modify directly. */

#ifdef _WIN32
    POINT               target;
#endif

    khm_int32           flags;  /*!< combination of
                                 ::khui_alert_flags.  Do not modify
                                 directly. */

    kherr_context *     err_context; 
                                /*!< If non-NULL at the time the alert
                                  window is shown, this indicates that
                                  the alert window should provide an
                                  error viewer for the given error
                                  context. */

    kherr_event *       err_event; 
                                /*!< If non-NULL at the time the alert
                                  window is shown, this indicates that
                                  the alert window should provide an
                                  error viewer for the given error
                                  event.  If an \a err_context is also
                                  given, the error viewer for the
                                  context will be below this error. */

    khm_int32           response; 
                                /*!< Once the alert is displayed to
                                  the user, when the user clicks one
                                  of the command buttons, the command
                                  ID will be assigned here. */

    int                 refcount; /* internal */

    LDCL(struct tag_khui_alert); /* internal */
} khui_alert;

#define KHUI_ALERT_MAGIC 0x48c39ce9

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

    KHUI_ALERT_FLAG_VALID_TARGET    =0x00010000,
    /*!< There is a valid target for the alert */

    KHUI_ALERT_FLAG_VALID_ERROR     =0x00020000,
    /*!< There is a valid error context associated with the alert */

    KHUI_ALERT_FLAG_DISPLAY_WINDOW  =0x01000000,
    /*!< The alert has been displayed in a window */

    KHUI_ALERT_FLAG_DISPLAY_BALLOON =0x02000000,
    /*!< The alert has been displayed in a ballon */

    KHUI_ALERT_FLAG_REQUEST_WINDOW  =0x04000000,
    /*!< The alert should be displayed in a window */

    KHUI_ALERT_FLAG_REQUEST_BALLOON =0x08000000,
    /*!< The alert should be displayed in a balloon */

    KHUI_ALERT_FLAGMASK_RDWR        =0x0C000010,
    /*!< Bit mask of flags that can be set by khui_alert_set_flags() */
};

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

    The command ID should be a valid registered command.
 */
KHMEXP khm_int32 KHMAPI 
khui_alert_add_command(khui_alert * alert, 
                       khm_int32 command_id);

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
    necessary).  Clicking on the balloon will have the same effect as
    choosing the first command in the action.

    The placeholder balloon prompt will have a title derived from the
    first 63 characters of the \a title field in the alert and a
    message notifying the user that they should click the balloon
    prompt for more information.

    To this end, it is beneficial to limit the length of the title to
    63 characters (64 counting the terminating NULL).  This limit is
    enforced on Windows.  Also, try to make the title descriptive.
 */
KHMEXP khm_int32 KHMAPI 
khui_alert_show(khui_alert * alert);

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
        modifying the ::khui_alert structure directly.  Calling any of
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

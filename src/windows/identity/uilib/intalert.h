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

#ifndef __KHIMAIRA_KHALERTS_H_INTERNAL
#define __KHIMAIRA_KHALERTS_H_INTERNAL

#include<khalerts.h>
#include<khaction.h>

/*! \addtogroup khui_alert

@{ */

/*! \internal

    \brief An alert

    Describes an alert message that will be shown to the user in a
    variety of ways depending on the state of the NetIDMgr
    application.
 */
typedef struct tag_khui_alert {
    khm_int32           magic;
                                /*!< Magic number. Always set to
                                  KHUI_ALERT_MAGIC */

    khm_int32           severity;
                                /*!< The severity of the alert.  One
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
                                /*!< The number of commands in
                                  alert_commands[]. */

    wchar_t *           title;  /*!< The title of the alert.  Subject
                                  to ::KHUI_MAXCCH_TITLE.  Use
                                  khui_alert_set_title() to set.  Do
                                  not modify directly. */

    wchar_t *           message;
                                /*!< The main message of the alert.
                                  Subject to ::KHUI_MAXCCH_MESSAGE.
                                  Use khui_alert_set_message() to set.
                                  Do not modify direcly. */

    wchar_t *           suggestion;
                                /*!< A suggestion.  Appears below the
                                  message text. Use
                                  khui_alert_set_suggestion() to set.
                                  Do not modify directly. */

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

    khui_alert_type     alert_type;
                                /*!< The type of alert. */

    khui_action_context ctx;    /*!< Context to which this alert
                                  applies to. */

    khm_int32           response;
                                /*!< Once the alert is displayed to
                                  the user, when the user clicks one
                                  of the command buttons, the command
                                  ID will be assigned here. */

    int                 refcount;
                                /*!< internal */

    khm_boolean         displayed;
                                /*!< TRUE when then the alert is being
                                  displayed on screen.  Also used
                                  internally to determine when to
                                  terminate the modal loop */

    LDCL(struct tag_khui_alert);
                                /*!< internal */
} khui_alert;

#define KHUI_ALERT_MAGIC 0x48c39ce9

/*@}*/

#endif

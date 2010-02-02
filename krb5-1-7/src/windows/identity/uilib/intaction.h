/*
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

#ifndef __NETIDMGR_ACTION_H_INTERNAL
#define __NETIDMGR_ACTION_H_INTERNAL

/* Internal declarations for exports and data structured used in
   nidmgr32.dll and netidmgr.exe */

extern HWND khui_hwnd_main;

typedef struct tag_khui_ui_callback_data {
    khm_int32       magic;
    khm_ui_callback cb;
    void *          rock;
    khm_int32       rv;
} khui_ui_callback_data;

#define KHUI_UICBDATA_MAGIC 0x8a08572a

/*! \addtogroup khui_actions
@{ */

/*! \brief An action */
typedef struct tag_khui_action {
    khm_int32 cmd;            /*!< action identifier */
    khm_int32 type;           /*!< combination of KHUI_ACTIONTYPE_* */
    wchar_t * name;           /*!< name for named actions.  NULL if
                                not named. */

    /* The following fields are only for use by NetIDMgr */
    khm_int16 ib_normal;      /*!< (internal) normal bitmap (index) (toolbar sized icon) */
    khm_int16 ib_hot;         /*!< (internal) hot bitmap (index) (toolbar sized icon) */
    khm_int16 ib_disabled;    /*!< (internal) disabled bitmap (index) (toolbar sized icon) */

    khm_int16 ib_icon;        /*!< (internal) index of small (16x16) icon (for menu) (small icon) */
    khm_int16 ib_icon_dis;    /*!< (internal) index of disabled (greyed) icon (small icon) */

    khm_int16 is_caption;     /*!< (internal) index of string resource for caption */
    khm_int16 is_tooltip;     /*!< (internal) same for description / tooltip */
    khm_int16 ih_topic;       /*!< (internal) help topic */

    /* The following fields are specified for custom actions */
    wchar_t * caption;        /*!< Caption (localized) (limited by
                                  KHUI_MAXCCH_SHORT_DESC).  The
                                  caption is used for representing the
                                  action in menus and toolbars. */
    wchar_t * tooltip;        /*!< Tooltip (localized) (limited by
                                  KHUI_MAXCCH_SHORT_DESC).  If this is
                                  specified, whenever the user hovers
                                  over the menu item or toolbar button
                                  representing the action, the tooltip
                                  will be displayed either on a
                                  tooltip window or in the status
                                  bar. */
    khm_handle listener;      /*!< Listener of this action.  Should be
                                  a handle to a message
                                  subscription. When the action is
                                  invoked, a message of type
                                  ::KMSG_ACT and subtype
                                  ::KMSG_ACT_ACTIVATE will be posted
                                  to this subscriber. The \a uparam
                                  parameter of the message will have
                                  the identifier of the action. */
    void *    data;           /*!< User data for custom action.  This
                                  field is not used by the UI library.
                                  It is reserved for plugins to store
                                  data that is specific for this
                                  action.  The data that's passed in
                                  in the \a userdata parameter to
                                  khui_action_create() will be stored
                                  here and can be retrieved by calling
                                  khui_action_get_data(). */
    void *    reserved1;      /*!< Reserved. */
    void *    reserved2;      /*!< Reserved. */
    void *    reserved3;      /*!< Reserved. */

    /* For all actions */
    int state;                /*!< current state. combination of
                                  KHUI_ACTIONSTATE_* */
} khui_action;


#define KHUI_ACTIONTYPE_IDENTITY 0x00010000


/*@}*/

#endif

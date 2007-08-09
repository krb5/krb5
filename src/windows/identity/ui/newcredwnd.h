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

#ifndef __KHIMAIRA_NEWCREDWND_H
#define __KHIMAIRA_NEWCREDWND_H

#include<khuidefs.h>

#define KHUI_NEWCREDWND_CLASS L"KhmNewCredWnd"

typedef enum tag_nc_notification_types {
    NC_NOTIFY_NONE = 0,         /* no notification */
    NC_NOTIFY_MARQUEE,          /* marquee type notification */
    NC_NOTIFY_PROGRESS,         /* progress notification */
    NC_NOTIFY_MESSAGE,          /* a message */
} nc_notification_type;

typedef struct khui_nc_wnd_data_t {
    khui_new_creds * nc;

    /* The tab control */

    HWND tab_wnd;               /* tab control */
    int current_panel;          /* ordinal of the current panel being
                                   displayed. */

    /* The main panel */
    HWND dlg_main;              /* main dialog */
    RECT r_main;                /* the extent of the main panel that
                                   we have used so far.  The rect
                                   includes the size of the area used
                                   by the identity selector controls,
                                   the custom controls added by
                                   credentials providers and the
                                   buttons that may be required when
                                   in the mini mode. */
    RECT r_required;            /* required size of the main window */

    /* The button bar */

    HWND dlg_bb;                /* button bar */

    /* Sizing the new credentials window */

    BOOL animation_enabled;     /* Flag indicating whether animation
                                   is enabled for the dialg.  If this
                                   flag is off, we don't animate size
                                   changes even if the configuration
                                   says so. */
    BOOL size_changing;         /* flag indicating that the size of
                                   the main window is being
                                   adjusted. */
    RECT sz_ch_source;          /* Source size, from which we are
                                   going towards target size in
                                   sz_ch_max steps. The RECT is self
                                   relative (i.e. left=0 and top=0)*/
    RECT sz_ch_target;          /* If we are doing an incremental size
                                   change, this holds the target size
                                   that we were going for.  Note that
                                   the target size might change while
                                   we are adjusting the size.  So this
                                   helps keep track of whether we need
                                   to start the size change again. The
                                   RECT is self relative (i.e. left=0
                                   and top=0). */
    int  sz_ch_increment;       /* Current step of the incremental
                                   size change operation. */
    int  sz_ch_max;             /* Max number of steps in the size
                                   change operation. */
    int  sz_ch_timeout;         /* Milliseconds between each increment */

    BOOL flashing_enabled;      /* The window maybe still flashing
                                   from the last call to
                                   FlashWindowEx(). */

    /* Custom controls and identity specifiers */

    HWND hwnd_banner;           /* static control for banner */
    HWND hwnd_name;             /* static control for name */

    HWND hwnd_last_idspec;      /* last identity specifier control */

    /* Notification windows */

    nc_notification_type notif_type; /* Type of notification */
    HWND hwnd_notif_label;      /* Label for notifications */
    HWND hwnd_notif_aux;        /* Other control for notifications */

    /* Areas of the main panel */

    RECT r_idspec;          /* Area used by identity specifiers
                               (relative to client) */
    RECT r_custprompt;      /* Area used by custom controls (relative
                               to client) */
    RECT r_notif;           /* Area used for notifications. */

    /* Metrics for custom prompts and identity specifiers */

    RECT r_row;             /* Metrics for a control row (left=0,
                               top=0, right=width, bottom=height) */
    RECT r_area;            /* Area available for controls (relative
                               to client) */
    RECT r_n_label;         /* coords of the static control (relative
                               to row) */
    RECT r_n_input;         /* coords of the edit control (relative to
                               row) */
    RECT r_e_label;         /* coords of the extended edit control
                               (relative to row) */
    RECT r_e_input;         /* coords of the extended edit control
                               (relative to row) */
    RECT r_credtext;        /* Area for credtext window (relative to
                               row) */
} khui_nc_wnd_data;

void khm_register_newcredwnd_class(void);
void khm_unregister_newcredwnd_class(void);
HWND khm_create_newcredwnd(HWND parent, khui_new_creds * c);
void khm_prep_newcredwnd(HWND hwnd);
void khm_show_newcredwnd(HWND hwnd);

/* Width of the button bar in dialog units */
#define NCDLG_BBAR_WIDTH 66
/* Height of the button bar in dialog units */
#define NCDLG_BBAR_HEIGHT 190

/* Control identifier for the tab control in the new credentials
   dialog. We declare this here since we will be creating the control
   manually. */
#define IDC_NC_TABS 8001

/* This is the first control ID that is created in the custom tabstrip
   control buttons.  Subsequent buttons get consecutive IDs starting
   from this one.  */
#define NC_TS_CTRL_ID_MIN 8002

/* Maximum number of controls */
#define NC_TS_MAX_CTRLS 8

/* Maximum control ID */
#define NC_TS_CTRL_ID_MAX (NC_TS_CTRL_ID_MIN + NC_TS_MAX_CTRLS - 1)

#define NC_BN_SET_DEF_ID 8012

/* the first control ID that may be used by an identity provider */
#define NC_IS_CTRL_ID_MIN 8016

/* the maximum number of controls that may be created by an identity
   provider*/
#define NC_IS_CTRL_MAX_CTRLS 8

/* the maximum control ID that may be used by an identity provider */
#define NC_IS_CTRL_ID_MAX (NC_IS_CTRL_ID_MIN + NC_IS_MAX_CTRLS - 1)

#define NC_WINDOW_EX_STYLES (WS_EX_DLGMODALFRAME | WS_EX_CONTEXTHELP | WS_EX_APPWINDOW)
#define NC_WINDOW_STYLES    (WS_DLGFRAME | WS_POPUPWINDOW | WS_CLIPCHILDREN)

#define NC_SZ_STEPS_MIN 3
#define NC_SZ_STEPS_DEF 10
#define NC_SZ_STEPS_MAX 100

#define NC_SZ_TIMEOUT_MIN 5
#define NC_SZ_TIMEOUT_DEF 10
#define NC_SZ_TIMEOUT_MAX 500

#define NC_TIMER_SIZER         1001
#define NC_TIMER_ENABLEANIMATE 1002

#define ENABLEANIMATE_TIMEOUT  400

#endif

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

#ifndef __KHIMAIRA_NEWCREDWND_H
#define __KHIMAIRA_NEWCREDWND_H

#include<khuidefs.h>

#define KHUI_NEWCREDWND_CLASS L"KhmNewCredWnd"

typedef struct khui_nc_wnd_data_t {
    khui_new_creds * nc;

    HWND dlg_main;              /* main dialog */
    RECT r_main;
    HWND dlg_bb;                /* button bar */
    RECT r_bb;
    HWND dlg_ts;                /* tab strip */
    RECT r_ts;

    khm_size ctab;              /* current tab */

    HWND hwnd_tc_main;        /* tab control button for main dialog */

    HWND hwnd_banner;           /* static control for banner */
    HWND hwnd_name;             /* static control for name */

    HWND hwnd_last_idspec;      /* last identity specifier control */

    /* metrics for custom prompts and identity specifiers */

    RECT r_idspec;          /* Area used by identity specifiers
                               (relative to client) */
    RECT r_row;             /* Metrics for a control row
                               (top=0,left=0,right=width,
                               bottom=height) */
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

/* This is the first control ID that is created in the custom tabstrip
   control buttons.  Subsequent buttons get consecutive IDs starting
   from this one.  */
#define NC_TS_CTRL_ID_MIN 8001

/* Maximum number of controls */
#define NC_TS_MAX_CTRLS 8

/* Maximum control ID */
#define NC_TS_CTRL_ID_MAX (NC_TS_CTRL_ID_MIN + NC_TS_MAX_CTRLS - 1)

/* the first control ID that may be used by an identity provider */
#define NC_IS_CTRL_ID_MIN 8016

/* the maximum number of controls that may be created by an identity
   provider*/
#define NC_IS_CTRL_MAX_CTRLS 8

/* the maximum control ID that may be used by an identity provider */
#define NC_IS_CTRL_ID_MAX (NC_IS_CTRL_ID_MIN + NC_IS_MAX_CTRLS - 1)

#endif

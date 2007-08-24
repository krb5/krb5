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

#ifndef __KHIMAIRA_APPGLOBAL_H
#define __KHIMAIRA_APPGLOBAL_H

/* Helpfile */
#define NIDM_HELPFILE              L"netidmgr.chm"

/* global data */
extern HINSTANCE khm_hInstance;
extern int khm_nCmdShow;
extern const wchar_t * khm_facility;
extern kconf_schema schema_uiconfig[];
extern khm_ui_4 khm_commctl_version;
extern const khm_version app_version;

#define IS_COMMCTL6() (khm_commctl_version >= 0x60000)

/* The structure used to send command-line options to a remote
   NetIDMgr session for versions prior to 1.2. */
typedef struct tag_khm_startup_options_v1 {
    BOOL seen;
    BOOL processing;

    BOOL init;
    BOOL import;
    BOOL renew;
    BOOL destroy;

    BOOL autoinit;
    BOOL exit;
    BOOL error_exit;

    BOOL no_main_window;
} khm_startup_options_v1;

/* Used on NetIDMgr version 1.2.x */
typedef struct tag_khm_startup_options_v2 {
    khm_int32 magic;            /* set to STARTUP_OPTIONS_MAGIC */
    DWORD cb_size;              /* size of structure, in bytes */

    BOOL init;
    BOOL import;
    BOOL renew;
    BOOL destroy;

    BOOL autoinit;
    BOOL remote_exit;

    khm_int32 code;
} khm_startup_options_v2;

/* Used on NetIDMgr version 1.3.1 and later */
typedef struct tag_khm_startup_options_v3 {
    struct tag_khm_startup_options_v2 v2opt;

    khm_int32 remote_display;   /* combination of SOPTS_DISPLAY_* */
} khm_startup_options_v3;

#define STARTUP_OPTIONS_MAGIC 0x1f280e41

/* The following macros are used with
   tag_khm_startup_options_v3->remote_display */

/* Show (unhide) the main window. */
#define SOPTS_DISPLAY_SHOW    0x00000001

/* Hide the main window. (Can't be used with SOPTS_DISPLAY_SHOW) */
#define SOPTS_DISPLAY_HIDE    0x00000002

/* Suppress the default action on the remote end */
#define SOPTS_DISPLAY_NODEF   0x00000004

/* Used internally. */
typedef struct tag_khm_startup_options_int {
    khm_boolean seen;
    khm_boolean processing;
    khm_boolean remote;         /* is this a remote request? */

    khm_boolean init;
    khm_boolean import;
    khm_boolean renew;
    khm_boolean destroy;

    khm_boolean autoinit;
    khm_boolean exit;
    khm_boolean remote_exit;

    khm_boolean error_exit;

    khm_boolean no_main_window;
    khm_int32 display;          /* SOPTS_DISPLAY_* */

    LONG pending_renewals;
} khm_startup_options;

extern khm_startup_options khm_startup;

/* Used to query a remote instance of NetIDMgr for the version. */
typedef struct tag_khm_query_app_version_v1 {
    khm_int32 magic;

    khm_int32 code;

    khm_version ver_caller;
    khm_version ver_remote;

    khm_boolean request_swap;
} khm_query_app_version;

#define KHM_QUERY_APP_VER_MAGIC 0x38f8c2eb

void khm_add_dialog(HWND dlg);
void khm_del_dialog(HWND dlg);
BOOL khm_is_dialog_active(void);

void khm_enter_modal(HWND hwnd);
void khm_leave_modal(void);

void khm_add_property_sheet(khui_property_sheet * s);
void khm_del_property_sheet(khui_property_sheet * s);

void khm_init_gui(void);
void khm_exit_gui(void);

void khm_parse_commandline();
void khm_register_window_classes(void);

HWND khm_html_help(HWND hwnd, wchar_t * suffix, UINT command, DWORD_PTR data);

WPARAM khm_message_loop_int(khm_boolean * p_exit);

int khm_compare_version(const khm_version * v1, const khm_version * v2);

#define MAX_RES_STRING 1024

#define ELLIPSIS L"..."

#endif

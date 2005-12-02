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

#define IS_COMMCTL6() (khm_commctl_version >= 0x60000)

typedef struct tag_khm_startup_options {
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
} khm_startup_options;

extern khm_startup_options khm_startup;

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

HWND khm_html_help(HWND hwnd, UINT command, DWORD_PTR data);

#define MAX_RES_STRING 1024

#define ELIPSIS L"..."

#endif

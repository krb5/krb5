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

#ifndef __KHIMAIRA_MAINMENU_H
#define __KHIMAIRA_MAINMENU_H

extern HWND khui_main_menu_toolbar;

#define MENU_ACTIVATE_DEFAULT   -1
#define MENU_ACTIVATE_LEFT      -2
#define MENU_ACTIVATE_RIGHT     -3
#define MENU_ACTIVATE_NONE      -4

extern int mm_last_hot_item;
extern BOOL mm_hot_track;

void khm_menu_create_main(HWND rebar);
LRESULT khm_menu_handle_select(WPARAM wParam, LPARAM lParam);
LRESULT khm_menu_notify_main(LPNMHDR notice);
LRESULT khm_menu_activate(int menu_id);
void khm_menu_show_panel(int id, LONG x, LONG y);
void khm_menu_track_current(void);
LRESULT khm_menu_measure_item(WPARAM wParam, LPARAM lparam);
LRESULT khm_menu_draw_item(WPARAM wParam, LPARAM lparam);
void khm_menu_refresh_items(void);
khm_boolean khm_check_identity_menu_action(khm_int32 act_id);
void khm_refresh_identity_menus(void);
void khm_get_action_tooltip(khm_int32 action, wchar_t * buf, khm_size cb_buf);
void khm_get_action_caption(khm_int32 action, wchar_t * buf, khm_size cb_buf);

khm_int32 khm_get_identity_destroy_action(khm_handle ident);
khm_int32 khm_get_identity_renew_action(khm_handle ident);
khm_int32 khm_get_identity_new_creds_action(khm_handle ident);

static HMENU mm_create_menu_from_def(khui_menu_def * def, BOOL main);
static void mm_show_panel_def(khui_menu_def * def, LONG x, LONG y);

void khui_init_menu(void);
void khui_exit_menu(void);

#define MENU_SIZE_ICON_X 16
#define MENU_SIZE_ICON_Y 16

#endif

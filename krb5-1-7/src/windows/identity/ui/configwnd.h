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

#ifndef __KHIMAIRA_CONFIGWND_H
#define __KHIMAIRA_CONFIGWND_H

#define CFGACTION_MAGIC 0x38f8

void 
khm_show_config_pane(khui_config_node node);

void khm_init_config(void);
void khm_exit_config(void);

void khm_refresh_config(void);

/* window procedures for other configuration windows */
INT_PTR CALLBACK
khm_cfg_general_proc(HWND hwnd,
                     UINT uMsg,
                     WPARAM wParam,
                     LPARAM lParam);

INT_PTR CALLBACK
khm_cfg_identities_proc(HWND hwnd,
                        UINT uMsg,
                        WPARAM wParam,
                        LPARAM lParam);

INT_PTR CALLBACK
khm_cfg_identity_proc(HWND hwnd,
                      UINT uMsg,
                      WPARAM wParam,
                      LPARAM lParam);

INT_PTR CALLBACK
khm_cfg_id_tab_proc(HWND hwnd,
                    UINT uMsg,
                    WPARAM wParam,
                    LPARAM lParam);

INT_PTR CALLBACK
khm_cfg_ids_tab_proc(HWND hwnd,
                     UINT uMsg,
                     WPARAM wParam,
                     LPARAM lParam);

INT_PTR CALLBACK
khm_cfg_notifications_proc(HWND hwnd,
                           UINT uMsg,
                           WPARAM wParam,
                           LPARAM lParam);

INT_PTR CALLBACK
khm_cfg_plugins_proc(HWND hwnd,
                     UINT uMsg,
                     WPARAM wParam,
                     LPARAM lParam);

INT_PTR CALLBACK
khm_cfg_appearance_proc(HWND hwnd,
                        UINT uMsg,
                        WPARAM wParam,
                        LPARAM lParam);
#endif

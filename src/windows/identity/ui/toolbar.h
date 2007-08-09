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

#ifndef __KHIMAIRA_TOOLBAR_H
#define __KHIMAIRA_TOOLBAR_H

extern HWND khui_hwnd_standard_toolbar;

void khui_init_toolbar(void);
void khui_exit_toolbar(void);
LRESULT khm_toolbar_notify(LPNMHDR notice);
void khm_create_standard_toolbar(HWND rebar);
void khui_add_action_to_toolbar(HWND toolbar, khui_action * act, int opt, HIMAGELIST hiList);
void khm_update_standard_toolbar(void);

/* options for khui_add_action_to_toolbar */
#define KHUI_TOOLBAR_ADD_TEXT      0x00000001
#define KHUI_TOOLBAR_ADD_BITMAP    0x00000002
#define KHUI_TOOLBAR_ADD_LONGTEXT  0x00000005
#define KHUI_TOOLBAR_ADD_DROPDOWN  0x00000008
#define KHUI_TOOLBAR_ADD_SEP       0x00000010
#define KHUI_TOOLBAR_VARSIZE       0x00000020

#define KHUI_TOOLBAR_IMAGE_WIDTH 29
#define KHUI_TOOLBAR_IMAGE_HEIGHT 27
#define KHUI_TOOLBAR_BGCOLOR RGB(0xd7,0xd7,0xd7)
#define KHUI_TOOLBAR_MAX_BTNS 64

#endif

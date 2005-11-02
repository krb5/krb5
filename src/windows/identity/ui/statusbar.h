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

#ifndef __KHIMAIRA_STATUSBAR_H
#define __KHIMAIRA_STATUSBAR_H

typedef struct khui_statusbar_part_t {
    int id;
    int width;
    int wtype; /* one of KHUI_SB_WTYPE_* */
} khui_statusbar_part;

#define KHUI_SB_WTYPE_RELATIVE    1
#define KHUI_SB_WTYPE_ABSOLUTE    2
#define KHUI_SB_WTYPE_FILLER      4

/* statusbar parts */
#define KHUI_SBPART_INFO    1
#define KHUI_SBPART_NOTICE  2
#define KHUI_SBPART_LOC     3

extern HWND khui_hwnd_statusbar;
extern khui_statusbar_part khui_statusbar_parts[];
extern int khui_n_statusbar_parts;

void khui_create_statusbar(HWND p);
void khui_update_statusbar(HWND parent);
void khui_statusbar_set_text(int id, wchar_t * text);

#endif
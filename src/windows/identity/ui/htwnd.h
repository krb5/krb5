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

#ifndef __KHIMAIRA_HTWND_H
#define __KHIMAIRA_HTWND_H

#include<khuidefs.h>

/*
We currently support the following tags:

<a [id="string"] [param="paramstring"]>link text</a>
<center>foo</center>
<left>foo</left>
<right>foo</right>
*/

#define KHUI_HTWND_TRANSPARENT  1
#define KHUI_HTWND_CLIENTEDGE   2
#define KHUI_HTWND_HSCROLL      4
#define KHUI_HTWND_VSCROLL      8
#define KHUI_HTWND_FOCUS        2048

#define KHUI_HTWND_CLASS L"KhmHtWnd"
#define KHUI_HTWND_CTLID 2040

#define KHUI_HTWND_MAXCCH_TEXT 2048
#define KHUI_HTWND_MAXCB_TEXT (sizeof(wchar_t) * KHUI_HTWND_MAXCCH_TEXT)

HWND khm_create_htwnd(HWND parent, LPWSTR text, int x, int y, int width, int height, DWORD ex_style, DWORD style);
void khm_unregister_htwnd_class(void);
void khm_register_htwnd_class(void);

#endif

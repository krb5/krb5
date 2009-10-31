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

#define _NIMLIB_

#include<khuidefs.h>
#include<intaction.h>

#ifdef DEBUG
#include <assert.h>
#endif

KHMEXP khm_int32 KHMAPI
khui_request_UI_callback(khm_ui_callback cb, void * rock) {

    khui_ui_callback_data cbdata;

#ifdef DEBUG
    assert(khui_hwnd_main);
#endif

    if (khui_hwnd_main == NULL)
        return KHM_ERROR_NOT_READY;

    ZeroMemory(&cbdata, sizeof(cbdata));
    cbdata.magic = KHUI_UICBDATA_MAGIC;
    cbdata.cb = cb;
    cbdata.rock = rock;
    cbdata.rv = KHM_ERROR_NOT_IMPLEMENTED;

    SendMessage(khui_hwnd_main, WM_COMMAND,
                MAKEWPARAM(KHUI_ACTION_UICB, 0),
                (LPARAM) &cbdata);

    return cbdata.rv;
}

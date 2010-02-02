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

#include<khmapp.h>

#define COBJMACROS

#include<shobjidl.h>

#ifdef DEBUG
#include<assert.h>
#endif

ITaskbarList *itbl = NULL;

void
khm_init_taskbar_funcs(void) {
    HRESULT hr = NOERROR;

    hr = CoCreateInstance(&CLSID_TaskbarList, NULL, CLSCTX_INPROC_SERVER,
                          &IID_ITaskbarList, &itbl);

#ifdef DEBUG
    assert(itbl != NULL);
#endif

    if (itbl) {
        hr = ITaskbarList_HrInit(itbl);
#ifdef DEBUG
        assert(hr == NOERROR);
#endif
    }
}

void
khm_exit_taskbar_funcs(void) {
    if (itbl) {
        ITaskbarList_Release(itbl);
    }
}

void
khm_taskbar_add_window(HWND hwnd) {
    HRESULT hr = NOERROR;

    if (itbl) {
        hr = ITaskbarList_AddTab(itbl, hwnd);
#ifdef DEBUG
        assert(hr == NOERROR);
#endif
    }
}

void
khm_taskbar_remove_window(HWND hwnd) {
    HRESULT hr = NOERROR;

    if (itbl) {
        hr = ITaskbarList_DeleteTab(itbl, hwnd);
#ifdef DEBUG
        assert(hr == NOERROR);
#endif
    }
}

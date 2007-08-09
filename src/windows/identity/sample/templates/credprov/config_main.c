/*
 * Copyright (c) 2006 Secure Endpoints Inc.
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

#include "credprov.h"
#include <assert.h>

/* Dialog procedures and support functions for handling configuration
   dialogs for general plug-in configuration. */

/* Structure for holding dialog data for the configuration window. */
typedef struct tag_config_main_dlg_data {
    khui_config_node cnode;

    /* TODO: add fields as needed */
} config_main_dlg_data;

INT_PTR CALLBACK
config_dlgproc(HWND hwnd,
               UINT uMsg,
               WPARAM wParam,
               LPARAM lParam) {

    config_main_dlg_data * d;

    switch (uMsg) {
    case WM_INITDIALOG:
        d = malloc(sizeof(*d));
        assert(d);
        ZeroMemory(d, sizeof(*d));

        /* for configuration panels that are not subpanels, lParam is
           a held handle to the configuration node.  The handle will
           be held for the lifetime of the window. */

        d->cnode = (khui_config_node) lParam;

        /* TODO: perform any other required initialization stuff
           here */

#pragma warning(push)
#pragma warning(disable: 4244)
        SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) d);
#pragma warning(pop)

        break;

    case KHUI_WM_CFG_NOTIFY:
        {
            d = (config_main_dlg_data *)
                GetWindowLongPtr(hwnd, DWLP_USER);

            /* WMCFG_APPLY is the only notification we care about */

            if (HIWORD(wParam) == WMCFG_APPLY) {
                /* TODO: Apply changes and update the state */

                return TRUE;
            }
        }
        break;

    case WM_DESTROY:
        d = (config_main_dlg_data *)
            GetWindowLongPtr(hwnd, DWLP_USER);

        /* TODO: perform any other required uninitialization here */

        if (d)
            free(d);

        break;
    }

    return FALSE;

}

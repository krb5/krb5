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
   dialogs for per-identity configuration. When the configuration
   dialog is activated, an instance of this dialog will be created for
   each identity that the user touches. */

/* The structure that we use to hold state information for the
   dialog. */
typedef struct tag_config_id_dlg_data {
    khui_config_init_data cfg;  /* instance information for this
                                   dialog */

    khm_handle ident;           /* handle to the identity for this
                                   dialog */

    /* TODO: Add any fields for holding state here */
} config_id_dlg_data;

INT_PTR CALLBACK
config_id_dlgproc(HWND hwnd,
                  UINT uMsg,
                  WPARAM wParam,
                  LPARAM lParam) {

    config_id_dlg_data * d;

    switch (uMsg) {
    case WM_INITDIALOG:
        {
            wchar_t idname[KCDB_IDENT_MAXCCH_NAME];
            khm_size cb;
            khm_int32 rv;

            d = malloc(sizeof(*d));
            assert(d);
            ZeroMemory(d, sizeof(*d));

            /* for subpanels, lParam is a pointer to a
               khui_config_init_data strucutre that provides the
               instance and context information.  It's not a
               persistent strucutre, so we have to make a copy. */
            d->cfg = *((khui_config_init_data *) lParam);

            cb = sizeof(idname);
            rv = khui_cfg_get_name(d->cfg.ctx_node, idname, &cb);
            assert(KHM_SUCCEEDED(rv));

            rv = kcdb_identity_create(idname, 0, &d->ident);
            assert(KHM_SUCCEEDED(rv));

            /* TODO: perform any other required initialization */

#pragma warning(push)
#pragma warning(disable: 4244)
            SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) d);
#pragma warning(pop)
        }
        break;

    case KHUI_WM_CFG_NOTIFY:
        d = (config_id_dlg_data *)
            GetWindowLongPtr(hwnd, DWLP_USER);

        if (HIWORD(wParam) == WMCFG_APPLY) {
            /* TODO: apply changes */

            return TRUE;
        }
        break;

    case WM_DESTROY:
        {
            d = (config_id_dlg_data *)
                GetWindowLongPtr(hwnd, DWLP_USER);

            if (d) {
                if (d->ident)
                    kcdb_identity_release(d->ident);

                /* TODO: perform any other required uninitialization */

                free(d);
            }
        }
        break;
    }

    return FALSE;

}

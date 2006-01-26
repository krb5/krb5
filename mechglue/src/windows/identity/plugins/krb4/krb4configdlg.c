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

#include<krbcred.h>
#include<kherror.h>
#include<khuidefs.h>
#include<strsafe.h>
#include<assert.h>

typedef struct tag_k4_ids_data {
    khui_config_init_data cfg;

    khm_int32 get_tix;
} k4_ids_data;

static void
k4_ids_read_params(k4_ids_data * d) {
    khm_int32 t;
#ifdef DEBUG
    assert(csp_params);
#endif

    t = 1;
    khc_read_int32(csp_params, L"Krb4NewCreds", &t);
    d->get_tix = !!t;
}

static void
k4_ids_write_params(HWND hw, k4_ids_data * d) {
    khm_int32 nv;
    khm_boolean applied = FALSE;

    if (IsDlgButtonChecked(hw, IDC_CFG_GETTIX) == BST_CHECKED)
        nv = TRUE;
    else
        nv = FALSE;

    if (!!nv != !!d->get_tix) {
        d->get_tix = !!nv;
        khc_write_int32(csp_params, L"Krb4NewCreds", d->get_tix);
        applied = TRUE;
    }

    khui_cfg_set_flags_inst(&d->cfg,
                            (applied)?KHUI_CNFLAG_APPLIED:0,
                            KHUI_CNFLAG_APPLIED | KHUI_CNFLAG_MODIFIED);
}

static void
k4_ids_check_mod(HWND hw, k4_ids_data * d) {
    khm_int32 nv;

    if (IsDlgButtonChecked(hw, IDC_CFG_GETTIX) == BST_CHECKED)
        nv = TRUE;
    else
        nv = FALSE;

    khui_cfg_set_flags_inst(&d->cfg,
                            (!!nv != !!d->get_tix)? KHUI_CNFLAG_MODIFIED: 0,
                            KHUI_CNFLAG_MODIFIED);
}

INT_PTR CALLBACK
krb4_ids_config_proc(HWND hwnd,
                     UINT uMsg,
                     WPARAM wParam,
                     LPARAM lParam) {
    k4_ids_data * d;

    switch(uMsg) {
    case WM_INITDIALOG:
        d = PMALLOC(sizeof(*d));
        ZeroMemory(d, sizeof(*d));

        d->cfg = *((khui_config_init_data *) lParam);

#pragma warning(push)
#pragma warning(disable: 4244)
        SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) d);
#pragma warning(pop)

        k4_ids_read_params(d);

        CheckDlgButton(hwnd, IDC_CFG_GETTIX,
                       (d->get_tix)? BST_CHECKED: BST_UNCHECKED);

        break;

    case WM_COMMAND:
        d = (k4_ids_data *) (LONG_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);

        if (HIWORD(wParam) == BN_CLICKED) {
            k4_ids_check_mod(hwnd, d);
        }
        break;

    case KHUI_WM_CFG_NOTIFY:
        d = (k4_ids_data *) (LONG_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);

        if (HIWORD(wParam) == WMCFG_APPLY) {
            k4_ids_write_params(hwnd, d);
        }
        break;

    case WM_DESTROY:
        d = (k4_ids_data *) (LONG_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);

        PFREE(d);
        break;
    }

    return FALSE;
}

INT_PTR CALLBACK
krb4_id_config_proc(HWND hwnd,
                    UINT uMsg,
                    WPARAM wParam,
                    LPARAM lParam) {
    switch(uMsg) {
    case WM_INITDIALOG:
        {
            wchar_t idname[KCDB_IDENT_MAXCCH_NAME];
            khm_size cb;
            khui_config_init_data * d;
            khm_handle ident = NULL;
            khm_int32 gettix = 0;
            khm_int32 flags = 0;

            d = (khui_config_init_data *) lParam;

            khc_read_int32(csp_params, L"Krb4NewCreds", &gettix);
            if (gettix == 0)
                goto set_ui;

            *idname = 0;
            cb = sizeof(idname);
            khui_cfg_get_name(d->ctx_node, idname, &cb);

            kcdb_identity_create(idname, 0, &ident);

            if (ident == NULL) {
                gettix = 0;
                goto set_ui;
            }

            kcdb_identity_get_flags(ident, &flags);

            kcdb_identity_release(ident);

            if (!(flags & KCDB_IDENT_FLAG_DEFAULT))
                gettix = 0;

        set_ui:
            CheckDlgButton(hwnd, IDC_CFG_GETTIX,
                           (gettix)?BST_CHECKED: BST_UNCHECKED);
        }
        break;
    }

    return FALSE;
}


INT_PTR CALLBACK
krb4_confg_proc(HWND hwnd,
                UINT uMsg,
                WPARAM wParam,
                LPARAM lParam) {

    switch(uMsg) {
    case WM_INITDIALOG:
        {
            wchar_t wbuf[MAX_PATH];
            CHAR krb_path[MAX_PATH];
            CHAR krbrealm_path[MAX_PATH];
            CHAR ticketName[MAX_PATH];
            char * pticketName;
            unsigned int krb_path_sz = sizeof(krb_path);
            unsigned int krbrealm_path_sz = sizeof(krbrealm_path); 
    
            // Set KRB.CON 
            memset(krb_path, '\0', sizeof(krb_path));
            if (!pkrb_get_krbconf2(krb_path, &krb_path_sz)) {
                // Error has happened
            } else { // normal find
                AnsiStrToUnicode(wbuf, sizeof(wbuf), krb_path);
                SetDlgItemText(hwnd, IDC_CFG_CFGPATH, wbuf);
            }

            // Set KRBREALM.CON 
            memset(krbrealm_path, '\0', sizeof(krbrealm_path));
            if (!pkrb_get_krbrealm2(krbrealm_path, &krbrealm_path_sz)) {   
                // Error has happened
            } else {
                AnsiStrToUnicode(wbuf, sizeof(wbuf), krbrealm_path);
                SetDlgItemText(hwnd, IDC_CFG_RLMPATH, wbuf);
            }

            // Set TICKET.KRB file Editbox
            *ticketName = 0;
            pkrb_set_tkt_string(0);
    
            pticketName = ptkt_string(); 
            if (pticketName)
                StringCbCopyA(ticketName, sizeof(ticketName), pticketName);
	
            if (!*ticketName) {
                // error
            } else {
                AnsiStrToUnicode(wbuf, sizeof(wbuf), ticketName);
                SetDlgItemText(hwnd, IDC_CFG_CACHE, wbuf);
            }
        }
        break;

    case WM_DESTROY:
        break;
    }
    return FALSE;
}

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

        if (d == NULL)
            break;

        if (HIWORD(wParam) == BN_CLICKED) {
            k4_ids_check_mod(hwnd, d);
        }
        break;

    case KHUI_WM_CFG_NOTIFY:
        d = (k4_ids_data *) (LONG_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);

        if (d == NULL)
            break;

        if (HIWORD(wParam) == WMCFG_APPLY) {
            k4_ids_write_params(hwnd, d);
        }
        break;

    case WM_DESTROY:
        d = (k4_ids_data *) (LONG_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);

        if (d) {
            PFREE(d);
            SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) 0);
        }

        break;
    }

    return FALSE;
}

typedef struct tag_k4_id_data {
    khui_config_init_data cfg;
    khm_int32 gettix;           /* get tickets? */
    khm_boolean is_default_ident;
} k4_id_data;

void
k4_id_read_params(k4_id_data * d) {
    wchar_t idname[KCDB_IDENT_MAXCCH_NAME];
    khm_size cb;
    khm_handle ident = NULL;
    khm_handle csp_ident = NULL;
    khm_handle csp_idk4 = NULL;
    khm_int32 flags = 0;
    khm_int32 t;

    khc_read_int32(csp_params, L"Krb4NewCreds", &d->gettix);

    *idname = 0;
    cb = sizeof(idname);
    khui_cfg_get_name(d->cfg.ctx_node, idname, &cb);

    kcdb_identity_create(idname, 0, &ident);

    if (ident == NULL) {
        d->gettix = 0;
        goto done;
    }

    kcdb_identity_get_flags(ident, &flags);

    if (!(flags & KCDB_IDENT_FLAG_DEFAULT)) {
        d->gettix = 0;
        goto done;
    }

    d->is_default_ident = TRUE;

    if (d->gettix == 0)
        goto done;

    if (KHM_FAILED(kcdb_identity_get_config(ident, 0, &csp_ident)))
        goto done;

    if (KHM_FAILED(khc_open_space(csp_ident, CSNAME_KRB4CRED,
                                  0, &csp_idk4)))
        goto close_config;

    if (KHM_SUCCEEDED(khc_read_int32(csp_idk4, L"Krb4NewCreds", &t)) &&
        !t)
        d->gettix = 1;

 close_config:
    if (csp_ident)
        khc_close_space(csp_ident);

    if (csp_idk4)
        khc_close_space(csp_idk4);

 done:
    if (ident)
        kcdb_identity_release(ident);

    return;
}

khm_boolean
k4_id_write_params(HWND hwnd, k4_id_data * d) {
    wchar_t idname[KCDB_IDENT_MAXCCH_NAME];
    khm_size cb_idname = sizeof(idname);
    khm_handle ident = NULL;
    khm_int32 flags = 0;
    khm_handle csp_ident = NULL;
    khm_handle csp_idk4 = NULL;
    khm_int32 gettix = 0;
    khm_boolean applied = FALSE;

    khui_cfg_get_name(d->cfg.ctx_node, idname, &cb_idname);

    kcdb_identity_create(idname, 0, &ident);

    if (ident == NULL)
        return FALSE;

    kcdb_identity_get_flags(ident, &flags);

    if (!(flags & KCDB_IDENT_FLAG_DEFAULT))
        goto done_apply;

    if (IsDlgButtonChecked(hwnd, IDC_CFG_GETTIX) == BST_CHECKED)
        gettix = TRUE;

    if (KHM_FAILED(kcdb_identity_get_config(ident, KHM_FLAG_CREATE,
                                            &csp_ident)))
        goto done_apply;

    if (KHM_FAILED(khc_open_space(csp_ident, CSNAME_KRB4CRED,
                                  KHM_FLAG_CREATE | KCONF_FLAG_WRITEIFMOD,
                                  &csp_idk4)))
        goto done_apply;

    khc_write_int32(csp_idk4, L"Krb4NewCreds", gettix);

    applied = TRUE;

 done_apply:
    if (ident)
        kcdb_identity_release(ident);

    if (csp_ident)
        khc_close_space(csp_ident);
    
    if (csp_idk4)
        khc_close_space(csp_idk4);

    return applied;
}

INT_PTR CALLBACK
krb4_id_config_proc(HWND hwnd,
                    UINT uMsg,
                    WPARAM wParam,
                    LPARAM lParam) {
    switch(uMsg) {
    case WM_INITDIALOG:
        {
            k4_id_data * d;

            d = PMALLOC(sizeof(k4_id_data));

            if (!d)
                break;

            ZeroMemory(d, sizeof(*d));

            d->cfg = *((khui_config_init_data *) lParam);

#pragma warning(push)
#pragma warning(disable: 4244)
            SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) d);
#pragma warning(pop)

            k4_id_read_params(d);

            CheckDlgButton(hwnd, IDC_CFG_GETTIX,
                           (d->gettix)?BST_CHECKED: BST_UNCHECKED);
            EnableWindow(GetDlgItem(hwnd, IDC_CFG_GETTIX),
                         d->is_default_ident);

        }
        break;

    case WM_COMMAND:
        {
            k4_id_data * d;

            d = (k4_id_data *) (LONG_PTR)
                GetWindowLongPtr(hwnd, DWLP_USER);

            if (d == NULL)
                break;

            if (wParam == MAKEWPARAM(IDC_CFG_GETTIX,
                                     BN_CLICKED)) {
                int gettix = 0;
                int modified = 0;

                gettix = (IsDlgButtonChecked(hwnd, IDC_CFG_GETTIX) ==
                          BST_CHECKED);

                modified = (!!gettix != !!d->gettix);

                khui_cfg_set_flags_inst(&d->cfg,
                                        ((modified)?KHUI_CNFLAG_MODIFIED: 0),
                                        KHUI_CNFLAG_MODIFIED);
            }
        }
        break;

    case KHUI_WM_CFG_NOTIFY:
        {
            k4_id_data * d;

            d = (k4_id_data *) (LONG_PTR)
                GetWindowLongPtr(hwnd, DWLP_USER);

            if (d == NULL)
                break;

            if (HIWORD(wParam) == WMCFG_APPLY) {
                khm_int32 applied;

                applied = k4_id_write_params(hwnd, d);

                khui_cfg_set_flags_inst(&d->cfg,
                                        ((applied)? KHUI_CNFLAG_APPLIED: 0),
                                        (KHUI_CNFLAG_APPLIED | KHUI_CNFLAG_MODIFIED));
            }
        }
        break;

    case WM_DESTROY:
        {
            k4_id_data * d;

            d = (k4_id_data *) (LONG_PTR)
                GetWindowLongPtr(hwnd, DWLP_USER);

            if (d == NULL)
                break;

            PFREE(d);

            SetWindowLongPtr(hwnd, DWLP_USER, 0);
        }
        break;
    }

    return FALSE;
}

typedef struct tag_k4_config_dlg_data {
    khui_config_node node;
    char             krb_path[MAX_PATH];
    char             krbrealm_path[MAX_PATH];
    char             tkt_string[MAX_PATH];
} k4_config_dlg_data;

INT_PTR CALLBACK
krb4_confg_proc(HWND hwnd,
                UINT uMsg,
                WPARAM wParam,
                LPARAM lParam) {

    static BOOL in_init = FALSE;
    k4_config_dlg_data * d;

    switch(uMsg) {
    case WM_INITDIALOG:
        {
            wchar_t wbuf[MAX_PATH];
            CHAR krb_path[MAX_PATH];
            CHAR krbrealm_path[MAX_PATH];
            CHAR ticketName[MAX_PATH];
            char * pticketName;
            size_t krb_path_sz = sizeof(krb_path);
            size_t krbrealm_path_sz = sizeof(krbrealm_path);
            khm_size cbsize;

            d = PMALLOC(sizeof(*d));
            ZeroMemory(d, sizeof(*d));

#pragma warning(push)
#pragma warning(disable: 4244)
            SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) d);
#pragma warning(pop)

            d->node = (khui_config_node) lParam;

            in_init = TRUE;

            // Set KRB.CON 
            memset(krb_path, '\0', sizeof(krb_path));
            if (!pkrb_get_krbconf2(krb_path, &krb_path_sz)) {
                // Error has happened
            } else { // normal find
                AnsiStrToUnicode(wbuf, sizeof(wbuf), krb_path);
                SetDlgItemText(hwnd, IDC_CFG_CFGPATH, wbuf);
                StringCbCopyA(d->krb_path, sizeof(d->krb_path), krb_path);
            }

            // Set KRBREALM.CON 
            memset(krbrealm_path, '\0', sizeof(krbrealm_path));
            if (!pkrb_get_krbrealm2(krbrealm_path, &krbrealm_path_sz)) {   
                // Error has happened
            } else {
                AnsiStrToUnicode(wbuf, sizeof(wbuf), krbrealm_path);
                SetDlgItemText(hwnd, IDC_CFG_RLMPATH, wbuf);
                StringCbCopyA(d->krbrealm_path, sizeof(d->krbrealm_path),
                              krbrealm_path);
            }

            cbsize = sizeof(wbuf);
            if (KHM_SUCCEEDED(khc_read_string(csp_params, L"TktString",
                                              wbuf, &cbsize)) &&
                wbuf[0] != L'\0') {

                UnicodeStrToAnsi(ticketName, sizeof(ticketName), wbuf);

            } else {

                // Set TICKET.KRB file Editbox
                *ticketName = 0;
                pkrb_set_tkt_string(0);
    
                pticketName = ptkt_string(); 
                if (pticketName)
                    StringCbCopyA(ticketName, sizeof(ticketName), pticketName);

            }
	
            if (!*ticketName) {
                // error
            } else {
                AnsiStrToUnicode(wbuf, sizeof(wbuf), ticketName);
                SetDlgItemText(hwnd, IDC_CFG_CACHE, wbuf);
                StringCbCopyA(d->tkt_string, sizeof(d->tkt_string),
                              ticketName);
            }

            in_init = FALSE;

        }
        break;

    case WM_COMMAND:
        if (MAKEWPARAM(IDC_CFG_CACHE, EN_CHANGE)) {
            char tkt_string[MAX_PATH];
            wchar_t wtkt_string[MAX_PATH];

            if (in_init) {
                return TRUE;
            }

            d = (k4_config_dlg_data *) (LONG_PTR)
                GetWindowLongPtr(hwnd, DWLP_USER);

            if (d == NULL)
                return TRUE;

            tkt_string[0] = 0;
            wtkt_string[0] = 0;

            GetDlgItemText(hwnd, IDC_CFG_CACHE,
                           wtkt_string, ARRAYLENGTH(wtkt_string));
            UnicodeStrToAnsi(tkt_string, sizeof(tkt_string),
                             wtkt_string);

            if (_stricmp(tkt_string, d->tkt_string)) {
                khui_cfg_set_flags(d->node,
                                   KHUI_CNFLAG_MODIFIED,
                                   KHUI_CNFLAG_MODIFIED);
            } else {
                khui_cfg_set_flags(d->node,
                                   0,
                                   KHUI_CNFLAG_MODIFIED);
            }

            return TRUE;
        }
        break;

    case KHUI_WM_CFG_NOTIFY:
        if (HIWORD(wParam) == WMCFG_APPLY) {
            wchar_t wtkt_string[MAX_PATH];
            char tkt_string[MAX_PATH];
            int t;

            d = (k4_config_dlg_data *) (LONG_PTR)
                GetWindowLongPtr(hwnd, DWLP_USER);

            if (d == NULL)
                return TRUE;

            t = GetDlgItemText(hwnd, IDC_CFG_CACHE,
                               wtkt_string, ARRAYLENGTH(wtkt_string));
            if (t == 0)
                return TRUE;

            UnicodeStrToAnsi(tkt_string, sizeof(tkt_string), wtkt_string);

            if (_stricmp(tkt_string, d->tkt_string)) {

                pkrb_set_tkt_string(tkt_string);

                khc_write_string(csp_params, L"TktString", wtkt_string);

                khui_cfg_set_flags(d->node,
                                   KHUI_CNFLAG_APPLIED,
                                   KHUI_CNFLAG_APPLIED |
                                   KHUI_CNFLAG_MODIFIED);
                khm_krb4_list_tickets();
            } else {
                khui_cfg_set_flags(d->node,
                                   0,
                                   KHUI_CNFLAG_MODIFIED);
            }

            return TRUE;
        }
        break;

    case WM_DESTROY:
        d = (k4_config_dlg_data *) (LONG_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);

        if (d) {
            PFREE(d);
            SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) 0);
        }

        break;
    }
    return FALSE;
}

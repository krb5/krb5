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
#include<khmsgtypes.h>
#include<khuidefs.h>
#include<utils.h>
#include<commctrl.h>
#include<strsafe.h>
#include<krb5.h>
#include<assert.h>

/* method identifiers should be contiguous */
#define K4_METHOD_AUTO     0
#define K4_METHOD_PASSWORD 1
#define K4_METHOD_K524     2

int method_to_id[] = {
    IDC_NCK4_AUTO,
    IDC_NCK4_PWD,
    IDC_NCK4_K524
};

typedef struct tag_k4_dlg_data {
    HWND hwnd;
    khui_new_creds * nc;
    khui_new_creds_by_type * nct;

    khm_boolean      k4_enabled;
    khm_int32        method;
    time_t           lifetime;
} k4_dlg_data;

void k4_update_display(k4_dlg_data * d, BOOL update_methods) {
    CheckDlgButton(d->hwnd, IDC_NCK4_OBTAIN,
                   (d->k4_enabled)?BST_CHECKED: BST_UNCHECKED);

    if (d->k4_enabled) {
        EnableWindow(GetDlgItem(d->hwnd, IDC_NCK4_AUTO), TRUE);
        EnableWindow(GetDlgItem(d->hwnd, IDC_NCK4_K524), TRUE);
        EnableWindow(GetDlgItem(d->hwnd, IDC_NCK4_PWD ), TRUE);
    } else {
        EnableWindow(GetDlgItem(d->hwnd, IDC_NCK4_AUTO), FALSE);
        EnableWindow(GetDlgItem(d->hwnd, IDC_NCK4_K524), FALSE);
        EnableWindow(GetDlgItem(d->hwnd, IDC_NCK4_PWD ), FALSE);
    }

#ifdef DEBUG
    assert(d->method >= 0 && d->method < ARRAYLENGTH(method_to_id));
#endif

    CheckRadioButton(d->hwnd, IDC_NCK4_AUTO, IDC_NCK4_PWD, method_to_id[d->method]);

    khui_cw_enable_type(d->nc, credtype_id_krb4, d->k4_enabled);
}

void k4_update_data(k4_dlg_data * d) {
    int i;
    khm_boolean oldstate;

    oldstate = d->k4_enabled;

    if (IsDlgButtonChecked(d->hwnd, IDC_NCK4_OBTAIN) == BST_CHECKED)
        d->k4_enabled = TRUE;
    else
        d->k4_enabled = FALSE;

    if ((oldstate && !d->k4_enabled) ||
        (!oldstate && d->k4_enabled)) {

        khui_cw_enable_type(d->nc, credtype_id_krb4, d->k4_enabled);
    }

    d->method = K4_METHOD_AUTO;

    for (i=K4_METHOD_AUTO; i<=K4_METHOD_K524; i++) {
        if (IsDlgButtonChecked(d->hwnd, method_to_id[i]) == BST_CHECKED) {
            d->method = i;
            break;
        }
    }
}

khm_boolean k4_should_identity_get_k4(khm_handle ident) {
    khm_int32 idflags = 0;
    khm_int32 t = TRUE;
    khm_handle csp_ident = NULL;
    khm_handle csp_k4 = NULL;
    khm_boolean get_k4 = TRUE;
    khm_boolean id_spec = FALSE;

    if (KHM_FAILED(kcdb_identity_get_flags(ident, &idflags)))
        return FALSE;

    if (!(idflags & KCDB_IDENT_FLAG_DEFAULT)) {
        /* we only support k4 for one identity, and that is the
           default identity.  If we are trying to get tickets for a
           non-default identity, then we start off as disabled unless
           there is no default identity. */

        khm_handle defident = NULL;

        if (KHM_SUCCEEDED(kcdb_identity_get_default(&defident))) {
            kcdb_identity_release(defident);

            return FALSE;
        }
    }

    if (KHM_SUCCEEDED(kcdb_identity_get_config(ident, 0, &csp_ident))) {
        if (KHM_SUCCEEDED(khc_open_space(csp_ident, CSNAME_KRB4CRED, 0,
                                         &csp_k4))) {
            khm_int32 t = 0;

            if (KHM_SUCCEEDED(khc_read_int32(csp_k4, L"Krb4NewCreds", &t))) {
                get_k4 = !!t;
                id_spec = TRUE;
            }

            khc_close_space(csp_k4);
        }
        khc_close_space(csp_ident);
    }

    /* if there was a value specified for the identity, then that
       takes precedence. */
    if (id_spec || !get_k4)
        return get_k4;

    if (KHM_SUCCEEDED(khc_read_int32(csp_params, L"Krb4NewCreds", &t)) &&
        !t)
        return FALSE;

    return TRUE;
}

void k4_read_identity_data(k4_dlg_data * d) {
    khm_handle csp_ident = NULL;
    khm_handle csp_k4 = NULL;

    khm_int32 idflags = 0;
    khm_int32 t;

    if (KHM_SUCCEEDED(khc_read_int32(csp_params, L"Krb4NewCreds", &t)))
        d->k4_enabled = !!t;
    else
        d->k4_enabled = TRUE;

    if (KHM_SUCCEEDED(khc_read_int32(csp_params, L"Krb4Method", &t)))
        d->method = t;
    else
        d->method = K4_METHOD_AUTO;

    if (KHM_SUCCEEDED(khc_read_int32(csp_params, L"DefaultLifetime", &t)))
        d->lifetime = t;
    else
        d->lifetime = 10 * 60 * 60; /* 10 hours */

    if (d->nc->n_identities > 0 &&
        d->nc->identities[0]) {

        if (KHM_SUCCEEDED(kcdb_identity_get_config(d->nc->identities[0],
                                                   0,
                                                   &csp_ident))) {

            khc_open_space(csp_ident, CSNAME_KRB4CRED, 0, &csp_k4);
            
            if (csp_k4) {
                if (KHM_SUCCEEDED(khc_read_int32(csp_k4, L"Krb4NewCreds", &t)))
                    d->k4_enabled = !!t;
                if (KHM_SUCCEEDED(khc_read_int32(csp_k4, L"Krb4Method", &t)))
                    d->method = t;
                khc_close_space(csp_k4);
            }

            khc_close_space(csp_ident);
        }

        if (d->k4_enabled) {
            d->k4_enabled = k4_should_identity_get_k4(d->nc->identities[0]);
        }
    } else {
        d->k4_enabled = FALSE;
    }

    if (d->method < 0 || d->method > K4_METHOD_K524)
        d->method = K4_METHOD_AUTO;
}

void k4_write_identity_data(k4_dlg_data * d) {
    khm_handle csp_ident = NULL;
    khm_handle csp_k4 = NULL;

    if (d->nc->n_identities > 0 &&
        d->nc->identities[0] &&
        KHM_SUCCEEDED(kcdb_identity_get_config(d->nc->identities[0],
                                               KHM_FLAG_CREATE,
                                               &csp_ident))) {
        khc_open_space(csp_ident, CSNAME_KRB4CRED,
                       KHM_FLAG_CREATE | KCONF_FLAG_WRITEIFMOD,
                       &csp_k4);

        if (csp_k4) {
            khc_write_int32(csp_k4, L"Krb4NewCreds", !!d->k4_enabled);
            khc_write_int32(csp_k4, L"Krb4Method", d->method);

            khc_close_space(csp_k4);
        }

        khc_close_space(csp_ident);
    }
}

void k4_handle_wmnc_notify(k4_dlg_data * d,
                           WPARAM wParam,
                           LPARAM lParam) {
    switch(HIWORD(wParam)) {
    case WMNC_UPDATE_CREDTEXT:
        {
            if (d->nct->credtext) {
                PFREE(d->nct->credtext);
                d->nct->credtext = NULL;
            }

            if (d->nc->n_identities > 0 &&
                d->nc->identities[0]) {

                khm_int32 flags = 0;
                wchar_t idname[KCDB_IDENT_MAXCCH_NAME];
                wchar_t * atsign;
                wchar_t * realm;
                khm_size cb;

                kcdb_identity_get_flags(d->nc->identities[0], &flags);

                if (!(flags & KCDB_IDENT_FLAG_VALID)) {
                    break;
                }

                cb = sizeof(idname);
                kcdb_identity_get_name(d->nc->identities[0], idname,
                                       &cb);

                atsign = wcsrchr(idname, L'@');

                if (atsign == NULL || !atsign[1])
                    break;

                realm = ++atsign;

                if (d->k4_enabled) {
                    wchar_t wmethod[128];
                    wchar_t wfmt[128];
                    wchar_t wct[512];

                    LoadString(hResModule, IDS_CT_TGTFOR,
                               wfmt, ARRAYLENGTH(wfmt));

                    if (d->method == K4_METHOD_AUTO)
                        LoadString(hResModule, IDS_METHOD_AUTO, wmethod,
                                   ARRAYLENGTH(wmethod));
                    else if (d->method == K4_METHOD_PASSWORD)
                        LoadString(hResModule, IDS_METHOD_PWD, wmethod,
                                   ARRAYLENGTH(wmethod));
                    else if (d->method == K4_METHOD_K524)
                        LoadString(hResModule, IDS_METHOD_K524, wmethod,
                                   ARRAYLENGTH(wmethod));
                    else {
                        assert(FALSE);
                    }

                    StringCbPrintf(wct, sizeof(wct), wfmt, realm, wmethod);

                    StringCbLength(wct, sizeof(wct), &cb);
                    cb += sizeof(wchar_t);

                    d->nct->credtext = PMALLOC(cb);

                    StringCbCopy(d->nct->credtext, cb, wct);
                } else {
                    wchar_t wct[256];

                    LoadString(hResModule, IDS_CT_DISABLED,
                               wct, ARRAYLENGTH(wct));

                    StringCbLength(wct, sizeof(wct), &cb);
                    cb += sizeof(wchar_t);

                    d->nct->credtext = PMALLOC(cb);

                    StringCbCopy(d->nct->credtext, cb, wct);
                }
            }
            /* no identities were selected.  it is not the
               responsibility of krb4 to complain about this. */
        }
        break;

    case WMNC_IDENTITY_CHANGE:
        k4_read_identity_data(d);
        k4_update_display(d, TRUE);
        break;

    case WMNC_CREDTEXT_LINK:
        {
            wchar_t wid[KHUI_MAXCCH_HTLINK_FIELD];
            wchar_t * wids;
            khui_htwnd_link * l;

            l = (khui_htwnd_link *) lParam;

            StringCchCopyN(wid, ARRAYLENGTH(wid), l->id, l->id_len);
            wids = wcschr(wid, L':');

            if (!wids)
                break;
            else
                wids++;

            if (!wcscmp(wids, L"Enable")) {
                d->k4_enabled = TRUE;

                k4_update_display(d, TRUE);
                khui_cw_enable_type(d->nc, credtype_id_krb4, TRUE);
            }
        }
        break;
    }
}

INT_PTR CALLBACK k4_nc_dlg_proc(HWND hwnd,
                                UINT uMsg,
                                WPARAM wParam,
                                LPARAM lParam) {

    k4_dlg_data * d;

    switch(uMsg) {
    case WM_INITDIALOG:
        {
            d = PMALLOC(sizeof(*d));
            ZeroMemory(d, sizeof(*d));

            d->nc = (khui_new_creds *) lParam;
            khui_cw_find_type(d->nc, credtype_id_krb4, &d->nct);

#pragma warning(push)
#pragma warning(disable: 4244)
            SetWindowLongPtr(hwnd, DWLP_USER, (LPARAM) d);
#pragma warning(pop)

            d->nct->aux = (LPARAM) d;
            d->hwnd = hwnd;

            d->k4_enabled = TRUE;
            d->method = K4_METHOD_AUTO;

            k4_update_display(d, TRUE);
        }
        break;

    case WM_COMMAND:
        {
            if (HIWORD(wParam) == BN_CLICKED) {
                d = (k4_dlg_data *) (LONG_PTR)
                    GetWindowLongPtr(hwnd, DWLP_USER);

                k4_update_data(d);

                if (LOWORD(wParam) == IDC_NCK4_OBTAIN) {
                    k4_update_display(d, TRUE);
                }

                return TRUE;
            }
        }
        break;

    case KHUI_WM_NC_NOTIFY:
        {
            d = (k4_dlg_data *) (LONG_PTR)
                GetWindowLongPtr(hwnd, DWLP_USER);
            k4_handle_wmnc_notify(d, wParam, lParam);
        }
        break;

    case WM_DESTROY:
        {
            d = (k4_dlg_data *) (LONG_PTR)
                GetWindowLongPtr(hwnd, DWLP_USER);

            d->nct->aux = 0;

            PFREE(d);
        }
        break;
    }

    return FALSE;
}

khm_int32
krb4_msg_newcred(khm_int32 msg_type, khm_int32 msg_subtype,
                 khm_ui_4 uparam, void * vparam) {

    switch(msg_subtype) {
    case KMSG_CRED_NEW_CREDS:
        {
            khui_new_creds * nc;
            khui_new_creds_by_type * nct;
            khm_size cbsize;
            wchar_t wbuf[256];

            nc = (khui_new_creds *) vparam;

            nct = PMALLOC(sizeof(*nct));
#ifdef DEBUG
            assert(nct);
#endif
            ZeroMemory(nct, sizeof(*nct));

            nct->type = credtype_id_krb4;
            nct->ordinal = 3;
            LoadString(hResModule, IDS_NC_K4_SHORT,
                       wbuf, ARRAYLENGTH(wbuf));
            StringCbLength(wbuf, sizeof(wbuf), &cbsize);
            cbsize += sizeof(wchar_t);

            nct->name = PMALLOC(cbsize);
            StringCbCopy(nct->name, cbsize, wbuf);

            nct->type_deps[nct->n_type_deps++] = credtype_id_krb5;

            nct->h_module = hResModule;
            nct->dlg_proc = k4_nc_dlg_proc;
            nct->dlg_template = MAKEINTRESOURCE(IDD_NC_KRB4);

            khui_cw_add_type(nc, nct);
        }
        break;

    case KMSG_CRED_RENEW_CREDS:
        {
            khui_new_creds * nc;
            khui_new_creds_by_type * nct;
            khm_size cbsize;
            wchar_t wbuf[256];

            nc = (khui_new_creds *) vparam;

            if (!nc->ctx.identity)
                break;

            nct = PMALLOC(sizeof(*nct));
#ifdef DEBUG
            assert(nct);
#endif

            ZeroMemory(nct, sizeof(*nct));

            nct->type = credtype_id_krb4;
            nct->ordinal = 3;
            LoadString(hResModule, IDS_NC_K4_SHORT,
                       wbuf, ARRAYLENGTH(wbuf));
            StringCbLength(wbuf, sizeof(wbuf), &cbsize);
            cbsize += sizeof(wchar_t);

            nct->name = PMALLOC(cbsize);
            StringCbCopy(nct->name, cbsize, wbuf);

            nct->type_deps[nct->n_type_deps++] = credtype_id_krb5;

            khui_cw_add_type(nc, nct);
        }
        break;

    case KMSG_CRED_DIALOG_SETUP:
        break;

    case KMSG_CRED_PROCESS:
        {
            khui_new_creds * nc;
            khui_new_creds_by_type * nct = NULL;
            khm_handle ident = NULL;
            k4_dlg_data * d = NULL;
            long code = 0;
            wchar_t idname[KCDB_IDENT_MAXCCH_NAME];
            khm_size cb;

            nc = (khui_new_creds *) vparam;
            if (KHM_FAILED(khui_cw_find_type(nc, credtype_id_krb4, &nct)))
                break;

            if (nc->subtype == KMSG_CRED_NEW_CREDS ||
                nc->subtype == KMSG_CRED_RENEW_CREDS) {
                khm_int32 method;

                if (nc->subtype == KMSG_CRED_NEW_CREDS) {

                    d = (k4_dlg_data *) nct->aux;
                    if (!d ||
                        nc->n_identities == 0 ||
                        nc->identities[0] == NULL ||
                        nc->result != KHUI_NC_RESULT_PROCESS) {
                        khui_cw_set_response(nc, credtype_id_krb4,
                                             KHUI_NC_RESPONSE_SUCCESS |
                                             KHUI_NC_RESPONSE_EXIT);
                        break;
                    }

                    if (!d->k4_enabled) {
                        k4_write_identity_data(d);
                        khui_cw_set_response(nc, credtype_id_krb4,
                                             KHUI_NC_RESPONSE_SUCCESS |
                                             KHUI_NC_RESPONSE_EXIT);
                        break;
                    }

                    method = d->method;
                    ident = nc->identities[0];

                    cb = sizeof(idname);
                    kcdb_identity_get_name(ident, idname, &cb);
                    _begin_task(0);
                    _report_mr2(KHERR_NONE, MSG_K4_NEW_CREDS,
                                _cstr(ident), _int32(method));
                    _resolve();
                    _describe();

                } else if (nc->subtype == KMSG_CRED_RENEW_CREDS) {

                    if ((nc->ctx.scope == KHUI_SCOPE_IDENT &&
                         nc->ctx.identity != NULL) ||

                        (nc->ctx.scope == KHUI_SCOPE_CREDTYPE &&
                         nc->ctx.cred_type == credtype_id_krb4 &&
                         nc->ctx.identity != NULL) ||

                        (nc->ctx.scope == KHUI_SCOPE_CRED &&
                         nc->ctx.cred_type == credtype_id_krb4 &&
                         nc->ctx.identity != NULL &&
                         nc->ctx.cred != NULL)) {

                        ident = nc->ctx.identity;

                        if (!k4_should_identity_get_k4(ident)) {

                            _reportf(L"Kerberos 4 is not enabled for this identity.  Skipping");

                            khui_cw_set_response(nc, credtype_id_krb4,
                                                 KHUI_NC_RESPONSE_FAILED |
                                                 KHUI_NC_RESPONSE_EXIT);
                            break;
                        }

                    } else {

                        _reportf(L"Kerberos 4 is not within renewal scope. Skipping");

                        khui_cw_set_response(nc, credtype_id_krb4,
                                             KHUI_NC_RESPONSE_FAILED |
                                             KHUI_NC_RESPONSE_EXIT);
                        break;
                    }

                    method = K4_METHOD_K524; /* only k524 is supported
                                                for renewals */

                    _begin_task(0);
                    cb = sizeof(idname);
                    kcdb_identity_get_name(ident, idname, &cb);
                    _report_mr2(KHERR_NONE, MSG_K4_RENEW_CREDS,
                                _cstr(ident), _int32(method));
                    _resolve();
                    _describe();
                } else {
                    assert(FALSE);
                    break;
                }

                if ((method == K4_METHOD_AUTO ||
                     method == K4_METHOD_K524) &&
                    khui_cw_type_succeeded(nc, credtype_id_krb5)) {

                    khm_handle tgt;
                    FILETIME ft_prev;
                    FILETIME ft_new;
                    khm_size cb;

                    _report_mr0(KHERR_INFO, MSG_K4_TRY_K524);

                    tgt = khm_krb4_find_tgt(NULL, ident);
                    if (tgt) {
                        cb = sizeof(ft_prev);
                        if (KHM_FAILED(kcdb_cred_get_attr(tgt,
                                                          KCDB_ATTR_EXPIRE,
                                                          NULL,
                                                          &ft_prev,
                                                          &cb)))
                            ZeroMemory(&ft_prev, sizeof(ft_prev));
                        kcdb_cred_release(tgt);
                    }

                    code = khm_convert524(ident);

                    _reportf(L"khm_convert524 returns code %d", code);

                    if (code == 0) {
                        khui_cw_set_response(nc, credtype_id_krb4,
                                             KHUI_NC_RESPONSE_SUCCESS |
                                             KHUI_NC_RESPONSE_EXIT);

                        if (nc->subtype == KMSG_CRED_NEW_CREDS) {
                            assert(d != NULL);

                            k4_write_identity_data(d);

                        } else if (nc->subtype == KMSG_CRED_RENEW_CREDS &&
                                   (nc->ctx.scope == KHUI_SCOPE_CREDTYPE ||
                                    nc->ctx.scope == KHUI_SCOPE_CRED)) {

                            khm_krb4_list_tickets();

                            tgt = khm_krb4_find_tgt(NULL, ident);

                            if (tgt) {
                                cb = sizeof(ft_new);
                                ZeroMemory(&ft_new, sizeof(ft_new));

                                kcdb_cred_get_attr(tgt,
                                                   KCDB_ATTR_EXPIRE,
                                                   NULL,
                                                   &ft_new,
                                                   &cb);

                                kcdb_cred_release(tgt);
                            }

                            if (!tgt ||
                                CompareFileTime(&ft_new,
                                                &ft_prev) <= 0) {
                                /* The new TGT wasn't much of an
                                   improvement over what we already
                                   had.  We should go out and try to
                                   renew the identity now. */

                                khui_action_context ctx;

                                _reportf(L"Renewal of Krb4 creds failed to get a longer TGT.  Triggering identity renewal");

                                khui_context_create(&ctx,
                                                    KHUI_SCOPE_IDENT,
                                                    nc->ctx.identity,
                                                    KCDB_CREDTYPE_INVALID,
                                                    NULL);
                                khui_action_trigger(KHUI_ACTION_RENEW_CRED,
                                                    &ctx);

                                khui_context_release(&ctx);
                            }
                        }

                        _end_task();
                        break;

                    } else if (method == K4_METHOD_K524) {
                        khui_cw_set_response(nc, credtype_id_krb4,
                                             KHUI_NC_RESPONSE_FAILED |
                                             KHUI_NC_RESPONSE_EXIT);

			if (nc->subtype == KMSG_CRED_RENEW_CREDS &&
			    (nc->ctx.scope == KHUI_SCOPE_CREDTYPE ||
			     nc->ctx.scope == KHUI_SCOPE_CRED)) {
			    /* We were trying to get a new Krb4 TGT
			       for this identity.  Sometimes this
			       fails because of restrictions placed on
			       K524d regarding the lifetime of the
			       issued K4 TGT.  In this case, we
			       trigger a renewal of the identity in
			       the hope that the new K5 TGT will allow
			       us to successfully get a new K4 TGT
			       next time over using the new K5 TGT. */

			    khui_action_context ctx;

                            _reportf(L"Renewal of Krb4 creds failed using k524.  Triggerring identity renewal.");

			    khui_context_create(&ctx,
						KHUI_SCOPE_IDENT,
						nc->ctx.identity,
						KCDB_CREDTYPE_INVALID,
						NULL);

			    khui_action_trigger(KHUI_ACTION_RENEW_CRED,
						&ctx);

			    khui_context_release(&ctx);
			}

                        _end_task();
                        break;

                    }
                }

                /* only supported for new credentials */
                if (method == K4_METHOD_AUTO ||
                    method == K4_METHOD_PASSWORD) {
                    
                    khm_size n_prompts = 0;
                    khm_size idx;
                    khm_size cb;
                    wchar_t wpwd[KHUI_MAXCCH_PROMPT_VALUE];
                    char pwd[KHUI_MAXCCH_PROMPT_VALUE];
                    wchar_t widname[KCDB_IDENT_MAXCCH_NAME];
                    char idname[KCDB_IDENT_MAXCCH_NAME];

                    char * aname = NULL;
                    char * inst = NULL;
                    char * realm = NULL;

                    assert(nc->subtype == KMSG_CRED_NEW_CREDS);

                    _report_mr0(KHERR_INFO, MSG_K4_TRY_PASSWORD);

                    code = TRUE; /* just has to be non-zero */

                    khui_cw_get_prompt_count(nc, &n_prompts);

                    if (n_prompts == 0)
                        goto _skip_pwd;

                    for (idx = 0; idx < n_prompts; idx++) {
                        khui_new_creds_prompt * p;

                        if (KHM_FAILED(khui_cw_get_prompt(nc, idx, &p)))
                            continue;

                        if (p->type == KHUI_NCPROMPT_TYPE_PASSWORD)
                            break;
                    }

                    if (idx >= n_prompts) {
                        _reportf(L"Password prompt not found");
                        goto _skip_pwd;
                    }

                    khui_cw_sync_prompt_values(nc);

                    cb = sizeof(wpwd);
                    if (KHM_FAILED(khui_cw_get_prompt_value(nc, idx,
                                                            wpwd,
                                                            &cb))) {
                        _reportf(L"Failed to obtain password value");
                        goto _skip_pwd;
                    }

                    UnicodeStrToAnsi(pwd, sizeof(pwd), wpwd);

                    cb = sizeof(widname);
                    kcdb_identity_get_name(ident,
                                           widname,
                                           &cb);

                    UnicodeStrToAnsi(idname, sizeof(idname), widname);

                    {
                        char * atsign;

                        atsign = strchr(idname, '@');
                        if (atsign == NULL) {
                            _reportf(L"Identity name does not contain an '@'");
                            goto _skip_pwd;
                        }

                        *atsign++ = 0;

                        realm = atsign;
                    }

                    {
                        char * slash;

                        slash = strchr(idname, '/');
                        if (slash != NULL) {
                            *slash++ = 0;
                            inst = slash;
                        } else {
                            inst = "";
                        }
                    }

                    aname = idname;

                    code = khm_krb4_kinit(aname, inst, realm,
                                          (long) d->lifetime, pwd);

                    _reportf(L"khm_krb4_kinit returns code %d", code);

                _skip_pwd:

                    if (code) {
                        khui_cw_set_response(nc, credtype_id_krb4,
                                             KHUI_NC_RESPONSE_EXIT |
                                             KHUI_NC_RESPONSE_FAILED);

                    } else {
                        khui_cw_set_response(nc, credtype_id_krb4,
                                             KHUI_NC_RESPONSE_EXIT |
                                             KHUI_NC_RESPONSE_SUCCESS);

                        if (nc->subtype == KMSG_CRED_NEW_CREDS) {

                            assert(d != NULL);
                            k4_write_identity_data(d);

                        }
                    }
                }

                _end_task();
            }
        }
        break;

    case KMSG_CRED_END:
        {
            khui_new_creds * nc;
            khui_new_creds_by_type * nct = NULL;

            nc = (khui_new_creds *) vparam;
            if (KHM_FAILED(khui_cw_find_type(nc, credtype_id_krb4, &nct)))
                break;

            khui_cw_del_type(nc, credtype_id_krb4);

            if (nct->name)
                PFREE(nct->name);

            if (nct->credtext)
                PFREE(nct->credtext);

            PFREE(nct);
        }
        break;
    }

    return KHM_ERROR_SUCCESS;
}

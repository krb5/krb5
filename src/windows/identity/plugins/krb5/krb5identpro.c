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

#include<krbcred.h>
#include<kherror.h>
#include<khmsgtypes.h>
#include<commctrl.h>
#include<strsafe.h>
#include<krb5.h>
#include<assert.h>

#define K5_NCID_UN_LABEL    (KHUI_CW_ID_MIN + 0)
#define K5_NCID_UN          (KHUI_CW_ID_MIN + 1)
#define K5_NCID_REALM_LABEL (KHUI_CW_ID_MIN + 2)
#define K5_NCID_REALM       (KHUI_CW_ID_MIN + 3)

#define NC_UNCHANGE_TIMEOUT 3000
#define NC_UNCHANGE_TIMER   2
#define NC_REALMCHANGE_TIMEOUT NC_UNCHANGE_TIMEOUT
#define NC_REALMCHANGE_TIMER 3

typedef struct tag_k5_new_cred_data {
    HWND hw_username_label;
    HWND hw_username;
    HWND hw_realm_label;
    HWND hw_realm;
} k5_new_cred_data;

int 
k5_get_realm_from_nc(khui_new_creds * nc, 
                     wchar_t * buf, 
                     khm_size cch_buf) {
    k5_new_cred_data * d;

    d = (k5_new_cred_data *) nc->ident_aux;
    return GetWindowText(d->hw_realm, buf, (int) cch_buf);
}

/* set the primary identity of a new credentials dialog depending on
   the selection of the username and realm

   Runs in the UI thread
*/
static void 
set_identity_from_ui(khui_new_creds * nc,
                     k5_new_cred_data * d) {
    wchar_t un[KCDB_IDENT_MAXCCH_NAME];
    wchar_t * realm;
    khm_size cch;
    khm_size cch_left;
    khm_handle ident;
    LRESULT idx = CB_ERR;

    cch = GetWindowTextLength(d->hw_username);

    /* we already set the max length of the edit control to be this.
       shouldn't exceed it unless the edit control is confused. */
    assert(cch < KCDB_IDENT_MAXCCH_NAME - 1);

    GetWindowText(d->hw_username, un, ARRAYLENGTH(un));

    realm = khm_get_realm_from_princ(un);
    if (realm)          /* realm was specified */
        goto _set_ident;

    /* the cch we got from GetWindowTextLength can not be trusted to
       be exact.  For caveats see MSDN for GetWindowTextLength. */
    StringCchLength(un, KCDB_IDENT_MAXCCH_NAME, &cch);

    realm = un + cch;   /* now points at terminating NULL */
    cch_left = KCDB_IDENT_MAXCCH_NAME - cch;

    *realm++ = L'@';
    cch_left--;

    cch = GetWindowTextLength(d->hw_realm);
    if (cch == 0 || cch >= cch_left)
        goto _set_null_ident;

    GetWindowText(d->hw_realm, realm, (int) cch_left);

 _set_ident:
    if (KHM_FAILED(kcdb_identity_create(un,
                                        KCDB_IDENT_FLAG_CREATE,
                                        &ident)))
        goto _set_null_ident;

    khui_cw_set_primary_id(nc, ident);

    kcdb_identity_release(ident);
    return;

 _set_null_ident:
    khui_cw_set_primary_id(nc, NULL);
    return;
}

static BOOL
update_crossfeed(khui_new_creds * nc,
                 k5_new_cred_data * d,
                 int ctrl_id_src) {
    wchar_t un[KCDB_IDENT_MAXCCH_NAME];
    wchar_t * un_realm;
    wchar_t realm[KCDB_IDENT_MAXCCH_NAME];
    khm_size cch;
    khm_size cch_left;

    cch = (khm_size) GetWindowTextLength(d->hw_username);
#ifdef DEBUG
    assert(cch < KCDB_IDENT_MAXCCH_NAME);
#endif
    if (cch == 0)
        return FALSE;

    GetWindowText(d->hw_username,
                  un,
                  ARRAYLENGTH(un));

    un_realm = khm_get_realm_from_princ(un);

    if (un_realm == NULL)
        return FALSE;

    if (ctrl_id_src == K5_NCID_UN) {
        SendMessage(d->hw_realm,
                    CB_SELECTSTRING,
                    (WPARAM) -1,
                    (LPARAM) un_realm);

        SetWindowText(d->hw_realm,
                      un_realm);

        return TRUE;
    }
    /* else... */

    cch_left = KCDB_IDENT_MAXCCH_NAME - (un_realm - un);

    cch = (khm_size) GetWindowTextLength(d->hw_realm);

#ifdef DEBUG
    assert(cch < KCDB_IDENT_MAXCCH_NAME);
#endif
    if (cch == 0)
        return FALSE;

    GetWindowText(d->hw_realm, realm,
                  ARRAYLENGTH(realm));

    StringCchCopy(un_realm, cch_left, realm);

    SendMessage(d->hw_username,
                CB_SELECTSTRING,
                (WPARAM) -1,
                (LPARAM) un);

    SetWindowText(d->hw_username, un);

    return TRUE;    
}

/* Handle window messages for the identity specifiers

   runs in UI thread */
static LRESULT 
handle_wnd_msg(khui_new_creds * nc,
               HWND hwnd,
               UINT uMsg,
               WPARAM wParam,
               LPARAM lParam) {
    k5_new_cred_data * d;

    d = (k5_new_cred_data *) nc->ident_aux;

    switch(uMsg) {
    case WM_COMMAND:
        switch(wParam) {
        case MAKEWPARAM(K5_NCID_UN, CBN_EDITCHANGE):
            /* the username has changed.  Instead of handling this
               for every keystroke, set a timer that elapses some
               time afterwards and then handle the event. */
            SetTimer(hwnd, NC_UNCHANGE_TIMER, 
                     NC_UNCHANGE_TIMEOUT, NULL);
            return TRUE;

        case MAKEWPARAM(K5_NCID_UN, CBN_KILLFOCUS):
        case MAKEWPARAM(K5_NCID_UN, CBN_CLOSEUP):
            KillTimer(hwnd, NC_UNCHANGE_TIMER);

            update_crossfeed(nc,d,K5_NCID_UN);
            set_identity_from_ui(nc,d);
            return TRUE;

        case MAKEWPARAM(K5_NCID_REALM,CBN_EDITCHANGE):
            SetTimer(hwnd, NC_REALMCHANGE_TIMER,
                     NC_REALMCHANGE_TIMEOUT, NULL);
            return TRUE;

        case MAKEWPARAM(K5_NCID_REALM,CBN_KILLFOCUS):
        case MAKEWPARAM(K5_NCID_REALM,CBN_CLOSEUP):
            KillTimer(hwnd, NC_REALMCHANGE_TIMER);

            update_crossfeed(nc,d,K5_NCID_REALM);
            set_identity_from_ui(nc, d);
            return TRUE;
        }
        break;

    case WM_TIMER:
        if(wParam == NC_UNCHANGE_TIMER) {
            KillTimer(hwnd, NC_UNCHANGE_TIMER);

            update_crossfeed(nc, d, K5_NCID_UN);
            set_identity_from_ui(nc,d);
            return TRUE;
        } else if (wParam == NC_REALMCHANGE_TIMER) {
            KillTimer(hwnd, NC_REALMCHANGE_TIMER);

            update_crossfeed(nc, d, K5_NCID_REALM);
            set_identity_from_ui(nc, d);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

/* UI Callback

   runs in UI thread */
static LRESULT KHMAPI 
ui_cb(khui_new_creds * nc,
      UINT cmd,
      HWND hwnd,
      UINT uMsg,
      WPARAM wParam,
      LPARAM lParam) {
    k5_new_cred_data * d;

    d = (k5_new_cred_data *) nc->ident_aux;

    switch(cmd) {
    case WMNC_IDENT_INIT:
        {
            wchar_t defident[KCDB_IDENT_MAXCCH_NAME];
            wchar_t wbuf[1024];
            wchar_t * ms = NULL;
            wchar_t * t;
            wchar_t * defrealm = NULL;
            LRESULT lr;
            khm_size cb_ms;
            khm_size cb;
            HWND hw_parent;
            khm_int32 rv;
            khm_handle hident;

            hw_parent = (HWND) lParam;
            defident[0] = L'\0';

#ifdef DEBUG
            assert(d == NULL);
            assert(hw_parent != NULL);
#endif

            d = malloc(sizeof(*d));
            assert(d);
            ZeroMemory(d, sizeof(*d));

            khui_cw_lock_nc(nc);
            nc->ident_aux = (LPARAM) d;
            khui_cw_unlock_nc(nc);

            LoadString(hResModule, IDS_NC_USERNAME, 
                       wbuf, ARRAYLENGTH(wbuf));

            d->hw_username_label = CreateWindow
                (L"STATIC",
                 wbuf,
                 SS_SIMPLE | WS_CHILD | WS_VISIBLE,
                 0, 0, 100, 100, /* bogus values */
                 hw_parent,
                 (HMENU) K5_NCID_UN_LABEL,
                 hInstance,
                 NULL);
            assert(d->hw_username_label != NULL);

            d->hw_username = CreateWindow
                (L"COMBOBOX",
                 L"",
                 CBS_DROPDOWN | CBS_AUTOHSCROLL | CBS_SORT | 
                 WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                 0, 0, 100, 100, /* bogus values */
                 hw_parent,
                 (HMENU) K5_NCID_UN,
                 hInstance,
                 NULL);
            assert(d->hw_username != NULL);

            SendMessage(d->hw_username,
                        CB_LIMITTEXT,
                        (WPARAM)(KCDB_IDENT_MAXCCH_NAME - 1),
                        0);

            SendMessage(d->hw_username,
                        CB_SETEXTENDEDUI,
                        (WPARAM) TRUE,
                        0);

            khui_cw_add_control_row(nc,
                                    d->hw_username_label,
                                    d->hw_username,
                                    KHUI_CTRLSIZE_SMALL);

            LoadString(hResModule, IDS_NC_REALM,
                       wbuf, ARRAYLENGTH(wbuf));

            d->hw_realm_label = CreateWindow
                (L"STATIC",
                 wbuf,
                 SS_SIMPLE | WS_CHILD | WS_VISIBLE,
                 0, 0, 100, 100, /* bogus */
                 hw_parent,
                 (HMENU) K5_NCID_REALM_LABEL,
                 hInstance,
                 NULL);
            assert(d->hw_realm_label != NULL);

            d->hw_realm = CreateWindow
                (L"COMBOBOX",
                 L"",
                 CBS_DROPDOWN | CBS_AUTOHSCROLL | CBS_SORT | 
                 WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                 0, 0, 100, 100, /* bogus */
                 hw_parent,
                 (HMENU) K5_NCID_REALM,
                 hInstance,
                 NULL);
            assert(d->hw_realm != NULL);

            SendMessage(d->hw_realm,
                        CB_LIMITTEXT,
                        (WPARAM) (KCDB_IDENT_MAXCCH_NAME - 1),
                        0);

            SendMessage(d->hw_realm,
                        CB_SETEXTENDEDUI,
                        (WPARAM) TRUE,
                        0);

            khui_cw_add_control_row(nc,
                                    d->hw_realm_label,
                                    d->hw_realm,
                                    KHUI_CTRLSIZE_SMALL);

            /* add the LRU realms and principals to the dropdown
               lists */
            rv = khc_read_multi_string(csp_params,
                                       L"LRUPrincipals",
                                       NULL,
                                       &cb_ms);

            if (rv != KHM_ERROR_TOO_LONG)
                goto _add_lru_realms;

            ms = malloc(cb_ms);
            assert(ms != NULL);

            cb = cb_ms;
            rv = khc_read_multi_string(csp_params,
                                       L"LRUPrincipals",
                                       ms,
                                       &cb);

            assert(KHM_SUCCEEDED(rv));

            /* the first of these is considered the default identity
               if no other default is known */
            StringCbCopy(defident, sizeof(defident), ms);

            t = ms;
            while(t && *t) {
                SendMessage(d->hw_username,
                            CB_ADDSTRING,
                            0,
                            (LPARAM) t);

                t = multi_string_next(t);
            }

        _add_lru_realms:
            /* add the default realm first */
            defrealm = khm_krb5_get_default_realm();
            if (defrealm) {
                SendMessage(d->hw_realm,
                            CB_ADDSTRING,
                            0,
                            (LPARAM) defrealm);
            }

            rv = khc_read_multi_string(csp_params,
                                       L"LRURealms",
                                       NULL,
                                       &cb);

            if (rv != KHM_ERROR_TOO_LONG)
                goto _done_adding_lru;

            if (ms != NULL) {
                if (cb_ms < cb) {
                    free(ms);
                    ms = malloc(cb);
                    assert(ms);
                    cb_ms = cb;
                }
            } else {
                ms = malloc(cb);
                cb_ms = cb;
            }

            rv = khc_read_multi_string(csp_params,
                                       L"LRURealms",
                                       ms,
                                       &cb);

            assert(KHM_SUCCEEDED(rv));

            for (t = ms; t && *t; t = multi_string_next(t)) {
                lr = SendMessage(d->hw_realm,
                                 CB_FINDSTRINGEXACT,
                                 (WPARAM) -1,
                                 (LPARAM) t);
                if (lr != CB_ERR)
                    continue;

                SendMessage(d->hw_realm,
                            CB_ADDSTRING,
                            0,
                            (LPARAM) t);
            }

        _done_adding_lru:
            /* set the current selection of the realms list */
            if (defrealm) {
                SendMessage(d->hw_realm,
                            CB_SELECTSTRING,
                            (WPARAM) -1,
                            (LPARAM) defrealm);
            } else {
                SendMessage(d->hw_realm,
                            CB_SETCURSEL,
                            (WPARAM) 0,
                            (LPARAM) 0);
            }

            if (defrealm)
                free(defrealm);

            if (ms)
                free(ms);

            /* now see about that default identity */
            if (nc->ctx.identity) {
                cb = sizeof(defident);
                kcdb_identity_get_name(nc->ctx.identity,
                                       defident,
                                       &cb);
            }

            if (defident[0] == L'\0' &&
                KHM_SUCCEEDED(kcdb_identity_get_default(&hident))) {
                cb = sizeof(defident);
                kcdb_identity_get_name(hident, defident, &cb);
                kcdb_identity_release(hident);
            }

            if (defident[0] == L'\0') {
                DWORD dw;

                dw = ARRAYLENGTH(defident);
                GetUserName(defident, &dw);
            }

            t = khm_get_realm_from_princ(defident);
            if (t) {
                /* there is a realm */
                assert(t != defident);
                *--t = L'\0';
                t++;

                SendMessage(d->hw_realm,
                            CB_SELECTSTRING,
                            (WPARAM) -1,
                            (LPARAM) t);

                SendMessage(d->hw_realm,
                            WM_SETTEXT,
                            0,
                            (LPARAM) t);
            }

            if (defident[0] != L'\0') {
                /* there is a username */
                SendMessage(d->hw_username,
                            CB_SELECTSTRING,
                            (WPARAM) -1,
                            (LPARAM) defident);

                SendMessage(d->hw_username,
                            WM_SETTEXT,
                            0,
                            (LPARAM) defident);
            }

            set_identity_from_ui(nc, d);
        }
        return TRUE;

    case WMNC_IDENT_WMSG:
        return handle_wnd_msg(nc, hwnd, uMsg, wParam, lParam);

    case WMNC_IDENT_EXIT:
        {
#ifdef DEBUG
            assert(d != NULL);
#endif
            khui_cw_lock_nc(nc);
            nc->ident_aux = 0;
            khui_cw_unlock_nc(nc);
            
            /* since we created all the windows as child windows of
               the new creds window, they will be destroyed when that
               window is destroyed. */
            free(d);
        }
        return TRUE;
    }
    return FALSE;
}

static khm_int32
k5_ident_valiate_name(khm_int32 msg_type,
                      khm_int32 msg_subtype,
                      khm_ui_4 uparam,
                      void * vparam) {
    krb5_principal princ = NULL;
    char princ_name[KCDB_IDENT_MAXCCH_NAME];
    kcdb_ident_name_xfer * nx;
    krb5_error_code code;

    nx = (kcdb_ident_name_xfer *) vparam;

    if(UnicodeStrToAnsi(princ_name, sizeof(princ_name),
                        nx->name_src) == 0) {
        nx->result = KHM_ERROR_INVALID_NAME;
        return KHM_ERROR_SUCCESS;
    }

    assert(k5_identpro_ctx != NULL);

    code = pkrb5_parse_name(k5_identpro_ctx,
                            princ_name,
                            &princ);

    if (code) {
        nx->result = KHM_ERROR_INVALID_NAME;
        return KHM_ERROR_SUCCESS;
    }

    if (princ != NULL) 
        pkrb5_free_principal(k5_identpro_ctx,
                             princ);

    nx->result = KHM_ERROR_SUCCESS;

    return KHM_ERROR_SUCCESS;
}

static khm_int32
k5_ident_set_default(khm_int32 msg_type,
                     khm_int32 msg_subtype,
                     khm_ui_4 uparam,
                     void * vparam) {

    /* Logic for setting the default identity:

    When setting identity I as the default;

    - If KRB5CCNAME is set
    - If I["Krb5CCName"] == %KRB5CCNAME%
    - do nothing
    - Else
    - Copy the contents of I["Krb5CCName"] to %KRB5CCNAME
    - Set I["Krb5CCName"] to %KRB5CCNAME
    - Else
    - Set HKCU\Software\MIT\kerberos5,ccname to 
    "API:".I["Krb5CCName"]
    */

    if (uparam) {
        /* an identity is being made default */
        khm_handle def_ident = (khm_handle) vparam;
        wchar_t env_ccname[KRB5_MAXCCH_CCNAME];
        wchar_t id_ccname[KRB5_MAXCCH_CCNAME];
        khm_size cb;
        DWORD dw;
        LONG l;

#ifdef DEBUG
        assert(def_ident != NULL);
#endif

        cb = sizeof(id_ccname);
        if (KHM_FAILED(kcdb_identity_get_attr(def_ident,
                                              attr_id_krb5_ccname,
                                              NULL,
                                              id_ccname,
                                              &cb)))
            return KHM_ERROR_UNKNOWN;

        khm_krb5_canon_cc_name(id_ccname, sizeof(id_ccname));

        StringCbLength(id_ccname, sizeof(id_ccname), &cb);
        cb += sizeof(wchar_t);

        dw = GetEnvironmentVariable(L"KRB5CCNAME",
                                    env_ccname,
                                    ARRAYLENGTH(env_ccname));

        if (dw == 0 &&
            GetLastError() == ERROR_ENVVAR_NOT_FOUND) {
            /* KRB5CCNAME not set */
            HKEY hk_ccname;
            DWORD dwType;
            DWORD dwSize;
            wchar_t reg_ccname[KRB5_MAXCCH_CCNAME];

            l = RegOpenKeyEx(HKEY_CURRENT_USER,
                             L"Software\\MIT\\kerberos5",
                             0,
                             KEY_READ | KEY_WRITE,
                             &hk_ccname);

            if (l != ERROR_SUCCESS)
                l = RegCreateKeyEx(HKEY_CURRENT_USER,
                                   L"Software\\MIT\\kerberos5",
                                   0,
                                   NULL,
                                   REG_OPTION_NON_VOLATILE,
                                   KEY_READ | KEY_WRITE,
                                   NULL,
                                   &hk_ccname,
                                   &dw);

            if (l != ERROR_SUCCESS)
                return KHM_ERROR_UNKNOWN;

            dwSize = sizeof(reg_ccname);

            l = RegQueryValueEx(hk_ccname,
                                L"ccname",
                                NULL,
                                &dwType,
                                (LPBYTE) reg_ccname,
                                &dwSize);

            if (l != ERROR_SUCCESS ||
                dwType != REG_SZ ||
                khm_krb5_cc_name_cmp(reg_ccname, id_ccname)) {

                /* we have to write the new value in */

                l = RegSetValueEx(hk_ccname,
                                  L"ccname",
                                  0,
                                  REG_SZ,
                                  (BYTE *) id_ccname,
                                  (DWORD) cb);
            }

            RegCloseKey(hk_ccname);

            if (l == ERROR_SUCCESS)
                return KHM_ERROR_SUCCESS;
            else
                return KHM_ERROR_UNKNOWN;

        } else if (dw > ARRAYLENGTH(env_ccname)) {
            /* buffer was not enough */
#ifdef DEBUG
            assert(FALSE);
#else
            return KHM_ERROR_UNKNOWN;
#endif
        } else {
            /* KRB5CCNAME is set */
            long code;
            krb5_context ctx;

            /* if the %KRB5CCNAME is the same as the identity
               ccache, then it is already the default. */
            if (!khm_krb5_cc_name_cmp(id_ccname, env_ccname))
                return KHM_ERROR_SUCCESS;

            /* if not, we have to copy the contents of id_ccname
               to env_ccname */
            code = pkrb5_init_context(&ctx);
            if (code)
                return KHM_ERROR_UNKNOWN;

            code = khm_krb5_copy_ccache_by_name(ctx, 
                                                env_ccname, 
                                                id_ccname);

            if (code == 0)
                khm_krb5_list_tickets(&ctx);

            if (ctx)
                pkrb5_free_context(ctx);

            return (code == 0)?KHM_ERROR_SUCCESS:KHM_ERROR_UNKNOWN;
        }
    } else {
        /* the default identity is being forgotten */

        /* we don't really do anything about this case */
    }

    return KHM_ERROR_SUCCESS;
}

static khm_int32
k5_ident_get_ui_cb(khm_int32 msg_type,
                   khm_int32 msg_subtype,
                   khm_ui_4 uparam,
                   void * vparam) {
    khui_ident_new_creds_cb * cb;

    cb = (khui_ident_new_creds_cb *) vparam;

    *cb = ui_cb;

    return KHM_ERROR_SUCCESS;
}

static khm_int32
k5_ident_notify_create(khm_int32 msg_type,
                       khm_int32 msg_subtype,
                       khm_ui_4 uparam,
                       void * vparam) {

    /* a new identity has been created.  What we want to do at
       this point is to check if the identity belongs to krb5
       and to see if it is the default. */

    krb5_ccache cc = NULL;
    krb5_error_code code;
    krb5_principal princ = NULL;
    char * princ_nameA = NULL;
    wchar_t princ_nameW[KCDB_IDENT_MAXCCH_NAME];
    wchar_t id_nameW[KCDB_IDENT_MAXCCH_NAME];
    khm_size cb;
    khm_handle ident;

    ident = (khm_handle) vparam;

    assert(k5_identpro_ctx != NULL);

    code = pkrb5_cc_default(k5_identpro_ctx, &cc);
    if (code)
        goto _nc_cleanup;

    code = pkrb5_cc_get_principal(k5_identpro_ctx,
                                  cc,
                                  &princ);
    if (code)
        goto _nc_cleanup;

    code = pkrb5_unparse_name(k5_identpro_ctx,
                              princ,
                              &princ_nameA);
    if (code)
        goto _nc_cleanup;

    AnsiStrToUnicode(princ_nameW,
                     sizeof(princ_nameW),
                     princ_nameA);

    cb = sizeof(id_nameW);

    if (KHM_FAILED(kcdb_identity_get_name(ident,
                                          id_nameW,
                                          &cb)))
        goto _nc_cleanup;

    if (!wcscmp(id_nameW, princ_nameW)) {
        kcdb_identity_set_default_int(ident);
    }

 _nc_cleanup:
    if (princ_nameA)
        pkrb5_free_unparsed_name(k5_identpro_ctx,
                                 princ_nameA);
    if (princ)
        pkrb5_free_principal(k5_identpro_ctx,
                             princ);
    if (cc)
        pkrb5_cc_close(k5_identpro_ctx, cc);


    return KHM_ERROR_SUCCESS;
}

static khm_int32 KHMAPI
k5_ident_update_apply_proc(khm_handle cred,
                           void * rock) {
    wchar_t ccname[KRB5_MAXCCH_CCNAME];
    khm_handle tident = (khm_handle) rock;
    khm_handle ident = NULL;
    khm_int32 t;
    khm_int32 flags;
    __int64 t_expire;
    __int64 t_rexpire;
    khm_size cb;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if (KHM_FAILED(kcdb_cred_get_type(cred, &t)) ||
        t != credtype_id_krb5 ||
        KHM_FAILED(kcdb_cred_get_identity(cred, &ident)))
        return KHM_ERROR_SUCCESS;

    if (ident != tident)
        goto _cleanup;

    if (KHM_FAILED(kcdb_cred_get_flags(cred, &flags)))
        flags = 0;

    cb = sizeof(t_expire);
    if (KHM_SUCCEEDED(kcdb_cred_get_attr(cred,
                                         KCDB_ATTR_EXPIRE,
                                         NULL,
                                         &t_expire,
                                         &cb))) {
        __int64 t_cexpire;

        cb = sizeof(t_cexpire);
        if ((flags & KCDB_CRED_FLAG_INITIAL) ||
            KHM_FAILED(kcdb_identity_get_attr(tident,
                                              KCDB_ATTR_EXPIRE,
                                              NULL,
                                              &t_cexpire,
                                              &cb)) ||
            t_cexpire > t_expire)
            kcdb_identity_set_attr(tident, KCDB_ATTR_EXPIRE,
                                   &t_expire, sizeof(t_expire));
    } else if (flags & KCDB_CRED_FLAG_INITIAL) {
        kcdb_identity_set_attr(tident, KCDB_ATTR_EXPIRE, NULL, 0);
    }

    cb = sizeof(ccname);
    if (KHM_SUCCEEDED(kcdb_cred_get_attr(cred, KCDB_ATTR_LOCATION,
                                         NULL,
                                         ccname,
                                         &cb))) {
        kcdb_identity_set_attr(tident, attr_id_krb5_ccname,
                               ccname, cb);
    } else {
        kcdb_identity_set_attr(tident, attr_id_krb5_ccname,
                               NULL, 0);
    }

    if (!(flags & KCDB_CRED_FLAG_INITIAL))
        goto _cleanup;

    cb = sizeof(t);
    if (KHM_SUCCEEDED(kcdb_cred_get_attr(cred,
                                         attr_id_krb5_flags,
                                         NULL,
                                         &t,
                                         &cb))) {
        kcdb_identity_set_attr(tident, attr_id_krb5_flags, 
                               &t, sizeof(t));

        cb = sizeof(t_rexpire);
        if (!(t & TKT_FLG_RENEWABLE) ||
            KHM_FAILED(kcdb_cred_get_attr(cred,
                                          KCDB_ATTR_RENEW_EXPIRE,
                                          NULL,
                                          &t_rexpire,
                                          &cb))) {
            kcdb_identity_set_attr(tident, KCDB_ATTR_RENEW_EXPIRE,
                                   NULL, 0);
        } else {
            kcdb_identity_set_attr(tident, KCDB_ATTR_RENEW_EXPIRE,
                                   &t_rexpire, sizeof(t_rexpire));
        }
    } else {
        kcdb_identity_set_attr(tident, attr_id_krb5_flags,
                               NULL, 0);
        kcdb_identity_set_attr(tident, KCDB_ATTR_RENEW_EXPIRE,
                               NULL, 0);
    }

    rv = KHM_ERROR_EXIT;

 _cleanup:
    if (ident)
        kcdb_identity_release(ident);

    return rv;
}

static khm_int32
k5_ident_update(khm_int32 msg_type,
                khm_int32 msg_subtype,
                khm_ui_4 uparam,
                void * vparam) {

    khm_handle ident;

    ident = (khm_handle) vparam;
    if (ident == NULL)
        return KHM_ERROR_SUCCESS;

    kcdb_credset_apply(NULL,
                       k5_ident_update_apply_proc,
                       (void *) ident);

    return KHM_ERROR_SUCCESS;
}


static khm_int32
k5_ident_init(khm_int32 msg_type,
              khm_int32 msg_subtype,
              khm_ui_4 uparam,
              void * vparam) {
    /* just like notify_create, except now we set the default identity
       based on what we find in the configuration */
    krb5_ccache cc = NULL;
    krb5_error_code code;
    krb5_principal princ = NULL;
    char * princ_nameA = NULL;
    wchar_t princ_nameW[KCDB_IDENT_MAXCCH_NAME];
    khm_handle ident = NULL;

    assert(k5_identpro_ctx != NULL);

    code = pkrb5_cc_default(k5_identpro_ctx, &cc);
    if (code)
        goto _nc_cleanup;

    code = pkrb5_cc_get_principal(k5_identpro_ctx,
                                  cc,
                                  &princ);
    if (code)
        goto _nc_cleanup;

    code = pkrb5_unparse_name(k5_identpro_ctx,
                              princ,
                              &princ_nameA);
    if (code)
        goto _nc_cleanup;

    AnsiStrToUnicode(princ_nameW,
                     sizeof(princ_nameW),
                     princ_nameA);

    if (KHM_FAILED(kcdb_identity_create(princ_nameW,
                                        0,
                                        &ident)))
        goto _nc_cleanup;

    kcdb_identity_set_default_int(ident);

 _nc_cleanup:
    if (princ_nameA)
        pkrb5_free_unparsed_name(k5_identpro_ctx,
                                 princ_nameA);
    if (princ)
        pkrb5_free_principal(k5_identpro_ctx,
                             princ);
    if (cc)
        pkrb5_cc_close(k5_identpro_ctx, cc);

    if (ident)
        kcdb_identity_release(ident);

    return KHM_ERROR_SUCCESS;
}

static khm_int32
k5_ident_exit(khm_int32 msg_type,
              khm_int32 msg_subtype,
              khm_ui_4 uparam,
              void * vparam) {
    /* don't really do anything */
    return KHM_ERROR_SUCCESS;
}

#if 0
/* copy and paste template for ident provider messages */
static khm_int32
k5_ident_(khm_int32 msg_type,
          khm_int32 msg_subtype,
          khm_ui_4 uparam,
          void * vparam) {
}
#endif

khm_int32 KHMAPI 
k5_msg_ident(khm_int32 msg_type, 
               khm_int32 msg_subtype, 
               khm_ui_4 uparam, 
               void * vparam)
{
    switch(msg_subtype) {
    case KMSG_IDENT_INIT:
        return k5_ident_init(msg_type,
                             msg_subtype,
                             uparam,
                             vparam);

    case KMSG_IDENT_EXIT:
        return k5_ident_exit(msg_type,
                             msg_subtype,
                             uparam,
                             vparam);

    case KMSG_IDENT_VALIDATE_NAME:
        return k5_ident_valiate_name(msg_type,
                                     msg_subtype,
                                     uparam,
                                     vparam);

    case KMSG_IDENT_VALIDATE_IDENTITY:
        /* TODO: handle KMSG_IDENT_VALIDATE_IDENTITY */
        break;

    case KMSG_IDENT_CANON_NAME:
        /* TODO: handle KMSG_IDENT_CANON_NAME */
        break;

    case KMSG_IDENT_COMPARE_NAME:
        /* TODO: handle KMSG_IDENT_COMPARE_NAME */
        break;

    case KMSG_IDENT_SET_DEFAULT:
        return k5_ident_set_default(msg_type,
                                    msg_subtype,
                                    uparam,
                                    vparam);

    case KMSG_IDENT_SET_SEARCHABLE:
        /* TODO: handle KMSG_IDENT_SET_SEARCHABLE */
        break;

    case KMSG_IDENT_GET_INFO:
        /* TODO: handle KMSG_IDENT_GET_INFO */
        break;

    case KMSG_IDENT_UPDATE:
        return k5_ident_update(msg_type,
                               msg_subtype,
                               uparam,
                               vparam);

    case KMSG_IDENT_ENUM_KNOWN:
        /* TODO: handle KMSG_IDENT_ENUM_KNOWN */
        break;

    case KMSG_IDENT_GET_UI_CALLBACK:
        return k5_ident_get_ui_cb(msg_type,
                                  msg_subtype,
                                  uparam,
                                  vparam);

    case KMSG_IDENT_NOTIFY_CREATE:
        return k5_ident_notify_create(msg_type,
                                      msg_subtype,
                                      uparam,
                                      vparam);
    }

    return KHM_ERROR_SUCCESS;
}

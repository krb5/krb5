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
#include<commctrl.h>
#include<strsafe.h>
#include<krb5.h>
#ifdef DEBUG
#include<assert.h>
#endif

/* Property page

   Runs in the context of the UI thread.
   */
INT_PTR CALLBACK krb5_pp_proc(HWND hwnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam
    )
{
    switch(uMsg) {
    case WM_INITDIALOG:
        {
            khui_property_sheet * s;
            PROPSHEETPAGE * p;
            wchar_t buf[512];
            wchar_t unavailable[64];
            khm_size cbsize;
            khm_int32 rv;
            khm_int32 tflags;

            p = (PROPSHEETPAGE *) lParam;
            s = (khui_property_sheet *) p->lParam;

#pragma warning(push)
#pragma warning(disable: 4244)
            SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) s);
#pragma warning(pop)

            LoadString(hResModule, IDS_UNAVAILABLE,
                       unavailable, ARRAYLENGTH(unavailable));

            if(s->cred) {
                cbsize = sizeof(buf);
                kcdb_cred_get_name(s->cred, buf, &cbsize);
                SetDlgItemText(hwnd, IDC_PPK5_NAME, buf);

                cbsize = sizeof(buf);
                rv = kcdb_cred_get_attr_string(s->cred,
                                               KCDB_ATTR_ISSUE,
                                               buf, &cbsize, 0);
                if (KHM_SUCCEEDED(rv))
                    SetDlgItemText(hwnd, IDC_PPK5_ISSUE, buf);
                else
                    SetDlgItemText(hwnd, IDC_PPK5_ISSUE, unavailable);

                cbsize = sizeof(buf);
                rv = kcdb_cred_get_attr_string(s->cred,
                                               KCDB_ATTR_EXPIRE,
                                               buf, &cbsize, 0);
                if (KHM_SUCCEEDED(rv))
                    SetDlgItemText(hwnd, IDC_PPK5_VALID, buf);
                else
                    SetDlgItemText(hwnd, IDC_PPK5_VALID, unavailable);

                cbsize = sizeof(buf);
                rv = kcdb_cred_get_attr_string(s->cred,
                                               KCDB_ATTR_RENEW_EXPIRE,
                                               buf, &cbsize, 0);
                if (KHM_SUCCEEDED(rv))
                    SetDlgItemText(hwnd, IDC_PPK5_RENEW, buf);
                else
                    SetDlgItemText(hwnd, IDC_PPK5_RENEW, unavailable);

                tflags = 0;
                cbsize = sizeof(tflags);
                rv = kcdb_cred_get_attr(s->cred,
                                        attr_id_krb5_flags,
                                        NULL,
                                        &tflags,
                                        &cbsize);
                if (KHM_SUCCEEDED(rv)) {

#define ADDBITFLAG(f,s) \
   if (tflags & f) {    \
     LoadString(hResModule, s, buf, ARRAYLENGTH(buf)); \
     SendDlgItemMessage(hwnd, IDC_PPK5_FLAGS, LB_ADDSTRING, 0, (LPARAM) buf); \
   }

                    ADDBITFLAG(TKT_FLG_FORWARDABLE, IDS_FLG_FORWARDABLE);
                    ADDBITFLAG(TKT_FLG_FORWARDED, IDS_FLG_FORWARDED);
                    ADDBITFLAG(TKT_FLG_PROXIABLE, IDS_FLG_PROXIABLE);
                    ADDBITFLAG(TKT_FLG_PROXY, IDS_FLG_PROXY);
                    ADDBITFLAG(TKT_FLG_MAY_POSTDATE, IDS_FLG_MAY_POSTDATE);
                    ADDBITFLAG(TKT_FLG_POSTDATED, IDS_FLG_POSTDATED);
                    ADDBITFLAG(TKT_FLG_INVALID, IDS_FLG_INVALID);
                    ADDBITFLAG(TKT_FLG_RENEWABLE, IDS_FLG_RENEWABLE);
                    ADDBITFLAG(TKT_FLG_INITIAL, IDS_FLG_INITIAL);
                    ADDBITFLAG(TKT_FLG_PRE_AUTH, IDS_FLG_PRE_AUTH);
                    ADDBITFLAG(TKT_FLG_HW_AUTH, IDS_FLG_HW_AUTH);
                    ADDBITFLAG(TKT_FLG_TRANSIT_POLICY_CHECKED, IDS_FLG_TRANSIT_POL);
                    ADDBITFLAG(TKT_FLG_OK_AS_DELEGATE, IDS_FLG_OK_DELEGATE);
                    ADDBITFLAG(TKT_FLG_ANONYMOUS, IDS_FLG_ANONYMOUS);

#undef ADDBITFLAG

                }
            } else {
#ifdef DEBUG
                assert(FALSE);
#endif
            }
        }
        return FALSE;
    }

    return FALSE;
}

void k5_pp_begin(khui_property_sheet * s)
{
    PROPSHEETPAGE *p;

    if(s->credtype == credtype_id_krb5 &&
       s->cred) {
        p = PMALLOC(sizeof(*p));
        ZeroMemory(p, sizeof(*p));

        p->dwSize = sizeof(*p);
        p->dwFlags = 0;
        p->hInstance = hResModule;
        p->pszTemplate = MAKEINTRESOURCE(IDD_PP_KRB5C);
        p->pfnDlgProc = krb5_pp_proc;
        p->lParam = (LPARAM) s;
        khui_ps_add_page(s, credtype_id_krb5, 0, p, NULL);
    }
}

void k5_pp_end(khui_property_sheet * s)
{
    khui_property_page * p = NULL;

    khui_ps_find_page(s, credtype_id_krb5, &p);
    if(p) {
        if(p->p_page)
            PFREE(p->p_page);
        p->p_page = NULL;
    }
}

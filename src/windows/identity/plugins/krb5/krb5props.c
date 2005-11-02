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
                khm_size cbsize;

                p = (PROPSHEETPAGE *) lParam;
                s = (khui_property_sheet *) p->lParam;

#pragma warning(push)
#pragma warning(disable: 4244)
                SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) s);
#pragma warning(pop)

                if(s->cred) {
                    cbsize = sizeof(buf);
                    kcdb_cred_get_name(s->cred, buf, &cbsize);
                    SetDlgItemText(hwnd, IDC_PPK5_NAME, buf);

                    cbsize = sizeof(buf);
                    kcdb_cred_get_attr_string(s->cred, KCDB_ATTR_ISSUE, buf, &cbsize, 0);
                    SetDlgItemText(hwnd, IDC_PPK5_ISSUE, buf);

                    cbsize = sizeof(buf);
                    kcdb_cred_get_attr_string(s->cred, KCDB_ATTR_EXPIRE, buf, &cbsize, 0);
                    SetDlgItemText(hwnd, IDC_PPK5_VALID, buf);

                    cbsize = sizeof(buf);
                    kcdb_cred_get_attr_string(s->cred, KCDB_ATTR_RENEW_EXPIRE, buf, &cbsize, 0);
                    SetDlgItemText(hwnd, IDC_PPK5_RENEW, buf);

                    /*TODO: select other properties */
                } else {
                    /*TODO: select properties */
                }
            }
            return FALSE;
    }

    return FALSE;
}

void k5_pp_begin(khui_property_sheet * s)
{
    PROPSHEETPAGE *p;

    if(s->credtype == credtype_id_krb5) {
        p = malloc(sizeof(*p));
        ZeroMemory(p, sizeof(*p));

        p->dwSize = sizeof(*p);
        p->dwFlags = 0;
        p->hInstance = hResModule;
        p->pszTemplate = (s->cred)? MAKEINTRESOURCE(IDD_PP_KRB5C): MAKEINTRESOURCE(IDD_PP_KRB5);
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
            free(p->p_page);
        p->p_page = NULL;
    }
}


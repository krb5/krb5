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
#include<khuidefs.h>
#include<strsafe.h>

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

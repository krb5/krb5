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

#include<khmapp.h>
#include<netidmgr_intver.h>
#include<tlhelp32.h>

#if DEBUG
#include<assert.h>
#endif

INT_PTR CALLBACK
about_dlg_proc(HWND hwnd,
               UINT uMsg,
               WPARAM wParam,
               LPARAM lParam) {

    switch(uMsg) {
    case WM_INITDIALOG:
        {
            HANDLE hsnap;
            HWND hw;

            SetDlgItemText(hwnd, IDC_PRODUCT,
                           TEXT(KH_VERSTR_PRODUCT_1033));
            /* retain the original copyright strings */
#ifdef OVERRIDE_COPYRIGHT
            SetDlgItemText(hwnd, IDC_COPYRIGHT,
                           TEXT(KH_VERSTR_COPYRIGHT_1033));
#endif
            SetDlgItemText(hwnd, IDC_BUILDINFO,
                           TEXT(KH_VERSTR_BUILDINFO_1033));

            hsnap =
                CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,
                                         0);

            if (hsnap != INVALID_HANDLE_VALUE) {
                LVCOLUMN lvc;
                MODULEENTRY32 mod;
                RECT r;

                hw = GetDlgItem(hwnd, IDC_MODULES);
#ifdef DEBUG
                assert(hw != NULL);
#endif

                GetWindowRect(hw, &r);
                OffsetRect(&r, -r.left, -r.top);

                ZeroMemory(&lvc, sizeof(lvc));
                lvc.mask = LVCF_TEXT | LVCF_WIDTH;

                lvc.pszText = L"Name";
                lvc.cx = r.right / 4;

                ListView_InsertColumn(hw, 0, &lvc);

                lvc.pszText = L"Path";
                lvc.cx = (r.right * 3) / 4;
                ListView_InsertColumn(hw, 1, &lvc);

                ZeroMemory(&mod, sizeof(mod));
                mod.dwSize = sizeof(mod);

                /* done with columns, now for the actual data */
                if (!Module32First(hsnap, &mod))
                    goto _done_with_modules;

                do {

                    LVITEM lvi;
                    int idx;

                    ZeroMemory(&lvi, sizeof(lvi));

                    lvi.mask = LVIF_TEXT;
                    lvi.pszText = mod.szModule;
                    idx = ListView_InsertItem(hw, &lvi);

                    lvi.mask = LVIF_TEXT;
                    lvi.iItem = idx;
                    lvi.iSubItem = 1;
                    lvi.pszText = mod.szExePath;
                    ListView_SetItem(hw, &lvi);

                    ZeroMemory(&mod, sizeof(mod));
                    mod.dwSize = sizeof(mod);
                } while(Module32Next(hsnap, &mod));

            _done_with_modules:
                CloseHandle(hsnap);
            }

            khm_add_dialog(hwnd);
            khm_enter_modal(hwnd);
        }
        return FALSE;

    case WM_DESTROY:
        khm_del_dialog(hwnd);
        return TRUE;

    case WM_CLOSE:
        khm_leave_modal();
        DestroyWindow(hwnd);
        return TRUE;

    case WM_COMMAND:
        if (wParam == MAKEWPARAM(IDOK, BN_CLICKED)) {
            khm_leave_modal();
            DestroyWindow(hwnd);
        }
        return TRUE;
    }

    return FALSE;
}

void
khm_create_about_window(void) {
    HWND hwnd;
    hwnd = CreateDialog(khm_hInstance,
                        MAKEINTRESOURCE(IDD_ABOUT),
                        khm_hwnd_main,
                        about_dlg_proc);

    ShowWindow(hwnd, SW_SHOW);
    /* no need to keep track of the hwnd, since we add it to the
       dialog chain in the dialog procedure */
}

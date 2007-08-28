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
#include<assert.h>

static int text_sizes[] = {
    4,6,8,9,10,12,14,16,18
};

typedef struct tag_dlg_data {
    khui_config_node  node;
    HWND              hwnd;
    LOGFONT           lf_base;
    LOGFONT           lf_work;
    HFONT             c_font_normal;
    HFONT             c_font_bold;
    int               size_idx[ARRAYLENGTH(text_sizes)];
} dlg_data;

static void
read_params(HWND hwnd, dlg_data * d) {

    HDC hdc;

    hdc = GetWindowDC(hwnd);

    khm_get_cw_element_font(hdc,
                            NULL,
                            FALSE,
                            &d->lf_base);

    d->lf_work = d->lf_base;

    ReleaseDC(hwnd, hdc);
}


static void
write_params(dlg_data * d) {
    khm_boolean applied = FALSE;

    if (memcmp(&d->lf_work, &d->lf_base, sizeof(LOGFONT))) {
        khm_set_cw_element_font(NULL, &d->lf_work);
        d->lf_base = d->lf_work;
        applied = TRUE;
    }

    khui_cfg_set_flags(d->node,
                       (applied)? KHUI_CNFLAG_APPLIED: 0,
                       KHUI_CNFLAG_APPLIED | KHUI_CNFLAG_MODIFIED);
}

static void
check_for_modification(dlg_data * d) {

    khui_cfg_set_flags(d->node,
                       ((memcmp(&d->lf_work, &d->lf_base, sizeof(LOGFONT)))?
                        KHUI_CNFLAG_MODIFIED: 0),
                       KHUI_CNFLAG_MODIFIED);
}

static void
refresh_view(HWND hwnd, dlg_data * d) {
    wchar_t sample[256];
    HFONT hf;
    LOGFONT lf;

    LoadString(khm_hInstance, IDS_APR_SAMPLE_TEXT_NORMAL,
               sample, ARRAYLENGTH(sample));

    SetDlgItemText(hwnd, IDC_CFG_SAMPLE_NORMAL, sample);

    LoadString(khm_hInstance, IDS_APR_SAMPLE_TEXT_SEL,
               sample, ARRAYLENGTH(sample));

    SetDlgItemText(hwnd, IDC_CFG_SAMPLE_BOLD, sample);

    lf = d->lf_work;
    hf = CreateFontIndirect(&lf);
    if (hf == NULL)
        return;

    SendDlgItemMessage(hwnd, IDC_CFG_SAMPLE_NORMAL, WM_SETFONT, (WPARAM) hf, TRUE);

    if (d->c_font_normal)
        DeleteObject(d->c_font_normal);

    d->c_font_normal = hf;

    lf.lfWeight = FW_BOLD;

    hf = CreateFontIndirect(&lf);
    if (hf == NULL)
        return;

    SendDlgItemMessage(hwnd, IDC_CFG_SAMPLE_BOLD, WM_SETFONT, (WPARAM) hf, TRUE);

    if (d->c_font_bold)
        DeleteObject(d->c_font_bold);

    d->c_font_bold = hf;
}

struct sel_update_blob {
    dlg_data * d;
    HDC hdc;
};

static int CALLBACK
enum_font_proc(ENUMLOGFONTEXDV * plfe,
               ENUMTEXTMETRIC * pntm,
               DWORD font_type,
               LPARAM lParam) {
    struct sel_update_blob * blob = (struct sel_update_blob *) lParam;
    LOGFONT * plf = &plfe->elfEnumLogfontEx.elfLogFont;
    LRESULT lr;

    lr = SendDlgItemMessage(blob->d->hwnd,
                            IDC_CFG_FONTS,
                            CB_SELECTSTRING,
                            (WPARAM) -1,
                            (LPARAM) plf->lfFaceName);

    if (lr == CB_ERR) {
        SendDlgItemMessage(blob->d->hwnd,
                           IDC_CFG_FONTS,
                           CB_SELECTSTRING,
                           (WPARAM) -1,
                           (LPARAM) plfe->elfEnumLogfontEx.elfFullName);
    }

    return FALSE;
}

static void
update_selection(dlg_data * d, BOOL update_fonts, BOOL update_effects) {
    LOGFONT lf;
    struct sel_update_blob blob;
    HDC hdc;

    if (update_fonts) {

        ZeroMemory(&lf, sizeof(lf));

        lf.lfCharSet = ANSI_CHARSET;
        StringCbCopy(lf.lfFaceName, sizeof(lf.lfFaceName),
                     d->lf_work.lfFaceName);

        hdc = GetWindowDC(d->hwnd);

        blob.d = d;
        blob.hdc = hdc;

        EnumFontFamiliesEx(hdc, &lf, (FONTENUMPROC) enum_font_proc,
                           (LPARAM) &blob, 0);

        ReleaseDC(d->hwnd, hdc);
    }

    if (update_effects) {
        int i;
        HDC hdc;
        int pt_height;

        if (d->lf_work.lfWeight >= FW_BOLD)
            CheckDlgButton(d->hwnd, IDC_CFG_BOLD, BST_CHECKED);
        else
            CheckDlgButton(d->hwnd, IDC_CFG_BOLD, BST_UNCHECKED);

        if (d->lf_work.lfItalic)
            CheckDlgButton(d->hwnd, IDC_CFG_ITALICS, BST_CHECKED);
        else
            CheckDlgButton(d->hwnd, IDC_CFG_ITALICS, BST_UNCHECKED);

        hdc = GetWindowDC(d->hwnd);

        pt_height = MulDiv(d->lf_work.lfHeight, 72,
                           GetDeviceCaps(hdc, LOGPIXELSY));


        ReleaseDC(d->hwnd, hdc);

        if (pt_height < 0)
            pt_height = - pt_height;

        for (i=0; i < ARRAYLENGTH(text_sizes); i++) {
            if (text_sizes[i] >= pt_height)
                break;
        }

        if (i >= ARRAYLENGTH(text_sizes))
            i = ARRAYLENGTH(text_sizes) - 1;

        SendDlgItemMessage(d->hwnd, IDC_CFG_SIZE, CB_SETCURSEL,
                           d->size_idx[i], 0);
    }
}

static int CALLBACK
enum_font_families_proc(ENUMLOGFONTEXDV * plfe,
                        ENUMTEXTMETRIC * pntm,
                        DWORD font_type,
                        LPARAM lParam) {

    dlg_data * d = (dlg_data *) lParam;

    SendDlgItemMessage(d->hwnd, IDC_CFG_FONTS,
                       CB_ADDSTRING, 0,
                       (LPARAM) plfe->elfEnumLogfontEx.elfLogFont.lfFaceName);

    return TRUE;
}

INT_PTR CALLBACK
khm_cfg_appearance_proc(HWND hwnd,
                        UINT uMsg,
                        WPARAM wParam,
                        LPARAM lParam) {

    dlg_data * d;

    switch(uMsg) {
    case WM_INITDIALOG:
        {
            HWND hw_cb;
            LOGFONT lf;
            HDC hdc;
            int i;
            wchar_t buf[4];

            d = PMALLOC(sizeof(*d));
#ifdef DEBUG
            assert(d != NULL);
#endif

#pragma warning(push)
#pragma warning(disable: 4244)
            SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) d);
#pragma warning(pop)

            ZeroMemory(d, sizeof(*d));

            d->node = (khui_config_node) lParam;
            d->hwnd = hwnd;

            read_params(hwnd, d);

            hw_cb = GetDlgItem(hwnd, IDC_CFG_FONTS);
#ifdef DEBUG
            assert(hw_cb);
#endif
            SendMessage(hw_cb, CB_RESETCONTENT, 0, 0);

            ZeroMemory(&lf, sizeof(lf));
            lf.lfCharSet = ANSI_CHARSET;

            hdc = GetWindowDC(hwnd);

            EnumFontFamiliesEx(hdc, &lf, (FONTENUMPROC) enum_font_families_proc,
                               (LPARAM) d, 0);

            ReleaseDC(hwnd, hdc);


            for (i=0; i < ARRAYLENGTH(text_sizes); i++) {
                LRESULT idx;

                StringCbPrintf(buf, sizeof(buf), L"%d", text_sizes[i]);

                idx = SendDlgItemMessage(hwnd, IDC_CFG_SIZE,
                                         CB_ADDSTRING, 0, (LPARAM) buf);

                SendDlgItemMessage(hwnd, IDC_CFG_SIZE,
                                   CB_SETITEMDATA, idx, text_sizes[i]);

                d->size_idx[i] = (int) idx;
            }

            update_selection(d, TRUE, TRUE);

            refresh_view(hwnd, d);
        }
        return FALSE;

    case WM_COMMAND:
        d = (dlg_data *) (LONG_PTR) GetWindowLongPtr(hwnd, DWLP_USER);
        if (d == NULL)
            return FALSE;

        if (wParam == MAKEWPARAM(IDC_CFG_FONTS, CBN_SELCHANGE)) {
            LRESULT idx;
            wchar_t facename[LF_FACESIZE];

            idx = SendDlgItemMessage(hwnd, IDC_CFG_FONTS,
                                     CB_GETCURSEL,
                                     0, 0);

            if (idx == CB_ERR)
                return TRUE;

            if (SendDlgItemMessage(hwnd, IDC_CFG_FONTS,
                                   CB_GETLBTEXTLEN, idx, 0)
                >= ARRAYLENGTH(facename))
                return TRUE;

            SendDlgItemMessage(hwnd, IDC_CFG_FONTS,
                               CB_GETLBTEXT, idx,
                               (LPARAM) facename);

            ZeroMemory(d->lf_work.lfFaceName,
                       sizeof(d->lf_work.lfFaceName));

            StringCbCopy(d->lf_work.lfFaceName,
                         sizeof(d->lf_work.lfFaceName),
                         facename);

            update_selection(d, FALSE, FALSE);

            refresh_view(hwnd, d);

            check_for_modification(d);

        } else if (wParam == MAKEWPARAM(IDC_CFG_BOLD, BN_CLICKED)) {

            if (IsDlgButtonChecked(hwnd, IDC_CFG_BOLD) == BST_CHECKED) {
                d->lf_work.lfWeight = FW_BOLD;
            } else {
                d->lf_work.lfWeight = 0;
            }

            refresh_view(hwnd, d);

            check_for_modification(d);

        } else if (wParam == MAKEWPARAM(IDC_CFG_ITALICS, BN_CLICKED)) {

            d->lf_work.lfItalic = (BYTE)
                (IsDlgButtonChecked(hwnd, IDC_CFG_ITALICS) == BST_CHECKED);

            refresh_view(hwnd, d);

            check_for_modification(d);

        } else if (wParam == MAKEWPARAM(IDC_CFG_REVERT, BN_CLICKED)) {
            HDC hdc;

            hdc = GetWindowDC(hwnd);

            khm_get_cw_element_font(hdc, NULL, TRUE, &d->lf_work);

            ReleaseDC(hwnd, hdc);

            update_selection(d, TRUE, TRUE);

            refresh_view(hwnd, d);

            check_for_modification(d);

        } else if (wParam == MAKEWPARAM(IDC_CFG_SIZE, CBN_SELCHANGE)) {
            HDC hdc;
            LPARAM idx;
            int points;

            idx = SendDlgItemMessage(hwnd, IDC_CFG_SIZE,
                                     CB_GETCURSEL, 0, 0);
            if (idx == CB_ERR)
                return TRUE;

            points = (int) SendDlgItemMessage(hwnd, IDC_CFG_SIZE,
                                              CB_GETITEMDATA, idx, 0);

            hdc = GetWindowDC(hwnd);

            d->lf_work.lfHeight = -MulDiv(points,
                                          GetDeviceCaps(hdc, LOGPIXELSY),
                                          72);

            ReleaseDC(hwnd, hdc);

            refresh_view(hwnd, d);

            check_for_modification(d);
        }

        return TRUE;

    case WM_DESTROY:
        d = (dlg_data *) (LONG_PTR) GetWindowLongPtr(hwnd, DWLP_USER);

        if (d) {
            if (d->c_font_bold)
                DeleteObject(d->c_font_bold);

            if (d->c_font_normal)
                DeleteObject(d->c_font_normal);

            PFREE(d);
            SetWindowLongPtr(hwnd, DWLP_USER, 0);
        }
        return TRUE;

    case KHUI_WM_CFG_NOTIFY:
        d = (dlg_data *) (LONG_PTR) GetWindowLongPtr(hwnd, DWLP_USER);
        if (d == NULL)
            return FALSE;

        if (HIWORD(wParam) == WMCFG_APPLY) {
            write_params(d);
            khui_action_trigger(KHUI_ACTION_LAYOUT_RELOAD, NULL);
        }

        return TRUE;
    }

    return FALSE;
}

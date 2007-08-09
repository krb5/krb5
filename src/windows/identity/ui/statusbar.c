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
#ifdef DEBUG
#include<assert.h>
#endif

khm_statusbar_part khm_statusbar_parts[] = {
    {KHUI_SBPART_INFO, 0, KHUI_SB_WTYPE_FILLER, NULL},
    {KHUI_SBPART_NOTICE, 40, KHUI_SB_WTYPE_RELATIVE, NULL},
#if 0
    /* Not implemented. This was originally intended to provide
       location information. */
    {KHUI_SBPART_LOC, 40, KHUI_SB_WTYPE_ABSOLUTE, NULL}
#endif
};

int khm_n_statusbar_parts = sizeof(khm_statusbar_parts) / sizeof(khm_statusbar_part);

HWND khm_hwnd_statusbar = NULL;

LRESULT 
khm_statusbar_notify(LPNMHDR nmhdr) {
    LPNMMOUSE pnmm;

    switch(nmhdr->code) {
    case NM_CLICK:
    case NM_DBLCLK:
        pnmm = (LPNMMOUSE) nmhdr;

        if (pnmm->dwItemSpec >= (DWORD) khm_n_statusbar_parts)
            return TRUE;

        if (khm_statusbar_parts[pnmm->dwItemSpec].id == KHUI_SBPART_NOTICE) {
            /* means, show next notification */
            kmq_post_message(KMSG_ALERT, KMSG_ALERT_SHOW_QUEUED, 0, 0);
        }

        return TRUE;
    }

    return FALSE;
}

void 
khui_statusbar_set_parts(HWND parent) {
    int i;
    int fillerwidth;
    int staticwidth;
    int lastx;
    int width;
    RECT r;
    INT * parts;

    GetClientRect(parent, &r);
    width = r.right - r.left;

    /* calculate fillerwidth and staticwidth */
    staticwidth = 0;
    for(i=0;i<khm_n_statusbar_parts;i++) {
        if(khm_statusbar_parts[i].wtype == KHUI_SB_WTYPE_ABSOLUTE) {
            staticwidth += khm_statusbar_parts[i].width;
        } else if(khm_statusbar_parts[i].wtype == KHUI_SB_WTYPE_RELATIVE) {
            staticwidth += (khm_statusbar_parts[i].width * width) / 100;
        }
    }

    fillerwidth = width - staticwidth;

    parts = PMALLOC(sizeof(INT) * khm_n_statusbar_parts);

    lastx = 0;
    for(i=0;i<khm_n_statusbar_parts;i++) {
        int w = 0;
        switch(khm_statusbar_parts[i].wtype) {
        case KHUI_SB_WTYPE_ABSOLUTE:
            w = khm_statusbar_parts[i].width;
            break;

        case KHUI_SB_WTYPE_RELATIVE:
            w = (khm_statusbar_parts[i].width * width) / 100;
            break;

        case KHUI_SB_WTYPE_FILLER:
            w = fillerwidth;
            break;

        default:
            w = 0;
#ifdef DEBUG
            assert(FALSE);
#endif
        }
        lastx += w;

        if(i==khm_n_statusbar_parts - 1)
            parts[i] = -1;
        else
            parts[i] = lastx;
    }

    SendMessage(
        khm_hwnd_statusbar,
        SB_SETPARTS,
        khm_n_statusbar_parts,
        (LPARAM) parts);

    PFREE(parts);
}

void khm_create_statusbar(HWND parent) {
    HWND hwsb;

    hwsb = CreateWindowEx(
        0,
        STATUSCLASSNAME,
        NULL,
        SBARS_SIZEGRIP | WS_CHILD | WS_VISIBLE,
        0,0,0,0,
        parent,
        NULL,
        khm_hInstance,
        NULL);

    if(!hwsb)
        return;

    khm_hwnd_statusbar = hwsb;

    khui_statusbar_set_parts(parent);

    kmq_post_message(KMSG_ALERT, KMSG_ALERT_CHECK_QUEUE, 0, 0);
}

void khm_update_statusbar(HWND parent) {
    MoveWindow(khm_hwnd_statusbar, 0, 0, 0, 0, TRUE);
    khui_statusbar_set_parts(parent);
}

int sb_find_index(int id) {
    int i;

    for(i=0;i<khm_n_statusbar_parts;i++) {
        if(khm_statusbar_parts[i].id == id)
            return i;
    }

    return -1;
}

void khm_statusbar_set_part(int id, HICON icon, wchar_t * text) {
    int idx;

    if (!khm_hwnd_statusbar)
        return;

    idx = sb_find_index(id);
    if(idx < 0)
        return;

    if (khm_statusbar_parts[idx].hIcon != NULL) {
        DestroyIcon(khm_statusbar_parts[idx].hIcon);
        khm_statusbar_parts[idx].hIcon = NULL;
    }

    if (icon) {
        khm_statusbar_parts[idx].hIcon = CopyImage(icon, IMAGE_ICON,
                                                   GetSystemMetrics(SM_CXSMICON),
                                                   GetSystemMetrics(SM_CYSMICON),
                                                   LR_COPYFROMRESOURCE);
    }

    SendMessage(khm_hwnd_statusbar,
                SB_SETICON,
                idx,
                (LPARAM) (khm_statusbar_parts[idx].hIcon ? khm_statusbar_parts[idx].hIcon:icon));

    SendMessage(khm_hwnd_statusbar,
                SB_SETTEXT,
                idx,
                (LPARAM) text);
}



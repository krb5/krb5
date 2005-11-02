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

#include<khmapp.h>

khui_statusbar_part khui_statusbar_parts[] = {
    {KHUI_SBPART_INFO, 0, KHUI_SB_WTYPE_FILLER},
    {KHUI_SBPART_NOTICE, 40, KHUI_SB_WTYPE_RELATIVE},
    {KHUI_SBPART_LOC, 40, KHUI_SB_WTYPE_ABSOLUTE}
};

int khui_n_statusbar_parts = sizeof(khui_statusbar_parts) / sizeof(khui_statusbar_part);

HWND khui_hwnd_statusbar = NULL;

void khui_statusbar_set_parts(HWND parent) {
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
    for(i=0;i<khui_n_statusbar_parts;i++) {
        if(khui_statusbar_parts[i].wtype == KHUI_SB_WTYPE_ABSOLUTE) {
            staticwidth += khui_statusbar_parts[i].width;
        } else if(khui_statusbar_parts[i].wtype == KHUI_SB_WTYPE_RELATIVE) {
            staticwidth += (khui_statusbar_parts[i].width * width) / 100;
        }
    }

    fillerwidth = width - staticwidth;

    parts = malloc(sizeof(INT) * khui_n_statusbar_parts);

    lastx = 0;
    for(i=0;i<khui_n_statusbar_parts;i++) {
        int w;
        switch(khui_statusbar_parts[i].wtype) {
            case KHUI_SB_WTYPE_ABSOLUTE:
                w = khui_statusbar_parts[i].width;
                break;

            case KHUI_SB_WTYPE_RELATIVE:
                w = (khui_statusbar_parts[i].width * width) / 100;
                break;

            case KHUI_SB_WTYPE_FILLER:
                w = fillerwidth;
                break;
        }
        lastx += w;

        if(i==khui_n_statusbar_parts - 1)
            parts[i] = -1;
        else
            parts[i] = lastx;
    }

    SendMessage(
        khui_hwnd_statusbar,
        SB_SETPARTS,
        khui_n_statusbar_parts,
        (LPARAM) parts);

    free(parts);
}

void khui_create_statusbar(HWND parent) {
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

    khui_hwnd_statusbar = hwsb;

    khui_statusbar_set_parts(parent);
}

void khui_update_statusbar(HWND parent) {
    MoveWindow(khui_hwnd_statusbar, 0, 0, 0, 0, TRUE);
    khui_statusbar_set_parts(parent);
}

int sb_find_index(int id) {
    int i;

    for(i=0;i<khui_n_statusbar_parts;i++) {
        if(khui_statusbar_parts[i].id == id)
            return i;
    }

    return -1;
}

void khui_statusbar_set_text(int id, wchar_t * text) {
    int idx;

    idx = sb_find_index(id);
    if(idx < 0)
        return;

    SendMessage(
        khui_hwnd_statusbar,
        SB_SETTEXT,
        idx,
        (LPARAM) text);
}


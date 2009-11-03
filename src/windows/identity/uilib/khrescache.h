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

#ifndef __KHIMAIRA_RESCACHE_H
#define __KHIMAIRA_RESCACHE_H

#include<khdefs.h>

KHMEXP void KHMAPI
khui_init_rescache(void);

KHMEXP void KHMAPI
khui_exit_rescache(void);

KHMEXP void KHMAPI
khui_cache_bitmap(UINT id, HBITMAP hbm);

KHMEXP HBITMAP KHMAPI
khui_get_cached_bitmap(UINT id);

typedef struct khui_ilist_t {
    int cx;
    int cy;
    int n;
    int ng;
    int nused;
    HBITMAP img;
    HBITMAP mask;
    int *idlist;
} khui_ilist;

typedef struct khui_bitmap_t {
    HBITMAP hbmp;
    int cx;
    int cy;
} khui_bitmap;

KHMEXP void KHMAPI
khui_bitmap_from_hbmp(khui_bitmap * kbm, HBITMAP hbm);

KHMEXP void KHMAPI
khui_delete_bitmap(khui_bitmap * kbm);

KHMEXP void KHMAPI
khui_draw_bitmap(HDC hdc, int x, int y, khui_bitmap * kbm);

/* image lists */
KHMEXP khui_ilist * KHMAPI
khui_create_ilist(int cx, int cy, int n, int ng, int opt);

KHMEXP BOOL KHMAPI
khui_delete_ilist(khui_ilist * il);

KHMEXP int KHMAPI
khui_ilist_add_masked(khui_ilist * il, HBITMAP hbm, COLORREF cbkg);

KHMEXP int KHMAPI
khui_ilist_add_masked_id(khui_ilist *il, HBITMAP hbm,
                         COLORREF cbkg, int id);

KHMEXP int KHMAPI
khui_ilist_lookup_id(khui_ilist *il, int id);

KHMEXP void KHMAPI
khui_ilist_draw(khui_ilist * il, int idx, HDC dc, int x, int y, int opt);

KHMEXP void KHMAPI
khui_ilist_draw_bg(khui_ilist * il, int idx, HDC dc, int x, int y,
                   int opt, COLORREF bgcolor);

#define khui_ilist_draw_id(il, id, dc, x, y, opt) \
    khui_ilist_draw((il),khui_ilist_lookup_id((il),(id)),(dc),(x),(y),(opt))

#define KHUI_SMICON_CX 16
#define KHUI_SMICON_CY 16

#endif

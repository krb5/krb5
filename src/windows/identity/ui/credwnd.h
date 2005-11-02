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

#ifndef __KHIMAIRA_CREDWND_H
#define __KHIMAIRA_CREDWND_H

#define KHUI_CREDWND_CLASS_NAME L"NetIDMgrCredWnd"

#define KHUI_CREDWND_FLAG_ATTRNAME L"CredWndFlags"

extern khm_int32 khui_cw_flag_id;

/* The expiration states */
#define CW_EXPSTATE_NONE        0
#define CW_EXPSTATE_WARN        1024
#define CW_EXPSTATE_CRITICAL    2048
#define CW_EXPSTATE_EXPIRED     3072

#define CW_EXPSTATE_MASK        3072

typedef struct khui_credwnd_outline_t {
    khm_int32   flags;      /* combination of KHUI_CW_O_* */
    khm_int32   start;      /* first row of outline */
    khm_int32   length;     /* number of rows in outline */
    khm_int32   level;      /* outline level */
    khm_int32   col;        /* outline column */
    wchar_t     *header;    /* character string associated with header */
    khm_int32   attr_id;
    void *      data;       /* level specific data :
                               Identity -> handle to identity
                               Type -> type ID
                               otherwise -> canonical data buffer
                            */
    khm_size    cb_data;

    khm_size    idx_start;  /* index of the first cred in the credset */
    khm_size    idx_end;    /* index of the last cred in the credset */
    TDCL(struct khui_credwnd_outline_t);
} khui_credwnd_outline;

#define KHUI_CW_O_EXPAND     0x00000001
#define KHUI_CW_O_STICKY     0x00000002
#define KHUI_CW_O_VISIBLE    0x00000004
#define KHUI_CW_O_SHOWFLAG   0x00000008
#define KHUI_CW_O_SELECTED   0x00000010
#define KHUI_CW_O_DATAALLOC  0x00000020

typedef struct khui_credwnd_row_t {
    khm_int32   flags;
    khm_int32   col;
    khm_handle  data;
    khm_size idx_start;
    khm_size idx_end;
} khui_credwnd_row;

#define KHUI_CW_ROW_CRED        2
#define KHUI_CW_ROW_HEADER      4
#define KHUI_CW_ROW_TIMERSET    8
#define KHUI_CW_ROW_SELECTED    16

/* row allocation */
/* initial number of rows to be allocated */
#define KHUI_CW_ROW_INITIAL     512
/* allocation increment, if we run out of space */
#define KHUI_CW_ROW_INCREMENT   512

typedef struct khui_credwnd_col_t {
    khm_int32 attr_id;
    khm_int32 width;        /* width of the column (screen units) */
    khm_int32 x;            /* starting x coordinate (screen units) */
    khm_int32 flags;        /* combination of KHUI_CW_COL_* */
    khm_int32 sort_index;
    wchar_t * title;
} khui_credwnd_col;

/* column allocation */
/* initial number of columns to be allocated */
#define KHUI_CW_COL_INITIAL     16
/* allocation increment, if we run out of space */
#define KHUI_CW_COL_INCREMENT   16

#define KHUI_CW_COL_AUTOSIZE    1
#define KHUI_CW_COL_SORT_INC    2
#define KHUI_CW_COL_SORT_DEC    4
#define KHUI_CW_COL_GROUP       8
#define KHUI_CW_COL_FIXED_WIDTH 16
#define KHUI_CW_COL_FIXED_POS   32
#define KHUI_CW_COL_META        64

/* Custom column attributes (are not kcdb attributes) */
#define CW_CA_FLAGS -1
#define CW_CANAME_FLAGS L"_CWFlags"

#define CW_CA_TYPEICON -2
#define CW_CANAME_TYPEICON L"_CWTypeIcon"

#define cw_is_custom_attr(i) ((i)<0)

typedef struct khui_credwnd_tbl_t {
    HWND hwnd;                  /* the window that this table belongs to */

    khm_int32 scr_top;          /* screen units */
    khm_int32 scr_left;         /* screen units */
    khm_int32 ext_width;        /* screen units */
    khm_int32 ext_height;       /* screen units */
    khm_int32 cell_height;      /* screen units */

    HWND hwnd_header;           /* header control */
    khm_int32 header_height;    /* height of the header */
    HWND hwnd_notif;            /* notification control */

    khui_credwnd_col * cols;    /* n_cols elements */
    khui_credwnd_row * rows;    /* n_rows elements */
    khm_size  n_cols;
    khm_size  n_total_cols;     /* number of columns actually
                                   allocated in cols */
    khm_size  n_rows;
    khm_size  n_total_rows;     /* number of rows actually allocated
                                   in rows */

    khui_credwnd_outline * outline;

    khm_int32 flags;            /* combo of KHUI_CW_TBL_* */

    khm_int32 cursor_row;       /* cursor and selection */
    khm_int32 anchor_row;       /* anchor, for range selections */

    /* view parameters */
    khm_int32 hpad;
    khm_int32 vpad;
    khm_int32 hpad_h;       /* horizontal padding correction for headers */
    khm_int32 threshold_warn;  /* Warning threshold, in seconds*/
    khm_int32 threshold_critical; /* Critical threshold, in seconds */

    /* graphics objects we are going to need. */
    HFONT hf_normal;        /* normal text */
    HFONT hf_header;        /* header text */
    HFONT hf_bold;          /* bold text */
    HFONT hf_bold_header;   /* bold header text */
    HBRUSH hb_normal;       /* normal background brush */
    HBRUSH hb_grey;         /* normal grey background brush */
    HBRUSH hb_sel;          /* selected background brush */
    COLORREF cr_hdr_outline;/* header outline color */
    COLORREF cr_normal;     /* normal text color */
    COLORREF cr_sel;        /* selected text color */
    COLORREF cr_hdr_normal; /* normal header text color */
    COLORREF cr_hdr_sel;    /* selected header text color */
    HBRUSH hb_hdr_bg;       /* header background color (normal) */
    HBRUSH hb_hdr_bg_exp;   /* header background color (expired) */
    HBRUSH hb_hdr_bg_warn;  /* header background color (warn) */
    HBRUSH hb_hdr_bg_crit;  /* header background color (critical) */
    HBRUSH hb_hdr_bg_sel;   /* header background color (selected) */
    HCURSOR hc_hand;        /* the HAND cursor */
    khui_ilist * ilist;     /* image list */

#if 0
    /* icon indices */
    int idx_expand;         /* index of 'expanded' icon in image list */
    int idx_expand_hi;      /* index of 'expanded' icon (highlighted) in image list */
    int idx_collapse;       /* index of 'collapsed' icon in image list */
    int idx_collapse_hi;    /* index of 'collapsed' icon (highlighted) in image list */
    int idx_ident;          /* index of 'identity' icon in image list */
#endif

    /* mouse state */
    khm_int32 mouse_state;        /* state of the mouse can be combo of CW_MOUSE_* values */
    khm_int32 mouse_row;          /* row that the mouse state applies to */
    khm_int32 mouse_col;          /* col that the mouse state applies to */

    khui_bitmap kbm_logo_shade;

    /* the credentials set */
    khm_handle credset;
} khui_credwnd_tbl;

#define KHUI_MAXCB_HEADING 256

/* table flags */
#define KHUI_CW_TBL_INITIALIZED 0x00000001
#define KHUI_CW_TBL_COL_DIRTY   0x00000002
#define KHUI_CW_TBL_ROW_DIRTY   0x00000004
#define KHUI_CW_TBL_ACTIVE      0x00000100

/* mouse_state constants */
#define CW_MOUSE_NONE       0   /* nothing interesting */
#define CW_MOUSE_OUTLINE    1   /* mouse is highlighting an outline widget */
#define CW_MOUSE_LDOWN      2   /* left button is down */
#define CW_MOUSE_ROW        4   /* mouse is acive over a valid row */

void khm_unregister_credwnd_class(void);

void khm_register_credwnd_class(void);

HWND khm_create_credwnd(HWND parent);

LRESULT CALLBACK khm_credwnd_proc(HWND hwnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam
    );

void    cw_load_view(khui_credwnd_tbl * tbl, wchar_t * viewname, HWND hwnd);

void    cw_update_creds(khui_credwnd_tbl * tbl);

void    cw_unload_view(khui_credwnd_tbl * tbl);

void    cw_hditem_from_tbl_col(khui_credwnd_col * col, HDITEM *phi);

int     cw_update_extents(khui_credwnd_tbl * tbl, khm_boolean update_scroll);

void    cw_insert_header_cols(khui_credwnd_tbl * tbl);

#endif

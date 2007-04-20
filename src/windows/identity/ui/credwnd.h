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

#ifndef __KHIMAIRA_CREDWND_H
#define __KHIMAIRA_CREDWND_H

#define KHUI_CREDWND_CLASS_NAME L"NetIDMgrCredWnd"

#define KHUI_CREDWND_FLAG_ATTRNAME L"CredWndFlags"

extern khm_int32 khui_cw_flag_id;

/* The expiration states */
#define CW_EXPSTATE_NONE        0x00000000
#define CW_EXPSTATE_WARN        0x00000400
#define CW_EXPSTATE_CRITICAL    0x00000800
#define CW_EXPSTATE_EXPIRED     0x00000c00

#define CW_EXPSTATE_MASK        0x00000c00

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

#define KHUI_CW_O_EXPAND        0x00000001
#define KHUI_CW_O_STICKY        0x00000002
#define KHUI_CW_O_VISIBLE       0x00000004
#define KHUI_CW_O_SHOWFLAG      0x00000008
#define KHUI_CW_O_SELECTED      0x00000010
#define KHUI_CW_O_DATAALLOC     0x00000020
#define KHUI_CW_O_NOOUTLINE     0x00000040
#define KHUI_CW_O_RELIDENT      0x00000080
#define KHUI_CW_O_EMPTY         0x00000100
/* NOTE: KHUI_CW_O_* shares the same bit-space as CW_EXPSTATE_* */

typedef struct khui_credwnd_row_t {
    khm_int32   flags;
    khm_int32   col;
    khm_handle  data;
    khm_size idx_start;
    khm_size idx_end;
    RECT        r_ext;          /* extents of this row */
} khui_credwnd_row;

#define KHUI_CW_ROW_CRED        0x00000002
#define KHUI_CW_ROW_HEADER      0x00000004
#define KHUI_CW_ROW_TIMERSET    0x00000008
#define KHUI_CW_ROW_SELECTED    0x00000010
#define KHUI_CW_ROW_EXPVIEW     0x00000020
/* NOTE: KHUI_CW_ROW_* shares the same bit-space as CW_EXPSTATE_* */

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

#define KHUI_CW_COL_AUTOSIZE    0x00000001
#define KHUI_CW_COL_SORT_INC    0x00000002
#define KHUI_CW_COL_SORT_DEC    0x00000004
#define KHUI_CW_COL_GROUP       0x00000008
#define KHUI_CW_COL_FIXED_WIDTH 0x00000010
#define KHUI_CW_COL_FIXED_POS   0x00000020
#define KHUI_CW_COL_META        0x00000040
#define KHUI_CW_COL_FILLER      0x00000080

/* Custom column attributes (are not kcdb attributes) */
#define CW_CA_FLAGS -1
#define CW_CANAME_FLAGS L"_CWFlags"

#define CW_CA_TYPEICON -2
#define CW_CANAME_TYPEICON L"_CWTypeIcon"

#define cw_is_custom_attr(i) ((i)<0)

typedef struct tag_khui_credwnd_ident {

    khm_handle ident;
    khm_int32  ident_flags;
    khm_int32  credtype;
    wchar_t    name[KCDB_IDENT_MAXCCH_NAME];
    wchar_t    credtype_name[KCDB_MAXCCH_NAME];

    khm_size   credcount;       /* count of all credentials */
    khm_size   id_credcount;    /* count of identity credentials
                                   (credentials that are of the
                                   identity type */
    khm_size   init_credcount;  /* count of initial credentials */
    FILETIME   ft_expire;

} khui_credwnd_ident;

#define CW_IDENT_ALLOC_INCR 4

#define CW_EXP_ROW_MULT 2

typedef struct khui_credwnd_tbl_t {
    HWND hwnd;                  /* the window that this table belongs to */

    khm_handle csp_view;        /* handle to the configuration space
                                   that defined the view */

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
    int       n_cols;
    int       n_total_cols;     /* number of columns actually
                                   allocated in cols */
    int       n_rows;
    int       n_total_rows;     /* number of rows actually allocated
                                   in rows */

    khui_credwnd_outline * outline;

    khm_int32 flags;            /* combo of KHUI_CW_TBL_* */

    int       cursor_row;       /* cursor and selection */
    int       anchor_row;       /* anchor, for range selections */

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
    HBRUSH hb_grey;         /* normal background brush (greyed) */
    HBRUSH hb_s;            /* normal background brush (selected) */

    HBRUSH hb_hdr_bg;       /* header background brush (normal) */
    HBRUSH hb_hdr_bg_exp;   /* header background brush (expired) */
    HBRUSH hb_hdr_bg_warn;  /* header background brush (warn) */
    HBRUSH hb_hdr_bg_crit;  /* header background brush (critical) */
    HBRUSH hb_hdr_bg_def;   /* header background brush (default) */

    HBRUSH hb_hdr_bg_s;     /* header background brush (selected) */
    HBRUSH hb_hdr_bg_exp_s; /* header background brush (expired,selected) */
    HBRUSH hb_hdr_bg_warn_s;/* header background brush (warn,selected) */
    HBRUSH hb_hdr_bg_crit_s;/* header background brush (critical,selected) */
    HBRUSH hb_hdr_bg_def_s; /* header background brush (default,selected) */

    COLORREF cr_normal;     /* text color (normal) */
    COLORREF cr_s;          /* text color (selected) */
    COLORREF cr_hdr_normal; /* header text color (normal) */
    COLORREF cr_hdr_s;      /* header text color (selected) */
    COLORREF cr_hdr_gray;   /* header text color (greyed) */
    COLORREF cr_hdr_gray_s; /* header text color (greyed,selected) */

    COLORREF cr_hdr_outline;/* header outline color */

    HCURSOR hc_hand;        /* the HAND cursor */
    khui_ilist * ilist;     /* image list */

    HICON   hi_lg_ident;    /* large identity icon */

    /* mouse state */
    khm_int32 mouse_state;        /* state of the mouse can be combo of CW_MOUSE_* values */
    khm_int32 mouse_row;          /* row that the mouse state applies to */
    khm_int32 mouse_col;          /* col that the mouse state applies to */

    khui_bitmap kbm_logo_shade;

    /* the credentials set */
    khm_handle credset;

    khui_credwnd_ident * idents;
    khm_size n_idents;
    khm_size nc_idents;

} khui_credwnd_tbl;

#define KHUI_MAXCB_HEADING 256

/* table flags */
#define KHUI_CW_TBL_INITIALIZED 0x00000001
#define KHUI_CW_TBL_COL_DIRTY   0x00000002
#define KHUI_CW_TBL_ROW_DIRTY   0x00000004
#define KHUI_CW_TBL_ACTIVE      0x00000100
#define KHUI_CW_TBL_CUSTVIEW    0x00000200
#define KHUI_CW_TBL_COLSKIP     0x00000400
#define KHUI_CW_TBL_EXPIDENT    0x00000800
#define KHUI_CW_TBL_NOHEADER    0x00001000

/* mouse_state constants */
#define CW_MOUSE_NONE       0x00000000 /* nothing interesting */
#define CW_MOUSE_WIDGET     0x00000001 /* mouse is highlighting a
                                          widget */
#define CW_MOUSE_LDOWN      0x00000002 /* left button is down */
#define CW_MOUSE_ROW        0x00000004 /* mouse is acive over a valid
                                          row */
#define CW_MOUSE_WOUTLINE   0x00000008 /* mouse is highlighting an
                                          outline widget */
#define CW_MOUSE_WSTICKY    0x00000010 /* mouse is highlighting a
                                          sticky widget */
#define CW_MOUSE_WICON      0x00000020 /* an icon widget.  represents
                                          the icon next to identities
                                          and next to credentials. */

#define CW_MOUSE_WMASK      0x00000039 /* all widget bits */

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

void    khm_get_cw_element_font(HDC hdc, wchar_t * name, BOOL use_default,
                                LOGFONT * pfont);

void    khm_set_cw_element_font(wchar_t * name, LOGFONT * pfont);

#endif

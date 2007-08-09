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
#include<crtdbg.h>

ATOM khui_htwnd_cls;

#define HTW_STYLE_NORMAL        0

/* There are currently 4 style "bits" and 3 sizes, which means
   there can be 2^4*3=48 possible styles max.  If someone is
   feeling adventurous you can slightly improve performance of
   the parser using this little fact.  For now, I don't care.
   (hint: combine size and style bits to form a single number
   and use it as an index into the styles array)
*/
#define HTW_STYLE_MAX           48

#define HTW_FORMAT_MAX          128

#define HTW_TAB_MAX             8

#define HTW_DEFAULT             (-1)

#define HTW_NORMAL_SIZE         8
#define HTW_LARGE_SIZE          12
#define HTW_HUGE_SIZE           20

/* font variant */
#define FV_ABSOLUTE     0x10000000

#define FV_ITALIC       0x00000002
#define FV_UNDERLINE    0x00000004
#define FV_STRIKEOUT    0x00000008
#define FV_BOLD         0x00000010

#define FV_NOITALIC     0x00020000
#define FV_NOUNDERLINE  0x00040000
#define FV_NOSTRIKEOUT  0x00080000
#define FV_NOBOLD       0x00100000

#define FV_NONE         0x00000000
#define FV_MASK         0x0000001f

#define HTW_LINK_ALLOC     8

#define ALIGN_LEFT      0
#define ALIGN_CENTER    1
#define ALIGN_RIGHT     2

struct tx_tbl_t {
    wchar_t *   string;
    LONG        value;
} 

htw_color_table[] = {
    {L"black", RGB(0,0,0)},
    {L"white", RGB(255,255,255)},
    {L"red", RGB(255,0,0)},
    {L"green", RGB(0,255,0)},
    {L"blue", RGB(0,0,255)},
    {L"grey", RGB(128,128,128)}
},

htw_size_table[] = {
    {L"normal", HTW_NORMAL_SIZE},
    {L"large", HTW_LARGE_SIZE},
    {L"huge", HTW_HUGE_SIZE}
},

htw_align_table[] = {
    {L"left", ALIGN_LEFT},
    {L"center", ALIGN_CENTER},
    {L"right", ALIGN_RIGHT}
};

typedef struct khui_htwnd_style_t {
    LONG height;
    LONG variation;     /* combination of FV_* */

    HFONT font;
} khui_htwnd_style;

typedef struct khui_format_t {
    int style_idx;
    COLORREF color;
} khui_format;

typedef struct format_stack_t {
    khui_format stack[HTW_FORMAT_MAX];
    int stack_top;
} format_stack;

typedef struct khui_htwnd_data_t {
    int id; /* control ID */
    int flags;
    wchar_t * text;
    int scroll_left;
    int scroll_top;
    int ext_width;
    int ext_height;
    COLORREF bk_color;
    HCURSOR hc_hand;
    int l_pixel_y;

    khui_htwnd_style styles[HTW_STYLE_MAX];
    int n_styles;

    khui_htwnd_link ** links;
    int n_links;
    int max_links;
    int active_link;
    int md_link;

    int tabs[HTW_TAB_MAX];
    int n_tabs;
} khui_htwnd_data;

static LONG table_lookup(struct tx_tbl_t * tbl, int n, wchar_t * v, int len)
{
    int i;

    for(i=0; i<n; i++) {
        if(!_wcsnicmp(tbl[i].string, v, len))
            return tbl[i].value;
    }

    return -1;
}

static void clear_styles(khui_htwnd_data * d)
{
    int i;

    for(i=0; i<d->n_styles; i++) {
        if(d->styles[i].font != NULL) {
            DeleteObject(d->styles[i].font);
            d->styles[i].font = NULL;
        }
    }

    d->n_styles = 0;
}

static void format_init(format_stack * s)
{
    s->stack_top = -1;
    ZeroMemory(s->stack, sizeof(s->stack));
}

static khui_format * format_current(format_stack * s)
{
    if(s->stack_top >= 0)
        return &(s->stack[s->stack_top]);
    else
        return NULL;
}

static int format_style(format_stack * s)
{
    if(s->stack_top >= 0)
        return s->stack[s->stack_top].style_idx;
    else
        return 0;
}

static COLORREF format_color(format_stack * s)
{
    if(s->stack_top >= 0)
        return s->stack[s->stack_top].color;
    else
        return 0;
}

static int format_level(format_stack * s)
{
    return s->stack_top;
}

static void format_unwind(format_stack * s, int level)
{
    s->stack_top = level;
}

static void format_push(format_stack * s, khui_htwnd_data * d, LONG height, LONG variation, COLORREF color)
{
    int i;
    khui_format * top;
    khui_htwnd_style * style;

    _ASSERT(s->stack_top < (HTW_FORMAT_MAX-1));

    /* formatting is additive unless FV_NORMAL is set in variation */
    top = format_current(s);
    if(top) {
        style = &(d->styles[top->style_idx]);
        if(height == HTW_DEFAULT)
            height = style->height;

        if(variation == HTW_DEFAULT)
            variation = style->variation;
        else if(!(variation & FV_ABSOLUTE))
            variation |= style->variation;

        if(color == HTW_DEFAULT)
            color = top->color;
    }

    variation &= ~FV_ABSOLUTE;
    variation ^= variation & (variation>>16);
    variation &= FV_MASK;

    /* now look for an existing style that matches the requested one */
    for(i=0; i<d->n_styles; i++) {
        style = &(d->styles[i]);

        if(style->height == height &&
            style->variation == variation)
            break;
    }

    s->stack_top++;

    if(i<d->n_styles) {
        s->stack[s->stack_top].style_idx = i;
    } else {
        if(d->n_styles == HTW_STYLE_MAX) {
            s->stack[s->stack_top].style_idx = 0;
        } else {
            s->stack[s->stack_top].style_idx = d->n_styles;
            d->styles[d->n_styles].font = NULL;
            d->styles[d->n_styles].height = height;
            d->styles[d->n_styles].variation = variation;
            d->n_styles++;
        }
    }
    s->stack[s->stack_top].color = color;
}

static void format_pop(format_stack * s) {
    if(s->stack_top >= 0)
        s->stack_top--;
}

static wchar_t * token_end(wchar_t * s) {
    while(iswalnum(*s) || *s == L'/')
        s++;
    return s;
}

static wchar_t * skip_ws(wchar_t * s) {
    while(iswspace(*s))
        s++;
    return s;
}

/* s points to something like " = \"value\"" 
   start and len will point to the start and
   length of value.  return value will point to the
   character following the last double quote. */
static wchar_t * read_attr(wchar_t * s, wchar_t ** start, int * len)
{
    wchar_t *e;

    *start = NULL;
    *len = 0;

    do {
        s = skip_ws(s);
        if(*s != L'=')
            break;
        s = skip_ws(++s);
        if(*s != L'"')
            break;
        e = wcschr(++s, L'"');
        if(!e)
            break;

        *start = s;
        *len = (int) (e - s);

        s = e + 1;
    } while(FALSE);

    return s;
}

/*
We currently support the following tags:

<a [id="string"] [param="paramstring"]>link text</a>
<b>foo</b>
<u>foo</u>
<i>foo</i>

<font [color="(color)"] [size="normal|large|huge|(point size)"]>foo</font>
   (color)=black|white|red|green|blue|grey
<large>foo</large>
<huge>foo</huge>

<center>foo</center>
<left>foo</left>
<right>foo</right>

<p [align="left|center|right"]>foo</p>
<settab pos="(pos)">
<tab>
*/

static int htw_parse_tag(
    wchar_t * start, 
    wchar_t ** end, 
    int * align, 
    khui_htwnd_data * d, 
    format_stack * s, 
    PPOINT p_abs,
    PPOINT p_rel,
    int lh, 
    BOOL dry_run)
{
    wchar_t * c;
    int n = 0;

    /* start initially points to the starting '<' */
    c = token_end(++start);

    if(!_wcsnicmp(start,L"a",c-start)) {
        /* start of an 'a' tag */
        wchar_t * id_start = NULL;
        int id_len = 0;
        wchar_t * param_start = NULL;
        int param_len = 0;

        /* We don't need to parse the link
           if it is just a dry run */
        if(dry_run) {
            format_push(s, d, HTW_DEFAULT, HTW_DEFAULT, RGB(0,0,255));
            *end = wcschr(start, L'>');
            return FALSE;
        }

        while(c && *c && *c != L'>') {
            wchar_t * e;

            c = skip_ws(c);
            e = token_end(c);

            if(c==e)
                break;

            if(!_wcsnicmp(c,L"id",e-c)) {
                c = read_attr(e, &id_start, &id_len);
            } else if(!_wcsnicmp(c,L"param",e-c)) {
                c = read_attr(e, &param_start, &param_len);
            }
        }

        if(d->active_link == d->n_links)
            format_push(s,d, HTW_DEFAULT, FV_UNDERLINE, RGB(0,0,255));
        else
            format_push(s,d, HTW_DEFAULT, FV_NONE, RGB(0,0,255));

        {
            khui_htwnd_link * l;

            if(!d->links) {
                d->links = PMALLOC(sizeof(khui_htwnd_link *) * HTW_LINK_ALLOC);
                ZeroMemory(d->links, sizeof(khui_htwnd_link *) * HTW_LINK_ALLOC);
                d->max_links = HTW_LINK_ALLOC;
                d->n_links = 0;
            }

            if(d->n_links >= d->max_links) {
                khui_htwnd_link ** ll;
                int n_new;

                n_new = UBOUNDSS(d->n_links + 1, HTW_LINK_ALLOC, HTW_LINK_ALLOC);

                ll = PMALLOC(sizeof(khui_htwnd_link *) * n_new);
                ZeroMemory(ll, sizeof(khui_htwnd_link *) * n_new);
                memcpy(ll, d->links, sizeof(khui_htwnd_link *) * d->max_links);
                PFREE(d->links);
                d->links = ll;
                d->max_links = n_new;
            }

            l = d->links[d->n_links];
            if(!l) {
                l = PMALLOC(sizeof(khui_htwnd_link));
                d->links[d->n_links] = l;
            }

            l->id = id_start;
            l->id_len = id_len;
            l->param = param_start;
            l->param_len = param_len;

            l->r.left = p_abs->x;
            l->r.top = p_abs->y;

            d->n_links++;
        }

    } else if(!_wcsnicmp(start, L"/a", c - start)) {
        khui_htwnd_link * l;

        c = wcschr(c,L'>');
        if(!c)
            c = c + wcslen(c);

        format_pop(s);

        if(!dry_run) {
            l = d->links[d->n_links - 1]; /* last link */
            l->r.right = p_abs->x;
            l->r.bottom = p_abs->y + lh;
        }
    } else if(!_wcsnicmp(start, L"p", c - start)) {
        wchar_t * e;
        wchar_t * align_s = NULL;
        int align_len = 0;

        c = skip_ws(c);
        e = token_end(c);

        if(c != e && !_wcsnicmp(c,L"align",e-c)) {
            c = read_attr(e, &align_s, &align_len);
        }

        c = wcschr(c, L'>');
        if(!c)
            c = c + wcslen(c);
        

        if(align_s)
            *align = table_lookup(htw_align_table, ARRAYLENGTH(htw_align_table), align_s, align_len);
        else
            *align = ALIGN_LEFT;

        n = 1;
    } else if(!_wcsnicmp(start, L"b", c - start)) {
        format_push(s,d, HTW_DEFAULT, FV_BOLD, HTW_DEFAULT);
    } else if(!_wcsnicmp(start, L"/b", c - start)) {
        format_pop(s);
    } else if(!_wcsnicmp(start, L"u", c - start)) {
        format_push(s,d, HTW_DEFAULT, FV_UNDERLINE, HTW_DEFAULT);
    } else if(!_wcsnicmp(start, L"/u", c - start)) {
        format_pop(s);
    } else if(!_wcsnicmp(start, L"i", c - start)) {
        format_push(s,d, HTW_DEFAULT, FV_ITALIC, HTW_DEFAULT);
    } else if(!_wcsnicmp(start, L"/i", c - start)) {
        format_pop(s);
    } else if(!_wcsnicmp(start, L"large", c - start)) {
        format_push(s,d,-MulDiv(HTW_LARGE_SIZE, d->l_pixel_y, 72), HTW_DEFAULT, HTW_DEFAULT);
    } else if(!_wcsnicmp(start, L"/large", c - start)) {
        format_pop(s);
    } else if(!_wcsnicmp(start, L"huge", c - start)) {
        format_push(s,d,-MulDiv(HTW_HUGE_SIZE, d->l_pixel_y, 72), HTW_DEFAULT, HTW_DEFAULT);
    } else if(!_wcsnicmp(start, L"/huge", c - start)) {
        format_pop(s);
    } else if(!_wcsnicmp(start, L"center", c - start)) {
        c = wcschr(c, L'>');
        if(!c)
            c = c + wcslen(c);
        *align = ALIGN_CENTER;
        n = 1;
    } else if(!_wcsnicmp(start, L"left", c - start) ||
        !_wcsnicmp(start, L"p", c - start)) 
    {
        c = wcschr(c, L'>');
        if(!c)
            c = c + wcslen(c);
        *align = ALIGN_LEFT;
        n = 1;
    } else if(!_wcsnicmp(start, L"right", c - start)) {
        c = wcschr(c, L'>');
        if(!c)
            c = c + wcslen(c);
        *align = ALIGN_RIGHT;
        n = 1;
    } else if(!_wcsnicmp(start, L"/center", c - start) ||
              !_wcsnicmp(start, L"/left", c - start) ||
              !_wcsnicmp(start, L"/right", c - start) ||
              !_wcsnicmp(start, L"/p", c - start)) {
        c = wcschr(c, L'>');
        if(!c)
            c = c + wcslen(c);
        *align = ALIGN_LEFT;
        n = 1;
    } else if(!_wcsnicmp(start, L"font", c - start)) {
        wchar_t * color_s = NULL;
        int color_len = 0;
        wchar_t * size_s = NULL;
        int size_len = 0;
        LONG color = HTW_DEFAULT;
        LONG h = HTW_DEFAULT;

        while(c && *c && *c != L'>') {
            wchar_t * e;

            c = skip_ws(c);
            e = token_end(c);

            if(c==e)
                break;

            if(!_wcsnicmp(c,L"color",e-c)) {
                c = read_attr(e, &color_s, &color_len);
            } else if(!_wcsnicmp(c,L"size",e-c)) {
                c = read_attr(e, &size_s, &size_len);
            }
        }

        if(color_s)
            color = table_lookup(htw_color_table, ARRAYLENGTH(htw_color_table), color_s, color_len);
        if(size_s) {
            h = table_lookup(htw_size_table, ARRAYLENGTH(htw_size_table), size_s, size_len);
            if(h)
                h = -MulDiv(h, d->l_pixel_y, 72);
            else
                h = -MulDiv(HTW_NORMAL_SIZE, d->l_pixel_y, 72);
        }

        format_push(s,d,h,HTW_DEFAULT,color);
    } else if(!_wcsnicmp(start, L"/font", c - start)) {
        format_pop(s);
    } else if(!_wcsnicmp(start, L"settab", c - start)) {
        wchar_t * e;
        wchar_t * pos_s = NULL;
        int pos_len;

        c = skip_ws(c);
        e = token_end(c);

        if(c != e && !_wcsnicmp(c,L"pos",e-c)) {
            c = read_attr(e, &pos_s, &pos_len);
        }

        c = wcschr(c, L'>');
        if(!c)
            c = c + wcslen(c);

        if(pos_s && d->n_tabs < HTW_TAB_MAX && !dry_run) {
            wchar_t * dummy;
            LONG bu;
            int bx;
            int dx;

            bu = GetDialogBaseUnits();
            bx = LOWORD(bu);

            dx = wcstol(pos_s, &dummy, 10);

            d->tabs[d->n_tabs++] = MulDiv(dx, bx, 4);
        }
    } else if(!_wcsnicmp(start, L"tab", c - start)) {
        int i;

        if(!dry_run) {
            for(i=0; i < d->n_tabs; i++) {
                if(d->tabs[i] > p_rel->x) {
                    p_rel->x = d->tabs[i];
                    break;
                }
            }
        }
    }

    if(*c)
        c++;
    *end = c;

    return n;
}

static void htw_assert_style(HDC hdc, khui_htwnd_data * d, int style)
{
    LOGFONT lf;

    if(d->styles[style].font)
        return;

    /*TODO: we need select different fonts depending on system locale */
    lf.lfHeight = d->styles[style].height; //-MulDiv(8, GetDeviceCaps(hdc, LOGPIXELSY), 72);
    lf.lfWidth = 0;
    lf.lfEscapement = 0;
    lf.lfOrientation = 0;
    lf.lfWeight = (d->styles[style].variation & FV_BOLD)? FW_BOLD: FW_NORMAL;
    lf.lfItalic = !!(d->styles[style].variation & FV_ITALIC);
    lf.lfUnderline = !!(d->styles[style].variation & FV_UNDERLINE);
    lf.lfStrikeOut = !!(d->styles[style].variation & FV_STRIKEOUT);
    lf.lfCharSet = DEFAULT_CHARSET;
    lf.lfOutPrecision = OUT_DEFAULT_PRECIS;
    lf.lfClipPrecision = CLIP_DEFAULT_PRECIS;
    lf.lfQuality = DEFAULT_QUALITY;
    lf.lfPitchAndFamily = DEFAULT_PITCH;

    LoadString(khm_hInstance, IDS_DEFAULT_FONT, lf.lfFaceName, ARRAYLENGTH(lf.lfFaceName));

    d->styles[style].font = CreateFontIndirect(&lf);
}

static LRESULT htw_paint(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    PAINTSTRUCT ps;
    HBRUSH hbk;
    khui_htwnd_data * d;
    RECT r;
    SIZE s;
    HDC hdc;
    wchar_t * text;
    format_stack s_stack;

    int align;
    int y;
    wchar_t * par_start;
    int ext_width = 0;
    int ext_height = 0;

    d = (khui_htwnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);

    if(!GetUpdateRect(hwnd, &r, !(d->flags & KHUI_HTWND_TRANSPARENT)))
        return 0;

    if(d->text == NULL)
        return 0;

    text = d->text;

    hdc = BeginPaint(hwnd, &ps);

    GetClientRect(hwnd, &r);

#ifdef DRAW_HTWND_CLIENT_EDGE
    /* for the moment, we are skipping on the client edge. */
    if(d->flags & KHUI_HTWND_CLIENTEDGE)
        DrawEdge(hdc, &r, EDGE_SUNKEN, BF_ADJUST | BF_RECT | BF_FLAT);
#endif

    hbk = GetSysColorBrush(COLOR_WINDOW);
    FillRect(hdc, &r, hbk);
    hbk = NULL;                 /* We don't need to destroy system
                                   brushes */

    /* push the default format */
    format_init(&s_stack);

    d->l_pixel_y = GetDeviceCaps(hdc, LOGPIXELSY);
    format_push(&s_stack,d, -MulDiv(HTW_NORMAL_SIZE, d->l_pixel_y, 72), FV_NONE, RGB(0,0,0));

    y = r.top - d->scroll_top;

    par_start = text;

    align = ALIGN_LEFT;

    SetTextAlign(hdc, TA_TOP | TA_LEFT | TA_NOUPDATECP);
    if(d->flags & KHUI_HTWND_TRANSPARENT)
        SetBkMode(hdc, TRANSPARENT);

    d->n_links = 0;
    d->n_tabs = 0;

    while(*par_start) {
        wchar_t * p = par_start;
        wchar_t * c = NULL;
        int p_width = 0;
        int s_start;
        int l_height = 0;
        int x = 0;
        POINT pt;
        POINT pt_rel;

        s_start = format_level(&s_stack);

        /* begin dry run */
        while(*p) {
            if(*p == L'<') {
                int talign = -1;
                int n = htw_parse_tag(p,&c,&talign,d,&s_stack,NULL,NULL,0,TRUE);

                if(n && p_width)
                    break;

                p = c;

                if(n && talign >= 0)
                    align = talign;
            } else {
                HFONT hfold;
                c = wcschr(p, L'<');
                if(!c)
                    c = p + wcslen(p);

                htw_assert_style(hdc, d, format_style(&s_stack));
                hfold = SelectFont(hdc, d->styles[format_style(&s_stack)].font);
                GetTextExtentPoint32(hdc, p, (int)(c - p), &s);
                SelectFont(hdc, hfold);

                p_width += s.cx;
                if(s.cy > l_height)
                    l_height = s.cy;

                p = c;
            }
        }

        /* dry run ends */

        x = r.left - d->scroll_left;

        if(align == ALIGN_CENTER) {
            if (r.right - r.left > p_width)
                x += (r.right - r.left)/2 - p_width / 2;
        }

        else if(align == ALIGN_RIGHT) {
            if (r.right - r.left > p_width)
                x += (r.right - r.left) - p_width;
        }

        /* begin wet run */
        p = par_start;
        format_unwind(&s_stack, s_start); /* unwind format stack */

        p_width = 0;

        while(p && *p) {
            if(*p == L'<') {
                int talign = -1;
                int n;

                pt.x = x + p_width;
                pt.y = y;
                pt_rel.x = p_width;
                pt_rel.y = 0;

                n = htw_parse_tag(p, &c, &talign, d, &s_stack, &pt, &pt_rel, l_height, FALSE);

                if(n && p_width) {
                    break;
                }

                p_width = pt_rel.x;

                p = c;
                if(n && talign >= 0)
                    align = talign;
            } else {
                HFONT hfold;
                RECT rd;

                c = wcschr(p, L'<');
                if(!c)
                    c = p + wcslen(p);

                htw_assert_style(hdc, d, format_style(&s_stack));
                hfold = SelectFont(hdc, d->styles[format_style(&s_stack)].font);
                SetTextColor(hdc, format_color(&s_stack));

                GetTextExtentPoint32(hdc, p, (int)(c - p), &s);
                rd.left = x + p_width;
                rd.top = y;
                rd.right = rd.left + s.cx;
                rd.bottom = rd.top + l_height;

                DrawText(hdc, p, (int)(c - p), &rd,
                         DT_BOTTOM | DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);

                p_width += s.cx;

                SelectFont(hdc, hfold);
                p = c;
            }
        }

        if (p_width > ext_width)
            ext_width = p_width;

        y += l_height;
        par_start = p;
    }

    if (y > ext_height)
        ext_height = y;

    EndPaint(hwnd, &ps);

    if (d->ext_width < ext_width ||
        d->ext_height < ext_height) {
        SCROLLINFO si;
        LONG l;

        /* the extents need to be adjusted.  But first check if we
           have exactly the right scroll bars we need. */
        if ((ext_width > (r.right - r.left) &&
             !(d->flags & KHUI_HTWND_HSCROLL)) ||
            (ext_height > (r.bottom - r.top) &&
             !(d->flags & KHUI_HTWND_VSCROLL)) ||

            (ext_width <= (r.right - r.left) &&
             (d->flags & KHUI_HTWND_HSCROLL)) ||
            (ext_height <= (r.bottom - r.top) &&
             (d->flags & KHUI_HTWND_VSCROLL))) {

            /* need to add scroll bars */
            if (ext_width > (r.right - r.left))
                d->flags |= KHUI_HTWND_HSCROLL;
            else
                d->flags &= ~KHUI_HTWND_HSCROLL;

            if (ext_height > (r.bottom - r.top))
                d->flags |= KHUI_HTWND_VSCROLL;
            else
                d->flags &= ~KHUI_HTWND_VSCROLL;

            l = GetWindowLongPtr(hwnd, GWL_STYLE);
            l &= ~(WS_HSCROLL | WS_VSCROLL);

            l |= ((d->flags & KHUI_HTWND_HSCROLL) ? WS_HSCROLL : 0) |
                ((d->flags & KHUI_HTWND_VSCROLL) ? WS_VSCROLL : 0);

            SetWindowLongPtr(hwnd, GWL_STYLE, l);

            InvalidateRect(hwnd, NULL, FALSE);
            /* since the client area changed, we do another redraw
               before updating the scroll bar positions. */
        } else {
            d->ext_width = ext_width;
            d->ext_height = ext_height;

            if (d->flags & KHUI_HTWND_HSCROLL) {
                ZeroMemory(&si, sizeof(si));
                si.cbSize = sizeof(si);
                si.fMask = SIF_ALL | SIF_DISABLENOSCROLL;
                si.nMin = 0;
                si.nMax = ext_width;
                si.nPage = r.right - r.left;
                si.nPos = d->scroll_left;

                SetScrollInfo(hwnd, SB_HORZ, &si, TRUE);
            }

            if (d->flags & KHUI_HTWND_VSCROLL) {
                ZeroMemory(&si, sizeof(si));
                si.cbSize = sizeof(si);
                si.fMask = SIF_ALL | SIF_DISABLENOSCROLL;
                si.nMin = 0;
                si.nMax = ext_height;
                si.nPage = r.bottom - r.top;
                si.nPos = d->scroll_top;

                SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
            }
        }
    }

    return 0;
}

LRESULT CALLBACK khui_htwnd_proc(HWND hwnd,
                                 UINT uMsg,
                                 WPARAM wParam,
                                 LPARAM lParam
                                 )
{
    switch(uMsg) {
    case WM_CREATE:
        {
            CREATESTRUCT * cs;
            khui_htwnd_data * d;
            size_t cbsize;

            cs = (CREATESTRUCT *) lParam;

            d = PMALLOC(sizeof(*d));
            ZeroMemory(d, sizeof(*d));

            if(cs->dwExStyle & WS_EX_TRANSPARENT) {
                d->flags |= KHUI_HTWND_TRANSPARENT;
            }
            if(cs->dwExStyle & WS_EX_CLIENTEDGE) {
                d->flags |= KHUI_HTWND_CLIENTEDGE;
            }
            if(cs->style & WS_HSCROLL) {
                d->flags |= KHUI_HTWND_HSCROLL;
            }
            if(cs->style & WS_VSCROLL) {
                d->flags |= KHUI_HTWND_VSCROLL;
            }
            d->id = (int)(INT_PTR) cs->hMenu;

            d->active_link = -1;
            d->bk_color = RGB(255,255,255);
            d->hc_hand = LoadCursor(NULL, IDC_HAND);

            if(SUCCEEDED(StringCbLength(cs->lpszName, KHUI_HTWND_MAXCB_TEXT, &cbsize))) {
                cbsize += sizeof(wchar_t);
                d->text = PMALLOC(cbsize);
                StringCbCopy(d->text, cbsize, cs->lpszName);
            }

            /* this is just a flag to the WM_PAINT handler that the
               extents haven't been set yet. */
            d->ext_width = -1;

#pragma warning(push)
#pragma warning(disable: 4244)
            SetWindowLongPtr(hwnd, 0, (LONG_PTR) d);
#pragma warning(pop)

            return 0;
        }
        break;

    case WM_SETTEXT:
        {
            wchar_t * newtext;
            size_t cbsize;
            khui_htwnd_data * d;
            BOOL rv;

            d = (khui_htwnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);
            newtext = (wchar_t *) lParam;

            if(d->text) {
                PFREE(d->text);
                d->text = NULL;
            }

            if(SUCCEEDED(StringCbLength(newtext, KHUI_HTWND_MAXCB_TEXT, &cbsize))) {
                cbsize += sizeof(wchar_t);
                d->text = PMALLOC(cbsize);
                StringCbCopy(d->text, cbsize, newtext);
                rv = TRUE;
            } else
                rv = FALSE;

            clear_styles(d);

            d->ext_width = -1;
            d->scroll_left = 0;
            d->scroll_top = 0;

            InvalidateRect(hwnd, NULL, TRUE);

            return rv;
        }
        break;

    case WM_DESTROY:
        {
            khui_htwnd_data * d;
            int i;

            d = (khui_htwnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);
            if(d->text)
                PFREE(d->text);
            d->text = 0;

            if(d->links) {
                for(i=0;i<d->max_links;i++) {
                    if(d->links[i])
                        PFREE(d->links[i]);
                }
                PFREE(d->links);
            }

            clear_styles(d);

            PFREE(d);
        }
        break;

    case WM_ERASEBKGND:
        {
            HDC hdc = (HDC) wParam;
            khui_htwnd_data * d;
            HBRUSH hbr;
            RECT r;

            d = (khui_htwnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);

            GetClientRect(hwnd, &r);
            hbr = GetSysColorBrush(COLOR_WINDOW);
            FillRect(hdc, &r, hbr);

            /* no need to destroy the brush since it's a system
               brush. */

            return TRUE;
        }

    case WM_SIZE:
        {
            khui_htwnd_data * d;

            d = (khui_htwnd_data *) (LONG_PTR) GetWindowLongPtr(hwnd, 0);

            if (d) {
                d->ext_width = 0;
                d->ext_height = 0;
            }
        }
        return 0;

    case WM_PAINT:
        htw_paint(hwnd, uMsg, wParam, lParam);
        return 0;

    case WM_SETCURSOR:
        {
            khui_htwnd_data * d;

            if(hwnd != (HWND)wParam)
                break;
                
            d = (khui_htwnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);

            if(d->active_link >= 0) {
                SetCursor(d->hc_hand);
                return TRUE;
            }
        }
        break;

    case WM_SETFOCUS:
        {
            khui_htwnd_data * d;

            d = (khui_htwnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);

            d->flags |= KHUI_HTWND_FOCUS;

            InvalidateRect(hwnd, NULL, TRUE);
        }
        break;

    case WM_KILLFOCUS:
        {
            khui_htwnd_data * d;

            d = (khui_htwnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);

            d->flags &= ~KHUI_HTWND_FOCUS;

            InvalidateRect(hwnd, NULL, TRUE);
        }
        break;

    case WM_LBUTTONDOWN:
        {
            khui_htwnd_data * d;

            d = (khui_htwnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);

            d->md_link = d->active_link;

            SetCapture(hwnd);
        }
        break;

    case WM_LBUTTONUP:
        {
            khui_htwnd_data * d;

            d = (khui_htwnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);

            if(d->md_link == d->active_link && d->md_link >= 0) {
                /* clicked */
                SendMessage(GetParent(hwnd), WM_COMMAND, MAKEWPARAM(d->id, BN_CLICKED), (LPARAM) d->links[d->md_link]);
            }

            ReleaseCapture();
        }
        break;

    case WM_HSCROLL:
        {
            khui_htwnd_data * d;
            int old_pos;
            int new_pos;
            int ext;
            SCROLLINFO si;
            RECT r;

            d = (khui_htwnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);

            old_pos = new_pos = d->scroll_left;
            ext = d->ext_width;

            switch(LOWORD(wParam)) {
            case SB_THUMBPOSITION:
            case SB_ENDSCROLL:
                ZeroMemory(&si, sizeof(si));
                si.cbSize = sizeof(si);
                si.fMask = SIF_POS;
                GetScrollInfo(hwnd, SB_HORZ, &si);
                new_pos = si.nPos;
                break;

            case SB_THUMBTRACK:
                ZeroMemory(&si, sizeof(si));
                si.cbSize = sizeof(si);
                si.fMask = SIF_TRACKPOS;
                GetScrollInfo(hwnd, SB_HORZ, &si);
                new_pos = si.nTrackPos;
                break;

            case SB_LINELEFT:
                new_pos -= ext / 12; /* arbitrary unit */
                break;

            case SB_LINERIGHT:
                new_pos += ext / 12; /* arbitrary unit */
                break;

            case SB_PAGELEFT:
                GetClientRect(hwnd, &r);
                new_pos -= r.right - r.left;
                break;

            case SB_PAGERIGHT:
                GetClientRect(hwnd, &r);
                new_pos += r.right - r.left;
                break;
            }

            if (new_pos == old_pos)
                break;

            GetClientRect(hwnd, &r);

            if (new_pos > ext - (r.right - r.left))
                new_pos = ext - (r.right - r.left);

            if (new_pos < 0)
                new_pos = 0;

            if (new_pos == old_pos)
                break;

            ZeroMemory(&si, sizeof(si));
            si.cbSize = sizeof(si);
            si.fMask = SIF_POS;
            si.nPos = new_pos;
            SetScrollInfo(hwnd, SB_HORZ, &si, TRUE);
            /* note that Windows sometimes adjusts the position after
               setting it with SetScrollInfo.  We have to look it up
               again to see what value it ended up at. */
            GetScrollInfo(hwnd, SB_HORZ, &si);
            new_pos = si.nPos;

            if (new_pos == old_pos)
                break;

            d->scroll_left = new_pos;

            ScrollWindow(hwnd, old_pos - new_pos, 0, NULL, NULL);

            return 0;
        }
        break;

    case WM_MOUSEMOVE:
        {
            khui_htwnd_data * d;
            int i;
            POINT p;
            int nl;

            d = (khui_htwnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);
            p.x = GET_X_LPARAM(lParam) + d->scroll_left;
            p.y = GET_Y_LPARAM(lParam) + d->scroll_top;
                
            for(i=0; i<d->n_links; i++) {
                if(d->links && d->links[i] && PtInRect(&(d->links[i]->r), p))
                    break;
            }

            if(i == d->n_links)
                nl = -1;
            else
                nl = i;

            if(d->active_link != nl) {
                if(d->active_link >= 0) {
                    if(d->flags & KHUI_HTWND_TRANSPARENT) {
                        HWND parent = GetParent(hwnd);
                        if(parent) {
                            RECT rdest = d->links[d->active_link]->r;

                            MapWindowPoints(hwnd, parent, (LPPOINT) &rdest, 2);
                            InvalidateRect(parent, &rdest, TRUE);
                        }
                    }
                    /* although we are invalidating the rect before setting active_link,
                       WM_PAINT will not be issued until wndproc returns */
                    InvalidateRect(hwnd, &(d->links[d->active_link]->r), TRUE);
                }
                d->active_link = nl;
                if(d->active_link >= 0) {
                    /* although we are invalidating the rect before setting active_link,
                       WM_PAINT will not be issued until wndproc returns */
                    if(d->flags & KHUI_HTWND_TRANSPARENT) {
                        HWND parent = GetParent(hwnd);
                        if(parent) {
                            RECT rdest = d->links[d->active_link]->r;

                            MapWindowPoints(hwnd, parent, (LPPOINT) &rdest, 2);
                            InvalidateRect(parent, &rdest, TRUE);
                        }
                    }
                    InvalidateRect(hwnd, &(d->links[d->active_link]->r), TRUE);
                }
            }
        }
        break;
    }

    return DefWindowProc(hwnd, uMsg,wParam,lParam);
}

void khm_register_htwnd_class(void)
{
    WNDCLASSEX wcx;

    wcx.cbSize = sizeof(wcx);
    wcx.style = CS_DBLCLKS | CS_OWNDC | CS_HREDRAW | CS_VREDRAW;
    wcx.lpfnWndProc = khui_htwnd_proc;
    wcx.cbClsExtra = 0;
    wcx.cbWndExtra = sizeof(LONG_PTR);
    wcx.hInstance = khm_hInstance;
    wcx.hIcon = NULL;
    wcx.hCursor = LoadCursor((HINSTANCE) NULL, IDC_ARROW);
    wcx.hbrBackground = CreateSolidBrush(RGB(255,255,255));
    wcx.lpszMenuName = NULL;
    wcx.lpszClassName = KHUI_HTWND_CLASS;
    wcx.hIconSm = NULL;

    khui_htwnd_cls = RegisterClassEx(&wcx);
}

void khm_unregister_htwnd_class(void)
{
    UnregisterClass(MAKEINTATOM(khui_htwnd_cls), khm_hInstance);
}

HWND khm_create_htwnd(HWND parent, LPWSTR text, int x, int y, int width, int height, DWORD ex_style, DWORD style)
{

    return CreateWindowEx(
        ex_style,
        MAKEINTATOM(khui_htwnd_cls),
        text,
        style | WS_CHILD,
        x,y,width,height,
        parent,
        (HMENU) KHUI_HTWND_CTLID,
        khm_hInstance,
        NULL);
}

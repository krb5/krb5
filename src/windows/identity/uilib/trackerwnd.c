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

#include<khuidefs.h>
#include<commctrl.h>
#include<assert.h>

#define K5_SLIDER_WIDTH 208
#define K5_SLIDER_HEIGHT 40

#define K5_SLIDER_LBL_HPAD   5
#define K5_SLIDER_LBL_VPAD  22

#define KHUI_TRACKER_PROP L"KhmTrackerData"


/* Count the number of ticks between tmin and tmax, inclusive
*/
int time_t_to_ticks(time_t tmin, time_t tmax)
{
    int c = 0;
    time_t lo, hi;

    tmin -= tmin % 60; /* our smallest gran is 1 min */
    if(tmax % 60)
        tmax += 60 - (tmax % 60);

    lo = tmin;

#define TFORWARD(limit,gran) \
    if(lo < limit && lo < tmax) { \
        hi = min(tmax, limit); \
        c += (int)((hi - lo) / (gran)); \
        lo = hi; \
    }

    TFORWARD(300,60);
    TFORWARD(3600,300);
    TFORWARD(3600*4, 60*15);
    TFORWARD(3600*10,60*30);
    TFORWARD(3600*24,3600);
    TFORWARD(3600*24*4,3600*6);
    TFORWARD(((time_t)(INFINITE & INT_MAX)),3600*24);

#undef TFORWARD

    return c;
}

/* Compute tmax given tmin and ticks such that there are ticks ticks
   between tmin and tmax
   */
time_t ticks_to_time_t(int ticks, time_t tmin)
{
    int c = 0;
    tmin -= tmin % 60; /* our smallest gran is 1 min */

#define SFORWARD(limit,gran) \
    if(tmin < limit && ticks > 0) { \
        c = (int) min(ticks, (limit - tmin) / (gran)); \
        tmin += c * gran; \
        ticks -= c; \
    }

    SFORWARD(300,60);
    SFORWARD(3600,300);
    SFORWARD(3600*4,60*15);
    SFORWARD(3600*10,60*30);
    SFORWARD(3600*24,3600);
    SFORWARD(3600*24*4,3600*6);
    SFORWARD(((time_t)(INFINITE & INT_MAX)),3600*24);

#undef SFORWARD

    return tmin;
}

/*  Prep a tracker control which works in conjunction with the
    duration edit control.

    NOTE: Runs in the context of the UI thread
*/
void 
initialize_tracker(HWND hwnd, 
                   khui_tracker * tc)
{
    RECT r;
    FILETIME ft;
    wchar_t wbuf[256];
    khm_size cbbuf;

    SendMessage(tc->hw_slider, TBM_SETRANGE, 0, MAKELONG(0, time_t_to_ticks(tc->min, tc->max)));
    SendMessage(tc->hw_slider, TBM_SETPOS, TRUE, (LPARAM) time_t_to_ticks(tc->min, tc->current));

    r.left = K5_SLIDER_LBL_HPAD;
    r.top = K5_SLIDER_LBL_VPAD;
    r.right = K5_SLIDER_WIDTH - K5_SLIDER_LBL_HPAD;
    r.bottom = r.top;

    MapDialogRect(hwnd, &r);

    tc->lbl_y = r.top;
    tc->lbl_lx = r.left;
    tc->lbl_rx = r.right;

    TimetToFileTimeInterval(tc->current, &ft);
    cbbuf = sizeof(wbuf);
    FtIntervalToString(&ft, wbuf, &cbbuf);

    SendMessage(tc->hw_edit, WM_SETTEXT, 0, (LPARAM)wbuf);
}


/* We instance-subclass each tracker control to provide the
   functionality that we need.  This is the replacement window
   procedure

   NOTE: Runs in the context of the UI thread
   */
LRESULT CALLBACK 
duration_tracker_proc(HWND hwnd,
                      UINT uMsg,
                      WPARAM wParam,
                      LPARAM lParam)
{
    khui_tracker * tc;

    tc = (khui_tracker *) GetProp(hwnd, KHUI_TRACKER_PROP);
#ifdef DEBUG
    assert(tc != NULL);
#endif

    switch(uMsg) {
    case WM_PAINT:
        {
            HDC hdc;
            HFONT hf, hfold;
            LRESULT lr;
            FILETIME ft;
            wchar_t buf[256];
            khm_size cbbuf;

            lr = CallWindowProc(tc->fn_tracker, hwnd, uMsg, wParam, lParam);

            /* Can't use BeginPaint here, since we already called the
               window proc */
            hdc = GetWindowDC(hwnd);

            hf = (HFONT) SendMessage(tc->hw_edit, WM_GETFONT, 0, 0);

            hfold = ((HFONT) SelectObject((hdc), (HGDIOBJ)(HFONT)(hf)));

            TimetToFileTimeInterval(tc->min, &ft);
            cbbuf = sizeof(buf);
            FtIntervalToString(&ft, buf, &cbbuf);

            SetTextColor(hdc, RGB(0,0,0));
            SetBkMode(hdc, TRANSPARENT);

            SetTextAlign(hdc, TA_LEFT | TA_TOP | TA_NOUPDATECP);
            TextOut(hdc, tc->lbl_lx, tc->lbl_y, buf, (int) wcslen(buf));
                
            TimetToFileTimeInterval(tc->max, &ft);
            cbbuf = sizeof(buf);
            FtIntervalToString(&ft, buf, &cbbuf);

            SetTextAlign(hdc, TA_RIGHT | TA_TOP | TA_NOUPDATECP);
            TextOut(hdc, tc->lbl_rx, tc->lbl_y, buf, (int) wcslen(buf));

            ((HFONT) SelectObject((hdc), (HGDIOBJ)(HFONT)(hfold)));

            ReleaseDC(hwnd, hdc);
                
            return lr;
        }
        break;

    case WM_KILLFOCUS:
        {
            if((HWND)wParam != tc->hw_edit)
                ShowWindow(hwnd, SW_HIDE);
        }
        break;

    case WM_LBUTTONUP:
    case WM_MOUSEMOVE:
        {
            LRESULT lr;

            lr = CallWindowProc(tc->fn_tracker, hwnd, uMsg, wParam, lParam);

            if(wParam & MK_LBUTTON) {
                int c = (int) SendMessage(hwnd, TBM_GETPOS, 0, 0);
                time_t t = ticks_to_time_t(c, tc->min);

                if(t != tc->current) {
                    wchar_t buf[256];
                    FILETIME ft;
                    khm_size cbbuf;

                    tc->current = t;
                    //d->dirty = TRUE;
                    cbbuf = sizeof(buf);
                    TimetToFileTimeInterval(t, &ft);
                    FtIntervalToString(&ft, buf, &cbbuf);
                    SendMessage(tc->hw_edit, WM_SETTEXT, 0, (LPARAM) buf);
                }
            }
            return lr;
        }
    }

    return CallWindowProc(tc->fn_tracker, hwnd, uMsg, wParam, lParam);
}


/* Create the subclassed duration slider on behalf of an edit control */
void 
create_edit_sliders(HWND hwnd, 
                       HWND hwnd_dlg, 
                       khui_tracker * tc)
{
    RECT r;
    RECT rs;

    GetWindowRect(hwnd, &r);

    rs.top = 0;
    rs.left = 0;
    rs.right = K5_SLIDER_WIDTH;
    rs.bottom = K5_SLIDER_HEIGHT;
    MapDialogRect(hwnd_dlg, &rs);
    rs.right -= rs.left;
    rs.bottom -= rs.top;

    tc->hw_slider = 
        CreateWindowEx(WS_EX_OVERLAPPEDWINDOW,
                       TRACKBAR_CLASS,
                       L"NetIDMgrTimeTickerTrackbar",
                       WS_POPUP | TBS_AUTOTICKS | TBS_BOTTOM |
#if (_WIN32_IE >= 0x0501)
                       TBS_DOWNISLEFT | 
#endif
                       TBS_HORZ | WS_CLIPCHILDREN,
                       r.left,r.bottom,rs.right,rs.bottom,
                       hwnd,
                       NULL,
                       (HINSTANCE)(DWORD_PTR) 
                       GetWindowLongPtr(hwnd, GWLP_HINSTANCE),
                       NULL);

    SetProp(tc->hw_slider, KHUI_TRACKER_PROP,
            (HANDLE) tc);

#pragma warning(push)
#pragma warning(disable: 4244)
    tc->fn_tracker = (WNDPROC)(LONG_PTR) SetWindowLongPtr(tc->hw_slider, GWLP_WNDPROC, (LONG_PTR) duration_tracker_proc);
#pragma warning(pop)
}

/*  An edit control is instance-subclassed to create an edit control
    that holds a duration.  Welcome to the window procedure.

    NOTE: Runs in the context of the UI thread
    */
LRESULT CALLBACK 
duration_edit_proc(HWND hwnd,
                   UINT uMsg,
                   WPARAM wParam,
                   LPARAM lParam)
{
    khui_tracker * tc;

    tc = (khui_tracker *) GetProp(hwnd, KHUI_TRACKER_PROP);

#ifdef DEBUG
    assert(tc != NULL);
#endif

    switch(uMsg) {
    case WM_SETFOCUS:
        {
            HWND p;

            p = GetParent(hwnd);

            /* we are being activated. */
            if(tc->hw_slider == NULL) {
                create_edit_sliders(hwnd, p, tc);
                initialize_tracker(p, tc);
            }

            khui_tracker_reposition(tc);

#ifdef SHOW_PANEL_ON_FIRST_ACTIVATE
            ShowWindow(tc->hw_slider, SW_SHOWNOACTIVATE);
#endif

            tc->act_time = GetTickCount();
        }
        break;

    case WM_KILLFOCUS:
        {
            wchar_t wbuf[256];
            FILETIME ft;
            khm_size cbbuf;

            if((HWND) wParam != tc->hw_slider)
                ShowWindow(tc->hw_slider, SW_HIDE);

            TimetToFileTimeInterval(tc->current, &ft);
            cbbuf = sizeof(wbuf);
            FtIntervalToString(&ft, wbuf, &cbbuf);

            SendMessage(tc->hw_edit, WM_SETTEXT, 0, (LPARAM)wbuf);
        }
        break;

    case KHUI_WM_NC_NOTIFY:
        if(HIWORD(wParam) == WMNC_DIALOG_SETUP) {
            HWND p;

            p = GetParent(hwnd);

            if(tc->hw_slider == NULL) {
                create_edit_sliders(hwnd,p,tc);
            }

            initialize_tracker(p, tc);
        }
        return TRUE;

    case WM_LBUTTONUP:
        if (IsWindowVisible(tc->hw_slider)) {
            DWORD tm;

            tm = GetTickCount();
            if (tm - tc->act_time > 000)
                ShowWindow(tc->hw_slider, SW_HIDE);
        } else {
            ShowWindow(tc->hw_slider, SW_SHOWNOACTIVATE);
        }
        break;

        /*  these messages can potentially change the text in the edit
            control.  We intercept them and see what changed.  We may
            need to grab and handle them */
    case EM_REPLACESEL:
    case EM_UNDO:
    case WM_UNDO:
    case WM_CHAR:
#if (_WIN32_WINNT >= 0x0501)
    case WM_UNICHAR:
#endif
        {
            wchar_t buf[256];
            size_t nchars;
            time_t ts;
            FILETIME ft;
            BOOL modified;
            LRESULT lr = CallWindowProc(tc->fn_edit, hwnd, uMsg, wParam, lParam);

            modified = (BOOL) SendMessage(hwnd, EM_GETMODIFY, 0, 0);
            if(modified) {
                /* parse the string */
                if(nchars = (size_t) SendMessage(hwnd, WM_GETTEXT, ARRAYLENGTH(buf), (LPARAM) buf)) {
                    buf[nchars] = 0;

                    if(KHM_SUCCEEDED(IntervalStringToFt(&ft, buf))) {
                        ts = FtIntervalToSeconds(&ft);
                        if(ts >= tc->min && ts <= tc->max) {
                            tc->current = ts;
                            //d->dirty = TRUE;
                            if(tc->hw_slider != NULL)
                                SendMessage(tc->hw_slider, TBM_SETPOS, TRUE, (LPARAM) time_t_to_ticks(tc->min, tc->current));
                        }
                    }
                }
                SendMessage(hwnd, EM_SETMODIFY, FALSE, 0);
            }

            return lr;
        }
    }

    return CallWindowProc(tc->fn_edit, hwnd, uMsg, wParam, lParam);
}

KHMEXP void KHMAPI
khui_tracker_install(HWND hwnd_edit, khui_tracker * tc) {
#ifdef DEBUG
    assert(hwnd_edit);
    assert(tc);
#endif

    tc->hw_edit = hwnd_edit;

    SetProp(hwnd_edit, KHUI_TRACKER_PROP, (HANDLE) tc);

#pragma warning(push)
#pragma warning(disable: 4244)
    tc->fn_edit = (WNDPROC)(LONG_PTR) 
        SetWindowLongPtr(hwnd_edit, GWLP_WNDPROC, 
                         (LONG_PTR) duration_edit_proc);
#pragma warning(pop)
}

KHMEXP void KHMAPI
khui_tracker_reposition(khui_tracker * tc) {
    RECT r;

    if(tc->hw_slider && tc->hw_edit) {
        GetWindowRect(tc->hw_edit, &r);
        SetWindowPos(tc->hw_slider,
                     NULL,
                     r.left, r.bottom, 
                     0, 0, 
                     SWP_NOOWNERZORDER | SWP_NOSIZE | 
                     SWP_NOZORDER | SWP_NOACTIVATE);
    }
}

KHMEXP void KHMAPI
khui_tracker_initialize(khui_tracker * tc) {
    ZeroMemory(tc, sizeof(*tc));
}

KHMEXP void KHMAPI
khui_tracker_refresh(khui_tracker * tc) {
    if (!tc->hw_edit)
        return;

    SendMessage(tc->hw_edit,
                KHUI_WM_NC_NOTIFY, 
                MAKEWPARAM(0,WMNC_DIALOG_SETUP), 0);
}

KHMEXP void KHMAPI
khui_tracker_kill_controls(khui_tracker * tc) {
    if (tc->hw_slider)
        DestroyWindow(tc->hw_slider);
    if (tc->hw_edit)
        DestroyWindow(tc->hw_edit);
    tc->hw_slider = NULL;
    tc->hw_edit = NULL;
    tc->fn_edit = NULL;
    tc->fn_tracker = NULL;
}



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

#define OEMRESOURCE

#include<khmapp.h>
#include<assert.h>

#define KHUI_NOTIFIER_CLASS         L"KhuiNotifierMsgWindowClass"
#define KHUI_ALERTER_CLASS          L"KhuiAlerterWindowClass"

#define KHUI_NOTIFIER_WINDOW        L"KhuiNotifierMsgWindow"

/* notifier message for notification icon */
#define KHUI_WM_NOTIFIER            WM_COMMAND

#define KHUI_ALERT_QUEUE_MAX        64

/* window class registration atom for message only notifier window
   class */
ATOM atom_notifier = 0;

/* window class registration atom for alert windows */
ATOM atom_alerter = 0;

/* notifier message window */
HWND hwnd_notifier = NULL;

BOOL notifier_ready = FALSE;

khui_alert * current_alert = NULL;

khui_alert * alert_queue[KHUI_ALERT_QUEUE_MAX];
khm_int32    alert_queue_head = 0;
khm_int32    alert_queue_tail = 0;

#define is_alert_queue_empty() (alert_queue_head == alert_queue_tail)
#define is_alert_queue_full()  (((alert_queue_tail + 1) % KHUI_ALERT_QUEUE_MAX) == alert_queue_head)

static void 
add_to_alert_queue(khui_alert * a) {
    if (is_alert_queue_full()) return;
    alert_queue[alert_queue_tail++] = a;
    khui_alert_hold(a);
    alert_queue_tail %= KHUI_ALERT_QUEUE_MAX;
}

static khui_alert * 
del_from_alert_queue(void) {
    khui_alert * a;

    if (is_alert_queue_empty()) return NULL;
    a = alert_queue[alert_queue_head++];
    alert_queue_head %= KHUI_ALERT_QUEUE_MAX;

    return a;                   /* held */
}

static khui_alert * 
peek_alert_queue(void) {
    if (is_alert_queue_empty()) return NULL;
    return alert_queue[alert_queue_head];
}

static void
check_for_queued_alerts(void) {
    if (!is_alert_queue_empty()) {
        khui_alert * a;

        a = peek_alert_queue();

        if (a->title) {
            HICON hi;
            int res;

            if (a->severity == KHERR_ERROR)
                res = OIC_ERROR;
            else if (a->severity == KHERR_WARNING)
                res = OIC_WARNING;
            else
                res = OIC_INFORMATION;

            hi = LoadImage(0, MAKEINTRESOURCE(res),
                           IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                           LR_SHARED);

            khm_statusbar_set_part(KHUI_SBPART_NOTICE,
                                   hi,
                                   a->title);
        }
    } else {
        khm_statusbar_set_part(KHUI_SBPART_NOTICE,
                               NULL, NULL);
    }
}


/* forward dcls */
static khm_int32 
alert_show(khui_alert * a);

static khm_int32 
alert_show_minimized(khui_alert * a);

static khm_int32
alert_show_normal(khui_alert * a);

static khm_int32
alert_enqueue(khui_alert * a);

/**********************************************************************
  Notifier
***********************************************************************

The notifier is a message only window that listens for notifier
messages.  This window will exist for the lifetime of the application
and will use alerter windows as needed to show application alerts.
*/

static LRESULT CALLBACK 
notifier_wnd_proc(HWND hwnd,
                  UINT uMsg,
                  WPARAM wParam,
                  LPARAM lParam)
{
    kmq_message * m;
    khm_int32 rv;

    if(uMsg == KMQ_WM_DISPATCH) {
        kmq_wm_begin(lParam, &m);
        rv = KHM_ERROR_SUCCESS;

        if(m->type == KMSG_ALERT) {
            /* handle notifier messages */
            switch(m->subtype) {
            case KMSG_ALERT_SHOW:
                rv = alert_show((khui_alert *) m->vparam);
                khui_alert_release((khui_alert *) m->vparam);
                break;

            case KMSG_ALERT_QUEUE:
                rv = alert_enqueue((khui_alert *) m->vparam);
                khui_alert_release((khui_alert *) m->vparam);
                break;

            case KMSG_ALERT_CHECK_QUEUE:
                check_for_queued_alerts();
                break;

            case KMSG_ALERT_SHOW_QUEUED:
                if (current_alert == NULL) {
                    khui_alert * a;

                    a = del_from_alert_queue();
                    if (a) {
                        rv = alert_show(a);
                        check_for_queued_alerts();
                        khui_alert_release(a);
                    }
                }
                break;
            }
        } else if (m->type == KMSG_CRED &&
                   m->subtype == KMSG_CRED_ROOTDELTA) {

            KillTimer(hwnd, KHUI_REFRESH_TIMER_ID);
            SetTimer(hwnd, KHUI_REFRESH_TIMER_ID,
                     KHUI_REFRESH_TIMEOUT,
                     NULL);

        }

        return kmq_wm_end(m, rv);
    } else if (uMsg == KHUI_WM_NOTIFIER) {
        /* Handle events generated from the notification icon */

        /* wParam is the identifier of the notify icon, but we only
           have one. */
        switch(lParam) {
        case WM_CONTEXTMENU: 
            {
                POINT pt;
                int menu_id;

                GetCursorPos(&pt);

                if (khm_is_main_window_visible())
                    menu_id = KHUI_MENU_ICO_CTX_NORMAL;
                else
                    menu_id = KHUI_MENU_ICO_CTX_MIN;

                SetForegroundWindow(khm_hwnd_main);

                khm_menu_show_panel(menu_id, pt.x, pt.y);

                PostMessage(khm_hwnd_main, WM_NULL, 0, 0);
            }
            break;

        case WM_LBUTTONDOWN:
            /* we actually wait for the WM_LBUTTONUP before doing
               anything */
            break;

        case WM_LBUTTONUP:
            /* fall through */

        case NIN_SELECT:
        case NIN_KEYSELECT:
            khm_show_main_window();
            break;

#if (_WIN32_IE >= 0x0501)
        case NIN_BALLOONUSERCLICK:
            if (current_alert) {
                if ((current_alert->flags & KHUI_ALERT_FLAG_DEFACTION) &&
                    current_alert->n_alert_commands > 0) {
                    PostMessage(khm_hwnd_main, WM_COMMAND,
                                MAKEWPARAM(current_alert->alert_commands[0], 
                                           0),
                                0);
                } else if (current_alert->flags & 
                           KHUI_ALERT_FLAG_REQUEST_WINDOW) {
                    khm_show_main_window();
                    alert_show_normal(current_alert);
                }
            }
            /* fallthrough */
        case NIN_BALLOONTIMEOUT:
            khm_notify_icon_change(KHERR_NONE);
            if (current_alert) {
                khui_alert_release(current_alert);
                current_alert = NULL;
            }
            break;
#endif
        }
    } else if (uMsg == WM_TIMER) {
        if (wParam == KHUI_TRIGGER_TIMER_ID) {
            KillTimer(hwnd, KHUI_TRIGGER_TIMER_ID);
            khm_timer_fire(hwnd);
        } else if (wParam == KHUI_REFRESH_TIMER_ID) {
            KillTimer(hwnd, KHUI_REFRESH_TIMER_ID);
            khm_timer_refresh(hwnd);
        }
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

ATOM 
khm_register_notifier_wnd_class(void)
{
    WNDCLASSEX wcx;

    ZeroMemory(&wcx, sizeof(wcx));

    wcx.cbSize = sizeof(wcx);
    wcx.style = 0;
    wcx.lpfnWndProc = notifier_wnd_proc;
    wcx.cbClsExtra = 0;
    wcx.cbWndExtra = 0;
    wcx.hInstance = khm_hInstance;
    wcx.hIcon = NULL;
    wcx.hCursor = NULL;
    wcx.hbrBackground = NULL;
    wcx.lpszMenuName = NULL;
    wcx.lpszClassName = KHUI_NOTIFIER_CLASS;
    wcx.hIconSm = NULL;

    atom_notifier = RegisterClassEx(&wcx);

    return atom_notifier;
}

/*********************************************************************
  Alerter
**********************************************************************/

typedef struct tag_alerter_wnd_data {
    khui_alert * alert;

    HWND            hwnd;
    HFONT           hfont;

    BOOL            metrics_done;

    HWND            hwnd_buttons[KHUI_MAX_ALERT_COMMANDS];

    /* various metrics */

    /* calculated during WM_CREATE and adjusted during WM_PAINT */
    int             dy_message;
    int             dy_suggestion;

    /* calculated during WM_CREATE */
    int             dx_button;
    int             dy_button;
    int             dx_button_incr;
    int             dx_margin;
    int             dy_margin;
    int             dy_bb;
    int             x_message;
    int             dx_message;
    int             dx_icon;
    int             dy_icon;
    int             dx_suggest_pad;

    /* calculated during WM_CREATE and adjusted during WM_PAINT */
    int             dx_client;
    int             dy_client;

    /* calculated during WM_PAINT */
    int             y_message;
    int             y_suggestion;

    LDCL(struct tag_alerter_wnd_data);
} alerter_wnd_data;

alerter_wnd_data * khui_alerts = NULL;

#define NTF_PARAM DWLP_USER

/* dialog sizes in base dialog units */

#define NTF_MARGIN 5
#define NTF_WIDTH 200

#define NTF_BB_HEIGHT 15

#define NTF_ICON_X NTF_MARGIN
#define NTF_ICON_WIDTH 20
#define NTF_ICON_HEIGHT 20

#define NTF_MSG_X (NTF_ICON_X + NTF_ICON_WIDTH + NTF_MARGIN)
#define NTF_MSG_WIDTH ((NTF_WIDTH - NTF_MARGIN) - NTF_MSG_X)
#define NTF_MSG_HEIGHT 15

#define NTF_SUG_X NTF_MSG_X
#define NTF_SUG_WIDTH NTF_MSG_WIDTH
#define NTF_SUG_HEIGHT NTF_MSG_HEIGHT
#define NTF_SUG_PAD 2

#define NTF_BUTTON_X NTF_MSG_X

#define NTF_BUTTON_WIDTH ((NTF_MSG_WIDTH - 3*NTF_MARGIN) / 4)
#define NTF_BUTTON_XINCR  (NTF_BUTTON_WIDTH + NTF_MARGIN)
#define NTF_BUTTON_HEIGHT (NTF_BB_HEIGHT - NTF_MARGIN)

#define NTF_TIMEOUT 20000

static khm_int32 
alert_show_minimized(khui_alert * a) {
    wchar_t tbuf[64];
    wchar_t mbuf[256];

    if (a->message == NULL)
        return KHM_ERROR_SUCCESS;

    if (a->title == NULL) {
        LoadString(khm_hInstance, IDS_ALERT_DEFAULT,
                   tbuf, ARRAYLENGTH(tbuf));
    } else {
        StringCbCopy(tbuf, sizeof(tbuf), a->title);
    }

    if (FAILED(StringCbCopy(mbuf, sizeof(mbuf), a->message)) ||
        (!(a->flags & KHUI_ALERT_FLAG_DEFACTION) &&
         (a->n_alert_commands > 0 ||
          a->suggestion ||
          (a->flags & KHUI_ALERT_FLAG_VALID_ERROR)))) {
        /* if mbuf wasn't big enough, this should have copied a
           truncated version of it */
        size_t cch_m, cch_p;
        wchar_t postfix[256];

        cch_p = LoadString(khm_hInstance, IDS_ALERT_MOREINFO, postfix,
                           ARRAYLENGTH(postfix));
        cch_p++;                /* account for NULL */

        StringCchLength(mbuf, ARRAYLENGTH(mbuf), &cch_m);
        cch_m = min(cch_m, ARRAYLENGTH(mbuf) - cch_p);

        StringCchCopy(mbuf + cch_m, ARRAYLENGTH(mbuf) - cch_m,
                      postfix);

        a->flags |= KHUI_ALERT_FLAG_REQUEST_WINDOW;
    }

    a->flags |= KHUI_ALERT_FLAG_DISPLAY_BALLOON;

#if (_WIN32_IE >= 0x0501)
    current_alert = a;
    khui_alert_hold(a);
#endif

    khm_notify_icon_balloon(a->severity,
                             tbuf,
                             mbuf,
                             NTF_TIMEOUT);

    return KHM_ERROR_SUCCESS;
}

static khm_int32 
alert_show_normal(khui_alert * a) {
    HWND hwa;
    wchar_t buf[256];
    wchar_t * title;

    if(a->title == NULL) {
        LoadString(khm_hInstance, IDS_ALERT_DEFAULT, 
                   buf, ARRAYLENGTH(buf));
        title = buf;
    } else
        title = a->title;

    /* if we don't have any commands, we just add a "close" button */
    if (a->n_alert_commands == 0) {
        khui_alert_add_command(a, KHUI_PACTION_CLOSE);
    }

    if (!is_alert_queue_empty()) {
        khui_alert_add_command(a, KHUI_PACTION_NEXT);
    }

    /* we don't need to keep track of the window handle
       because the window procedure adds it to the dialog
       list automatically */

    hwa = 
        CreateWindowEx(WS_EX_DLGMODALFRAME | WS_EX_CONTEXTHELP,
                       MAKEINTATOM(atom_alerter),
                       title,
                       WS_DLGFRAME | WS_POPUPWINDOW | WS_CLIPCHILDREN |
                       WS_VISIBLE,
                       0, 0, 300, 300, // bogus values
                       khm_hwnd_main,
                       (HMENU) NULL,
                       khm_hInstance,
                       (LPVOID) a);

    return KHM_ERROR_SUCCESS;
}

static khm_int32 
alert_show(khui_alert * a) {
    /* is there an alert already?  If so, we just enqueue the message
       and let it sit. */
    if (current_alert) {
        return alert_enqueue(a);
    }

    /* the window has already been shown */
    if((a->flags & KHUI_ALERT_FLAG_DISPLAY_WINDOW) ||
        ((a->flags & KHUI_ALERT_FLAG_DISPLAY_BALLOON) &&
         !(a->flags & KHUI_ALERT_FLAG_REQUEST_WINDOW)))
        return KHM_ERROR_SUCCESS;

    if(a->err_context != NULL ||
       a->err_event != NULL) {
        khui_alert_lock(a);
        a->flags |= KHUI_ALERT_FLAG_VALID_ERROR;
        khui_alert_unlock(a);
    }

    /* depending on the state of the main window, we
       need to either show a window or a balloon */
    if(khm_is_main_window_active() &&
       !(a->flags & KHUI_ALERT_FLAG_REQUEST_BALLOON))
        return alert_show_normal(a);
    else
        return alert_show_minimized(a);
}

static khm_int32
alert_enqueue(khui_alert * a) {
    if (is_alert_queue_full())
        return KHM_ERROR_NO_RESOURCES;

    add_to_alert_queue(a);
    check_for_queued_alerts();

    return KHM_ERROR_SUCCESS;
}

/* the alerter window is actually a dialog */
static LRESULT CALLBACK 
alerter_wnd_proc(HWND hwnd,
                 UINT uMsg,
                 WPARAM wParam,
                 LPARAM lParam)
{
    switch(uMsg) {
    case WM_CREATE:
        {
            LONG dlgb;
            HWND hwnd_parent;
            RECT r_parent;
            POINT pos;
            SIZE s;
            LPCREATESTRUCT lpcs;
            khui_alert * a;
            alerter_wnd_data * d;

            lpcs = (LPCREATESTRUCT) lParam;
            a = (khui_alert *) lpcs->lpCreateParams;
            khui_alert_hold(a);

            d = PMALLOC(sizeof(*d));
            ZeroMemory(d, sizeof(*d));

            d->alert = a;
            d->hwnd = hwnd;

            khui_alert_lock(a);

            a->flags |= KHUI_ALERT_FLAG_DISPLAY_WINDOW;
            LPUSH(&khui_alerts, d);

#pragma warning(push)
#pragma warning(disable: 4244)
            SetWindowLongPtr(hwnd, NTF_PARAM, (LONG_PTR) d);
#pragma warning(pop)

            khm_add_dialog(hwnd);
            khm_enter_modal(hwnd);

            /* now figure out the size and position of the window */

            hwnd_parent = GetWindow(hwnd, GW_OWNER);
            GetWindowRect(hwnd_parent, &r_parent);

            dlgb = GetDialogBaseUnits();

#define DLG2SCNX(x) MulDiv((x), LOWORD(dlgb), 4)
#define DLG2SCNY(y) MulDiv((y), HIWORD(dlgb), 8)

            d->dx_margin = DLG2SCNX(NTF_MARGIN);
            d->dy_margin = DLG2SCNY(NTF_MARGIN);

            d->x_message = DLG2SCNX(NTF_MSG_X);
            d->dx_message = DLG2SCNX(NTF_MSG_WIDTH);

            if (a->message) {
                d->dy_message = DLG2SCNY(NTF_MSG_HEIGHT);
            }

            if (a->suggestion) {
                d->dy_suggestion = DLG2SCNY(NTF_SUG_HEIGHT);
                d->dx_suggest_pad = DLG2SCNX(NTF_SUG_PAD);
            }

            d->dy_bb = DLG2SCNY(NTF_BB_HEIGHT);
            d->dx_button = DLG2SCNX(NTF_BUTTON_WIDTH);
            d->dy_button = DLG2SCNY(NTF_BUTTON_HEIGHT);
            d->dx_button_incr = DLG2SCNX(NTF_BUTTON_XINCR);

            d->dx_icon = DLG2SCNX(NTF_ICON_WIDTH);
            d->dy_icon = DLG2SCNY(NTF_ICON_HEIGHT);

            d->dx_client = DLG2SCNX(NTF_WIDTH);
            d->dy_client = max(d->dy_icon,
                               d->dy_message +
                               ((d->dy_suggestion > 0)?
                                (d->dy_suggestion + d->dy_margin):
                                0)) +
                d->dy_margin * 3 + d->dy_bb;

            /* adjust for client rect */
            s.cx = d->dx_client;
            s.cy = d->dy_client;

            {
                RECT c_r;
                RECT w_r;

                GetWindowRect(hwnd, &w_r);
                GetClientRect(hwnd, &c_r);

                s.cx += (w_r.right - w_r.left) - (c_r.right - c_r.left);
                s.cy += (w_r.bottom - w_r.top) - (c_r.bottom - c_r.top);
            }

            pos.x = (r_parent.left + r_parent.right - s.cx) / 2;
            pos.y = (r_parent.top + r_parent.bottom - s.cy) / 2;

            SetWindowPos(hwnd,
                         HWND_TOP,
                         pos.x, pos.y,
                         s.cx, s.cy,
                         SWP_SHOWWINDOW);

            {
                LOGFONT lf;
                HDC hdc_dt;

                hdc_dt = GetDC(NULL);

                lf.lfHeight = -MulDiv(8, 
                                      GetDeviceCaps(hdc_dt, LOGPIXELSY), 
                                      72);
                lf.lfWidth = 0;
                lf.lfEscapement = 0;
                lf.lfOrientation = 0;
                lf.lfWeight = FW_NORMAL;
                lf.lfItalic = FALSE;
                lf.lfUnderline = FALSE;
                lf.lfStrikeOut = FALSE;
                lf.lfCharSet = DEFAULT_CHARSET;
                lf.lfOutPrecision = OUT_DEFAULT_PRECIS;
                lf.lfClipPrecision = CLIP_DEFAULT_PRECIS;
                lf.lfQuality = DEFAULT_QUALITY;
                lf.lfPitchAndFamily = DEFAULT_PITCH;

                LoadString(khm_hInstance, IDS_DEFAULT_FONT, 
                           lf.lfFaceName, ARRAYLENGTH(lf.lfFaceName));

                d->hfont = CreateFontIndirect(&lf);

                ReleaseDC(NULL, hdc_dt);
            }

            /* create dialog controls now */
            {
                int x,y;
                int width, height;
                int i;

                x = d->x_message;
                y = d->dy_client - d->dy_bb;
                width = d->dx_button;
                height = d->dy_button;

                for(i=0; i<a->n_alert_commands; i++) {
                    wchar_t caption[256];
                    khui_action * action;
                    HWND hw_button;

                    if(a->alert_commands[i] == 0)
                        continue;

                    action = khui_find_action(a->alert_commands[i]);
                    if(action == NULL)
                        continue;

                    LoadString(khm_hInstance, action->is_caption, 
                               caption, ARRAYLENGTH(caption));
                        
                    hw_button = 
                        CreateWindowEx(0,
                                       L"BUTTON",
                                       caption,
                                       WS_VISIBLE | WS_CHILD,
                                       x,y,width,height,
                                       hwnd,
                                       (HMENU)(INT_PTR) (action->cmd),
                                       khm_hInstance,
                                       NULL);

                    SendMessage(hw_button, WM_SETFONT, 
                                (WPARAM) d->hfont, MAKELPARAM(TRUE, 0));

                    d->hwnd_buttons[i] = hw_button;

                    x += d->dx_button_incr;
                }
            }

            khm_notify_icon_change(a->severity);

            khui_alert_unlock(a);

            d->metrics_done = FALSE;
                
            return TRUE;
        }
        break; /* not reached */

    case WM_DESTROY:
        {
            alerter_wnd_data * d;

            /* khm_leave_modal() could be here, but instead it is in
               the WM_COMMAND handler.  This is because the modal loop
               has to be exited before DestroyWindow() is issued. */
            //khm_leave_modal();
            khm_del_dialog(hwnd);

            d = (alerter_wnd_data *)(LONG_PTR) 
                GetWindowLongPtr(hwnd, NTF_PARAM);

            LDELETE(&khui_alerts, d);

            khui_alert_lock(d->alert);
            d->alert->flags &= ~KHUI_ALERT_FLAG_DISPLAY_WINDOW;
            khui_alert_unlock(d->alert);

            khui_alert_release(d->alert);

            DeleteObject(d->hfont);

            PFREE(d);

            khm_notify_icon_change(KHERR_NONE);

            return TRUE;
        }
        break;

    case WM_PAINT:
        {
            RECT r_update;
            PAINTSTRUCT ps;
            HDC hdc;
            LONG dlgb;
            alerter_wnd_data * d;
            HFONT hf_old;
            BOOL need_resize = FALSE;

            if(!GetUpdateRect(hwnd, &r_update, TRUE))
                return FALSE;

            d = (alerter_wnd_data *)(LONG_PTR)
                GetWindowLongPtr(hwnd, NTF_PARAM);

            dlgb = GetDialogBaseUnits();

            hdc = BeginPaint(hwnd, &ps);

            hf_old = SelectFont(hdc, d->hfont);

            khui_alert_lock(d->alert);

            // draw the severity icon
            {
                HICON hicon;
                int x,y;
                int iid;

                /* GOINGHERE! If the metrics for the window haven't
                   been calculated yet, then calculate them.  If the
                   hight needs to be expanded, then do that and wait
                   for the next repaint cycle.  Also move the button
                   controls down. */
                x = d->dx_margin;
                y = d->dy_margin;

                if(d->alert->severity == KHERR_ERROR)
                    iid = OIC_HAND;
                else if(d->alert->severity == KHERR_WARNING)
                    iid = OIC_BANG;
                else
                    iid = OIC_NOTE;

                hicon = LoadImage(NULL, 
                                  MAKEINTRESOURCE(iid), 
                                  IMAGE_ICON,
                                  GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                                  LR_SHARED);

                DrawIcon(hdc, x, y, hicon);
            }

            // draw the message
            if(d->alert->message) {
                RECT r;
                int width;
                int height;
                size_t cch;

                r.left = d->x_message;
                r.top = d->dy_margin;
                width = d->dx_message;
                r.right = r.left + width;
                height = d->dy_message;
                r.bottom = r.top + height;

                StringCchLength(d->alert->message, 
                                KHUI_MAXCCH_MESSAGE, &cch);
                
                height = DrawText(hdc,
                                  d->alert->message,
                                  (int) cch,
                                  &r,
                                  DT_WORDBREAK |
                                  DT_CALCRECT);

                if (height > d->dy_message) {
                    d->dy_message = height;
                    need_resize = TRUE;
                } else {
                    DrawText(hdc,
                             d->alert->message,
                             (int) cch,
                             &r,
                             DT_WORDBREAK);
                }

                d->y_message = r.top;
            }

            // and the suggestion
            if (d->alert->suggestion) {
                RECT r, ro;
                int height;
                size_t cch;
                HICON h_sug_ico;

                r.left = d->x_message;
                r.top = d->y_message + d->dy_message + d->dy_margin;
                r.right = r.left + d->dx_message;
                r.bottom = r.top + d->dy_suggestion;

                CopyRect(&ro, &r);

                // adjust for icon and padding
                r.left += GetSystemMetrics(SM_CXSMICON) + d->dx_suggest_pad * 2;
                r.top += d->dx_suggest_pad;
                r.right -= d->dx_suggest_pad;
                r.bottom -= d->dx_suggest_pad;

                StringCchLength(d->alert->suggestion,
                                KHUI_MAXCCH_SUGGESTION, &cch);

                height = DrawText(hdc,
                                  d->alert->suggestion,
                                  (int) cch,
                                  &r,
                                  DT_WORDBREAK |
                                  DT_CALCRECT);

                if (height > d->dy_suggestion) {
                    d->dy_suggestion = height;
                    need_resize = TRUE;
                } else {
                    int old_bk_mode;

                    ro.bottom = r.bottom + d->dx_suggest_pad;

                    FillRect(hdc, &ro, (HBRUSH) (COLOR_INFOBK + 1));
                    DrawEdge(hdc, &ro, EDGE_SUNKEN, BF_FLAT | BF_RECT);

                    h_sug_ico = 
                        LoadImage(0,
                                  MAKEINTRESOURCE(OIC_INFORMATION),
                                  IMAGE_ICON,
                                  GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                                  LR_SHARED);

                    assert(h_sug_ico != NULL);

                    DrawIconEx(hdc, 
                               ro.left + d->dx_suggest_pad, 
                               ro.top + d->dx_suggest_pad, 
                               h_sug_ico,
                               GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                               0, NULL,
                               DI_NORMAL);

                    old_bk_mode = SetBkMode(hdc, TRANSPARENT);

                    DrawText(hdc,
                             d->alert->suggestion,
                             (int) cch,
                             &r,
                             DT_WORDBREAK);

                    SetBkMode(hdc, old_bk_mode);
                }

                d->y_suggestion = r.top;
            }

            khui_alert_unlock(d->alert);

            SelectObject(hdc, hf_old);

            EndPaint(hwnd, &ps);

            if (need_resize) {
                RECT r;
                int x,y;
                int width, height;
                int i;
                
                GetClientRect(hwnd, &r);

                height = max(d->dy_icon,
                             d->dy_message +
                             ((d->dy_suggestion > 0)?
                              (d->dy_suggestion + d->dy_margin):
                              0)) +
                    d->dy_margin * 3 + d->dy_bb;
                r.bottom = r.top + height;

                d->dy_client = height;

                AdjustWindowRectEx(&r,
                                   GetWindowLongPtr(hwnd, GWL_STYLE),
                                   FALSE,
                                   GetWindowLongPtr(hwnd, GWL_EXSTYLE));

                SetWindowPos(hwnd,
                             NULL,
                             0, 0,
                             r.right - r.left,
                             r.bottom - r.top,
                             SWP_NOACTIVATE | SWP_NOCOPYBITS |
                             SWP_NOMOVE | SWP_NOOWNERZORDER |
                             SWP_NOZORDER);

                x = d->x_message;
                y = d->dy_client - d->dy_bb;
                width = d->dx_button;
                height = d->dy_button;

                for(i=0; i<d->alert->n_alert_commands; i++) {
                    MoveWindow(d->hwnd_buttons[i],
                               x,y,
                               width,height,
                               TRUE);

                    x += d->dx_button_incr;
                }
            }

            return FALSE;
        }
        break; /* not reached */

    case WM_COMMAND:
        {
            alerter_wnd_data * d;

            d = (alerter_wnd_data *)(LONG_PTR) 
                GetWindowLongPtr(hwnd, NTF_PARAM);

            if(HIWORD(wParam) == BN_CLICKED) {
                khui_alert_lock(d->alert);
                d->alert->response = LOWORD(wParam);
                khui_alert_unlock(d->alert);

                khm_leave_modal();

                DestroyWindow(hwnd);

                if (LOWORD(wParam) == KHUI_PACTION_NEXT)
                    kmq_post_message(KMSG_ALERT, KMSG_ALERT_SHOW_QUEUED, 0, 0);
                return 0;
            }
        }
        break;
    }

    return DefDlgProc(hwnd, uMsg, wParam, lParam);
    //return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

ATOM khm_register_alerter_wnd_class(void)
{
    WNDCLASSEX wcx;

    ZeroMemory(&wcx, sizeof(wcx));

    wcx.cbSize = sizeof(wcx);
    wcx.style =
        CS_OWNDC |
#if(_WIN32_WINNT >= 0x0501)
        ((IS_COMMCTL6())? CS_DROPSHADOW: 0) |
#endif
        0;
    wcx.lpfnWndProc = alerter_wnd_proc;
    wcx.cbClsExtra = 0;
    wcx.cbWndExtra = DLGWINDOWEXTRA + sizeof(LONG_PTR);
    wcx.hInstance = khm_hInstance;
    wcx.hIcon = LoadIcon(khm_hInstance, MAKEINTRESOURCE(IDI_MAIN_APP));
    wcx.hCursor = LoadCursor(NULL, MAKEINTRESOURCE(IDC_ARROW));
    wcx.hbrBackground = (HBRUSH)(COLOR_BACKGROUND + 1);
    wcx.lpszMenuName = NULL;
    wcx.lpszClassName = KHUI_ALERTER_CLASS;
    wcx.hIconSm = NULL;

    atom_alerter = RegisterClassEx(&wcx);

    return atom_alerter;
}

/**********************************************************************
  Notification Icon
***********************************************************************/

#define KHUI_NOTIFY_ICON_ID 0

void khm_notify_icon_add(void) {
    NOTIFYICONDATA ni;
    wchar_t buf[256];

    ZeroMemory(&ni, sizeof(ni));

    ni.cbSize = sizeof(ni);
    ni.hWnd = hwnd_notifier;
    ni.uID = KHUI_NOTIFY_ICON_ID;
    ni.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    ni.hIcon = LoadIcon(khm_hInstance, MAKEINTRESOURCE(IDI_NOTIFY_NONE));
    ni.uCallbackMessage = KHUI_WM_NOTIFIER;
    LoadString(khm_hInstance, IDS_NOTIFY_PREFIX, buf, ARRAYLENGTH(buf));
    StringCbCopy(ni.szTip, sizeof(ni.szTip), buf);
    LoadString(khm_hInstance, IDS_NOTIFY_READY, buf, ARRAYLENGTH(buf));
    StringCbCat(ni.szTip, sizeof(ni.szTip), buf);

    Shell_NotifyIcon(NIM_ADD, &ni);

    ni.cbSize = sizeof(ni);
    ni.uVersion = NOTIFYICON_VERSION;
    Shell_NotifyIcon(NIM_SETVERSION, &ni);

    DestroyIcon(ni.hIcon);
}

void 
khm_notify_icon_balloon(khm_int32 severity,
                         wchar_t * title,
                         wchar_t * msg,
                         khm_int32 timeout) {
    NOTIFYICONDATA ni;
    int iid;

    if (!msg || !title)
        return;

    ZeroMemory(&ni, sizeof(ni));
    ni.cbSize = sizeof(ni);

    if (severity == KHERR_INFO) {
        ni.dwInfoFlags = NIIF_INFO;
        iid = IDI_NOTIFY_INFO;
    } else if (severity == KHERR_WARNING) {
        ni.dwInfoFlags = NIIF_WARNING;
        iid = IDI_NOTIFY_WARN;
    } else if (severity == KHERR_ERROR) {
        ni.dwInfoFlags = NIIF_ERROR;
        iid = IDI_NOTIFY_ERROR;
    } else {
        ni.dwInfoFlags = NIIF_NONE;
        iid = IDI_NOTIFY_NONE;
    }

    ni.hWnd = hwnd_notifier;
    ni.uID = KHUI_NOTIFY_ICON_ID;
    ni.uFlags = NIF_INFO | NIF_ICON;
    ni.hIcon = LoadIcon(khm_hInstance, MAKEINTRESOURCE(iid));

    if (FAILED(StringCbCopy(ni.szInfo, sizeof(ni.szInfo), msg))) {
        /* too long? */
        StringCchCopyN(ni.szInfo, ARRAYLENGTH(ni.szInfo),
                       msg, 
                       ARRAYLENGTH(ni.szInfo) - ARRAYLENGTH(ELIPSIS));
        StringCchCat(ni.szInfo, ARRAYLENGTH(ni.szInfo),
                     ELIPSIS);
    }

    if (FAILED(StringCbCopy(ni.szInfoTitle, sizeof(ni.szInfoTitle), 
                            title))) {
        StringCchCopyN(ni.szInfoTitle, ARRAYLENGTH(ni.szInfoTitle),
                       title, 
                       ARRAYLENGTH(ni.szInfoTitle) - ARRAYLENGTH(ELIPSIS));
        StringCchCat(ni.szInfoTitle, ARRAYLENGTH(ni.szInfoTitle),
                     ELIPSIS);
    }
    ni.uTimeout = timeout;

    Shell_NotifyIcon(NIM_MODIFY, &ni);

    DestroyIcon(ni.hIcon);
}

void khm_notify_icon_change(khm_int32 severity) {
    NOTIFYICONDATA ni;
    wchar_t buf[256];
    int iid;

    if (severity == KHERR_INFO)
        iid = IDI_NOTIFY_INFO;
    else if (severity == KHERR_WARNING)
        iid = IDI_NOTIFY_WARN;
    else if (severity == KHERR_ERROR)
        iid = IDI_NOTIFY_ERROR;
    else
        iid = IDI_NOTIFY_NONE;

    ZeroMemory(&ni, sizeof(ni));

    ni.cbSize = sizeof(ni);
    ni.hWnd = hwnd_notifier;
    ni.uID = KHUI_NOTIFY_ICON_ID;
    ni.uFlags = NIF_ICON | NIF_TIP;
    ni.hIcon = LoadIcon(khm_hInstance, MAKEINTRESOURCE(iid));
    LoadString(khm_hInstance, IDS_NOTIFY_PREFIX, buf, ARRAYLENGTH(buf));
    StringCbCopy(ni.szTip, sizeof(ni.szTip), buf);
    if(severity == KHERR_NONE)
        LoadString(khm_hInstance, IDS_NOTIFY_READY, buf, ARRAYLENGTH(buf));
    else
        LoadString(khm_hInstance, IDS_NOTIFY_ATTENTION, buf, ARRAYLENGTH(buf));
    StringCbCat(ni.szTip, sizeof(ni.szTip), buf);

    Shell_NotifyIcon(NIM_MODIFY, &ni);

    DestroyIcon(ni.hIcon);
}

void khm_notify_icon_remove(void) {
    NOTIFYICONDATA ni;

    ZeroMemory(&ni, sizeof(ni));

    ni.cbSize = sizeof(ni);
    ni.hWnd = hwnd_notifier;
    ni.uID = KHUI_NOTIFY_ICON_ID;

    Shell_NotifyIcon(NIM_DELETE, &ni);
}

/*********************************************************************
  Initialization
**********************************************************************/

void khm_init_notifier(void)
{
    if(!khm_register_notifier_wnd_class())
        return;

    if(!khm_register_alerter_wnd_class())
        return;

    hwnd_notifier = CreateWindowEx(0,
                                   MAKEINTATOM(atom_notifier),
                                   KHUI_NOTIFIER_WINDOW,
                                   0,
                                   0,0,0,0,
                                   HWND_MESSAGE,
                                   NULL,
                                   khm_hInstance,
                                   NULL);

    if(hwnd_notifier != NULL) {
        kmq_subscribe_hwnd(KMSG_ALERT, hwnd_notifier);
        kmq_subscribe_hwnd(KMSG_CRED, hwnd_notifier);
        notifier_ready = TRUE;

        khm_notify_icon_add();
    }
#ifdef DEBUG
    else {
        assert(hwnd_notifier != NULL);
    }
#endif
    khm_timer_init();

    khm_addr_change_notifier_init();
}

void khm_exit_notifier(void)
{
    khm_addr_change_notifier_exit();

    khm_timer_exit();

    if(hwnd_notifier != NULL) {
        khm_notify_icon_remove();
        kmq_unsubscribe_hwnd(KMSG_ALERT, hwnd_notifier);
        kmq_unsubscribe_hwnd(KMSG_CRED, hwnd_notifier);
        DestroyWindow(hwnd_notifier);
        hwnd_notifier = NULL;
    }

    if(atom_notifier != 0) {
        UnregisterClass(MAKEINTATOM(atom_notifier), khm_hInstance);
        atom_notifier = 0;
    }

    if(atom_alerter != 0) {
        UnregisterClass(MAKEINTATOM(atom_alerter), khm_hInstance);
        atom_alerter = 0;
    }

    notifier_ready = FALSE;
}

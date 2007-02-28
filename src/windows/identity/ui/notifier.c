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
 * ACTION OF CONTRACT TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* $Id$ */

#define OEMRESOURCE

#include<khmapp.h>
#include<assert.h>

#define KHUI_NOTIFIER_CLASS         L"KhuiNotifierMsgWindowClass"
#define KHUI_ALERTER_CLASS          L"KhuiAlerterWindowClass"
#define KHUI_ALERTBIN_CLASS         L"KhuiAlertBinWindowClass"

#define KHUI_NOTIFIER_WINDOW        L"KhuiNotifierMsgWindow"

/* notifier message for notification icon */
#define KHUI_WM_NOTIFIER            WM_COMMAND

#define DRAWTEXTOPTIONS (DT_CALCRECT | DT_NOPREFIX | DT_WORDBREAK)

/* are we showing an alert? */
#define ALERT_DISPLAYED() (balloon_alert != NULL || khui_alert_windows != NULL)

/* Forward declarations */

struct tag_alerter_wnd_data;
typedef struct tag_alerter_wnd_data alerter_wnd_data;

struct tag_alert_list;
typedef struct tag_alert_list alert_list;

static khm_int32 
alert_show(khui_alert * a);

static khm_int32 
alert_show_minimized(khui_alert * a);

static khm_int32
alert_show_normal(khui_alert * a);

static khm_int32
alert_show_list(alert_list * alist);

static khm_int32
alert_enqueue(khui_alert * a);

static void
check_for_queued_alerts(void);

static khm_int32
alert_consolidate(alert_list * alist,
                  khui_alert * alert,
                  khm_boolean add_from_queue);

/* Globals */

/* window class registration atom for message only notifier window
   class */
ATOM atom_notifier = 0;

/* window class registration atom for alert windows */
ATOM atom_alerter = 0;
/* window class registration atom for the alert "bin", which is the
   window that holds all the alerts. */
ATOM atom_alert_bin = 0;

/* notifier message window */
HWND hwnd_notifier = NULL;

BOOL notifier_ready = FALSE;

/* The list of alert windows currently active */
alerter_wnd_data * khui_alert_windows = NULL;

/* Notification icon for when there are no alerts to be displayed */
int  iid_normal = IDI_NOTIFY_NONE;

/* The alert currently being displayed in a balloon */
khui_alert * balloon_alert;

/**********************************************************************
  Alert Queue

  The alert queue is the data structure that keeps track of all the
  alerts that are waiting to be displayed.  Alerts will be placed on
  the queue if they cannot be immediately displayed for some reason
  (e.g. another alert is being displayed, or the user is working in
  another window).
***********************************************************************/

#define KHUI_ALERT_QUEUE_MAX        64

khui_alert * alert_queue[KHUI_ALERT_QUEUE_MAX];
khm_int32    alert_queue_head = 0;
khm_int32    alert_queue_tail = 0;

#define is_alert_queue_empty() (alert_queue_head == alert_queue_tail)
#define is_alert_queue_full()  (((alert_queue_tail + 1) % KHUI_ALERT_QUEUE_MAX) == alert_queue_head)

/* NOTE: the alert queue functions are unsafe to call from any thread
   other than the UI thread. */

static void 
alert_queue_put_alert(khui_alert * a) {
    if (is_alert_queue_full()) return;
    alert_queue[alert_queue_tail++] = a;
    khui_alert_hold(a);
    alert_queue_tail %= KHUI_ALERT_QUEUE_MAX;
}

/* the caller needs to release the alert that's returned  */
static khui_alert * 
alert_queue_get_alert(void) {
    khui_alert * a;

    if (is_alert_queue_empty()) return NULL;
    a = alert_queue[alert_queue_head++];
    alert_queue_head %= KHUI_ALERT_QUEUE_MAX;

    return a;                   /* held */
}

static int
alert_queue_get_size(void) {
    if (is_alert_queue_empty())
        return 0;

    if (alert_queue_tail < alert_queue_head) {
        return (alert_queue_tail + KHUI_ALERT_QUEUE_MAX - alert_queue_head);
    } else {
        return alert_queue_tail - alert_queue_head;
    }
}

static khui_alert *
alert_queue_get_alert_by_pos(int pos) {
    khui_alert * a;

    if (is_alert_queue_empty() ||
        pos >= alert_queue_get_size() ||
        pos < 0) {
        return NULL;
    }

    a = alert_queue[(alert_queue_head + pos) % KHUI_ALERT_QUEUE_MAX];
    if (a) {
        khui_alert_hold(a);
    }
    return a;
}

static int
alert_queue_delete_alert(khui_alert * a) {
    int idx;
    int succ;

    idx = alert_queue_head;
    while(idx != alert_queue_tail) {
        if (alert_queue[idx] == a)
            break;

        idx = (idx + 1) % KHUI_ALERT_QUEUE_MAX;
    }

    if (idx == alert_queue_tail)
        return 0;

#ifdef DEBUG
    assert(alert_queue[idx]);
#endif
    khui_alert_release(alert_queue[idx]);

    succ = (idx + 1) % KHUI_ALERT_QUEUE_MAX;
    while(succ != alert_queue_tail) {
        alert_queue[idx] = alert_queue[succ];

        succ = (succ + 1) % KHUI_ALERT_QUEUE_MAX;
        idx = (idx + 1) % KHUI_ALERT_QUEUE_MAX;
    }

    alert_queue_tail = idx;
    return 1;
}

/* the caller needs to release the alert that's returned */
static khui_alert * 
alert_queue_peek(void) {
    khui_alert * a;

    if (is_alert_queue_empty())
        return NULL;

    a = alert_queue[alert_queue_head];
    khui_alert_hold(a);

    return a;
}

/**********************************************************************
  Alert List

  A list of alerts.  Currently has a fixed upper limit, but the limit
  is high enough for now.
***********************************************************************/

typedef struct tag_alert_list {
    khui_alert * alerts[KHUI_ALERT_QUEUE_MAX];
    int          n_alerts;
    wchar_t      title[KHUI_MAXCCH_TITLE];
} alert_list;

static void
alert_list_init(alert_list * alist) {
    ZeroMemory(alist, sizeof(*alist));
}

static void
alert_list_set_title(alert_list * alist, wchar_t * title) {
    StringCbCopy(alist->title, sizeof(alist->title), title);
}

static khm_int32
alert_list_add_alert(alert_list * alist,
                     khui_alert * alert) {

    if (alist->n_alerts == ARRAYLENGTH(alist->alerts))
        return KHM_ERROR_NO_RESOURCES;

    khui_alert_hold(alert);
    alist->alerts[alist->n_alerts++] = alert;

    return KHM_ERROR_SUCCESS;
}

static void
alert_list_destroy(alert_list * alist) {
    int i;

    for (i=0; i < alist->n_alerts; i++) {
        if (alist->alerts[i] != NULL) {
            khui_alert_release(alist->alerts[i]);
            alist->alerts[i] = NULL;
        }
    }

    alist->n_alerts = 0;
}


/**********************************************************************
  Notifier Window

  The notifier window manages the notification icon and handles
  KMSG_ALERT messages sent from the UI library.  The window will exist
  for the lifetime of the application.
***********************************************************************/

/* These are defined for APPVER >= 0x501.  We are defining them here
   so that we can build with APPVER = 0x500 and use the same binaries
   with Win XP. */

#ifndef NIN_BALLOONSHOW
#define NIN_BALLOONSHOW (WM_USER + 2)
#endif

#ifndef NIN_BALLOONHIDE
#define NIN_BALLOONHIDE (WM_USER + 3)
#endif

#ifndef NIN_BALLOONTIMEOUT
#define NIN_BALLOONTIMEOUT (WM_USER + 4)
#endif

#ifndef NIN_BALLOONUSERCLICK
#define NIN_BALLOONUSERCLICK (WM_USER + 5)
#endif


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
                {
                    khui_alert * a;

                    a = (khui_alert *) m->vparam;
#ifdef DEBUG
                    assert(a != NULL);
#endif
                    rv = alert_show(a);
                    khui_alert_release(a);
                }
                break;

            case KMSG_ALERT_QUEUE:
                {
                    khui_alert * a;

                    a = (khui_alert *) m->vparam;
#ifdef DEBUG
                    assert(a != NULL);
#endif
                    rv = alert_enqueue(a);
                    khui_alert_release(a);
                }
                break;

            case KMSG_ALERT_CHECK_QUEUE:
                check_for_queued_alerts();
                break;

            case KMSG_ALERT_SHOW_QUEUED:
                if (!ALERT_DISPLAYED()) {

                    /* show next consolidated batch */
                    alert_list alist;
                    int n;

                    alert_list_init(&alist);
                    n = alert_consolidate(&alist, NULL, TRUE);

                    if (n) {
                        if (n == 1) {
                            khui_alert_lock(alist.alerts[0]);

                            if (alist.alerts[0]->title) {
                                alert_list_set_title(&alist, alist.alerts[0]->title);
                            } else {
                                wchar_t title[KHUI_MAXCCH_TITLE];
                                LoadString(khm_hInstance, IDS_ALERT_DEFAULT,
                                           title, ARRAYLENGTH(title));
                                alert_list_set_title(&alist, title);
                            }

                            khui_alert_unlock(alist.alerts[0]);
                        } else {
                            wchar_t title[KHUI_MAXCCH_TITLE];
                            LoadString(khm_hInstance, IDS_ALERT_DEFAULT,
                                       title, ARRAYLENGTH(title));
                            alert_list_set_title(&alist, title);
                        }

                        alert_show_list(&alist);
                    }

                    alert_list_destroy(&alist);

                    check_for_queued_alerts();
                }
                break;

            case KMSG_ALERT_SHOW_MODAL:
                {
                    khui_alert * a;

                    a = (khui_alert *) m->vparam;
#ifdef DEBUG
                    assert(a != NULL);
#endif
                    khui_alert_lock(a);
                    a->flags |= KHUI_ALERT_FLAG_MODAL;
                    khui_alert_unlock(a);

                    rv = alert_show(a);

                    if (KHM_SUCCEEDED(rv)) {
                        khm_message_loop_int(&a->displayed);
                    }

                    khui_alert_release(a);
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
            /* fall through */
        case NIN_KEYSELECT:
            khm_show_main_window();
            break;

        case NIN_BALLOONUSERCLICK:
            if (balloon_alert) {
                khm_notify_icon_change(KHERR_NONE);

                khui_alert_lock(balloon_alert);

                if ((balloon_alert->flags & KHUI_ALERT_FLAG_DEFACTION) &&
                    (balloon_alert->flags & KHUI_ALERT_FLAG_REQUEST_BALLOON) &&
                    balloon_alert->n_alert_commands > 0) {
                    PostMessage(khm_hwnd_main, WM_COMMAND,
                                MAKEWPARAM(balloon_alert->alert_commands[0], 
                                           0),
                                0);
                } else if (balloon_alert->flags & 
                           KHUI_ALERT_FLAG_REQUEST_WINDOW) {
                    khm_show_main_window();
                    alert_show_normal(balloon_alert);
                }

                khui_alert_unlock(balloon_alert);
                khui_alert_release(balloon_alert);
                balloon_alert = NULL;
            } else {
#ifdef DEBUG
                assert(FALSE);
#endif
            }
            break;

        case NIN_BALLOONHIDE:
        case NIN_BALLOONTIMEOUT:
            khm_notify_icon_change(KHERR_NONE);
            if (balloon_alert) {
                khui_alert_release(balloon_alert);
                balloon_alert = NULL;
            }
            break;
        }
    } else if (uMsg == WM_TIMER) {
        if (wParam == KHUI_TRIGGER_TIMER_ID) {
            KillTimer(hwnd, KHUI_TRIGGER_TIMER_ID);
            khm_timer_fire(hwnd);
        } else if (wParam == KHUI_REFRESH_TIMER_ID) {
            KillTimer(hwnd, KHUI_REFRESH_TIMER_ID);
            kcdb_identity_refresh_all();
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

typedef struct tag_alerter_alert_data {
    khui_alert * alert;

    BOOL         seen;          /* has the user seen this alert? */

    BOOL         has_commands;  /* we cache the value here.  otherwise
                                   we'll have to get a lock on the
                                   alert each time we have to find out
                                   whether there are any commands for
                                   this alert. */

    RECT         r_alert;    /* the entire alert, relative to self. */

    /* the following rects are relative to the top left of r_alert. */

    RECT         r_title;       /* the title.  deflate by padding to
                                   get the text rect. */
    RECT         r_icon;        /* rect for icon */
    RECT         r_message;     /* rect for the text. no padding
                                   necessary. */
    RECT         r_suggestion;  /* rect for the suggestion.  deflate
                                   by padding to get the suggestion
                                   rect.  The suggestion rect includes
                                   space for the small icon on the
                                   left and padding between the icon
                                   and the text. The size of the small
                                   icon are as per system metrics
                                   SM_C{X,Y}SMICON. Padding is
                                   s_pad.cx vertical. */

    int          n_cmd_buttons; /* number of command buttons in this alert. */

    RECT         r_buttons[KHUI_MAX_ALERT_COMMANDS];
                                /* rects for the command buttons. */

    HWND         hwnd_buttons[KHUI_MAX_ALERT_COMMANDS];
                                /* handles for the command buttons */

    LDCL(struct tag_alerter_alert_data);
} alerter_alert_data;

typedef struct tag_alerter_wnd_data {
    HWND            hwnd;
    HFONT           hfont;

    wchar_t         caption[KHUI_MAXCCH_TITLE]; /* the original
                                                   caption for the
                                                   dialog. */

    HWND            hw_bin;
    HWND            hw_scroll;
    HWND            hw_close;

    int             scroll_top;

    int             n_cmd_buttons; /* total number of command buttons
                                      in all the alerts being shown in
                                      this dialog. */

    /* various metrics */
    /* calculated during WM_CREATE */
    SIZE            s_button;
    SIZE            s_margin;
    RECT            r_text;     /* only .left and .right are used. rest are 0 */
    RECT            r_title;    /* only .left, .right and .bottom are used. .top=0 */
    SIZE            s_icon;
    SIZE            s_pad;

    int             cx_wnd;
    int             cy_max_wnd;

    /* derived from the alert sizes */
    SIZE            s_alerts;

    QDCL(alerter_alert_data);   /* queue of alerts that are being
                                   shown in this window. */

    LDCL(struct tag_alerter_wnd_data); /* for adding to
                                          khui_alert_windows list. */

    int             n_alerts;

} alerter_wnd_data;

#define NTF_PARAM DWLP_USER

/* dialog sizes in base dialog units */

#define NTF_MARGIN          5
#define NTF_WIDTH           200
#define NTF_MAXHEIGHT       150

#define NTF_TITLE_X         NTF_MARGIN
#define NTF_TITLE_WIDTH     (NTF_WIDTH - NTF_MARGIN*2)
#define NTF_TITLE_HEIGHT    10

#define NTF_ICON_WIDTH      20
#define NTF_ICON_HEIGHT     20

#define NTF_TEXT_X          (NTF_MARGIN + NTF_ICON_WIDTH + NTF_MARGIN)
#define NTF_TEXT_WIDTH      ((NTF_WIDTH - NTF_MARGIN) - NTF_TEXT_X)
#define NTF_TEXT_PAD        2

#define NTF_BUTTON_WIDTH    ((NTF_TEXT_WIDTH - (KHUI_MAX_ALERT_COMMANDS - 1)*NTF_MARGIN) / KHUI_MAX_ALERT_COMMANDS)
#define NTF_BUTTON_HEIGHT   15

#define NTF_TIMEOUT 20000

#define ALERT_WINDOW_EX_SYLES (WS_EX_DLGMODALFRAME | WS_EX_CONTEXTHELP)
#define ALERT_WINDOW_STYLES   (WS_DLGFRAME | WS_POPUPWINDOW | WS_CLIPCHILDREN)

/* Control ids */
#define IDC_NTF_ALERTBIN 998
#define IDC_NTF_CLOSE    999

#define IDC_NTF_CMDBUTTONS 1001
#define IDC_FROM_IDX(alert, bn) ((alert) * KHUI_MAX_ALERT_COMMANDS + (bn) + IDC_NTF_CMDBUTTONS)
#define ALERT_FROM_IDC(idc)  (((idc) - IDC_NTF_CMDBUTTONS) / KHUI_MAX_ALERT_COMMANDS)
#define BUTTON_FROM_IDC(idc) (((idc) - IDC_NTF_CMDBUTTONS) % KHUI_MAX_ALERT_COMMANDS)

/* if the only command in an alert is "Close", we assume that the
   alert has no commands. */
#define ALERT_HAS_CMDS(a) ((a)->n_alert_commands > 1 || ((a)->n_alert_commands == 1 && (a)->alert_commands[0] != KHUI_PACTION_CLOSE))

static void
add_alert_to_wnd_data(alerter_wnd_data * d,
                      khui_alert * a) {
    alerter_alert_data * adata;

    adata = PMALLOC(sizeof(*adata));
    ZeroMemory(adata, sizeof(*adata));

    adata->alert = a;
    khui_alert_hold(a);

    khui_alert_lock(a);

    a->flags |= KHUI_ALERT_FLAG_DISPLAY_WINDOW;

    a->displayed = TRUE;

    khui_alert_unlock(a);

    QPUT(d, adata);
}

static alerter_wnd_data *
create_alerter_wnd_data(HWND hwnd, alert_list * l) {
    alerter_wnd_data * d;
    int i;
    LONG dlgb;

    d = PMALLOC(sizeof(*d));
    ZeroMemory(d, sizeof(*d));

    d->hwnd = hwnd;

    GetWindowText(hwnd, d->caption, ARRAYLENGTH(d->caption));

    for (i=0; i < l->n_alerts; i++) {
        add_alert_to_wnd_data(d, l->alerts[i]);
    }

    d->n_alerts = l->n_alerts;

    LPUSH(&khui_alert_windows, d);

    /* Compute a few metrics first */

    dlgb = GetDialogBaseUnits();

#define DLG2SCNX(x) MulDiv((x), LOWORD(dlgb), 4)
#define DLG2SCNY(y) MulDiv((y), HIWORD(dlgb), 8)

    d->cx_wnd = DLG2SCNX(NTF_WIDTH);
    d->cy_max_wnd = DLG2SCNY(NTF_MAXHEIGHT);

    d->s_button.cx = DLG2SCNX(NTF_BUTTON_WIDTH);
    d->s_button.cy = DLG2SCNY(NTF_BUTTON_HEIGHT);

    d->s_margin.cx = DLG2SCNX(NTF_MARGIN);
    d->s_margin.cy = DLG2SCNY(NTF_MARGIN);

    d->r_text.left = DLG2SCNX(NTF_TEXT_X);
    d->r_text.right = DLG2SCNX(NTF_TEXT_WIDTH + NTF_TEXT_X);
    d->r_text.top = 0;
    d->r_text.bottom = 0;

    d->r_title.left = DLG2SCNX(NTF_TITLE_X);
    d->r_title.right = DLG2SCNX(NTF_TITLE_X + NTF_TITLE_WIDTH);
    d->r_title.top = 0;
    d->r_title.bottom = DLG2SCNY(NTF_TITLE_HEIGHT);

    d->s_icon.cx = DLG2SCNX(NTF_ICON_WIDTH);
    d->s_icon.cy = DLG2SCNY(NTF_ICON_HEIGHT);

    d->s_pad.cx = DLG2SCNX(NTF_TEXT_PAD);
    d->s_pad.cy = DLG2SCNY(NTF_TEXT_PAD);

#undef DLG2SCNX
#undef DLG2SCNY

    return d;
}

static void
layout_alert(HDC hdc, alerter_wnd_data * d,
             alerter_alert_data * adata) {
    RECT r;
    size_t len;
    int y;
    int icon_y;

#ifdef DEBUG
    assert(adata->alert);
#endif

    khui_alert_lock(adata->alert);

    y = 0;

    /* Title */

    y += d->s_margin.cy;

    if (adata->alert->title &&
        wcscmp(adata->alert->title, d->caption)) {

        CopyRect(&adata->r_title, &d->r_title);
        OffsetRect(&adata->r_title, 0, y);

        y = adata->r_title.bottom + d->s_margin.cy;

    } else {

        SetRectEmpty(&adata->r_title);

    }

    /* Icon */

    SetRect(&adata->r_icon, d->s_margin.cx, y,
            d->s_margin.cx + d->s_icon.cx,
            y + d->s_icon.cy);

    icon_y = adata->r_icon.bottom + d->s_margin.cy; /* the bottom of the icon */

    /* Message */

    if (adata->alert->message &&
        SUCCEEDED(StringCchLength(adata->alert->message,
                                  KHUI_MAXCCH_MESSAGE,
                                  &len))) {

        CopyRect(&r, &d->r_text);

        DrawTextEx(hdc, adata->alert->message, (int) len,
                   &r,
                   DRAWTEXTOPTIONS,
                   NULL);

        OffsetRect(&r, 0, y);
        CopyRect(&adata->r_message, &r);

        y = r.bottom + d->s_margin.cy;

    } else {

        SetRectEmpty(&adata->r_message);

    }

    /* Suggestion */

    if (adata->alert->suggestion &&
        SUCCEEDED(StringCchLength(adata->alert->suggestion,
                                  KHUI_MAXCCH_SUGGESTION,
                                  &len))) {
        int pad = d->s_pad.cx + GetSystemMetrics(SM_CXSMICON);

        CopyRect(&r, &d->r_text);
        r.left += pad;

        DrawTextEx(hdc, adata->alert->suggestion, (int) len,
                   &r,
                   DRAWTEXTOPTIONS,
                   NULL);

        r.left -= pad;

        InflateRect(&r, d->s_pad.cx, d->s_pad.cy);
        OffsetRect(&r, 0, -r.top + y);
        CopyRect(&adata->r_suggestion, &r);

        y = r.bottom + d->s_margin.cy;

    } else {

        SetRectEmpty(&adata->r_suggestion);

    }

    y = max(y, icon_y);

    /* Buttons */

    if (ALERT_HAS_CMDS(adata->alert)) {
        khm_int32 i;
        int x;

        adata->has_commands = TRUE;

        x = d->r_text.left;

#ifdef DEBUG
        assert(adata->alert->n_alert_commands <= KHUI_MAX_ALERT_COMMANDS);
#endif

        for (i=0; i < adata->alert->n_alert_commands; i++) {
            SetRect(&adata->r_buttons[i], x, y, x + d->s_button.cx, y + d->s_button.cy);

            x += d->s_button.cx + d->s_margin.cx;
        }

        y += d->s_button.cy + d->s_margin.cy;
    }

    khui_alert_unlock(adata->alert);

    /* Now set the rect for the whole alert */
    SetRect(&adata->r_alert, 0, 0, d->cx_wnd, y);

}

static void
estimate_alerter_wnd_sizes(alerter_wnd_data * d) {
    HDC hdc;
    HFONT hf_old;
    int height = 0;

    alerter_alert_data * adata;

    hdc = GetDC(d->hwnd);
#ifdef DEBUG
    assert(hdc);
#endif

    if (d->hfont == NULL)
        d->hfont = (HFONT) GetStockObject(DEFAULT_GUI_FONT);

#ifdef DEBUG
    assert(d->hfont);
#endif

    hf_old = SelectFont(hdc, d->hfont);

    adata = QTOP(d);
    while(adata) {
        layout_alert(hdc, d, adata);

        height += adata->r_alert.bottom;

        adata = QNEXT(adata);
    }

    SelectFont(hdc, hf_old);
    ReleaseDC(d->hwnd, hdc);

    d->s_alerts.cx = d->cx_wnd;
    d->s_alerts.cy = height;
}

static void
layout_command_buttons(alerter_wnd_data * d) {

    alerter_alert_data * adata;
    HDWP hdefer;
    int y;

    hdefer = BeginDeferWindowPos(d->n_cmd_buttons);

    y = 0;
    adata = QTOP(d);
    while (adata) {
        RECT r;
        int i;

        if (!adata->has_commands)
            goto done;

        for (i=0; i < adata->n_cmd_buttons; i++) {
            if (IsRectEmpty(&adata->r_buttons[i]) ||
                adata->hwnd_buttons[i] == NULL) {
#ifdef DEBUG
                assert(FALSE);
#endif
                continue;
            }

            CopyRect(&r, &adata->r_buttons[i]);
            OffsetRect(&r, 0, y - d->scroll_top);

            DeferWindowPos(hdefer,
                           adata->hwnd_buttons[i], NULL,
                           r.left, r.top, 0, 0,
                           SWP_NOACTIVATE | SWP_NOOWNERZORDER | SWP_NOZORDER |
                           SWP_NOSIZE);
        }

    done:
        y += adata->r_alert.bottom;
        adata = QNEXT(adata);
    }

    EndDeferWindowPos(hdefer);
}

static void
setup_alerter_window_controls(alerter_wnd_data * d) {

    RECT r_alerts;
    RECT r_window;
    RECT r_client;
    RECT r_parent;
    HWND hw_parent;
    BOOL close_button = FALSE;
    BOOL scrollbar = FALSE;
    BOOL redraw_scollbar = FALSE;

    /* estimate_alerter_wnd_sizes() must be called before calling
       this. */
#ifdef DEBUG
    assert(d->s_alerts.cy > 0);
#endif

    r_alerts.left = 0;
    r_alerts.top = 0;
    r_alerts.right = d->cx_wnd;

    if (d->s_alerts.cy > d->cy_max_wnd) {

        BOOL redraw = FALSE;

        r_alerts.right += GetSystemMetrics(SM_CXVSCROLL);
        r_alerts.bottom = d->cy_max_wnd;

        CopyRect(&r_client, &r_alerts);
        r_client.bottom += d->s_margin.cy * 2 + d->s_button.cy;
        close_button = TRUE;

        if (d->scroll_top > d->s_alerts.cy - d->cy_max_wnd)
            d->scroll_top = d->s_alerts.cy - d->cy_max_wnd;

        scrollbar = TRUE;
    } else {
        r_alerts.bottom = d->s_alerts.cy;

        CopyRect(&r_client, &r_alerts);

        if (d->n_alerts == 1) {

            if (!QTOP(d)->has_commands) {
                r_client.bottom += d->s_margin.cy * 2 + d->s_button.cy;
                close_button = TRUE;
            }

        } else {

            r_client.bottom += d->s_margin.cy * 2 + d->s_button.cy;
            close_button = TRUE;
        }

        d->scroll_top = 0;
    }

    if (d->hw_bin == NULL) {
        d->hw_bin = CreateWindowEx(WS_EX_CONTROLPARENT,
                                   MAKEINTATOM(atom_alert_bin),
                                   L"",
                                   WS_CHILD | WS_CLIPCHILDREN |
                                   WS_VISIBLE |
                                   ((scrollbar)? WS_VSCROLL : 0),
                                   r_alerts.left, r_alerts.top,
                                   r_alerts.right - r_alerts.left,
                                   r_alerts.bottom - r_alerts.top,
                                   d->hwnd,
                                   (HMENU) IDC_NTF_ALERTBIN,
                                   khm_hInstance,
                                   (LPVOID) d);
    } else {
        redraw_scollbar = TRUE;
        SetWindowLongPtr(d->hw_bin, GWL_STYLE,
                         WS_CHILD | WS_CLIPCHILDREN |
                         WS_VISIBLE |
                         ((scrollbar)? WS_VSCROLL : 0));
        SetWindowPos(d->hw_bin, NULL,
                     r_alerts.left, r_alerts.top,
                     r_alerts.right - r_alerts.left,
                     r_alerts.bottom - r_alerts.top,
                     SWP_NOOWNERZORDER | SWP_NOZORDER | SWP_NOACTIVATE);
    }

    if (scrollbar) {
        SCROLLINFO si;

        ZeroMemory(&si, sizeof(si));
        si.cbSize = sizeof(si);
        si.fMask = SIF_PAGE | SIF_POS | SIF_RANGE;
        si.nMin = 0;
        si.nMax = d->s_alerts.cy;
        si.nPage = d->cy_max_wnd;
        si.nPos = d->scroll_top;

        SetScrollInfo(d->hw_bin, SB_VERT, &si, redraw_scollbar);
    }

    /* create the action buttons */
    {
        alerter_alert_data * adata;
        int y;
        int idx;
        HWND last_window = HWND_TOP;
        int n_buttons = 0;

        idx = 0;
        y = - d->scroll_top;
        adata = QTOP(d);
        while(adata) {
            if (adata->has_commands) {
                int i;
                wchar_t caption[KHUI_MAXCCH_SHORT_DESC];
                khui_action * action;
                RECT r;

                khui_alert_lock(adata->alert);

                adata->n_cmd_buttons = adata->alert->n_alert_commands;

                for (i=0; i < adata->alert->n_alert_commands; i++) {

                    n_buttons ++;

                    if (adata->hwnd_buttons[i] != NULL) {
                        /* already there */
                        CopyRect(&r, &adata->r_buttons[i]);
                        OffsetRect(&r, 0, y);

                        SetWindowPos(adata->hwnd_buttons[i], last_window,
                                     r.left, r.top,
                                     r.right - r.left,
                                     r.bottom - r.top,
                                     SWP_NOACTIVATE | SWP_NOOWNERZORDER |
                                     SWP_SHOWWINDOW);

                        last_window = adata->hwnd_buttons[i];

                        continue;
                    }

                    action = khui_find_action(adata->alert->alert_commands[i]);

                    if (action == NULL) {
#ifdef DEBUG
                        assert(FALSE);
#endif
                        continue;
                    }

                    if (action->caption)
                        StringCbCopy(caption, sizeof(caption), action->caption);
                    else if (action->is_caption)
                        LoadString(khm_hInstance, action->is_caption, caption,
                                   ARRAYLENGTH(caption));
                    else {
#ifdef DEBUG
                        assert(FALSE);
#endif
                        caption[0] = L'\0';
                    }

                    CopyRect(&r, &adata->r_buttons[i]);
                    OffsetRect(&r, 0, y);

                    adata->hwnd_buttons[i] =
                        CreateWindowEx(0,
                                       L"BUTTON",
                                       caption,
                                       WS_CHILD | WS_TABSTOP,
                                       r.left, r.top,
                                       r.right - r.left,
                                       r.bottom - r.top,
                                       d->hw_bin,
                                       (HMENU) (INT_PTR) IDC_FROM_IDX(idx, i),
                                       khm_hInstance,
                                       NULL);
#ifdef DEBUG
                    assert(adata->hwnd_buttons[i]);
#endif
                    SetWindowPos(adata->hwnd_buttons[i], last_window,
                                 0, 0, 0, 0,
                                 SWP_NOACTIVATE | SWP_NOOWNERZORDER |
                                 SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
                    last_window = adata->hwnd_buttons[i];
                }

                khui_alert_unlock(adata->alert);
            }

            y += adata->r_alert.bottom;
            adata = QNEXT(adata);
        }

        d->n_cmd_buttons = n_buttons;
    }

    if (close_button) {
        if (d->hw_close == NULL) {
            khui_action * close_action;
            wchar_t caption[256];

            close_action = khui_find_action(KHUI_PACTION_CLOSE);
#ifdef DEBUG
            assert(close_action);
#endif
            if (close_action->caption)
                StringCbCopy(caption, sizeof(caption), close_action->caption);
            else if (close_action->is_caption)
                LoadString(khm_hInstance, close_action->is_caption, caption,
                           ARRAYLENGTH(caption));
            else {
#ifdef DEBUG
                assert(FALSE);
#endif
                caption[0] = L'\0';
            }

            d->hw_close = CreateWindowEx(0,
                                         L"BUTTON",
                                         caption,
                                         WS_CHILD | BS_DEFPUSHBUTTON,
                                         0,0,100,100,
                                         d->hwnd,
                                         (HMENU) IDC_NTF_CLOSE,
                                         khm_hInstance,
                                         NULL);

#ifdef DEBUG
            assert(d->hw_close);
            assert(d->hfont);
#endif
            if (d->hfont)
                SendMessage(d->hw_close, WM_SETFONT, (WPARAM) d->hfont, FALSE);
        }

        {
            int x,y,width,height;

            x = d->r_text.left;
            y = r_client.bottom - (d->s_margin.cy + d->s_button.cy);
            width = d->s_button.cx;
            height = d->s_button.cy;

            SetWindowPos(d->hw_close, NULL,
                         x, y, width, height,
                         SWP_NOACTIVATE | SWP_NOOWNERZORDER | SWP_NOZORDER |
                         SWP_SHOWWINDOW);
        }
    }

    CopyRect(&r_window, &r_client);
    AdjustWindowRectEx(&r_window, ALERT_WINDOW_STYLES,
                       FALSE, ALERT_WINDOW_EX_SYLES);
    OffsetRect(&r_window, -r_window.left, -r_window.top);

    /* center the window above the parent window. */

    hw_parent = GetWindow(d->hwnd, GW_OWNER);
    GetWindowRect(hw_parent, &r_parent);

    {
        int x,y;

        x = (r_parent.left + r_parent.right - (r_window.right - r_window.left)) / 2;
        y = (r_parent.top + r_parent.bottom - (r_window.bottom - r_window.top)) / 2;

        SetWindowPos(d->hwnd,
                     HWND_TOP,
                     x, y,
                     r_window.right - r_window.left,
                     r_window.bottom - r_window.top,
                     SWP_SHOWWINDOW | SWP_NOOWNERZORDER);

    }
}

static void
destroy_alerter_wnd_data(alerter_wnd_data * d) {
    alerter_alert_data * adata;

    LDELETE(&khui_alert_windows, d);

    QGET(d, &adata);
    while(adata) {

        if (adata->alert) {

            khui_alert_lock(adata->alert);

            adata->alert->flags &= ~KHUI_ALERT_FLAG_DISPLAY_WINDOW;

            adata->alert->displayed = FALSE;

            khui_alert_unlock(adata->alert);

            khui_alert_release(adata->alert);
            adata->alert = NULL;
        }

        PFREE(adata);

        QGET(d, &adata);
    }

    PFREE(d);
}

/* both ref and to_add must be locked and held */
static khm_boolean
alert_can_consolidate(khui_alert * ref,
                      khui_alert * to_add,
                      alert_list * alist) {

    /* first check if we can add anything */
    if (alist->n_alerts == ARRAYLENGTH(alist->alerts))
        return FALSE;

#ifdef DEBUG
    assert(to_add != NULL);
#endif

    if (ref == NULL) {
        /* we are testing whether to_add should be added to the alist
           on its own. */
        if ((to_add->flags & KHUI_ALERT_FLAG_DISPLAY_BALLOON) &&
            !(to_add->flags & KHUI_ALERT_FLAG_DISPLAY_WINDOW)) {
            /* already displayed */
            return FALSE;
        }

        if ((to_add->flags & (KHUI_ALERT_FLAG_REQUEST_BALLOON |
                              KHUI_ALERT_FLAG_REQUEST_WINDOW)) == KHUI_ALERT_FLAG_REQUEST_BALLOON) {
            /* needs to be shown in a balloon */
            return FALSE;
        }

        return TRUE;
    }

    /* if the ref or to_add are marked for modal, then we can't
       consolidate them */
    if ((ref->flags & KHUI_ALERT_FLAG_MODAL) ||
        (to_add->flags & KHUI_ALERT_FLAG_MODAL))
        return FALSE;

    /* also, if either of them have requested to be exclusively shown
       in a balloon, then we can't consolidate them. */
    if (((ref->flags & (KHUI_ALERT_FLAG_REQUEST_BALLOON |
                        KHUI_ALERT_FLAG_REQUEST_WINDOW)) == KHUI_ALERT_FLAG_REQUEST_BALLOON)

        ||

        ((to_add->flags & (KHUI_ALERT_FLAG_REQUEST_BALLOON |
                           KHUI_ALERT_FLAG_REQUEST_WINDOW)) == KHUI_ALERT_FLAG_REQUEST_BALLOON))
        return FALSE;

    /* for now, all we check if whether they are of the same type. */
    if (ref->alert_type != KHUI_ALERTTYPE_NONE &&
        ref->alert_type == to_add->alert_type)
        return TRUE;
    else
        return FALSE;
}

/* the return value is the number of alerts added to alist */
static khm_int32
alert_consolidate(alert_list * alist,
                  khui_alert * alert,
                  khm_boolean add_from_queue) {

    khui_alert * listtop;
    int queue_size = 0;
    int i;
    khm_int32 n_added = 0;

#ifdef DEBUG
    assert(alist);
#endif

    if (alist->n_alerts == ARRAYLENGTH(alist->alerts)) {
        /* can't add anything */

        return 0;
    }

    /* if the list is empty, we just add one alert */
    if (alist->n_alerts == 0) {

        if (alert) {
            khui_alert_lock(alert);
            if (alert_can_consolidate(NULL, alert, alist)) {
                alert_list_add_alert(alist, alert);
                n_added ++;
                alert = NULL;
            }
            khui_alert_unlock(alert);
        }

        if (n_added == 0 && add_from_queue) {
            khui_alert * q;
            int s, i;

            s = alert_queue_get_size();
            for (i=0; i < s && n_added == 0; i++) {
                q = alert_queue_get_alert_by_pos(i);
                if (q) {
                    khui_alert_lock(q);
                    if (alert_can_consolidate(NULL, q, alist)) {
                        alert_list_add_alert(alist, q);
                        n_added++;
                        alert_queue_delete_alert(q);
                    }
                    khui_alert_unlock(q);
                    khui_alert_release(q);
                }
            }
        }

        if (n_added == 0) {
            /* nothing to add */
            return 0;
        }
    }

    /* at this point, the alert list is not empty */
#ifdef DEBUG
    assert(alist->n_alerts != 0);
    assert(alist->alerts[0]);
#endif

    listtop = alist->alerts[0];
    khui_alert_hold(listtop);
    khui_alert_lock(listtop);

    queue_size = alert_queue_get_size();

    if (alert) {
        khui_alert_lock(alert);
        if (alert_can_consolidate(listtop, alert, alist)) {
            alert_list_add_alert(alist, alert);
            n_added ++;
        }
        khui_alert_unlock(alert);
    }

    if (add_from_queue) {
        for (i=0; i < queue_size; i++) {
            khui_alert * a;

            a = alert_queue_get_alert_by_pos(i);
            if (a == NULL)
                continue;

            khui_alert_lock(a);
            if (alert_can_consolidate(listtop, a, alist)) {
                alert_queue_delete_alert(a);
                alert_list_add_alert(alist, a);
                n_added ++;
                queue_size = alert_queue_get_size();
            }
            khui_alert_unlock(a);
            khui_alert_release(a);
        }
    }

    khui_alert_unlock(listtop);
    khui_alert_release(listtop);

    return n_added;
}

static khm_int32
alert_check_consolidate_window(alerter_wnd_data * d, khui_alert * a) {
    alert_list alist;
    alerter_alert_data * adata;
    int n_added;

    alert_list_init(&alist);

    adata = QTOP(d);
    while(adata) {

#ifdef DEBUG
        assert(adata->alert);
#endif
        alert_list_add_alert(&alist, adata->alert);

        adata = QNEXT(adata);
    }

    n_added = alert_consolidate(&alist, a, FALSE);

    alert_list_destroy(&alist);

    return n_added;
}

static khm_int32 
alert_show_minimized(khui_alert * a) {
    wchar_t tbuf[64];           /* corresponds to NOTIFYICONDATA::szInfoTitle[] */
    wchar_t mbuf[256];          /* corresponds to NOTIFYICONDATA::szInfo[] */

#ifdef DEBUG
    assert(a);
#endif
    if (a == NULL)
        return KHM_ERROR_INVALID_PARAM;

    khui_alert_lock(a);

    if (a->message == NULL)
        goto done;

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
    if (balloon_alert) {
        khui_alert_release(balloon_alert);
        balloon_alert = NULL;
    }

    balloon_alert = a;
    khui_alert_hold(a);
#endif

    khm_notify_icon_balloon(a->severity,
                            tbuf,
                            mbuf,
                            NTF_TIMEOUT);

 done:
    khui_alert_unlock(a);

    return KHM_ERROR_SUCCESS;
}

static khm_int32 
alert_show_normal(khui_alert * a) {
    wchar_t buf[256];
    wchar_t * title;
    alert_list alist;

    khui_alert_lock(a);

    if(a->title == NULL) {
        LoadString(khm_hInstance, IDS_ALERT_DEFAULT, 
                   buf, ARRAYLENGTH(buf));
        title = buf;
    } else
        title = a->title;

    khui_alert_unlock(a);

    alert_list_init(&alist);
    alert_list_set_title(&alist, title);
    alert_list_add_alert(&alist, a);

    alert_show_list(&alist);

    alert_list_destroy(&alist);

    return KHM_ERROR_SUCCESS;
}

static khm_int32
alert_show_list(alert_list * alist) {
    HWND hwa;

    /* we don't need to keep track of the window handle
       because the window procedure adds it to the dialog
       list automatically */

    hwa = 
        CreateWindowEx(ALERT_WINDOW_EX_SYLES,
                       MAKEINTATOM(atom_alerter),
                       alist->title,
                       ALERT_WINDOW_STYLES,
                       0, 0, 300, 300, // bogus values
                       khm_hwnd_main,
                       (HMENU) NULL,
                       khm_hInstance,
                       (LPVOID) alist);

    ShowWindow(hwa, SW_SHOW);

    return (hwa != NULL);
}

static khm_int32 
alert_show(khui_alert * a) {
    khm_boolean show_normal = FALSE;
    khm_boolean show_mini = FALSE;

    khui_alert_lock(a);

    /* is there an alert already?  If so, we just enqueue the message
       and let it sit. */
    if (ALERT_DISPLAYED() &&
        !(a->flags & KHUI_ALERT_FLAG_MODAL)) {
        khm_int32 rv;
        alerter_wnd_data * wdata;

        khui_alert_unlock(a);

        /* if there are any alerter windows displayed, check if this
           alert can be consolidated with any of them.  If so, we
           should consolidate it.  Otherwise, just enqueue it. */
        for(wdata = khui_alert_windows;
            wdata;
            wdata = LNEXT(wdata)) {
            if (alert_check_consolidate_window(wdata, a)) {

                add_alert_to_wnd_data(wdata, a);
                estimate_alerter_wnd_sizes(wdata);
                setup_alerter_window_controls(wdata);

                return KHM_ERROR_SUCCESS;

            }
        }

        rv = alert_enqueue(a);

        if (KHM_SUCCEEDED(rv))
            return KHM_ERROR_HELD;
        else
            return rv;
    }

    if((a->flags & KHUI_ALERT_FLAG_DISPLAY_WINDOW) ||
       ((a->flags & KHUI_ALERT_FLAG_DISPLAY_BALLOON) &&
        !(a->flags & KHUI_ALERT_FLAG_REQUEST_WINDOW))) {

        /* The alert has already been displayed. */

        show_normal = FALSE;
        show_mini = FALSE;

    } else {

        if(a->err_context != NULL ||
           a->err_event != NULL) {
            a->flags |= KHUI_ALERT_FLAG_VALID_ERROR;
        }

        /* depending on the state of the main window, we
           need to either show a window or a balloon */
        if ((a->flags & KHUI_ALERT_FLAG_MODAL) ||
            (khm_is_main_window_active() &&
             !(a->flags & KHUI_ALERT_FLAG_REQUEST_BALLOON)) ||
            (a->flags & KHUI_ALERT_FLAG_REQUEST_WINDOW)) {

            show_normal = TRUE;

        } else {

            show_mini = TRUE;

        }
    }

    khui_alert_unlock(a);

    if (show_normal)
        return alert_show_normal(a);
    else if (show_mini)
        return alert_show_minimized(a);
    else
        return KHM_ERROR_SUCCESS;
}

static void
check_for_queued_alerts(void) {
    if (!is_alert_queue_empty()) {
        khui_alert * a;

        a = alert_queue_peek();

        khui_alert_lock(a);

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

        khui_alert_unlock(a);
        khui_alert_release(a);

    } else {
        khm_statusbar_set_part(KHUI_SBPART_NOTICE,
                               NULL, NULL);
    }
}

static khm_int32
alert_enqueue(khui_alert * a) {
    if (is_alert_queue_full())
        return KHM_ERROR_NO_RESOURCES;

    alert_queue_put_alert(a);
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
            LPCREATESTRUCT lpcs;
            alert_list * alist;
            alerter_wnd_data * d;

            lpcs = (LPCREATESTRUCT) lParam;
            alist = (alert_list *) lpcs->lpCreateParams;

            d = create_alerter_wnd_data(hwnd, alist);

#pragma warning(push)
#pragma warning(disable: 4244)
            SetWindowLongPtr(hwnd, NTF_PARAM, (LONG_PTR) d);
#pragma warning(pop)

            khm_add_dialog(hwnd);
            khm_enter_modal(hwnd);

            estimate_alerter_wnd_sizes(d);
            setup_alerter_window_controls(d);

            if (d->hw_close) {
                SetFocus(d->hw_close);
            }

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

            destroy_alerter_wnd_data(d);

            return TRUE;
        }
        break;

#if 0
    case WM_PAINT:
        {
            RECT r_update;
            PAINTSTRUCT ps;
            HDC hdc;
            alerter_wnd_data * d;

            if(!GetUpdateRect(hwnd, &r_update, TRUE))
                return FALSE;

            d = (alerter_wnd_data *)(LONG_PTR)
                GetWindowLongPtr(hwnd, NTF_PARAM);

            hdc = BeginPaint(hwnd, &ps);

            EndPaint(hwnd, &ps);

            return FALSE;
        }
        break; /* not reached */
#endif

    case WM_COMMAND:
        {
            alerter_wnd_data * d;

            d = (alerter_wnd_data *)(LONG_PTR) 
                GetWindowLongPtr(hwnd, NTF_PARAM);

            if(HIWORD(wParam) == BN_CLICKED) {
                if (LOWORD(wParam) == IDC_NTF_CLOSE ||
                    LOWORD(wParam) == KHUI_PACTION_NEXT) {

                    khm_leave_modal();

                    DestroyWindow(hwnd);

#ifdef FORLATER
                    if (LOWORD(wParam) == KHUI_PACTION_NEXT) {
                        kmq_post_message(KMSG_ALERT, KMSG_ALERT_SHOW_QUEUED, 0, 0);
                    }
#endif
                    return 0;
                }
            }
        }
        break;
    }

    return DefDlgProc(hwnd, uMsg, wParam, lParam);
    //return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

static LRESULT CALLBACK 
alert_bin_wnd_proc(HWND hwnd,
                   UINT uMsg,
                   WPARAM wParam,
                   LPARAM lParam)
{
    BOOL in_printclient = FALSE;

    switch(uMsg) {
    case WM_CREATE:
        {
            LPCREATESTRUCT lpcs;
            alerter_wnd_data * d;

            lpcs = (LPCREATESTRUCT) lParam;
            d = (alerter_wnd_data *) lpcs->lpCreateParams;

#pragma warning(push)
#pragma warning(disable: 4244)
            SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR) d);
#pragma warning(pop)
        }
        return 0;

    case WM_PRINTCLIENT:
        in_printclient = TRUE;
        /* fallthrough */
    case WM_PAINT:
        {
            HDC hdc;
            PAINTSTRUCT ps;
            RECT r;
            HFONT hf_old;
            int y;
            alerter_wnd_data * d;
            alerter_alert_data * adata;
            size_t len;

            d = (alerter_wnd_data *) (LONG_PTR) GetWindowLongPtr(hwnd, GWLP_USERDATA);
#ifdef DEBUG
            assert(d);
#endif

            if (in_printclient) {
                hdc = (HDC) wParam;
            } else {
                hdc = BeginPaint(hwnd, &ps);
            }

#ifdef DEBUG
            assert(hdc);
            assert(d->hfont);
#endif

            if (in_printclient || ps.fErase) {
                HBRUSH hb_background;

                hb_background = GetSysColorBrush(COLOR_BTNFACE);

                GetClientRect(hwnd, &r);
                FillRect(hdc, &r, hb_background);
            }

            SetBkMode(hdc, TRANSPARENT);

            hf_old = SelectFont(hdc, d->hfont);

            y = -d->scroll_top;

            /* go through the alerts and display them */
            adata = QTOP(d);
            while(adata) {
                khui_alert * a;

                a = adata->alert;
#ifdef DEBUG
                assert(a != NULL);
#endif
                khui_alert_lock(a);

                /* if the alert has a title and it's different from
                   the original caption for the alert dialog, we have
                   to display the title. */
                if (a->title &&
                    wcscmp(a->title, d->caption)) {

                    CopyRect(&r, &adata->r_title);
                    OffsetRect(&r, 0, y);

                    StringCchLength(a->title, KHUI_MAXCCH_TITLE, &len);

                    DrawEdge(hdc, &r, EDGE_RAISED, BF_RECT | BF_MIDDLE);

                    InflateRect(&r, -d->s_pad.cx, -d->s_pad.cy);

                    DrawText(hdc, a->title, (int) len, &r,
                             DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
                }

                {
                    HICON hicon;
                    int iid;

                    CopyRect(&r, &adata->r_icon);
                    OffsetRect(&r, 0, y);

                    if(a->severity == KHERR_ERROR)
                        iid = OIC_HAND;
                    else if(a->severity == KHERR_WARNING)
                        iid = OIC_BANG;
                    else
                        iid = OIC_NOTE;

                    hicon = (HICON) LoadImage(NULL, 
                                              MAKEINTRESOURCE(iid), 
                                              IMAGE_ICON,
                                              GetSystemMetrics(SM_CXICON),
                                              GetSystemMetrics(SM_CYICON),
                                              LR_SHARED);

                    DrawIcon(hdc, r.left, r.top, hicon);
                }

                if (a->message) {

                    CopyRect(&r, &adata->r_message);
                    OffsetRect(&r, 0, y);

                    StringCchLength(a->message, KHUI_MAXCCH_MESSAGE, &len);

                    DrawText(hdc, a->message, (int) len, &r,
                             DT_WORDBREAK);
                }

                if (a->suggestion) {
                    HICON hicon;

                    CopyRect(&r, &adata->r_suggestion);
                    OffsetRect(&r, 0, y);

                    DrawEdge(hdc, &r, EDGE_SUNKEN, BF_RECT | BF_MIDDLE);

                    InflateRect(&r, -d->s_pad.cx, -d->s_pad.cy);

                    hicon = (HICON) LoadImage(NULL,
                                              MAKEINTRESOURCE(OIC_NOTE),
                                              IMAGE_ICON,
                                              GetSystemMetrics(SM_CXSMICON),
                                              GetSystemMetrics(SM_CYSMICON),
                                              LR_SHARED);

                    DrawIcon(hdc, r.left, r.top, hicon);

                    r.left += d->s_pad.cx + GetSystemMetrics(SM_CXSMICON);

                    StringCchLength(a->suggestion, KHUI_MAXCCH_SUGGESTION, &len);

                    DrawText(hdc, a->suggestion, (int) len, &r,
                             DT_WORDBREAK);
                }
                khui_alert_unlock(a);

                y += adata->r_alert.bottom;

                adata = QNEXT(adata);
            }

            SelectFont(hdc, hf_old);

            if (!in_printclient) {
                EndPaint(hwnd, &ps);
            }
        }
        return 0;

    case WM_VSCROLL:
        {
        }
        return 0;

    case WM_COMMAND:
        {
        }
        break;

    case WM_DESTROY:
        {
        }
        return 0;
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
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
    wcx.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wcx.lpszMenuName = NULL;
    wcx.lpszClassName = KHUI_ALERTER_CLASS;
    wcx.hIconSm = NULL;

    atom_alerter = RegisterClassEx(&wcx);

    return atom_alerter;
}

ATOM khm_register_alert_bin_wnd_class(void)
{
    WNDCLASSEX wcx;

    ZeroMemory(&wcx, sizeof(wcx));

    wcx.cbSize = sizeof(wcx);
    wcx.style = CS_OWNDC;

    wcx.lpfnWndProc = alert_bin_wnd_proc;
    wcx.cbClsExtra = 0;
    wcx.cbWndExtra = sizeof(LONG_PTR);
    wcx.hInstance = khm_hInstance;
    wcx.hIcon = NULL;
    wcx.hCursor = LoadCursor(NULL, MAKEINTRESOURCE(IDC_ARROW));
    wcx.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wcx.lpszMenuName = NULL;
    wcx.lpszClassName = KHUI_ALERTBIN_CLASS;
    wcx.hIconSm = NULL;

    atom_alert_bin = RegisterClassEx(&wcx);

    return atom_alert_bin;
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
    ni.hIcon = LoadIcon(khm_hInstance, MAKEINTRESOURCE(iid_normal));
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
        iid = iid_normal;
    }

    ni.hWnd = hwnd_notifier;
    ni.uID = KHUI_NOTIFY_ICON_ID;
    ni.uFlags = NIF_INFO | NIF_ICON;
    ni.hIcon = LoadIcon(khm_hInstance, MAKEINTRESOURCE(iid));

    if (FAILED(StringCbCopy(ni.szInfo, sizeof(ni.szInfo), msg))) {
        /* too long? */
        StringCchCopyN(ni.szInfo, ARRAYLENGTH(ni.szInfo),
                       msg, 
                       ARRAYLENGTH(ni.szInfo) - ARRAYLENGTH(ELLIPSIS));
        StringCchCat(ni.szInfo, ARRAYLENGTH(ni.szInfo),
                     ELLIPSIS);
    }

    if (FAILED(StringCbCopy(ni.szInfoTitle, sizeof(ni.szInfoTitle), 
                            title))) {
        StringCchCopyN(ni.szInfoTitle, ARRAYLENGTH(ni.szInfoTitle),
                       title, 
                       ARRAYLENGTH(ni.szInfoTitle) - ARRAYLENGTH(ELLIPSIS));
        StringCchCat(ni.szInfoTitle, ARRAYLENGTH(ni.szInfoTitle),
                     ELLIPSIS);
    }

    ni.uTimeout = timeout;

    Shell_NotifyIcon(NIM_MODIFY, &ni);

    DestroyIcon(ni.hIcon);
}

void khm_notify_icon_expstate(enum khm_notif_expstate expseverity) {
    int new_iid;

    if (expseverity == KHM_NOTIF_OK)
        new_iid = IDI_APPICON_OK;
    else if (expseverity == KHM_NOTIF_WARN)
        new_iid = IDI_APPICON_WARN;
    else if (expseverity == KHM_NOTIF_EXP)
        new_iid = IDI_APPICON_EXP;
    else
        new_iid = IDI_NOTIFY_NONE;

    if (iid_normal == new_iid)
        return;

    iid_normal = new_iid;

    if (balloon_alert == NULL)
        khm_notify_icon_change(KHERR_NONE);
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
        iid = iid_normal;

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

    if(!khm_register_alert_bin_wnd_class())
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
    } else {
#ifdef DEBUG
        assert(hwnd_notifier != NULL);
#endif
    }
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

    if(atom_alert_bin != 0) {
        UnregisterClass(MAKEINTATOM(atom_alert_bin), khm_hInstance);
        atom_alert_bin = 0;
    }

    notifier_ready = FALSE;
}

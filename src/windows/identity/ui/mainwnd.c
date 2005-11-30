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

ATOM khm_main_window_class;
ATOM khm_null_window_class;
HWND khm_hwnd_null;
HWND khm_hwnd_main;
HWND khm_hwnd_rebar;
HWND khm_hwnd_main_cred;

#define MW_RESIZE_TIMER 1
#define MW_RESIZE_TIMEOUT 2000
#define MW_REFRESH_TIMER 2
#define MW_REFRESH_TIMEOUT 600

void
khm_set_dialog_result(HWND hwnd, LRESULT lr) {
#pragma warning(push)
#pragma warning(disable: 4244)
    SetWindowLongPtr(hwnd, DWL_MSGRESULT, lr);
#pragma warning(pop)
}

static void
mw_restart_refresh_timer(HWND hwnd) {
    khm_handle csp_cw;
    khm_int32 timeout;

    KillTimer(hwnd, MW_REFRESH_TIMER);
    if (KHM_SUCCEEDED(khc_open_space(NULL,
                                     L"CredWindow",
                                     KHM_PERM_READ,
                                     &csp_cw))) {
        if (KHM_FAILED(khc_read_int32(csp_cw,
                                      L"RefreshTimeout",
                                      &timeout)))
            timeout = MW_REFRESH_TIMEOUT;
        khc_close_space(csp_cw);
    } else
        timeout = MW_REFRESH_TIMEOUT;

    timeout *= 1000;            /* convert to milliseconds */

    SetTimer(hwnd, MW_REFRESH_TIMER, timeout, NULL);
}

LRESULT CALLBACK khm_main_wnd_proc(
    HWND hwnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam
    ) 
{
    LPNMHDR lpnm;

    switch(uMsg) {
    case WM_CREATE:
        khm_create_main_window_controls(hwnd);
        kmq_subscribe_hwnd(KMSG_CRED, hwnd);
        kmq_subscribe_hwnd(KMSG_ACT, hwnd);
        kmq_subscribe_hwnd(KMSG_KMM, hwnd);
        mw_restart_refresh_timer(hwnd);

        if (!kmm_load_pending())
            kmq_post_message(KMSG_ACT, KMSG_ACT_BEGIN_CMDLINE, 0, 0);
        break;

    case WM_DESTROY:
        kmq_unsubscribe_hwnd(KMSG_ACT, hwnd);
        kmq_unsubscribe_hwnd(KMSG_CRED, hwnd);
        HtmlHelp(NULL, NULL, HH_CLOSE_ALL, 0);
        PostQuitMessage(0);
        break;

    case WM_NOTIFY:
        lpnm = (LPNMHDR) lParam;
        if(lpnm->hwndFrom == khui_main_menu_toolbar) {
            return khm_menu_notify_main(lpnm);
        } else if(lpnm->hwndFrom == khui_hwnd_standard_toolbar) {
            return khm_toolbar_notify(lpnm);
        } else if(lpnm->hwndFrom == khm_hwnd_rebar) {
            return khm_rebar_notify(lpnm);
        } else if(lpnm->hwndFrom == khm_hwnd_statusbar) {
            return khm_statusbar_notify(lpnm);
        }
        break;

    case WM_HELP:
        MessageBox(khm_hwnd_main, L"WM_HELP", L"Notice", MB_OK);
        break;

    case WM_COMMAND:
        switch(LOWORD(wParam)) {
            /* general actions */
        case KHUI_ACTION_VIEW_REFRESH:
            khm_cred_refresh();
            InvalidateRect(khm_hwnd_main_cred, NULL, FALSE);
            return 0;

        case KHUI_ACTION_PASSWD_ID:
            khm_cred_change_password(NULL);
            return 0;

        case KHUI_ACTION_NEW_CRED:
            khm_cred_obtain_new_creds(NULL);
            return 0;

        case KHUI_ACTION_RENEW_CRED:
            khm_cred_renew_creds();
            return 0;

        case KHUI_ACTION_DESTROY_CRED:
            khm_cred_destroy_creds();
            return 0;

        case KHUI_ACTION_SET_DEF_ID:
            khm_cred_set_default();
            return 0;

        case KHUI_ACTION_EXIT:
            DestroyWindow(hwnd);
            break;

        case KHUI_ACTION_OPEN_APP:
            khm_show_main_window();
            break;

        case KHUI_ACTION_CLOSE_APP:
            khm_hide_main_window();
            break;

        case KHUI_ACTION_OPT_KHIM:
            khm_show_config_pane(NULL);
            break;

        case KHUI_ACTION_OPT_IDENTS: {
            khui_config_node node;

            khui_cfg_open(NULL, L"KhmIdentities", &node);
            khm_show_config_pane(node);
        }
            break;

        case KHUI_ACTION_OPT_NOTIF: {
            khui_config_node node;

            khui_cfg_open(NULL, L"KhmNotifications", &node);
            khm_show_config_pane(node);
        }
            break;

        case KHUI_ACTION_HELP_CTX:
            HtmlHelp(khm_hwnd_main, NIDM_HELPFILE,
                     HH_HELP_CONTEXT, IDH_WELCOME);
            break;

        case KHUI_ACTION_HELP_CONTENTS:
            HtmlHelp(khm_hwnd_main, NIDM_HELPFILE,
                     HH_DISPLAY_TOC, 0);
            break;

        case KHUI_ACTION_HELP_INDEX:
            HtmlHelp(khm_hwnd_main, NIDM_HELPFILE,
                     HH_DISPLAY_INDEX, (DWORD_PTR) L"");
            break;

        case KHUI_ACTION_HELP_ABOUT:
            khm_create_about_window();
            break;

        case KHUI_ACTION_PROPERTIES:
            /* properties are not handled by the main window.
               Just bounce it to credwnd.  However, use SendMessage
               instead of PostMessage so we don't lose context */
            return SendMessage(khm_hwnd_main_cred, uMsg, 
                               wParam, lParam);

            /* menu commands */
        case KHUI_PACTION_MENU:
            if(HIWORD(lParam) == 1)
                mm_last_hot_item = LOWORD(lParam);
            return khm_menu_activate(MENU_ACTIVATE_DEFAULT);

            /* generic, retargetting */
        case KHUI_PACTION_UP:
        case KHUI_PACTION_UP_TOGGLE:
        case KHUI_PACTION_UP_EXTEND:
        case KHUI_PACTION_DOWN:
        case KHUI_PACTION_DOWN_TOGGLE:
        case KHUI_PACTION_DOWN_EXTEND:
        case KHUI_PACTION_LEFT:
        case KHUI_PACTION_RIGHT:
        case KHUI_PACTION_ESC:
        case KHUI_PACTION_ENTER:
            /* menu tracking */
            if(mm_last_hot_item != -1) {
                switch(LOWORD(wParam)) {
                case KHUI_PACTION_LEFT:
                    khm_menu_activate(MENU_ACTIVATE_LEFT);
                    break;

                case KHUI_PACTION_RIGHT:
                    khm_menu_activate(MENU_ACTIVATE_RIGHT);
                    break;

                case KHUI_PACTION_ESC:
                case KHUI_PACTION_ENTER:
                    khm_menu_activate(MENU_ACTIVATE_NONE);
                    break;

                case KHUI_PACTION_DOWN:
                    khm_menu_track_current();
                    break;
                }
                return 0;
            }

            /*FALLTHROUGH*/

        case KHUI_PACTION_DELETE:

        case KHUI_PACTION_SELALL:
        case KHUI_ACTION_LAYOUT_ID:
        case KHUI_ACTION_LAYOUT_TYPE:
        case KHUI_ACTION_LAYOUT_LOC:
            /* otherwise fallthrough and bounce to the creds window */
            return SendMessage(khm_hwnd_main_cred, uMsg, 
                               wParam, lParam);
        }
        break;              /* WM_COMMAND */

    case WM_SYSCOMMAND:
        switch(wParam & 0xfff0) {
        case SC_MINIMIZE:
            khm_hide_main_window();
            return 0;

        case SC_CLOSE:
            {
                khm_handle csp_cw;
                BOOL keep_running = FALSE;

                if (KHM_SUCCEEDED(khc_open_space(NULL, L"CredWindow",
                                                 KHM_PERM_READ, &csp_cw))) {
                    khm_int32 t;

                    if (KHM_SUCCEEDED(khc_read_int32(csp_cw, L"KeepRunning", 
                                                     &t)))
                        keep_running = t;
#ifdef DEBUG
                    else
                        assert(FALSE);
#endif

                    khc_close_space(csp_cw);
                }
#ifdef DEBUG
                else
                    assert(FALSE);
#endif

                if (keep_running)
                    khm_hide_main_window();
                else
                    DestroyWindow(hwnd);
            }
            return 0;
        }
        break;

    case WM_MEASUREITEM:
        /* sent to measure the bitmaps associated with a menu item */
        if(!wParam) /* sent by menu */
            return khm_menu_measure_item(wParam, lParam);
        break;

    case WM_DRAWITEM:
        /* sent to draw a menu item */
        if(!wParam) 
            return khm_menu_draw_item(wParam, lParam);
        break;

    case WM_ERASEBKGND:
        /* Don't erase the background.  The whole client area is
           covered with children.  It doesn't need to be erased */
        return TRUE;
        break;

    case WM_SIZE: 
        if(hwnd == khm_hwnd_main && 
           (wParam == SIZE_MAXIMIZED || wParam == SIZE_RESTORED)) {
            int cwidth, cheight;
            RECT r_rebar, r_status;

            cwidth = LOWORD(lParam);
            cheight = HIWORD(lParam);

            /* resize the rebar control */
            SendMessage(khm_hwnd_rebar, WM_SIZE, 0, 0);

            khm_update_statusbar(hwnd);
            
            GetWindowRect(khm_hwnd_rebar, &r_rebar);
            GetWindowRect(khm_hwnd_statusbar, &r_status);

            /* the cred window fills the area between the rebar
               and the status bar */
            MoveWindow(khm_hwnd_main_cred, 0, 
                       r_rebar.bottom - r_rebar.top, 
                       r_status.right - r_status.left, 
                       r_status.top - r_rebar.bottom, TRUE);

            SetTimer(hwnd,
                     MW_RESIZE_TIMER,
                     MW_RESIZE_TIMEOUT,
                     NULL);
            return 0;
        }
        break;

    case WM_MOVE:
        {
            SetTimer(hwnd,
                     MW_RESIZE_TIMER,
                     MW_RESIZE_TIMEOUT,
                     NULL);
        }
        break;

    case WM_TIMER:
        if (wParam == MW_RESIZE_TIMER) {
            RECT r;
            khm_handle csp_cw;
            khm_handle csp_mw;

            KillTimer(hwnd, wParam);

            GetWindowRect(hwnd, &r);

            if (KHM_SUCCEEDED(khc_open_space(NULL,
                                             L"CredWindow",
                                             KHM_PERM_WRITE,
                                             &csp_cw))) {
                if (KHM_SUCCEEDED(khc_open_space(csp_cw,
                                                 L"Windows\\Main",
                                                 KHM_PERM_WRITE,
                                                 &csp_mw))) {
                    khc_write_int32(csp_mw, L"XPos", r.left);
                    khc_write_int32(csp_mw, L"YPos", r.top);
                    khc_write_int32(csp_mw, L"Width",
                                    r.right - r.left);
                    khc_write_int32(csp_mw, L"Height",
                                    r.bottom - r.top);

                    khc_close_space(csp_mw);
                }
                khc_close_space(csp_cw);
            }
        } else if (wParam == MW_REFRESH_TIMER) {
            kmq_post_message(KMSG_CRED, KMSG_CRED_REFRESH, 0, 0);
        }
        break;

    case WM_MENUSELECT:
        return khm_menu_handle_select(wParam, lParam);
        break;

    case KMQ_WM_DISPATCH:
        {
            kmq_message * m;
            khm_int32 rv = KHM_ERROR_SUCCESS;

            kmq_wm_begin(lParam, &m);
            if (m->type == KMSG_ACT &&
                m->subtype == KMSG_ACT_REFRESH) {
                khm_update_standard_toolbar();
            } else if (m->type == KMSG_ACT &&
                       m->subtype == KMSG_ACT_BEGIN_CMDLINE) {
                khm_cred_begin_commandline();
            } else if (m->type == KMSG_CRED &&
                  m->subtype == KMSG_CRED_REFRESH) {
                mw_restart_refresh_timer(hwnd);
            } else if (m->type == KMSG_CRED &&
                       m->subtype == KMSG_CRED_ADDR_CHANGE) {
                khm_cred_addr_change();
            } else if (m->type == KMSG_KMM &&
                       m->subtype == KMSG_KMM_I_DONE) {
                kmq_post_message(KMSG_ACT, KMSG_ACT_BEGIN_CMDLINE, 0, 0);
            }
            return kmq_wm_end(m, rv);
        }
        break;

    case WM_KHUI_ASSIGN_COMMANDLINE:
        {
            HANDLE hmap;
            void * xfer;
            wchar_t mapname[256];

            StringCbPrintf(mapname, sizeof(mapname),
                           COMMANDLINE_MAP_FMT, (DWORD) lParam);

            hmap = OpenFileMapping(FILE_MAP_READ, FALSE, mapname);

            if (hmap == NULL)
                return 1;

            xfer = MapViewOfFile(hmap, FILE_MAP_READ, 0, 0,
                                 sizeof(khm_startup));

            if (xfer) {
                memcpy(&khm_startup, xfer, sizeof(khm_startup));

                UnmapViewOfFile(xfer);
            }

            CloseHandle(hmap);

            if(InSendMessage())
                ReplyMessage(0);

            khm_startup.exit = FALSE;

            khm_startup.seen = FALSE;
            khm_startup.processing = FALSE;

            khm_cred_begin_commandline();
        }
        break;
    }
    return DefWindowProc(hwnd,uMsg,wParam,lParam);
}

LRESULT CALLBACK khm_null_wnd_proc(
    HWND hwnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam
    ) {
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT khm_rebar_notify(LPNMHDR lpnm) {
    switch(lpnm->code) {
#if (_WIN32_WINNT >= 0x0501)
    case RBN_AUTOBREAK:
        {
            LPNMREBARAUTOBREAK lpra = (LPNMREBARAUTOBREAK) lpnm;
            lpra->fAutoBreak = TRUE;
        }
        break;
#endif
    case RBN_BEGINDRAG:
        {
            LPNMREBAR lprb = (LPNMREBAR) lpnm;
            if ((lprb->dwMask & RBNM_ID) &&
                lprb->wID == 0)
                return 1;
            else
                return 0;
        }
        break;

    case NM_CUSTOMDRAW:
        return CDRF_DODEFAULT;
        break;
    }

    return 1;
}

void khm_create_main_window_controls(HWND hwnd_main) {
    REBARINFO rbi;
    HWND hwRebar;

    hwRebar = 
        CreateWindowEx(WS_EX_TOOLWINDOW,
                       REBARCLASSNAME,
                       L"Rebar",
                       WS_CHILD | 
                       WS_VISIBLE| 
                       WS_CLIPSIBLINGS | 
                       WS_CLIPCHILDREN |
                       CCS_NODIVIDER |
                       RBS_VARHEIGHT |
                       RBS_FIXEDORDER,
                       0,0,0,0,
                       hwnd_main,
                       NULL,
                       khm_hInstance,
                       NULL);

    if(!hwRebar) {
        DWORD dwe = GetLastError();
        return;
    }

    khm_hwnd_rebar = hwRebar;

    rbi.cbSize = sizeof(rbi);
    rbi.fMask = 0;
    rbi.himl = (HIMAGELIST) NULL;
    if(!SendMessage(hwRebar, RB_SETBARINFO, 0, (LPARAM) &rbi))
        return;

    /* self attach */
    khm_menu_create_main(hwRebar);
    khm_create_standard_toolbar(hwRebar);
    khm_create_statusbar(hwnd_main);

    /* manual attach */
    khm_hwnd_main_cred = khm_create_credwnd(hwnd_main);
}

void khm_create_main_window(void) {
    wchar_t buf[1024];
    khm_handle csp_cw = NULL;
    khm_handle csp_mw = NULL;
    int x,y,width,height;

    LoadString(khm_hInstance, IDS_MAIN_WINDOW_TITLE, 
               buf, ARRAYLENGTH(buf));

    khm_hwnd_null =
        CreateWindow(MAKEINTATOM(khm_null_window_class),
                     buf,
                     0,         /* Style */
                     0, 0,      /* x, y */
                     100, 100,  /* width, height */
                     NULL,      /* parent */
                     NULL,      /* menu */
                     NULL,      /* HINSTANCE */
                     0);        /* lparam */

    if (!khm_hwnd_null)
        return;

    x = CW_USEDEFAULT;
    y = CW_USEDEFAULT;
    width = CW_USEDEFAULT;
    height = CW_USEDEFAULT;

    if (KHM_SUCCEEDED(khc_open_space(NULL, L"CredWindow",
                                     KHM_PERM_READ,
                                     &csp_cw))) {
        if (KHM_SUCCEEDED(khc_open_space(csp_cw,
                                         L"Windows\\Main",
                                         KHM_PERM_READ,
                                         &csp_mw))) {
            khm_int32 t;

            if (KHM_SUCCEEDED(khc_read_int32(csp_mw, L"XPos", &t)))
                x = t;
            if (KHM_SUCCEEDED(khc_read_int32(csp_mw, L"YPos", &t)))
                y = t;
            if (KHM_SUCCEEDED(khc_read_int32(csp_mw, L"Width", &t)))
                width = t;
            if (KHM_SUCCEEDED(khc_read_int32(csp_mw, L"Height", &t)))
                height = t;

            khc_close_space(csp_mw);
        }
        khc_close_space(csp_cw);
    }

    khm_hwnd_main = 
        CreateWindowEx(WS_EX_OVERLAPPEDWINDOW,
                       MAKEINTATOM(khm_main_window_class),
                       buf,
                       WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | 
                       WS_CLIPSIBLINGS,
                       x, y, width, height,
                       khm_hwnd_null,
                       NULL,
                       NULL,
                       NULL);

}

void khm_show_main_window(void) {

    if (khm_nCmdShow == SW_RESTORE) {
        HWND hw;

        hw = GetForegroundWindow();
        if (hw != khm_hwnd_main)
            SetForegroundWindow(khm_hwnd_main);
    }

    if (khm_nCmdShow == SW_SHOWMINIMIZED ||
        khm_nCmdShow == SW_SHOWMINNOACTIVE ||
        khm_nCmdShow == SW_MINIMIZE) {
        khm_hide_main_window();
    } else {
        ShowWindow(khm_hwnd_main, khm_nCmdShow);
        UpdateWindow(khm_hwnd_main);
    }

    khm_nCmdShow = SW_RESTORE;
}

void khm_hide_main_window(void) {
    khm_handle csp_notices = NULL;
    khm_int32 show_warning = FALSE;

    if (khm_nCmdShow != SW_MINIMIZE &&
        KHM_SUCCEEDED(khc_open_space(NULL, L"CredWindow\\Notices",
                                     KHM_PERM_WRITE, &csp_notices)) &&
        KHM_SUCCEEDED(khc_read_int32(csp_notices, L"MinimizeWarning",
                                     &show_warning)) &&
        show_warning != 0) {

        khui_alert * alert;
        wchar_t title[KHUI_MAXCCH_TITLE];
        wchar_t msg[KHUI_MAXCCH_MESSAGE];

        LoadString(khm_hInstance, IDS_WARN_WM_TITLE,
                   title, ARRAYLENGTH(title));
        LoadString(khm_hInstance, IDS_WARN_WM_MSG,
                   msg, ARRAYLENGTH(msg));

        khui_alert_create_simple(title, msg, KHERR_INFO, &alert);
        khui_alert_set_flags(alert, KHUI_ALERT_FLAG_REQUEST_BALLOON,
                             KHUI_ALERT_FLAG_REQUEST_BALLOON);

        khui_alert_show(alert);

        khc_write_int32(csp_notices, L"MinimizeWarning", 0);
    }

    if (csp_notices != NULL)
        khc_close_space(csp_notices);

    ShowWindow(khm_hwnd_main, SW_HIDE);
}

BOOL khm_is_main_window_visible(void) {
    return IsWindowVisible(khm_hwnd_main);
}

BOOL khm_is_main_window_active(void) {
    if (!IsWindowVisible(khm_hwnd_main))
        return FALSE;
    if (GetForegroundWindow() == khm_hwnd_main)
        return TRUE;
    return khm_is_dialog_active();
}

void khm_register_main_wnd_class(void) {
    WNDCLASSEX wc;

    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = 0;
    wc.lpfnWndProc = khm_null_wnd_proc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = khm_hInstance;
    wc.hIcon = LoadIcon(khm_hInstance, MAKEINTRESOURCE(IDI_MAIN_APP));
    wc.hCursor = LoadCursor((HINSTANCE) NULL, MAKEINTRESOURCE(IDC_ARROW));
    wc.hIconSm = LoadImage(khm_hInstance, MAKEINTRESOURCE(IDI_MAIN_APP), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE);
    wc.hbrBackground = (HBRUSH) (COLOR_APPWORKSPACE);
    wc.lpszMenuName = NULL;
    wc.lpszClassName = KHUI_NULL_WINDOW_CLASS;

    khm_null_window_class = RegisterClassEx(&wc);


    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_DBLCLKS | CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = khm_main_wnd_proc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = khm_hInstance;
    wc.hIcon = LoadIcon(khm_hInstance, MAKEINTRESOURCE(IDI_MAIN_APP));
    wc.hCursor = LoadCursor((HINSTANCE) NULL, MAKEINTRESOURCE(IDC_ARROW));
    wc.hIconSm = LoadImage(khm_hInstance, MAKEINTRESOURCE(IDI_MAIN_APP), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE);
    wc.hbrBackground = (HBRUSH) (COLOR_APPWORKSPACE);
    wc.lpszMenuName = NULL;
    wc.lpszClassName = KHUI_MAIN_WINDOW_CLASS;

    khm_main_window_class = RegisterClassEx(&wc);
}

void khm_unregister_main_wnd_class(void) {
    UnregisterClass(MAKEINTATOM(khm_main_window_class),khm_hInstance);
    UnregisterClass(MAKEINTATOM(khm_null_window_class),khm_hInstance);
}

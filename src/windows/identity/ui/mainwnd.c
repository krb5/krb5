/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
 * Copyright (c) 2007 Secure Endpoints Inc.
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
#include<intaction.h>
#include<assert.h>

ATOM khm_main_window_class;
ATOM khm_null_window_class;
HWND khm_hwnd_null;
HWND khm_hwnd_main;
HWND khm_hwnd_rebar;
HWND khm_hwnd_main_cred;

int  khm_main_wnd_mode = KHM_MAIN_WND_NORMAL;

#define MW_RESIZE_TIMER 1
#define MW_RESIZE_TIMEOUT 2000
#define MW_REFRESH_TIMER 2
#define MW_REFRESH_TIMEOUT 600

void
khm_set_dialog_result(HWND hwnd, LRESULT lr) {
#pragma warning(push)
#pragma warning(disable: 4244)
    SetWindowLongPtr(hwnd, DWLP_MSGRESULT, lr);
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
    } else {
        timeout = MW_REFRESH_TIMEOUT;
    }

    timeout *= 1000;            /* convert to milliseconds */

    SetTimer(hwnd, MW_REFRESH_TIMER, timeout, NULL);
}

khm_int32 KHMAPI
mw_select_cred(khm_handle cred, void * rock) {
    if (cred)
        kcdb_cred_set_flags(cred,
                            KCDB_CRED_FLAG_SELECTED,
                            KCDB_CRED_FLAG_SELECTED);

    return KHM_ERROR_SUCCESS;
}

/* perform shutdown operations */
static void
khm_pre_shutdown(void) {
    khm_handle csp_cw = NULL;
    khm_handle credset = NULL;
    khm_int32 t;
    khm_size s;

    /* Check if we should destroy all credentials on exit... */

    if (KHM_FAILED(khc_open_space(NULL, L"CredWindow", 0, &csp_cw)))
        return;

    if (KHM_FAILED(khc_read_int32(csp_cw, L"DestroyCredsOnExit", &t)) ||
        !t)
        goto _cleanup;

    if (KHM_FAILED(kcdb_credset_create(&credset)))
        goto _cleanup;

    if (KHM_FAILED(kcdb_credset_extract(credset, NULL, NULL,
                                        KCDB_TYPE_INVALID)))
        goto _cleanup;

    if (KHM_FAILED(kcdb_credset_get_size(credset, &s)) ||
        s == 0)
        goto _cleanup;

    kcdb_credset_apply(credset, mw_select_cred, NULL);

    khui_context_set(KHUI_SCOPE_GROUP,
                     NULL,
                     KCDB_CREDTYPE_INVALID,
                     NULL,
                     NULL,
                     0,
                     credset);

    khm_cred_destroy_creds(TRUE, TRUE);

 _cleanup:

    if (credset)
        kcdb_credset_delete(credset);

    if (csp_cw)
        khc_close_space(csp_cw);
}

void
khm_process_query_app_ver(khm_query_app_version * papp_ver) {

    if (!papp_ver || papp_ver->magic != KHM_QUERY_APP_VER_MAGIC)
        return;

    papp_ver->ver_remote = app_version;

    /* the remote instance has requested swapping in.  we check the
       version numbers and if the remote instance is newer than us,
       then we exit and let the remote instance take over. */
    if (papp_ver->request_swap) {
        khm_version ver_caller = papp_ver->ver_caller;

        if (ver_caller.major >   app_version.major ||

            (ver_caller.major == app_version.major &&
             ver_caller.minor >  app_version.minor) ||

            (ver_caller.major == app_version.major &&
             ver_caller.minor == app_version.minor &&
             ver_caller.aux >    app_version.aux) ||

            (ver_caller.major == app_version.major &&
             ver_caller.minor == app_version.minor &&
             ver_caller.aux ==   app_version.aux &&
             ver_caller.patch >  app_version.patch)) {

            papp_ver->request_swap = TRUE;

            if (khm_hwnd_main)
                DestroyWindow(khm_hwnd_main);

        } else {

            papp_ver->request_swap = FALSE;

        }
    }

    papp_ver->code = KHM_ERROR_SUCCESS;
}

static void
khm_ui_cb(LPARAM lParam) {
    khui_ui_callback_data * pcbdata;

    pcbdata = (khui_ui_callback_data *) lParam;

    if (pcbdata == NULL || pcbdata->magic != KHUI_UICBDATA_MAGIC) {
#ifdef DEBUG
        assert(FALSE);
#endif
        return;
    }

#ifdef DEBUG
    assert(pcbdata->cb);
#endif

    /* make the call */
    if (!IsBadCodePtr(pcbdata->cb))
        pcbdata->rv = (*pcbdata->cb)(khm_hwnd_main, pcbdata->rock);
    else {
#ifdef DEBUG
        assert(FALSE);
#endif
        pcbdata->rv = KHM_ERROR_INVALID_PARAM;
    }
}

LRESULT CALLBACK 
khm_main_wnd_proc(HWND hwnd,
                  UINT uMsg,
                  WPARAM wParam,
                  LPARAM lParam) 
{
    LPNMHDR lpnm;

    switch(uMsg) {
    case WM_CREATE:
        khm_create_main_window_controls(hwnd);
        kmq_subscribe_hwnd(KMSG_CRED, hwnd);
        kmq_subscribe_hwnd(KMSG_ACT, hwnd);
        kmq_subscribe_hwnd(KMSG_KMM, hwnd);
        mw_restart_refresh_timer(hwnd);

        /* if the plug-ins finished loading before the window was
           created, we would have missed the KMSG_KMM_I_DONE message.
           So we check if the module load is complete and if so, fire
           off KMSG_ACT_BEGIN_CMDLINE. */
        if (!kmm_load_pending())
            kmq_post_message(KMSG_ACT, KMSG_ACT_BEGIN_CMDLINE, 0, 0);
        break;

    case WM_DESTROY:
        khm_pre_shutdown();
        kmq_unsubscribe_hwnd(KMSG_ACT, hwnd);
        kmq_unsubscribe_hwnd(KMSG_CRED, hwnd);
        kmq_unsubscribe_hwnd(KMSG_KMM, hwnd);
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
        khm_html_help(khm_hwnd_main, NULL, HH_HELP_CONTEXT, IDH_WELCOME);
        break;

    case WM_COMMAND:
        switch(LOWORD(wParam)) {
            /* general actions */
        case KHUI_ACTION_VIEW_REFRESH:
            khm_cred_refresh();
            InvalidateRect(khm_hwnd_main_cred, NULL, FALSE);
            return 0;

        case KHUI_ACTION_PASSWD_ID:
            if (khm_startup.processing)
                return 0;

            khm_cred_change_password(NULL);
            return 0;

        case KHUI_ACTION_NEW_CRED:
            if (khm_startup.processing)
                return 0;

            khm_cred_obtain_new_creds(NULL);
            return 0;

        case KHUI_ACTION_RENEW_CRED:
            if (khm_startup.processing)
                return 0;

            khm_cred_renew_creds();
            return 0;

        case KHUI_ACTION_DESTROY_CRED:
            if (khm_startup.processing)
                return 0;

            khm_cred_destroy_creds(FALSE, FALSE);
            return 0;

        case KHUI_ACTION_SET_DEF_ID:
            if (khm_startup.processing)
                return 0;

            khm_cred_set_default();
            return 0;

        case KHUI_ACTION_EXIT:
            DestroyWindow(hwnd);
            return 0;

        case KHUI_ACTION_OPEN_APP:
            khm_show_main_window();
            return 0;

        case KHUI_ACTION_CLOSE_APP:
            khm_hide_main_window();
            return 0;

        case KHUI_ACTION_OPT_KHIM: {
            khui_config_node node = NULL;

            khui_cfg_open(NULL, L"KhmGeneral", &node);
            khm_show_config_pane(node);
        }
            return 0;

        case KHUI_ACTION_OPT_IDENTS: {
            khui_config_node node = NULL;

            khui_cfg_open(NULL, L"KhmIdentities", &node);
            khm_show_config_pane(node);
        }
            return 0;

        case KHUI_ACTION_OPT_APPEAR: {
            khui_config_node node = NULL;

            khui_cfg_open(NULL, L"KhmAppear", &node);
            khm_show_config_pane(node);
        }
            return 0;

        case KHUI_ACTION_OPT_NOTIF: {
            khui_config_node node = NULL;

            khui_cfg_open(NULL, L"KhmNotifications", &node);
            khm_show_config_pane(node);
        }
            return 0;

        case KHUI_ACTION_OPT_PLUGINS: {
            khui_config_node node = NULL;

            khui_cfg_open(NULL, L"KhmPlugins", &node);
            khm_show_config_pane(node);
        }
            return 0;

        case KHUI_ACTION_HELP_CTX:
            khm_html_help(khm_hwnd_main, NULL, HH_HELP_CONTEXT, IDH_WELCOME);
            return 0;

        case KHUI_ACTION_HELP_CONTENTS:
            khm_html_help(khm_hwnd_main, NULL, HH_DISPLAY_TOC, 0);
            return 0;

        case KHUI_ACTION_HELP_INDEX:
            khm_html_help(khm_hwnd_main, NULL, HH_DISPLAY_INDEX, (DWORD_PTR) L"");
            return 0;

        case KHUI_ACTION_HELP_ABOUT:
            khm_create_about_window();
            return 0;

        case KHUI_ACTION_IMPORT:
            khm_cred_import();
            return 0;

        case KHUI_ACTION_PROPERTIES:
            /* properties are not handled by the main window.
               Just bounce it to credwnd.  However, use SendMessage
               instead of PostMessage so we don't lose context */
            return SendMessage(khm_hwnd_main_cred, uMsg, 
                               wParam, lParam);

        case KHUI_ACTION_UICB:
            khm_ui_cb(lParam);
            return 0;

            /* layout control */
        case KHUI_ACTION_LAYOUT_MINI:
            if (khm_main_wnd_mode == KHM_MAIN_WND_MINI) {
                khm_set_main_window_mode(KHM_MAIN_WND_NORMAL);
            } else {
                khm_set_main_window_mode(KHM_MAIN_WND_MINI);
            }
            return SendMessage(khm_hwnd_main_cred, uMsg, 
                               wParam, lParam);

        case KHUI_ACTION_LAYOUT_RELOAD:
            return SendMessage(khm_hwnd_main_cred, uMsg, 
                               wParam, lParam);

        case KHUI_ACTION_LAYOUT_ID:
        case KHUI_ACTION_LAYOUT_TYPE:
        case KHUI_ACTION_LAYOUT_LOC:
        case KHUI_ACTION_LAYOUT_CUST:
            khm_set_main_window_mode(KHM_MAIN_WND_NORMAL);
            return SendMessage(khm_hwnd_main_cred, uMsg, 
                               wParam, lParam);

            /* menu commands */
        case KHUI_PACTION_MENU:
            if(HIWORD(lParam) == 1)
                mm_last_hot_item = LOWORD(lParam);
            return khm_menu_activate(MENU_ACTIVATE_DEFAULT);

        case KHUI_PACTION_ESC:
            /* if esc is pressed while no menu is active, we close the
               main window */
            if (mm_last_hot_item == -1) {
                khm_close_main_window();
                return 0;
            }

            /* generic, retargetting */
        case KHUI_PACTION_UP:
        case KHUI_PACTION_UP_TOGGLE:
        case KHUI_PACTION_UP_EXTEND:
        case KHUI_PACTION_PGUP:
        case KHUI_PACTION_PGUP_EXTEND:
        case KHUI_PACTION_DOWN:
        case KHUI_PACTION_DOWN_TOGGLE:
        case KHUI_PACTION_DOWN_EXTEND:
        case KHUI_PACTION_PGDN:
        case KHUI_PACTION_PGDN_EXTEND:
        case KHUI_PACTION_LEFT:
        case KHUI_PACTION_RIGHT:
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
            /* otherwise fallthrough and bounce to the creds window */
            return SendMessage(khm_hwnd_main_cred, uMsg, 
                               wParam, lParam);

        default:
            /* handle custom actions here */
            {
                khui_action * act;

                /* check if this is an identity menu action.  (custom
                   actions that were created for renewing or
                   destroying specific identities). */
                if (khm_check_identity_menu_action(LOWORD(wParam)))
                    break;

                act = khui_find_action(LOWORD(wParam));
                if (act && act->listener) {
                    kmq_post_sub_msg(act->listener, KMSG_ACT, KMSG_ACT_ACTIVATE, act->cmd, NULL);
                    return 0;
                }
            }
        }
        break;              /* WM_COMMAND */

    case WM_SYSCOMMAND:
        switch(wParam & 0xfff0) {
        case SC_MINIMIZE:
            khm_hide_main_window();
            return 0;

        case SC_CLOSE:
            khm_close_main_window();
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

            return 0;
        }
        break;

    case WM_MOVING:
        {
            RECT * r;

            r = (RECT *) lParam;
            khm_adjust_window_dimensions_for_display(r,
                                                     KHM_DOCK_AUTO | KHM_DOCKF_XBORDER);
        }
        return TRUE;

    case WM_TIMER:
        if (wParam == MW_RESIZE_TIMER) {
            RECT r;
            khm_handle csp_cw;
            khm_handle csp_mw;
            const wchar_t * wconfig;

            if (khm_main_wnd_mode == KHM_MAIN_WND_MINI)
                wconfig = L"Windows\\MainMini";
            else
                wconfig = L"Windows\\Main";

            KillTimer(hwnd, wParam);

            GetWindowRect(hwnd, &r);

            if (KHM_SUCCEEDED(khc_open_space(NULL,
                                             L"CredWindow",
                                             KHM_PERM_WRITE,
                                             &csp_cw))) {
                if (KHM_SUCCEEDED(khc_open_space(csp_cw,
                                                 wconfig,
                                                 KHM_PERM_WRITE,
                                                 &csp_mw))) {
                    khm_int32 t;

                    khc_write_int32(csp_mw, L"XPos", r.left);
                    khc_write_int32(csp_mw, L"YPos", r.top);
                    khc_write_int32(csp_mw, L"Width",
                                    r.right - r.left);
                    khc_write_int32(csp_mw, L"Height",
                                    r.bottom - r.top);

                    if (KHM_SUCCEEDED(khc_read_int32(csp_mw, L"Dock", &t)) &&
                        t != KHM_DOCK_NONE) {
                        khc_write_int32(csp_mw, L"Dock", KHM_DOCK_AUTO);
                    }

                    khc_close_space(csp_mw);
                }
                khc_close_space(csp_cw);
            }

            return 0;

        } else if (wParam == MW_REFRESH_TIMER) {
            kmq_post_message(KMSG_CRED, KMSG_CRED_REFRESH, 0, 0);

            return 0;

        }
        break;

    case WM_MENUSELECT:
        return khm_menu_handle_select(wParam, lParam);

    case KMQ_WM_DISPATCH:
        {
            kmq_message * m;
            khm_int32 rv = KHM_ERROR_SUCCESS;

            kmq_wm_begin(lParam, &m);
            if (m->type == KMSG_ACT &&
                m->subtype == KMSG_ACT_REFRESH) {
                khm_menu_refresh_items();
                khm_update_standard_toolbar();
            } else if (m->type == KMSG_ACT &&
                       m->subtype == KMSG_ACT_BEGIN_CMDLINE) {
                khm_cred_begin_startup_actions();
            } else if (m->type == KMSG_ACT &&
                       m->subtype == KMSG_ACT_CONTINUE_CMDLINE) {
                khm_cred_process_startup_actions();
            } else if (m->type == KMSG_ACT &&
                       m->subtype == KMSG_ACT_END_CMDLINE) {
                /* nothing yet */
            } else if (m->type == KMSG_ACT &&
                       m->subtype == KMSG_ACT_SYNC_CFG) {
                khm_refresh_config();
            } else if (m->type == KMSG_ACT &&
                       m->subtype == KMSG_ACT_ACTIVATE) {
                /* some custom action fired */

                khm_int32 action;
                khui_action * paction;

                action = m->uparam;
                paction = khui_find_action(action);
                if (paction && paction->data == (void *) CFGACTION_MAGIC) {
                    /* a custom configuration needs to be invoked */
                    khui_config_node node;

                    if (KHM_SUCCEEDED(khui_cfg_open(NULL, paction->name, &node))) {
                        khm_show_config_pane(node);
                        khui_cfg_release(node);
                    }
                }
            } else if (m->type == KMSG_CRED &&
                  m->subtype == KMSG_CRED_REFRESH) {
                mw_restart_refresh_timer(hwnd);
            } else if (m->type == KMSG_CRED &&
                       m->subtype == KMSG_CRED_ADDR_CHANGE) {
                khm_cred_addr_change();
            } else if (m->type == KMSG_CRED &&
                       m->subtype == KMSG_CRED_ROOTDELTA) {
                khm_refresh_identity_menus();
            } else if (m->type == KMSG_KMM &&
                       m->subtype == KMSG_KMM_I_DONE) {
                kmq_post_message(KMSG_ACT, KMSG_ACT_BEGIN_CMDLINE, 0, 0);
            }

            return kmq_wm_end(m, rv);
        }
        return 0;

    case WM_KHUI_ASSIGN_COMMANDLINE_V1:
        {
            HANDLE hmap;
            void * xfer;
            wchar_t mapname[256];
            struct tag_khm_startup_options_v1 * pv1opt;
            int code = KHM_ERROR_SUCCESS;

            StringCbPrintf(mapname, sizeof(mapname),
                           COMMANDLINE_MAP_FMT, (DWORD) lParam);

            hmap = OpenFileMapping(FILE_MAP_READ, FALSE, mapname);

            if (hmap == NULL)
                return 1;

            xfer = MapViewOfFile(hmap, FILE_MAP_READ, 0, 0,
                                 sizeof(*pv1opt));

            if (xfer) {
                pv1opt = (struct tag_khm_startup_options_v1 *) xfer;

                khm_startup.init = pv1opt->init;
                khm_startup.import = pv1opt->import;
                khm_startup.renew = pv1opt->renew;
                khm_startup.destroy = pv1opt->destroy;

                khm_startup.autoinit = pv1opt->autoinit;
                khm_startup.error_exit = FALSE;

                khm_startup.no_main_window = FALSE;
                khm_startup.remote_exit = FALSE;

                UnmapViewOfFile(xfer);
            } else {
                code = KHM_ERROR_NOT_FOUND;
            }

            CloseHandle(hmap);

            if(InSendMessage())
                ReplyMessage(code);

            if (code == KHM_ERROR_SUCCESS) {
                khm_startup.exit = FALSE;

                khm_startup.seen = FALSE;
                khm_startup.remote = TRUE;
#ifdef DEBUG
                assert(!khm_startup.processing);
#endif
                khm_startup.processing = FALSE;

                khm_cred_begin_startup_actions();
            }

            return code;
        }

    case WM_KHUI_ASSIGN_COMMANDLINE_V2:
        {
            HANDLE hmap;
            void * xfer;
            wchar_t mapname[256];
            struct tag_khm_startup_options_v2 *pv2opt;
            int code = KHM_ERROR_SUCCESS;

            StringCbPrintf(mapname, sizeof(mapname),
                           COMMANDLINE_MAP_FMT, (DWORD) lParam);

            hmap = OpenFileMapping(FILE_MAP_WRITE, FALSE, mapname);

            if (hmap == NULL)
                return 1;

            xfer = MapViewOfFile(hmap, FILE_MAP_WRITE, 0, 0,
                                 sizeof(*pv2opt));

            if (xfer) {
                pv2opt = (struct tag_khm_startup_options_v2 *) xfer;

                if (pv2opt->magic != STARTUP_OPTIONS_MAGIC ||
                    pv2opt->cb_size != sizeof(*pv2opt)) {
                    code = KHM_ERROR_INVALID_PARAM;
                    goto done_with_v2_opt;
                }

                khm_startup.init = pv2opt->init;
                khm_startup.import = pv2opt->import;
                khm_startup.renew = pv2opt->renew;
                khm_startup.destroy = pv2opt->destroy;

                khm_startup.autoinit = pv2opt->autoinit;
                khm_startup.exit = pv2opt->remote_exit;

                pv2opt->code = KHM_ERROR_SUCCESS;

            done_with_v2_opt:
                UnmapViewOfFile(xfer);
            } else {
                code = KHM_ERROR_NOT_FOUND;
            }

            CloseHandle(hmap);

            if(InSendMessage())
                ReplyMessage(code);

            if (code == KHM_ERROR_SUCCESS) {
                khm_startup.seen = FALSE;
                khm_startup.remote = TRUE;
#ifdef DEBUG
                assert(!khm_startup.processing);
#endif
                khm_startup.processing = FALSE;

                khm_cred_begin_startup_actions();
            }

            return code;
        }

    case WM_KHUI_QUERY_APP_VERSION:
        {
            HANDLE hmap;
            void * xfer;
            wchar_t mapname[256];

            StringCbPrintf(mapname, sizeof(mapname),
                           QUERY_APP_VER_MAP_FMT, (DWORD) lParam);

            hmap = OpenFileMapping(FILE_MAP_READ | FILE_MAP_WRITE,
                                   FALSE, mapname);

            if (hmap == NULL)
                return 1;

            xfer = MapViewOfFile(hmap, FILE_MAP_WRITE, 0, 0,
                                 sizeof(khm_query_app_version));
            
            if (xfer) {
                khm_process_query_app_ver((khm_query_app_version *) xfer);

                UnmapViewOfFile(xfer);
            }

            CloseHandle(hmap);
        }
        return 0;

    }
    return DefWindowProc(hwnd,uMsg,wParam,lParam);
}

LRESULT CALLBACK 
khm_null_wnd_proc(HWND hwnd,
                  UINT uMsg,
                  WPARAM wParam,
                  LPARAM lParam) {
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT 
khm_rebar_notify(LPNMHDR lpnm) {
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

void 
khm_create_main_window_controls(HWND hwnd_main) {
    REBARINFO rbi;
    HWND hwRebar;

    khm_menu_create_main(hwnd_main);

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
    khm_create_standard_toolbar(hwRebar);
    khm_create_statusbar(hwnd_main);

    /* manual attach */
    khm_hwnd_main_cred = khm_create_credwnd(hwnd_main);
}

void
khm_adjust_window_dimensions_for_display(RECT * pr, int dock) {

    HMONITOR hmon;
    RECT     rm;
    long x, y, width, height;

    x = pr->left;
    y = pr->top;
    width = pr->right - pr->left;
    height = pr->bottom - pr->top;

    /* if the rect doesn't intersect with the display area of any
       monitor, we just default to the primary monitor. */
    hmon = MonitorFromRect(pr, MONITOR_DEFAULTTOPRIMARY);

    if (hmon == NULL) {
        /* huh? we'll just center this on the primary screen */
        goto nomonitor;
    } else {
        MONITORINFO mi;

        ZeroMemory(&mi, sizeof(mi));
        mi.cbSize = sizeof(mi);

        if (!GetMonitorInfo(hmon, &mi))
            goto nomonitor;

        CopyRect(&rm, &mi.rcWork);

        goto adjust_dims;
    }

 nomonitor:
    /* for some reason we couldn't get a handle on a monitor or we
       couldn't get the metrics for that monitor.  We default to
       setting things up on the primary monitor. */

    SetRectEmpty(&rm);
    if (!SystemParametersInfo(SPI_GETWORKAREA, 0, (PVOID) &rm, 0))
        goto done_with_monitor;

 adjust_dims:

    if (width > (rm.right - rm.left))
        width = rm.right - rm.left;
    if (height > (rm.bottom - rm.top))
        height = rm.bottom - rm.top;

    switch (dock & KHM_DOCKF_DOCKHINT) {
    case KHM_DOCK_TOPLEFT:
        x = rm.left;
        y = rm.top;
        break;

    case KHM_DOCK_TOPRIGHT:
        x = rm.right - width;
        y = rm.top;
        break;

    case KHM_DOCK_BOTTOMRIGHT:
        x = rm.right - width;
        y = rm.bottom - height;
        break;

    case KHM_DOCK_BOTTOMLEFT:
        x = rm.left;
        y = rm.bottom - height;
        break;

    case KHM_DOCK_AUTO:
        {
            int cxt, cyt;

            cxt = GetSystemMetrics(SM_CXDRAG);
            cyt = GetSystemMetrics(SM_CYDRAG);

            if (x > rm.left && (x - rm.left) < cxt)
                x = rm.left;
            else if ((x + width) < rm.right && (rm.right - (x + width)) < cxt)
                x = rm.right - width;

            if (y > rm.top && (y - rm.top) < cyt)
                y = rm.top;
            else if ((y + height) < rm.bottom && (rm.bottom - (y + height)) < cyt)
                y = rm.bottom - height;
        }
        break;
    }

    if (!(dock & KHM_DOCKF_XBORDER)) {
        if (x < rm.left)
            x = rm.left;
        if (x + width > rm.right)
            x = rm.right - width;
        if (y < rm.top)
            y = rm.top;
        if (y + height > rm.bottom)
            y = rm.bottom - height;
    }

 done_with_monitor:
    pr->left = x;
    pr->top = y;
    pr->right = x + width;
    pr->bottom = y + height;

}

void
khm_get_main_window_rect(RECT * pr) {
    khm_handle csp_mw = NULL;
    int x,y,width,height,dock;
    RECT r;
    const wchar_t * wconfig;

    x = CW_USEDEFAULT;
    y = CW_USEDEFAULT;
    width = CW_USEDEFAULT;
    height = CW_USEDEFAULT;
    dock = KHM_DOCK_NONE;

    if (khm_main_wnd_mode == KHM_MAIN_WND_MINI)
        wconfig = L"CredWindow\\Windows\\MainMini";
    else
        wconfig = L"CredWindow\\Windows\\Main";

    if (KHM_SUCCEEDED(khc_open_space(NULL,
                                     wconfig,
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
        if (KHM_SUCCEEDED(khc_read_int32(csp_mw, L"Dock", &t)))
            dock = t;

        khc_close_space(csp_mw);
    }

    /* If there were no default values, we default to using 1/4 of the
       work area centered on the primary monitor.  If there were any
       docking hints, then the next call to
       khm_adjust_window_dimensions_for_display() will reposition the
       window. */
    if (width == CW_USEDEFAULT || x == CW_USEDEFAULT) {
        RECT wr;

        SetRectEmpty(&wr);
        SystemParametersInfo(SPI_GETWORKAREA, 0, &wr, 0);

        if (width == CW_USEDEFAULT) {
            width = (wr.right - wr.left) / 2;
            height = (wr.bottom - wr.top) / 2;
        }

        if (x == CW_USEDEFAULT) {
            x = (wr.left + wr.right) / 2 - width / 2;
            y = (wr.top + wr.bottom) / 2 - height / 2;
        }
    }

    /* The saved dimensions might not actually be visible if the user
       has changed the resolution of the display or if it's a multiple
       monitor system where the monitor on which the Network Identity
       Manager window was on previously is no longer connected.  We
       have to check for that and adjust the dimensions if needed. */
    SetRect(&r, x, y, x + width, y + height);
    khm_adjust_window_dimensions_for_display(&r, dock);

    *pr = r;
}

void
khm_set_main_window_mode(int mode) {

    RECT r;
    khm_handle csp_cw;

    if (mode == khm_main_wnd_mode)
        return;

    khui_check_action(KHUI_ACTION_LAYOUT_MINI,
                      ((mode == KHM_MAIN_WND_MINI)? FALSE : TRUE));
    khui_enable_action(KHUI_MENU_LAYOUT,
                       ((mode == KHM_MAIN_WND_MINI)? FALSE : TRUE));
    khui_enable_action(KHUI_MENU_COLUMNS,
                       ((mode == KHM_MAIN_WND_MINI)? FALSE : TRUE));

    khui_refresh_actions();

    khm_main_wnd_mode = mode;
    if (khm_hwnd_main) {
        khm_get_main_window_rect(&r);

        SetWindowPos(khm_hwnd_main,
                     NULL,
                     r.left, r.top,
                     r.right - r.left, r.bottom - r.top,
                     SWP_NOACTIVATE | SWP_NOOWNERZORDER |
                     SWP_NOZORDER);
    }

    if (KHM_SUCCEEDED(khc_open_space(NULL, L"CredWindow", KHM_PERM_WRITE,
                                     &csp_cw))) {

        khc_write_int32(csp_cw, L"DefaultWindowMode", mode);
        khc_close_space(csp_cw);

    }

    khm_cred_refresh();
}

void 
khm_create_main_window(void) {
    wchar_t buf[1024];
    khm_handle csp_cw = NULL;
    RECT r;

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

    if (KHM_SUCCEEDED(khc_open_space(NULL, L"CredWindow",
                                     KHM_PERM_READ,
                                     &csp_cw))) {
        khm_int32 t;

        if (KHM_SUCCEEDED(khc_read_int32(csp_cw, L"DefaultWindowMode", &t))) {
            khm_set_main_window_mode(t);
        }

        khc_close_space(csp_cw);
    }

    khm_get_main_window_rect(&r);

    khm_hwnd_main = 
        CreateWindowEx(WS_EX_OVERLAPPEDWINDOW | WS_EX_APPWINDOW,
                       MAKEINTATOM(khm_main_window_class),
                       buf,
                       WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | 
                       WS_CLIPSIBLINGS,
                       r.left, r.top,
                       r.right - r.left,
                       r.bottom - r.top,
                       khm_hwnd_null,
                       NULL,
                       NULL,
                       NULL);

    khui_set_main_window(khm_hwnd_main);
}

void 
khm_show_main_window(void) {

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

        khm_cred_refresh();
    }

    khm_nCmdShow = SW_RESTORE;
}

void
khm_activate_main_window(void) {

    if (!SetForegroundWindow(khm_hwnd_main)) {
        FLASHWINFO finfo;

        SetActiveWindow(khm_hwnd_main);

        ZeroMemory(&finfo, sizeof(finfo));
        finfo.cbSize = sizeof(finfo);
        finfo.hwnd = khm_hwnd_main;
        finfo.dwFlags = FLASHW_ALL;
        finfo.uCount = 3;
        finfo.dwTimeout = 0;

        FlashWindowEx(&finfo);
    }
}

void 
khm_close_main_window(void) {
    khm_handle csp_cw;
    BOOL keep_running = FALSE;

    if (KHM_SUCCEEDED(khc_open_space(NULL, L"CredWindow",
                                     KHM_PERM_READ, &csp_cw))) {
        khm_int32 t;

        if (KHM_SUCCEEDED(khc_read_int32(csp_cw, L"KeepRunning", 
                                         &t))) {
            keep_running = t;
        } else {
#ifdef DEBUG
            assert(FALSE);
#endif
        }

        khc_close_space(csp_cw);
    } else {
#ifdef DEBUG
        assert(FALSE);
#endif
    }

    if (keep_running)
        khm_hide_main_window();
    else
        DestroyWindow(khm_hwnd_main);
}

void 
khm_hide_main_window(void) {
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

BOOL 
khm_is_main_window_visible(void) {
    return IsWindowVisible(khm_hwnd_main);
}

BOOL 
khm_is_main_window_active(void) {
    if (!IsWindowVisible(khm_hwnd_main))
        return FALSE;
    if (GetForegroundWindow() == khm_hwnd_main)
        return TRUE;
    return khm_is_dialog_active();
}

void 
khm_register_main_wnd_class(void) {
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

void 
khm_unregister_main_wnd_class(void) {
    UnregisterClass(MAKEINTATOM(khm_main_window_class),khm_hInstance);
    UnregisterClass(MAKEINTATOM(khm_null_window_class),khm_hInstance);
}

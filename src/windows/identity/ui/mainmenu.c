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

HWND khui_main_menu_toolbar;
int mm_last_hot_item = -1;
int mm_next_hot_item = -1;
BOOL mm_hot_track = FALSE;

#define MAX_ILIST 256
/* not the same as MENU_SIZE_ICON_* */
#define ILIST_ICON_X 16
#define ILIST_ICON_Y 15

khui_ilist * il_icon;
int il_icon_id[MAX_ILIST];

void khui_init_menu(void) {
    int i;

    il_icon = khui_create_ilist(ILIST_ICON_X, 
                                ILIST_ICON_Y, 
                                MAX_ILIST, 5, 0);
    for(i=0;i<MAX_ILIST;i++)
        il_icon_id[i] = -1;
}

void khui_exit_menu(void) {
    khui_delete_ilist(il_icon);
}

int khui_get_icon_index(int id) {
    int i;
    HBITMAP hbm;

    for(i=0;i<MAX_ILIST;i++)
        if(il_icon_id[i] == id) {
            return i;
        }

    hbm = LoadImage(khm_hInstance, 
                    MAKEINTRESOURCE(id), 
                    IMAGE_BITMAP, 
                    ILIST_ICON_X, ILIST_ICON_Y, 
                    LR_DEFAULTCOLOR);
    i = khui_ilist_add_masked(il_icon, hbm, KHUI_TOOLBAR_BGCOLOR);
    il_icon_id[i] = id;
    DeleteObject(hbm);

    return i;
}

void add_action_to_menu(HMENU hm, khui_action * act, 
                        int idx, int flags) {
    MENUITEMINFO mii;
    wchar_t buf[MAX_RES_STRING] = L"";
    wchar_t accel[MAX_RES_STRING] = L"";

    assert(!act || act->cmd);

    mii.cbSize = sizeof(mii);
    mii.fMask = 0;

    if(act == NULL) {
        mii.fMask = MIIM_FTYPE;
        mii.fType = MFT_SEPARATOR;
    } else {
        khui_menu_def * def;

        if (act->caption) {
            StringCbCopy(buf, sizeof(buf), act->caption);
        } else {
            LoadString(khm_hInstance, 
                       act->is_caption, 
                       buf, ARRAYLENGTH(buf));
        }

        if(khui_get_cmd_accel_string(act->cmd, accel, 
                                     ARRAYLENGTH(accel))) {
            StringCbCat(buf, sizeof(buf), L"\t");
            StringCbCat(buf, sizeof(buf), accel);
        }

        mii.fMask = MIIM_FTYPE | MIIM_STRING | MIIM_ID;
        mii.fType = MFT_STRING;

        mii.dwTypeData = buf;
        mii.cch = (int) wcslen(buf);

        mii.wID = act->cmd;

        if(act->state & KHUI_ACTIONSTATE_DISABLED) {
            mii.fMask |= MIIM_STATE;
            mii.fState = MFS_DISABLED;
        } else {
            mii.fState = 0;
        }

        if((act->type & KHUI_ACTIONTYPE_TOGGLE) && 
           (act->state & KHUI_ACTIONSTATE_CHECKED)) {
            mii.fMask |= MIIM_STATE;
            mii.fState |= MFS_CHECKED;
        }

        if(act->ib_icon) {
            mii.fMask |= MIIM_BITMAP;
            mii.hbmpItem = HBMMENU_CALLBACK;
        }

        if (flags & KHUI_ACTIONREF_SUBMENU) {
            def = khui_find_menu(act->cmd);
            if(def) {
                mii.fMask |= MIIM_SUBMENU;
                mii.hSubMenu = mm_create_menu_from_def(def, FALSE);
            }
        }

        if(flags & KHUI_ACTIONREF_DEFAULT)
            mii.fState |= MFS_DEFAULT;
    }

    InsertMenuItem(hm,idx,TRUE,&mii);
}

static void refresh_menu(HMENU hm, khui_menu_def * def);

static void refresh_menu_item(HMENU hm, khui_action * act, 
                              int idx, int flags) {
    MENUITEMINFO mii;

    mii.cbSize = sizeof(mii);
    mii.fMask = 0;

    if (act == NULL)
        return;
    else {
        khui_menu_def * def;

        /* first check if the menu item is there.  Otherwise we need
           to add it. */
        mii.fMask = MIIM_STATE;
        if (!GetMenuItemInfo(hm, act->cmd, FALSE, &mii)) {
            /* the 1000 is fairly arbitrary, but there should be much
               less menu items on a menu anyway.  If there are that
               many items, the system would be unusable to the extent
               that the order of the items would be the least of our
               worries. */
            add_action_to_menu(hm, act, 1000, flags);
            return;
        }

        mii.fMask = 0;

        if(act->state & KHUI_ACTIONSTATE_DISABLED) {
            mii.fMask |= MIIM_STATE;
            mii.fState = MFS_DISABLED;
        } else {
            mii.fMask |= MIIM_STATE;
            mii.fState = MFS_ENABLED;
        }

        if(act->type & KHUI_ACTIONTYPE_TOGGLE) {
            mii.fMask |= MIIM_STATE;
            if (act->state & KHUI_ACTIONSTATE_CHECKED) {
                mii.fState |= MFS_CHECKED;
            } else {
                mii.fState |= MFS_UNCHECKED;
            }
        }

        SetMenuItemInfo(hm, act->cmd, FALSE, &mii);

        def = khui_find_menu(act->cmd);
        if(def) {
            MENUITEMINFO mii2;

            mii2.cbSize = sizeof(mii2);
            mii2.fMask = MIIM_SUBMENU;

            if (GetMenuItemInfo(hm, act->cmd, FALSE, &mii2)) {
                refresh_menu(mii2.hSubMenu, def);
            }
        }
    }
}

static void refresh_menu(HMENU hm, khui_menu_def * def) {
    khui_action_ref * act;
    int i;

    act = def->items;
    i = 0;
    while ((def->n_items == -1 && act->action != KHUI_MENU_END) ||
           (def->n_items >= 0 && i < (int) def->n_items)) {
        refresh_menu_item(hm, khui_find_action(act->action), i, act->flags);
        act++; i++;
    }
}

static HMENU mm_create_menu_from_def(khui_menu_def * def, BOOL main) {
    HMENU hm;
    khui_action_ref * act;
    int i;

    if (main)
        hm = CreateMenu();
    else
        hm = CreatePopupMenu();

    act = def->items;
    i = 0;
    while((!(def->state & KHUI_MENUSTATE_ALLOCD) && act->action != KHUI_MENU_END) ||
          ((def->state & KHUI_MENUSTATE_ALLOCD) && i < (int) def->n_items)) {
        add_action_to_menu(hm,khui_find_action(act->action),i,act->flags);
        act++; i++;
    }

    return hm;
}

void mm_begin_hot_track(void);
void mm_end_hot_track(void);

static void mm_show_panel_def(khui_menu_def * def, LONG x, LONG y)
{
    HMENU hm;

    hm = mm_create_menu_from_def(def, FALSE);

    mm_hot_track = (mm_last_hot_item >= 0);

    if (mm_hot_track)
        mm_begin_hot_track();

    TrackPopupMenuEx(hm, 
                     TPM_LEFTALIGN | TPM_TOPALIGN | 
                     TPM_VERPOSANIMATION, 
                     x, y, khm_hwnd_main, NULL);

    mm_last_hot_item = -1;

    if (mm_hot_track)
        mm_end_hot_track();

    mm_hot_track = FALSE;

    DestroyMenu(hm);
}

void khm_menu_show_panel(int id, LONG x, LONG y) {
    khui_menu_def * def;

    def = khui_find_menu(id);
    if(!def)
        return;

    mm_show_panel_def(def, x, y);
}

LRESULT khm_menu_activate(int menu_id) {
    khui_menu_def * mmdef;
    int nmm;

    mmdef = khui_find_menu(KHUI_MENU_MAIN);
    nmm = (int) khui_action_list_length(mmdef->items);

    if(menu_id == MENU_ACTIVATE_DEFAULT) {
        if (mm_last_hot_item != -1)
            menu_id = mm_last_hot_item;
        else
            menu_id = 0;
    } else if(menu_id == MENU_ACTIVATE_LEFT) {
        menu_id = (mm_last_hot_item > 0)? 
            mm_last_hot_item - 1: 
            ((mm_last_hot_item == 0)? nmm - 1: 0);
    } else if(menu_id == MENU_ACTIVATE_RIGHT) {
        menu_id = (mm_last_hot_item >=0 && mm_last_hot_item < nmm - 1)? 
            mm_last_hot_item + 1: 
            0;
    } else if(menu_id == MENU_ACTIVATE_NONE) {
        menu_id = -1;
    }
    
    SendMessage(khui_main_menu_toolbar,
                TB_SETHOTITEM,
                menu_id,
                0);

    khm_menu_track_current();

    return TRUE;
}

LRESULT khm_menu_measure_item(WPARAM wParam, LPARAM lParam) {
    /* all menu icons have a fixed size */
    LPMEASUREITEMSTRUCT lpm = (LPMEASUREITEMSTRUCT) lParam;
    lpm->itemWidth = MENU_SIZE_ICON_X;
    lpm->itemHeight = MENU_SIZE_ICON_Y;
    return TRUE;
}

LRESULT khm_menu_draw_item(WPARAM wParam, LPARAM lParam) {
    LPDRAWITEMSTRUCT lpd;
    khui_action * act;
    int resid;
    int iidx;
    UINT style;

    lpd = (LPDRAWITEMSTRUCT) lParam;
    act = khui_find_action(lpd->itemID);

    resid = 0;
    if((lpd->itemState & ODS_DISABLED) || (lpd->itemState & ODS_GRAYED)) {
        resid = act->ib_icon_dis;
    }
    if(!resid)
        resid = act->ib_icon;

    if(!resid) /* nothing to draw */
        return TRUE;

    
    iidx = khui_get_icon_index(resid);
    if(iidx == -1)
        return TRUE;


    style = ILD_TRANSPARENT;
    if(lpd->itemState & ODS_HOTLIGHT || lpd->itemState & ODS_SELECTED) {
        style |= ILD_SELECTED;
    }
    
    khui_ilist_draw(il_icon, 
                    iidx, 
                    lpd->hDC, 
                    lpd->rcItem.left, lpd->rcItem.top, style);

    return TRUE;
}

void khm_track_menu(int menu) {
    TBBUTTON bi;
    RECT r;
    RECT wr;

    if (menu != -1)
        mm_last_hot_item = menu;

    if (mm_last_hot_item != -1) {
        SendMessage(khui_main_menu_toolbar,
                    TB_GETBUTTON,
                    mm_last_hot_item,
                    (LPARAM) &bi);

        SendMessage(khui_main_menu_toolbar,
                    TB_GETITEMRECT,
                    mm_last_hot_item,
                    (LPARAM) &r);

        GetWindowRect(khui_main_menu_toolbar, &wr);

        khm_menu_show_panel(bi.idCommand, wr.left + r.left, wr.top + r.bottom);

        r.left = 0;

        if (mm_next_hot_item != -1) {
            mm_last_hot_item = mm_next_hot_item;
            mm_next_hot_item = -1;

            PostMessage(khm_hwnd_main, WM_COMMAND, 
                        MAKEWPARAM(KHUI_PACTION_MENU,0),
                        MAKELPARAM(mm_last_hot_item,1));
        }
    }
}

void khm_menu_track_current(void) {
    khm_track_menu(-1);
}

LRESULT khm_menu_handle_select(WPARAM wParam, LPARAM lParam) {
    if((HIWORD(wParam) == 0xffff && lParam == 0) || 
       (HIWORD(wParam) & MF_POPUP)) {
        /* the menu was closed */
        khm_statusbar_set_part(KHUI_SBPART_INFO, NULL, NULL);
    } else {
        khui_action * act;
        int id;
        wchar_t buf[MAX_RES_STRING] = L"";

        id = LOWORD(wParam);
        act = khui_find_action(id);
        if(act == NULL || (act->is_tooltip == 0 && act->tooltip == NULL))
            khm_statusbar_set_part(KHUI_SBPART_INFO, NULL, NULL);
        else {
            if (act->tooltip)
                StringCbCopy(buf, sizeof(buf), act->tooltip);
            else
                LoadString(khm_hInstance, 
                           act->is_tooltip, 
                           buf, ARRAYLENGTH(buf));
            khm_statusbar_set_part(KHUI_SBPART_INFO, NULL, buf);
        }
    }
    return 0;
}

HHOOK mm_hevt_hook = NULL;
HWND mm_hwnd_menu_panel = NULL;

LRESULT CALLBACK mm_event_filter(int code,
                                 WPARAM wParam,
                                 LPARAM lParam) {
    MSG * m;
    RECT r;
    int x,y;

    if (code == MSGF_MENU) {
        /* do stuff */
        m = (MSG *) lParam;
        GetWindowRect(khui_main_menu_toolbar, &r);

        if (m->hwnd != khm_hwnd_main)
            mm_hwnd_menu_panel = m->hwnd;

        switch(m->message) {
        case WM_MOUSEMOVE:

            x = GET_X_LPARAM(m->lParam);
            y = GET_Y_LPARAM(m->lParam);
            x -= r.left;
            y -= r.top;

            SendMessage(khui_main_menu_toolbar,
                        m->message,
                        m->wParam,
                        MAKELPARAM(x,y));
            break;
        }
    }

    return CallNextHookEx(mm_hevt_hook, code, wParam, lParam);
}


void mm_begin_hot_track(void) {

    if (mm_hevt_hook)
        UnhookWindowsHookEx(mm_hevt_hook);

    mm_hevt_hook = SetWindowsHookEx(WH_MSGFILTER,
                                    mm_event_filter,
                                    NULL,
                                    GetCurrentThreadId());
}

void mm_end_hot_track(void) {
    if (mm_hevt_hook)
        UnhookWindowsHookEx(mm_hevt_hook);

    mm_hevt_hook = NULL;
    mm_hwnd_menu_panel = NULL;
}

void mm_cancel_menu(void) {
    if (mm_hwnd_menu_panel)
        SendMessage(mm_hwnd_menu_panel, WM_CANCELMODE, 0, 0);
}

LRESULT khm_menu_notify_main(LPNMHDR notice) {
    LPNMTOOLBAR nmt;
    LRESULT ret = FALSE;
    RECT r;
    khui_menu_def * mmdef;
    khui_action_ref * mm;
    int nmm;

    mmdef = khui_find_menu(KHUI_MENU_MAIN);
    mm = mmdef->items;
    nmm = (int) khui_action_list_length(mm);

    GetWindowRect(khui_main_menu_toolbar, &r);

    nmt = (LPNMTOOLBAR) notice;
    switch(notice->code) {
    case TBN_DROPDOWN:
        khm_track_menu(-1);
        /*
        khm_menu_show_panel(nmt->iItem, 
                        r.left + nmt->rcButton.left, 
                        r.top + nmt->rcButton.bottom);
        */
        ret = TBDDRET_DEFAULT;
        break;

    case TBN_HOTITEMCHANGE:
        {
            LPNMTBHOTITEM nmhi;
            int new_item = -1;

            nmhi = (LPNMTBHOTITEM) notice;

            if(nmhi->dwFlags & HICF_LEAVING)
                new_item = -1;
            else {
                int i;
                for(i=0; i < nmm; i++) {
                    if(mm[i].action == nmhi->idNew) {
                        new_item = i;
                        break;
                    }
                }
            }

            if (mm_hot_track && 
                new_item != mm_last_hot_item &&
                new_item != -1 &&
                mm_last_hot_item != -1) {

                EndMenu();
                mm_next_hot_item = new_item;

            }

            ret = 0;

            if (!mm_hot_track || new_item != -1)
                mm_last_hot_item = new_item;

        } break;

    default:
        /* hmm. what to do */
        ret = FALSE;
    }
    return ret;
}

HMENU khui_hmenu_main = NULL;

void khm_menu_refresh_items(void) {
    khui_menu_def * def;

    if (!khui_hmenu_main)
        return;

    def = khui_find_menu(KHUI_MENU_MAIN);

    refresh_menu(khui_hmenu_main, def);

    DrawMenuBar(khm_hwnd_main);
}

void khm_menu_create_main(HWND parent) {
    HMENU hmenu;
    khui_menu_def * def;

    def = khui_find_menu(KHUI_MENU_MAIN);

    hmenu = mm_create_menu_from_def(def, TRUE);

    SetMenu(parent, hmenu);

    khui_hmenu_main = hmenu;

    return;

#ifdef USE_EXPLORER_STYLE_MENU_BAR
    HWND hwtb;
    REBARBANDINFO rbi;
    SIZE sz;
    int i;
    khui_menu_def * mmdef;
    khui_action_ref * mm;
    int nmm;

    mmdef = khui_find_menu(KHUI_MENU_MAIN);
    mm = mmdef->items;
    nmm = (int) khui_action_list_length(mm);

    hwtb = CreateWindowEx(0
#if (_WIN32_IE >= 0x0501)
                          | TBSTYLE_EX_MIXEDBUTTONS
#endif
                          ,
                          TOOLBARCLASSNAME,
                          (LPWSTR) NULL,
                          WS_CHILD | 
                          CCS_ADJUSTABLE | 
                          TBSTYLE_FLAT |
                          TBSTYLE_AUTOSIZE |
                          TBSTYLE_LIST |
                          CCS_NORESIZE |
                          CCS_NOPARENTALIGN |
                          CCS_NODIVIDER,
                          0, 0, 0, 0, rebar,
                          (HMENU) NULL, khm_hInstance,
                          NULL);

    if(!hwtb) {
#ifdef DEBUG
        assert(FALSE);
#else
        return;
#endif
    }

    khui_main_menu_toolbar = hwtb;

    SendMessage(hwtb,
                TB_BUTTONSTRUCTSIZE,
                (WPARAM) sizeof(TBBUTTON),
                0);

    for(i=0; i<nmm; i++) {
        khui_add_action_to_toolbar(hwtb, 
                                   khui_find_action(mm[i].action), 
                                   KHUI_TOOLBAR_ADD_TEXT | 
                                   KHUI_TOOLBAR_ADD_DROPDOWN | 
                                   KHUI_TOOLBAR_VARSIZE, 
                                   NULL);
    }

    SendMessage(hwtb,
                TB_AUTOSIZE,
                0,0);
    
    SendMessage(hwtb,
                TB_GETMAXSIZE,
                0,
                (LPARAM) &sz);

    ZeroMemory(&rbi, sizeof(rbi));

    rbi.cbSize = sizeof(rbi);

    rbi.fMask = 
        RBBIM_ID |
        RBBIM_STYLE | 
        RBBIM_CHILD | 
        RBBIM_CHILDSIZE | 
        RBBIM_SIZE | 
        RBBIM_IDEALSIZE; 

    rbi.fStyle = 
        RBBS_USECHEVRON;

    rbi.hwndChild = hwtb;
    rbi.wID = KHUI_MENU_MAIN;
    rbi.cx = sz.cx;
    rbi.cxMinChild = rbi.cx;
    rbi.cxIdeal = rbi.cx;
    rbi.cyMinChild = sz.cy;
    rbi.cyChild = rbi.cyMinChild;
    rbi.cyIntegral = rbi.cyMinChild;
    rbi.cyMaxChild = rbi.cyMinChild;

    SendMessage(rebar,
                RB_INSERTBAND,
                0,
                (LPARAM) &rbi);
#endif
}

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
#include<assert.h>

HWND khui_hwnd_standard_toolbar;
int khui_tb_blank;

khui_ilist * ilist_toolbar;

void khui_init_toolbar(void) {
    ilist_toolbar = khui_create_ilist(KHUI_TOOLBAR_IMAGE_WIDTH, KHUI_TOOLBAR_IMAGE_HEIGHT, KHUI_TOOLBAR_MAX_BTNS, 5, 0);
}

void khui_exit_toolbar(void) {
    khui_delete_ilist(ilist_toolbar);
}

LRESULT khm_toolbar_notify(LPNMHDR notice) {
    switch(notice->code) {
    case TBN_GETINFOTIP:
        {
            LPNMTBGETINFOTIP git = (LPNMTBGETINFOTIP) notice;
            int cmd;
            khui_action * a;

            cmd = git->iItem;
            a = khui_find_action(cmd);

            if (a) {
                if (a->caption) {
                    StringCchCopy(git->pszText, git->cchTextMax, a->caption);
                } else if (a->tooltip) {
                    StringCchCopy(git->pszText, git->cchTextMax, a->tooltip);
                } else if (a->is_caption) {
                    wchar_t buf[INFOTIPSIZE];

                    buf[0] = L'\0';
                    LoadString(khm_hInstance, a->is_caption,
                               buf, ARRAYLENGTH(buf));

                    StringCchCopy(git->pszText, git->cchTextMax, buf);
                } else {
                    StringCchCopy(git->pszText, git->cchTextMax, L"");
                }
            } else {
                StringCchCopy(git->pszText,
                              git->cchTextMax,
                              L"");
            }
        }
        break;

    case TBN_HOTITEMCHANGE:
        {
            LPNMTBHOTITEM hi = (LPNMTBHOTITEM) notice;

            if (hi->dwFlags & HICF_LEAVING) {
                khm_statusbar_set_part(KHUI_SBPART_INFO, NULL, L"");
            } else {
                khui_action * a;
                int cmd;
                wchar_t buf[256];

                cmd = hi->idNew;
                a = khui_find_action(cmd);

                buf[0] = L'\0';

                if (a) {
                    if (a->tooltip)
                        StringCbCopy(buf, sizeof(buf), a->tooltip);
                    else if (a->is_tooltip) {
                        LoadString(khm_hInstance, a->is_tooltip,
                                   buf, ARRAYLENGTH(buf));
                    }
                }

                khm_statusbar_set_part(KHUI_SBPART_INFO, NULL, buf);
            }
        }
        break;

    case TBN_DROPDOWN:
        {
            LPNMTOOLBAR nmtb = (LPNMTOOLBAR) notice;
            RECT r;

            GetWindowRect(khui_hwnd_standard_toolbar, &r);
            if (nmtb->iItem == KHUI_ACTION_DESTROY_CRED) {
                khm_menu_show_panel(KHUI_MENU_DESTROY_CRED,
                                    r.left + nmtb->rcButton.left,
                                    r.top + nmtb->rcButton.bottom);
            } else if (nmtb->iItem == KHUI_ACTION_RENEW_CRED) {
                khm_menu_show_panel(KHUI_MENU_RENEW_CRED,
                                    r.left + nmtb->rcButton.left,
                                    r.top + nmtb->rcButton.bottom);
            } else {
                return TBDDRET_NODEFAULT;
            }

            return TBDDRET_DEFAULT;
        }
        break;

    case NM_CUSTOMDRAW:
        {
            LPNMTBCUSTOMDRAW nmcd = (LPNMTBCUSTOMDRAW) notice;
            if(nmcd->nmcd.dwDrawStage == CDDS_PREPAINT) {
                return CDRF_NOTIFYITEMDRAW | CDRF_NOTIFYPOSTERASE;
            } else if(nmcd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                return CDRF_NOTIFYPOSTPAINT;
            } else if(nmcd->nmcd.dwDrawStage == CDDS_ITEMPOSTPAINT) {
                /* draw the actual icon */
                int iidx;
                int ibmp;
                HBITMAP hbmp;
                RECT r;

                khui_action * act =
                    khui_find_action((int) nmcd->nmcd.dwItemSpec);

                if(!act || !act->ib_normal)
                    return CDRF_DODEFAULT;

                if((act->state & KHUI_ACTIONSTATE_DISABLED) &&
                   act->ib_disabled) {
                    ibmp = act->ib_disabled;
                } else if(act->ib_hot &&
                          ((nmcd->nmcd.uItemState & CDIS_HOT) ||
                           (nmcd->nmcd.uItemState & CDIS_SELECTED))){
                    ibmp = act->ib_hot;
                } else {
                    ibmp = act->ib_normal;
                }

                iidx = khui_ilist_lookup_id(ilist_toolbar, ibmp);
                if(iidx < 0) {
                    hbmp = LoadImage(khm_hInstance,
                                     MAKEINTRESOURCE(ibmp),
                                     IMAGE_BITMAP,
                                     KHUI_TOOLBAR_IMAGE_WIDTH,
                                     KHUI_TOOLBAR_IMAGE_HEIGHT, 0);
                    iidx =
                        khui_ilist_add_masked_id(ilist_toolbar,
                                                 hbmp,
                                                 KHUI_TOOLBAR_BGCOLOR,
                                                 ibmp);
                    DeleteObject(hbmp);
                }

                if(iidx < 0)
                    return CDRF_DODEFAULT;

                CopyRect(&r, &(nmcd->nmcd.rc));
                r.left += ((r.bottom - r.top) -
                          KHUI_TOOLBAR_IMAGE_HEIGHT) / 2;
                r.top += ((r.bottom - r.top) -
                          KHUI_TOOLBAR_IMAGE_HEIGHT) / 2;
#if 0
                r.left += ((r.right - r.left) -
                           KHUI_TOOLBAR_IMAGE_WIDTH) / 2;
#endif
                khui_ilist_draw(ilist_toolbar,
                                iidx,
                                nmcd->nmcd.hdc,
                                r.left,
                                r.top,
                                0);

                return CDRF_DODEFAULT;
            }
        }
        break;
    }
    return 0;
}

void khui_add_action_to_toolbar(HWND tb, khui_action *a, int opt, HIMAGELIST hiList) {
    wchar_t buf[MAX_RES_STRING] = L"";
    int idx_caption = 0;
    TBBUTTON bn;
    LRESULT lr;

    ZeroMemory(&bn,sizeof(bn));

    if(opt & KHUI_TOOLBAR_ADD_SEP) {
        bn.fsStyle = BTNS_SEP;
        bn.iBitmap = 3;

        lr = SendMessage(tb,
                         TB_ADDBUTTONS,
                         1,
                         (LPARAM) &bn);
#ifdef DEBUG
        assert(lr);
#endif
        return;
    }

    bn.fsStyle = BTNS_BUTTON;

    if(opt & KHUI_TOOLBAR_VARSIZE) {
        bn.fsStyle |= BTNS_AUTOSIZE;
    }

    if(opt & KHUI_TOOLBAR_ADD_TEXT) {
        int sid = 0;
        if((opt & KHUI_TOOLBAR_ADD_LONGTEXT) ==
           KHUI_TOOLBAR_ADD_LONGTEXT) {
            sid = a->is_tooltip;
        }
        if(!sid)
            sid = a->is_caption;
        if(sid) {
            LoadString(khm_hInstance,
                       sid,
                       buf, ARRAYLENGTH(buf));
            buf[wcslen(buf) + 1] = L'\0';
            idx_caption = (int) SendMessage(tb,
                                            TB_ADDSTRING,
                                            (WPARAM) NULL,
                                            (LPARAM) buf);
#if (_WIN32_IE >= 0x0501)
            bn.fsStyle |= BTNS_SHOWTEXT;
#endif
            bn.iString = idx_caption;
        }
    }

    if(opt & KHUI_TOOLBAR_ADD_DROPDOWN) {
        bn.fsStyle |= BTNS_DROPDOWN;
    }

    if((opt & KHUI_TOOLBAR_ADD_BITMAP) && a->ib_normal) {
        bn.fsStyle |= TBSTYLE_CUSTOMERASE;
        bn.iBitmap = khui_tb_blank;
    } else {
#if (_WIN32_IE >= 0x0501)
        bn.iBitmap = I_IMAGENONE;
#endif
    }

    bn.idCommand = a->cmd;

    if(a->state & KHUI_ACTIONSTATE_DISABLED) {
        bn.fsState = 0;
    } else {
        bn.fsState = TBSTATE_ENABLED;
    }

    if(a->state & KHUI_ACTIONSTATE_CHECKED) {
        bn.fsState |= TBSTATE_CHECKED;
    }

    bn.dwData = 0;

    lr = SendMessage(
                     tb,
                     TB_ADDBUTTONS,
                     1,
                     (LPARAM) &bn);

#ifdef DEBUG
    assert(lr);
#endif
}

void khm_update_standard_toolbar(void)
{
    khui_menu_def * def;
    khui_action_ref * aref;
    khui_action * act;

    def = khui_find_menu(KHUI_TOOLBAR_STANDARD);

    aref = def->items;

    while(aref && aref->action != KHUI_MENU_END) {
        if(aref->action == KHUI_MENU_SEP) {
            aref++;
            continue;
        }

        act = khui_find_action(aref->action);
        if(act) {
            BOOL enable;

            enable = !(act->state & KHUI_ACTIONSTATE_DISABLED);
            SendMessage(khui_hwnd_standard_toolbar,
                        TB_ENABLEBUTTON,
                        (WPARAM) act->cmd,
                        MAKELPARAM(enable, 0));
        }

        aref++;
    }
}

void khm_create_standard_toolbar(HWND rebar) {
    HWND hwtb;
    SIZE sz;
    HBITMAP hbm_blank;
    HIMAGELIST hiList;
    REBARBANDINFO rbi;
    khui_menu_def * def;
    khui_action * act;
    khui_action_ref * aref;
    int idx_blank;

    def = khui_find_menu(KHUI_TOOLBAR_STANDARD);

    if (!def) {
#ifdef DEBUG
        assert(FALSE);
#endif
        return;
    }

    hwtb = CreateWindowEx(0 ,
                          TOOLBARCLASSNAME,
                          (LPWSTR) NULL,
                          WS_CHILD |
                          TBSTYLE_FLAT |
                          TBSTYLE_AUTOSIZE |
                          TBSTYLE_TOOLTIPS |
                          CCS_NORESIZE |
                          CCS_NOPARENTALIGN |
                          CCS_ADJUSTABLE |
                          CCS_NODIVIDER,
                          0, 0, 0, 0, rebar,
                          (HMENU) NULL, khm_hInstance,
                          NULL);

    if(!hwtb) {
#ifdef DEBUG
        assert(FALSE);
#endif
        return;
    }

#if (_WIN32_IE >= 0x0501)
    SendMessage(hwtb, TB_SETEXTENDEDSTYLE, 0,
                TBSTYLE_EX_MIXEDBUTTONS | TBSTYLE_EX_DRAWDDARROWS);
#endif

    hiList = ImageList_Create(
        KHUI_TOOLBAR_IMAGE_WIDTH,
        KHUI_TOOLBAR_IMAGE_HEIGHT,
        ILC_MASK,
        (int) khui_action_list_length(def->items),
        3);

    hbm_blank = LoadImage(khm_hInstance,
                          MAKEINTRESOURCE(IDB_TB_BLANK),
                          IMAGE_BITMAP,
                          KHUI_TOOLBAR_IMAGE_WIDTH,
                          KHUI_TOOLBAR_IMAGE_HEIGHT, 0);
    idx_blank = ImageList_AddMasked(hiList, hbm_blank, RGB(0,0,0));

    khui_hwnd_standard_toolbar = hwtb;
    khui_tb_blank = idx_blank;

    def = khui_find_menu(KHUI_TOOLBAR_STANDARD);

    aref = def->items;

    SendMessage(hwtb,
        TB_BUTTONSTRUCTSIZE,
        sizeof(TBBUTTON),
        0);

    SendMessage(hwtb,
        TB_SETBITMAPSIZE,
        0,
        MAKELONG(KHUI_TOOLBAR_IMAGE_WIDTH,KHUI_TOOLBAR_IMAGE_HEIGHT));

    SendMessage(hwtb,
        TB_SETIMAGELIST,
        0,
        (LPARAM) hiList);

    SendMessage(hwtb,
        TB_SETBUTTONSIZE,
        0,
        MAKELONG(KHUI_TOOLBAR_IMAGE_WIDTH,KHUI_TOOLBAR_IMAGE_HEIGHT));

    while(aref && aref->action != KHUI_MENU_END) {
        if(aref->action == KHUI_MENU_SEP) {
            khui_add_action_to_toolbar(hwtb,
                                       NULL,
                                       KHUI_TOOLBAR_ADD_SEP,
                                       hiList);
        } else {
            act = khui_find_action(aref->action);
            khui_add_action_to_toolbar(hwtb,
                                       act,
                                       KHUI_TOOLBAR_ADD_BITMAP |
                                       ((aref->flags & KHUI_ACTIONREF_SUBMENU)?
                                        KHUI_TOOLBAR_ADD_DROPDOWN: 0),
                                       hiList);
        }
        aref ++;
    }

    SendMessage(hwtb,
                TB_AUTOSIZE,
                0,0);

    SendMessage(hwtb,
                TB_GETMAXSIZE,
                0,
                (LPARAM) &sz);

    sz.cy += 5;

    ZeroMemory(&rbi, sizeof(rbi));

    rbi.cbSize = sizeof(rbi);
    rbi.fMask =
        RBBIM_ID |
        RBBIM_CHILD |
        RBBIM_CHILDSIZE |
        RBBIM_IDEALSIZE |
        RBBIM_SIZE |
        RBBIM_STYLE;
    rbi.fStyle =
        RBBS_USECHEVRON |
        RBBS_BREAK;
    rbi.hwndChild = hwtb;

    rbi.wID = KHUI_TOOLBAR_STANDARD;
    rbi.cx = sz.cx;
    rbi.cxMinChild = sz.cx;
    rbi.cyMinChild = sz.cy;
    rbi.cyChild = rbi.cyMinChild;
    rbi.cyMaxChild = rbi.cyMinChild;
    rbi.cyIntegral = rbi.cyMinChild;

    rbi.cxIdeal = rbi.cx;

    SendMessage(rebar,
        RB_INSERTBAND,
        0,
        (LPARAM) &rbi);
}

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

#define NOEXPORT
#include<khuidefs.h>
#include<intaction.h>
#include<utils.h>
#include<assert.h>

#include<strsafe.h>

khui_action_ref khui_main_menu[] = {
    MENU_SUBMENU(KHUI_MENU_FILE),
    MENU_SUBMENU(KHUI_MENU_CRED),
    MENU_SUBMENU(KHUI_MENU_VIEW),
    MENU_SUBMENU(KHUI_MENU_OPTIONS),
    MENU_SUBMENU(KHUI_MENU_HELP),
    MENU_END()
};

khui_action_ref khui_menu_file[] = {
    MENU_ACTION(KHUI_ACTION_PROPERTIES),
    MENU_SEP(),
    MENU_ACTION(KHUI_ACTION_EXIT),
    MENU_END()
};

khui_action_ref khui_menu_cred[] = {
    MENU_ACTION(KHUI_ACTION_NEW_CRED),
    MENU_SEP(),
    MENU_SUBMENU(KHUI_MENU_RENEW_CRED),
    MENU_ACTION(KHUI_ACTION_IMPORT),
    MENU_SUBMENU(KHUI_MENU_DESTROY_CRED),
    MENU_SEP(),
    MENU_ACTION(KHUI_ACTION_SET_DEF_ID),
#if 0
    /* not implemented yet */
    MENU_ACTION(KHUI_ACTION_SET_SRCH_ID),
#endif
    MENU_SEP(),
    MENU_ACTION(KHUI_ACTION_PASSWD_ID),
    MENU_END()
};

khui_action_ref khui_menu_layout[] = {
    MENU_ACTION(KHUI_ACTION_LAYOUT_ID),
    MENU_ACTION(KHUI_ACTION_LAYOUT_TYPE),
    MENU_ACTION(KHUI_ACTION_LAYOUT_LOC),
    MENU_ACTION(KHUI_ACTION_LAYOUT_CUST),
    MENU_END()
};

khui_action_ref khui_menu_toolbars[] = {
    MENU_ACTION(KHUI_ACTION_TB_STANDARD),
    MENU_END()
};

khui_action_ref khui_menu_view[] = {
    MENU_ACTION(KHUI_ACTION_LAYOUT_MINI),
    MENU_SUBMENU(KHUI_MENU_COLUMNS),
    MENU_SUBMENU(KHUI_MENU_LAYOUT),
#if 0
    /* not implemented yet */
    MENU_SUBMENU(KHUI_MENU_TOOLBARS),
#endif
    MENU_SEP(),
#if 0
    /* not implemented yet */
    MENU_ACTION(KHUI_ACTION_DEBUG_WINDOW),
    MENU_SEP(),
#endif
    MENU_ACTION(KHUI_ACTION_VIEW_REFRESH),
    MENU_END()
};

khui_action_ref khui_menu_options[] = {
    MENU_ACTION(KHUI_ACTION_OPT_KHIM),
    MENU_ACTION(KHUI_ACTION_OPT_APPEAR),
    MENU_ACTION(KHUI_ACTION_OPT_IDENTS),
    MENU_ACTION(KHUI_ACTION_OPT_NOTIF),
    MENU_ACTION(KHUI_ACTION_OPT_PLUGINS),
    MENU_SEP(),
    MENU_END()
};

khui_action_ref khui_menu_help[] = {
    MENU_ACTION(KHUI_ACTION_HELP_CTX),
    MENU_SEP(),
    MENU_ACTION(KHUI_ACTION_HELP_INDEX),
    MENU_SEP(),
    MENU_ACTION(KHUI_ACTION_HELP_ABOUT),
    MENU_END()
};

khui_action_ref khui_toolbar_standard[] = {
    MENU_ACTION(KHUI_ACTION_NEW_CRED),
    MENU_SUBMENU(KHUI_ACTION_RENEW_CRED),
    MENU_ACTION(KHUI_ACTION_IMPORT),
    MENU_SUBMENU(KHUI_ACTION_DESTROY_CRED),
    MENU_SEP(),
    MENU_ACTION(KHUI_ACTION_PASSWD_ID),
    MENU_SEP(),
    MENU_ACTION(KHUI_ACTION_VIEW_REFRESH),
    MENU_ACTION(KHUI_PACTION_BLANK),
    MENU_ACTION(KHUI_ACTION_HELP_CTX),
    MENU_END()
};

khui_action_ref khui_menu_ident_ctx[] = {
    MENU_ACTION(KHUI_ACTION_PROPERTIES),
    MENU_SEP(),
    MENU_ACTION(KHUI_ACTION_SET_DEF_ID),
    MENU_ACTION(KHUI_ACTION_SET_SRCH_ID),
    MENU_SEP(),
    MENU_ACTION(KHUI_ACTION_NEW_CRED),
    MENU_ACTION(KHUI_ACTION_RENEW_CRED),
    MENU_ACTION(KHUI_ACTION_DESTROY_CRED),
    MENU_END()
};

khui_action_ref khui_menu_tok_ctx[] = {
    MENU_ACTION(KHUI_ACTION_PROPERTIES),
    MENU_SEP(),
    MENU_ACTION(KHUI_ACTION_NEW_CRED),
    MENU_ACTION(KHUI_ACTION_RENEW_CRED),
    MENU_ACTION(KHUI_ACTION_DESTROY_CRED),
    MENU_END()
};

khui_action_ref khui_menu_ico_ctx_min[] = {
    MENU_DEFACTION(KHUI_ACTION_OPEN_APP),
    MENU_SEP(),
    MENU_ACTION(KHUI_ACTION_NEW_CRED),
    MENU_SUBMENU(KHUI_MENU_RENEW_CRED),
    MENU_ACTION(KHUI_ACTION_IMPORT),
    MENU_SUBMENU(KHUI_MENU_DESTROY_CRED),
    MENU_SEP(),
    MENU_ACTION(KHUI_ACTION_PASSWD_ID),
    MENU_SEP(),
    MENU_ACTION(KHUI_ACTION_HELP_CTX),
    MENU_ACTION(KHUI_ACTION_HELP_ABOUT),
    MENU_SEP(),
    MENU_ACTION(KHUI_ACTION_EXIT),
    MENU_END()
};

khui_action_ref khui_menu_ico_ctx_normal[] = {
    MENU_DEFACTION(KHUI_ACTION_CLOSE_APP),
    MENU_SEP(),
    MENU_ACTION(KHUI_ACTION_NEW_CRED),
    MENU_SUBMENU(KHUI_MENU_RENEW_CRED),
    MENU_ACTION(KHUI_ACTION_IMPORT),
    MENU_SUBMENU(KHUI_MENU_DESTROY_CRED),
    MENU_SEP(),
    MENU_ACTION(KHUI_ACTION_PASSWD_ID),
    MENU_SEP(),
    MENU_ACTION(KHUI_ACTION_HELP_CTX),
    MENU_ACTION(KHUI_ACTION_HELP_ABOUT),
    MENU_SEP(),
    MENU_ACTION(KHUI_ACTION_EXIT),
    MENU_END()
};

khui_action_ref khui_menu_cwheader_ctx[] = {
    MENU_SUBMENU(KHUI_MENU_COLUMNS),
    MENU_SUBMENU(KHUI_MENU_LAYOUT),
    MENU_END()
};

khui_action_ref khui_menu_columns[] = {
    MENU_END()
};

khui_action_ref khui_menu_destroy_cred[] = {
    MENU_DEFACTION(KHUI_ACTION_DESTROY_ALL),
    MENU_END()
};

khui_action_ref khui_menu_renew_cred[] = {
    MENU_DEFACTION(KHUI_ACTION_RENEW_ALL),
    MENU_END()
};

khui_action_ref khui_pmenu_tok_sel[] = {
    MENU_ACTION(KHUI_ACTION_RENEW_CRED),
    MENU_ACTION(KHUI_ACTION_DESTROY_CRED),
    MENU_END()
};

khui_action_ref khui_pmenu_id_sel[] = {
    MENU_ACTION(KHUI_ACTION_DESTROY_CRED),
    MENU_ACTION(KHUI_ACTION_RENEW_CRED),
    MENU_END()
};

/* all stock menus and toolbars */
khui_menu_def khui_all_menus[] = {
    CONSTMENU(KHUI_MENU_MAIN, KHUI_MENUSTATE_CONSTANT | KHUI_MENUSTATE_SYSTEM, khui_main_menu),
    CONSTMENU(KHUI_MENU_FILE, KHUI_MENUSTATE_CONSTANT | KHUI_MENUSTATE_SYSTEM, khui_menu_file),
    CONSTMENU(KHUI_MENU_CRED, KHUI_MENUSTATE_CONSTANT | KHUI_MENUSTATE_SYSTEM, khui_menu_cred),
    CONSTMENU(KHUI_MENU_VIEW, KHUI_MENUSTATE_CONSTANT | KHUI_MENUSTATE_SYSTEM, khui_menu_view),
    CONSTMENU(KHUI_MENU_LAYOUT, KHUI_MENUSTATE_CONSTANT | KHUI_MENUSTATE_SYSTEM, khui_menu_layout),
    CONSTMENU(KHUI_MENU_TOOLBARS, KHUI_MENUSTATE_CONSTANT | KHUI_MENUSTATE_SYSTEM, khui_menu_toolbars),
    CONSTMENU(KHUI_MENU_OPTIONS, KHUI_MENUSTATE_CONSTANT | KHUI_MENUSTATE_SYSTEM, khui_menu_options),
    CONSTMENU(KHUI_MENU_HELP, KHUI_MENUSTATE_CONSTANT | KHUI_MENUSTATE_SYSTEM, khui_menu_help),
    CONSTMENU(KHUI_MENU_COLUMNS, KHUI_MENUSTATE_CONSTANT | KHUI_MENUSTATE_SYSTEM, khui_menu_columns),
    CONSTMENU(KHUI_MENU_RENEW_CRED, KHUI_MENUSTATE_CONSTANT | KHUI_MENUSTATE_SYSTEM, khui_menu_renew_cred),
    CONSTMENU(KHUI_MENU_DESTROY_CRED, KHUI_MENUSTATE_CONSTANT | KHUI_MENUSTATE_SYSTEM, khui_menu_destroy_cred),

    /* toolbars */
    CONSTMENU(KHUI_TOOLBAR_STANDARD, KHUI_MENUSTATE_CONSTANT | KHUI_MENUSTATE_SYSTEM, khui_toolbar_standard),

    /* context menus */
    CONSTMENU(KHUI_MENU_IDENT_CTX, KHUI_MENUSTATE_CONSTANT, khui_menu_ident_ctx),
    CONSTMENU(KHUI_MENU_TOK_CTX, KHUI_MENUSTATE_CONSTANT, khui_menu_tok_ctx),
    CONSTMENU(KHUI_MENU_ICO_CTX_MIN, KHUI_MENUSTATE_CONSTANT, khui_menu_ico_ctx_min),
    CONSTMENU(KHUI_MENU_ICO_CTX_NORMAL, KHUI_MENUSTATE_CONSTANT, khui_menu_ico_ctx_normal),
    CONSTMENU(KHUI_MENU_CWHEADER_CTX, KHUI_MENUSTATE_CONSTANT, khui_menu_cwheader_ctx),

    /* pseudo menus */
    CONSTMENU(KHUI_PMENU_TOK_SEL, KHUI_MENUSTATE_CONSTANT, khui_pmenu_tok_sel),
    CONSTMENU(KHUI_PMENU_ID_SEL, KHUI_MENUSTATE_CONSTANT, khui_pmenu_id_sel)
};

int khui_n_all_menus = sizeof(khui_all_menus) / sizeof(khui_menu_def);
khui_menu_def ** khui_cust_menus = NULL;
int khui_nc_cust_menus = 0;
int khui_n_cust_menus = 0;
CRITICAL_SECTION cs_actions;

#define CACT_NC_ALLOC 32

khui_action ** khui_cust_actions = NULL;
int khui_nc_cust_actions = 0;
int khui_n_cust_actions = 0;

HWND khui_hwnd_main;			/* main window, for notifying
                                           action launches and
                                           dispatching messages to the
                                           application. */

KHMEXP void KHMAPI 
khui_init_actions(void) {
    InitializeCriticalSection(&cs_actions);
}

KHMEXP void KHMAPI 
khui_exit_actions(void) {
    DeleteCriticalSection(&cs_actions);
}

KHMEXP void KHMAPI
khui_refresh_actions(void) {
    kmq_post_message(KMSG_ACT, KMSG_ACT_REFRESH, 0, 0);
}

KHMEXP void KHMAPI
khui_action_lock(void) {
    EnterCriticalSection(&cs_actions);
}

KHMEXP void KHMAPI
khui_action_unlock(void) {
    LeaveCriticalSection(&cs_actions);
}

KHMEXP khm_int32 KHMAPI
khui_action_create(const wchar_t * name,
                   const wchar_t * caption,
                   const wchar_t * tooltip,
                   void * userdata,
                   khm_int32 type,
                   khm_handle hsub) {
    khui_action * act;
    khm_int32 action = 0;
    int i;
    size_t s;

    if ((name && FAILED(StringCchLength(name, KHUI_MAXCCH_NAME, &s))) ||
        !caption ||
        FAILED(StringCchLength(caption, KHUI_MAXCCH_SHORT_DESC, &s)) ||
        (tooltip && FAILED(StringCchLength(tooltip, KHUI_MAXCCH_SHORT_DESC, &s))) ||
        (type != KHUI_ACTIONTYPE_TRIGGER && type != KHUI_ACTIONTYPE_TOGGLE)) {
        return 0;
    }

    EnterCriticalSection(&cs_actions);
    if (name && (act = khui_find_named_action(name))) {
        /* named action already exists */
        action = act->cmd;
        goto _done;
    }

    for (i=0; i < khui_n_cust_actions; i++) {
        if (khui_cust_actions[i] == NULL ||
            (khui_cust_actions[i]->state & KHUI_ACTIONSTATE_DELETED))
            break;
    }

    if (i >= khui_n_cust_actions &&
        (khui_cust_actions == NULL ||
         khui_n_cust_actions + 1 > khui_nc_cust_actions)) {

        khui_nc_cust_actions = UBOUNDSS(khui_n_cust_actions + 1,
                                        CACT_NC_ALLOC,
                                        CACT_NC_ALLOC);
#ifdef DEBUG
        assert(khui_nc_cust_actions > khui_n_cust_actions + 1);
#endif
        khui_cust_actions = PREALLOC(khui_cust_actions,
                                     sizeof(*khui_cust_actions) * khui_nc_cust_actions);
#ifdef DEBUG
        assert(khui_cust_actions);
#endif
    }

    if (i >= khui_n_cust_actions) {
        i = khui_n_cust_actions ++;
        act = PMALLOC(sizeof(khui_action));
    } else {
        act = khui_cust_actions[i];
        if (act == NULL)
            act = PMALLOC(sizeof(khui_action));
    }

#ifdef DEBUG
    assert(act);
#endif

    khui_cust_actions[i] = act;

    ZeroMemory(act, sizeof(*act));

    act->cmd = KHUI_USERACTION_BASE + i;
    act->type = type;
    act->name = (name? PWCSDUP(name) : 0);
    act->caption = PWCSDUP(caption);
    act->tooltip = (tooltip? PWCSDUP(tooltip) : 0);
    act->listener = hsub;
    act->data = userdata;
    act->state = 0;

    action = act->cmd;

 _done:
    LeaveCriticalSection(&cs_actions);

    if (action)
        kmq_post_message(KMSG_ACT, KMSG_ACT_NEW, action, NULL);

    return action;
}

KHMEXP void * KHMAPI
khui_action_get_data(khm_int32 action) {
    khui_action * act;
    void * data;

    EnterCriticalSection(&cs_actions);
    act = khui_find_action(action);
    if (act == NULL || (act->state & KHUI_ACTIONSTATE_DELETED))
        data = NULL;
    else
        data = act->data;
    LeaveCriticalSection(&cs_actions);

    return data;
}

KHMEXP void KHMAPI
khui_action_delete(khm_int32 action) {
    khui_action * act;

    EnterCriticalSection(&cs_actions);

    act = khui_find_action(action);

    if (act == NULL) {
        LeaveCriticalSection(&cs_actions);
        return;
    }

    /* for the moment, even when the action is deleted, we don't free
       up the block of memory used by the khui_action structure.  When
       a new action is created, it will reuse deleted action
       structures. */
    act->state |= KHUI_ACTIONSTATE_DELETED;
    if (act->name)
        PFREE(act->name);
    if (act->caption)
        PFREE(act->caption);
    if (act->tooltip)
        PFREE(act->tooltip);
    if (act->listener)
        kmq_delete_subscription(act->listener);
    act->name = NULL;
    act->caption = NULL;
    act->tooltip = NULL;
    act->listener = NULL;
    LeaveCriticalSection(&cs_actions);

    kmq_post_message(KMSG_ACT, KMSG_ACT_DELETE, action, NULL);
}

#define MENU_NC_ITEMS 8

KHMEXP khui_menu_def * KHMAPI 
khui_menu_create(khm_int32 action)
{
    khui_menu_def * d;

    d = PMALLOC(sizeof(*d));
    ZeroMemory(d, sizeof(*d));

    d->cmd = action;
    d->nc_items = MENU_NC_ITEMS;
    d->items = PMALLOC(sizeof(*(d->items)) * d->nc_items);

    d->state = KHUI_MENUSTATE_ALLOCD;

    if (action) {
        int i;
        EnterCriticalSection(&cs_actions);

        for (i=0; i < khui_n_cust_menus; i++) {
            if (khui_cust_menus[i] == NULL)
                break;
        }

        if (i >= khui_n_cust_menus) {

            if (khui_n_cust_menus + 1 >= khui_nc_cust_menus) {
                khui_nc_cust_menus = UBOUNDSS(khui_n_cust_menus + 1,
                                              CACT_NC_ALLOC, CACT_NC_ALLOC);
                khui_cust_menus =
                    PREALLOC(khui_cust_menus,
                             sizeof(khui_cust_menus[0]) * khui_nc_cust_menus);
            }

            i = khui_n_cust_menus ++;
        }

        khui_cust_menus[i] = d;

        LeaveCriticalSection(&cs_actions);
    }

    return d;
}

KHMEXP void KHMAPI
khui_set_main_window(HWND hwnd) {
    khui_hwnd_main = hwnd;
}

KHMEXP void KHMAPI
khui_action_trigger(khm_int32 action, khui_action_context * ctx) {
    khui_action_context save;

    if (!khui_hwnd_main)
	return;

    if (ctx) {
	khui_context_get(&save);

	khui_context_set_indirect(ctx);
    }

    SendMessage(khui_hwnd_main, WM_COMMAND,
		MAKEWPARAM(action, 0), (LPARAM) 0);

    if (ctx) {
	khui_context_set_indirect(&save);
    }
}

KHMEXP khui_menu_def * KHMAPI 
khui_menu_dup(khui_menu_def * src)
{
    khui_menu_def * d;
    size_t i;
    size_t n;

    EnterCriticalSection(&cs_actions);

    d = khui_menu_create(src->cmd);

    if (!(src->state & KHUI_MENUSTATE_ALLOCD))
        n = khui_action_list_length(src->items);
    else
        n = src->n_items;

    for (i=0; i<n; i++) {
        if (src->items[i].flags & KHUI_ACTIONREF_PACTION) {
            khui_menu_insert_paction(d, -1, src->items[i].p_action, src->items[i].flags);
        } else {
            khui_menu_insert_action(d, -1, src->items[i].action, 0);
        }
    }

    LeaveCriticalSection(&cs_actions);

    return d;
}

KHMEXP void KHMAPI 
khui_menu_delete(khui_menu_def * d)
{
    int i;

    /* non-allocated menus are assumed to have no pointers to other
       allocated blocks */
    if(!(d->state & KHUI_MENUSTATE_ALLOCD)) {
        /* we shouldn't have tried to delete a constant menu */
#ifdef DEBUG
        assert(FALSE);
#endif
        return;
    }

    EnterCriticalSection(&cs_actions);

    for (i=0; i < khui_n_cust_menus; i++) {
        if (khui_cust_menus[i] == d) {
            khui_cust_menus[i] = NULL;
            break;
        }
    }

    for(i=0; i< (int) d->n_items; i++) {
        if(d->items[i].flags & KHUI_ACTIONREF_FREE_PACTION)
            PFREE(d->items[i].p_action);
    }

    if(d->items)
        PFREE(d->items);
    PFREE(d);

    LeaveCriticalSection(&cs_actions);
}

static void
menu_assert_size(khui_menu_def * d, size_t n)
{

    assert(d->state & KHUI_MENUSTATE_ALLOCD);

    if(n > (int) d->nc_items) {
        khui_action_ref * ni;

        d->nc_items = UBOUNDSS(n, MENU_NC_ITEMS, MENU_NC_ITEMS);
        ni = PMALLOC(sizeof(*(d->items)) * d->nc_items);
        memcpy(ni, d->items, sizeof(*(d->items)) * d->n_items);
        PFREE(d->items);
        d->items = ni;
    }
}

static void
menu_const_to_allocd(khui_menu_def * d)
{
    khui_action_ref * olist;
    khui_action_ref * nlist;
    khm_size n;

    assert(!(d->state & KHUI_MENUSTATE_ALLOCD));

    olist = d->items;
    n = khui_action_list_length(d->items);

    d->nc_items = UBOUNDSS(n, MENU_NC_ITEMS, MENU_NC_ITEMS);
    nlist = PMALLOC(sizeof(d->items[0]) * d->nc_items);
    memcpy(nlist, olist, sizeof(d->items[0]) * n);

    d->items = nlist;
    d->n_items = n;
    d->state |= KHUI_MENUSTATE_ALLOCD;
}

KHMEXP void KHMAPI
khui_menu_insert_action(khui_menu_def * d, khm_size idx, khm_int32 action, khm_int32 flags)
{
    khm_size i;

    EnterCriticalSection(&cs_actions);

    if (!(d->state & KHUI_MENUSTATE_ALLOCD))
        menu_const_to_allocd(d);

    assert(d->state & KHUI_MENUSTATE_ALLOCD);
    assert(action == KHUI_MENU_SEP || action > 0);

    if (idx < 0 || idx > d->n_items)
        idx = d->n_items;

    menu_assert_size(d, d->n_items + 1);

    if (idx < d->n_items) {
        memmove(&d->items[idx + 1], &d->items[idx], (d->n_items - idx) * sizeof(d->items[0]));
    }

    d->items[idx].flags = flags;
    d->items[idx].action = action;
    if (action == KHUI_MENU_SEP)
        d->items[idx].flags |= KHUI_ACTIONREF_SEP;

    d->n_items++;

    /* only one action is allowed to have the KHUI_ACTIONREF_DEFAULT
       flag */
    if (flags & KHUI_ACTIONREF_DEFAULT) {
        for (i=0; i < d->n_items; i++) {
            if (i != idx && (d->items[i].flags & KHUI_ACTIONREF_DEFAULT))
                d->items[i].flags &= ~KHUI_ACTIONREF_DEFAULT;
        }
    }

    LeaveCriticalSection(&cs_actions);
}

KHMEXP void KHMAPI
khui_menu_insert_paction(khui_menu_def * d, khm_size idx, khui_action * paction, int flags)
{
    khm_size i;

    if (paction == NULL)
        return;

    EnterCriticalSection(&cs_actions);

    if (!(d->state & KHUI_MENUSTATE_ALLOCD))
        menu_const_to_allocd(d);

    assert(d->state & KHUI_MENUSTATE_ALLOCD);

    if (idx < 0 || idx > d->n_items)
        idx = d->n_items;

    menu_assert_size(d, d->n_items + 1);

    if (idx < d->n_items) {
        memmove(&d->items[idx + 1], &d->items[idx], (d->n_items - idx) * sizeof(d->items[0]));
    }

    d->items[idx].flags = flags | KHUI_ACTIONREF_PACTION;
    d->items[idx].p_action = paction;

    d->n_items++;

    /* only one action is allowed to have the KHUI_ACTIONREF_DEFAULT
       flag */
    if (flags & KHUI_ACTIONREF_DEFAULT) {
        for (i=0; i < d->n_items; i++) {
            if (i != idx && (d->items[i].flags & KHUI_ACTIONREF_DEFAULT))
                d->items[i].flags &= ~KHUI_ACTIONREF_DEFAULT;
        }
    }

    LeaveCriticalSection(&cs_actions);
}

KHMEXP void KHMAPI
khui_menu_remove_action(khui_menu_def * d, khm_size idx) {

    EnterCriticalSection(&cs_actions);

    if (!(d->state & KHUI_MENUSTATE_ALLOCD))
        menu_const_to_allocd(d);

    assert(d->state & KHUI_MENUSTATE_ALLOCD);

    if (idx >= 0 && idx < d->n_items) {

        if (idx < d->n_items - 1) {
            memmove(&d->items[idx], &d->items[idx + 1],
                    ((d->n_items - 1) - idx) * sizeof(d->items[0]));
        }

        d->n_items--;

    }

    LeaveCriticalSection(&cs_actions);
}

KHMEXP khm_size KHMAPI
khui_menu_get_size(khui_menu_def * d) {

    khm_size size;

    EnterCriticalSection(&cs_actions);

    if (d->state & KHUI_MENUSTATE_ALLOCD)
        size = d->n_items;
    else
        size = khui_action_list_length(d->items);

    LeaveCriticalSection(&cs_actions);

    return size;
}

KHMEXP khui_action_ref *
khui_menu_get_action(khui_menu_def * d, khm_size idx) {

    khui_action_ref * act = NULL;
    khm_size n;

    EnterCriticalSection(&cs_actions);

    if (d->state & KHUI_MENUSTATE_ALLOCD)
        n = d->n_items;
    else
        n = khui_action_list_length(d->items);

    if (idx < 0 || idx >= n)
        act = NULL;
    else
        act = &d->items[idx];

    LeaveCriticalSection(&cs_actions);

    return act;
}

KHMEXP khui_menu_def * KHMAPI
khui_find_menu(khm_int32 id) {
    khui_menu_def * d;
    int i;

    if (id < KHUI_USERACTION_BASE) {

        /* the list of system menus are considered immutable. */

        d = khui_all_menus;
        for(i=0;i<khui_n_all_menus;i++) {
            if(id == d[i].cmd)
                return &d[i];
        }

        return NULL;
    } else {
        d = NULL;

        EnterCriticalSection(&cs_actions);
        for (i=0; i < khui_n_cust_menus; i++) {
            if (khui_cust_menus[i] &&
                khui_cust_menus[i]->cmd == id) {
                d = khui_cust_menus[i];
                break;
            }
        }
        LeaveCriticalSection(&cs_actions);

        return d;
    }
}

KHMEXP khui_action * KHMAPI
khui_find_action(khm_int32 id) {
    khui_action * act;
    int i;

    act = khui_actions;
    for(i=0;i<khui_n_actions;i++) {
        if(act[i].cmd == id)
            return &act[i];
    }

    act = NULL;

    EnterCriticalSection(&cs_actions);
    if (id >= KHUI_USERACTION_BASE &&
        (id - KHUI_USERACTION_BASE) < khui_n_cust_actions) {
        act = khui_cust_actions[id - KHUI_USERACTION_BASE];
#ifdef DEBUG
        assert(!act || act->cmd == id);
#endif
        if (act && (act->state & KHUI_ACTIONSTATE_DELETED))
            act = NULL;
    }
    LeaveCriticalSection(&cs_actions);

    return act;
}

KHMEXP khui_action * KHMAPI
khui_find_named_action(const wchar_t * name) {
    int i;
    khui_action * act;
    khui_action ** pact;

    if(!name)
        return NULL;

    act = khui_actions;
    for(i=0;i<khui_n_actions;i++) {
        if(!act[i].name)
            continue;
        if(!wcscmp(act[i].name, name))
            return &act[i];
    }

    act = NULL;

    EnterCriticalSection(&cs_actions);

    pact = khui_cust_actions;
    for(i=0;i<khui_n_cust_actions;i++) {
        if(!pact[i] || !pact[i]->name)
            continue;

        if(!wcscmp(pact[i]->name, name)) {

            if (!(pact[i]->state & KHUI_ACTIONSTATE_DELETED)) {
                act = pact[i];
            }
            break;
        }
    }

    LeaveCriticalSection(&cs_actions);

    return act;
}

KHMEXP size_t KHMAPI
khui_action_list_length(khui_action_ref * ref) {
    size_t c = 0;

    EnterCriticalSection(&cs_actions);

    while(ref && ref->action != KHUI_MENU_END &&
          !(ref->flags & KHUI_ACTIONREF_END)) {
        c++;
        ref++;
    }

    LeaveCriticalSection(&cs_actions);

    return c;
}

KHMEXP void KHMAPI
khui_check_radio_action(khui_menu_def * d, khm_int32 cmd)
{
    khui_action_ref * r;
    khui_action * act;

    EnterCriticalSection(&cs_actions);

    r = d->items;
    while(r && r->action != KHUI_MENU_END &&
          (!(d->state & KHUI_MENUSTATE_ALLOCD) || (r - d->items) < (int) d->n_items)) {
        if(r->flags & KHUI_ACTIONREF_PACTION) {
            act = r->p_action;
        } else {
            act = khui_find_action(r->action);
        }

        if(act) {
            if(act->cmd == cmd)
                act->state |= KHUI_ACTIONSTATE_CHECKED;
            else
                act->state &= ~KHUI_ACTIONSTATE_CHECKED;
        }
        r++;
    }

    LeaveCriticalSection(&cs_actions);

    kmq_post_message(KMSG_ACT, KMSG_ACT_CHECK, 0, 0);
}

KHMEXP void KHMAPI
khui_check_action(khm_int32 cmd, khm_boolean check) {
    khui_action * act;

    act = khui_find_action(cmd);
    if (!act)
        return;

    EnterCriticalSection(&cs_actions);

    if (check && !(act->state & KHUI_ACTIONSTATE_CHECKED))
        act->state |= KHUI_ACTIONSTATE_CHECKED;
    else if (!check && (act->state & KHUI_ACTIONSTATE_CHECKED))
        act->state &= ~KHUI_ACTIONSTATE_CHECKED;
    else {
        LeaveCriticalSection(&cs_actions);
        return;
    }

    LeaveCriticalSection(&cs_actions);

    kmq_post_message(KMSG_ACT, KMSG_ACT_CHECK, 0, 0);
}

KHMEXP void KHMAPI
khui_enable_actions(khui_menu_def * d, khm_boolean enable)
{
    khui_action_ref * r;
    int delta = FALSE;
    khui_action * act;

    EnterCriticalSection(&cs_actions);

    r = d->items;
    while(r && r->action != KHUI_MENU_END &&
          (!(d->state & KHUI_MENUSTATE_ALLOCD) || (r - d->items) < (int) d->n_items)) {
        if(r->flags & KHUI_ACTIONREF_PACTION) {
            act = r->p_action;
        } else {
            act = khui_find_action(r->action);
        }

        if(act) {
            int old_state = act->state;

            if(enable)
                act->state &= ~KHUI_ACTIONSTATE_DISABLED;
            else
                act->state |= KHUI_ACTIONSTATE_DISABLED;

            if(old_state != act->state)
                delta = TRUE;
        }
        r++;
    }

    LeaveCriticalSection(&cs_actions);

    if(delta) {
        kmq_post_message(KMSG_ACT, KMSG_ACT_ENABLE, 0, 0);
    }
}

KHMEXP void KHMAPI
khui_enable_action(khm_int32 cmd, khm_boolean enable) {
    khui_action * act;

    act = khui_find_action(cmd);
    if (!act)
        return;

    EnterCriticalSection(&cs_actions);

    if (enable && (act->state & KHUI_ACTIONSTATE_DISABLED)) {
        act->state &= ~KHUI_ACTIONSTATE_DISABLED;
    } else if (!enable && !(act->state & KHUI_ACTIONSTATE_DISABLED)) {
        act->state |= KHUI_ACTIONSTATE_DISABLED;
    } else {
        LeaveCriticalSection(&cs_actions);
        return;
    }

    LeaveCriticalSection(&cs_actions);

    kmq_post_message(KMSG_ACT, KMSG_ACT_ENABLE, 0, 0);
}

KHMEXP HACCEL KHMAPI
khui_create_global_accel_table(void) {
    int i;
    ACCEL * accels;
    HACCEL ha;

    accels = PMALLOC(sizeof(ACCEL) * khui_n_accel_global);
    for(i=0;i<khui_n_accel_global;i++) {
        accels[i].cmd = khui_accel_global[i].cmd;
        accels[i].fVirt = khui_accel_global[i].mod;
        accels[i].key = khui_accel_global[i].key;
    }

    ha = CreateAcceleratorTable(accels, khui_n_accel_global);

    PFREE(accels);

    return ha;
}

KHMEXP khm_boolean KHMAPI 
khui_get_cmd_accel_string(khm_int32 cmd, 
                          wchar_t * buf, 
                          khm_size bufsiz) {
    int i;
    khui_accel_def * def;

    /* should at least hold 2 characters */
    if(bufsiz < sizeof(wchar_t) * 2)
        return FALSE;

    buf[0] = L'\0';

    for(i=0;i<khui_n_accel_global;i++) {
        if(khui_accel_global[i].cmd == cmd)
            break;
    }

    if(i==khui_n_accel_global)
        return FALSE;

    def = &khui_accel_global[i];

    if(def->mod & FALT) {
        if(FAILED(StringCbCat(buf, bufsiz, L"Alt+")))
            return FALSE;
    }


    if(def->mod & FCONTROL) {
        if(FAILED(StringCbCat(buf, bufsiz, L"Ctrl+")))
            return FALSE;
    }

    if(def->mod & FSHIFT) {
        if(FAILED(StringCbCat(buf, bufsiz, L"Shift+")))
            return FALSE;
    }

    if(def->mod & FVIRTKEY) {
        wchar_t mbuf[6];
        wchar_t * ap = NULL;
        switch(def->key) {
        case VK_TAB:
            ap = L"Tab";
            break;

        case VK_ESCAPE:
            ap = L"Esc";
            break;

        case VK_RETURN:
            ap = L"Enter";
            break;

        case VK_F1:
            ap = L"F1";
            break;

        case VK_F2:
            ap = L"F2";
            break;

        case VK_F3:
            ap = L"F3";
            break;

        case VK_F4:
            ap = L"F4";
            break;

        case VK_F5:
            ap = L"F5";
            break;

        case VK_F6:
            ap = L"F6";
            break;

        case VK_F7:
            ap = L"F7";
            break;

        case VK_F8:
            ap = L"F8";
            break;

        case VK_F9:
            ap = L"F9";
            break;

        case VK_F10:
            ap = L"F10";
            break;

        case VK_F11:
            ap = L"F11";
            break;

        case VK_F12:
            ap = L"F12";
            break;

        case VK_DELETE:
            ap = L"Del";
            break;

        default:
            if((def->key >= '0' && 
                def->key <= '9') || 
               (def->key >= 'A' && 
                def->key <= 'Z')) {
                ap = mbuf;
                mbuf[0] = (wchar_t) def->key;
                mbuf[1] = L'\0';
            }
        }
        if(ap) {
            if(FAILED(StringCbCat(buf, bufsiz, ap)))
                return FALSE;
        }
        else {
            if(FAILED(StringCbCat(buf, bufsiz,L"???")))
                return FALSE;
        }

    } else {
        wchar_t mbuf[2];

        mbuf[0] = def->key;
        mbuf[1] = L'\0';

        if(FAILED(StringCbCat(buf, bufsiz, mbuf)))
            return FALSE;
    }

    return TRUE;
}

/******************************************/
/* contexts */

#define KHUI_ACTION_CONTEXT_MAGIC 0x39c49db5

static khm_int32 KHMAPI
khuiint_filter_selected(khm_handle cred,
                        khm_int32 vflags,
                        void * rock) {
    khm_int32 flags;
    if (KHM_SUCCEEDED(kcdb_cred_get_flags(cred, &flags)) &&
        (flags & KCDB_CRED_FLAG_SELECTED))
        return TRUE;
    else
        return FALSE;
}

static void
khuiint_context_release(khui_action_context * ctx) {
    ctx->scope = KHUI_SCOPE_NONE;
    if (ctx->identity)
        kcdb_identity_release(ctx->identity);
    ctx->identity = NULL;
    ctx->cred_type = KCDB_CREDTYPE_INVALID;
    if (ctx->cred)
        kcdb_cred_release(ctx->cred);
    ctx->cred = NULL;
    ctx->n_headers = 0;
    if (ctx->credset)
        kcdb_credset_flush(ctx->credset);
    ctx->n_sel_creds = 0;
    ctx->int_cb_used = 0;
    ctx->vparam = NULL;
    ctx->cb_vparam = 0;
}

static void
khuiint_copy_context(khui_action_context * ctxdest,
                     const khui_action_context * ctxsrc)
{
    ctxdest->scope = ctxsrc->scope;

    if (ctxsrc->scope == KHUI_SCOPE_IDENT) {
        ctxdest->identity = ctxsrc->identity;
        kcdb_identity_hold(ctxsrc->identity);
    } else if (ctxsrc->scope == KHUI_SCOPE_CREDTYPE) {
        ctxdest->identity = ctxsrc->identity;
        ctxdest->cred_type = ctxsrc->cred_type;
        if (ctxsrc->identity != NULL)
            kcdb_identity_hold(ctxsrc->identity);
    } else if (ctxsrc->scope == KHUI_SCOPE_CRED) {
        kcdb_cred_get_identity(ctxsrc->cred, &ctxdest->identity);
        kcdb_cred_get_type(ctxsrc->cred, &ctxdest->cred_type);
        ctxdest->cred = ctxsrc->cred;
        kcdb_cred_hold(ctxsrc->cred);
    } else if (ctxsrc->scope == KHUI_SCOPE_GROUP) {
        khm_size cb_total;
        int i;

        ctxdest->n_headers = ctxsrc->n_headers;
        cb_total = 0;
        for (i=0; i < (int) ctxsrc->n_headers; i++) {
            cb_total += UBOUND32(ctxsrc->headers[i].cb_data);
        }

        if (ctxdest->int_cb_buf < cb_total) {

            if (ctxdest->int_buf)
                PFREE(ctxdest->int_buf);

            ctxdest->int_cb_buf = cb_total;
            ctxdest->int_buf = PMALLOC(cb_total);
        }

#ifdef DEBUG
        assert(ctxdest->int_buf || cb_total == 0);
#endif
        ctxdest->int_cb_used = 0;

        for (i=0; i < (int) ctxsrc->n_headers; i++) {
            ctxdest->headers[i].attr_id = ctxsrc->headers[i].attr_id;
            ctxdest->headers[i].cb_data = ctxsrc->headers[i].cb_data;
            if (ctxsrc->headers[i].cb_data > 0) {
                ctxdest->headers[i].data = 
                    BYTEOFFSET(ctxdest->int_buf,
                               ctxdest->int_cb_used);
                memcpy(ctxdest->headers[i].data,
                       ctxsrc->headers[i].data,
                       ctxsrc->headers[i].cb_data);
                ctxdest->int_cb_used += 
                    UBOUND32(ctxsrc->headers[i].cb_data);
            } else {
                ctxdest->headers[i].data = NULL;
            }
        }
    }

    if (ctxsrc->credset) {

        if (ctxdest->credset == NULL)
            kcdb_credset_create(&ctxdest->credset);
#ifdef DEBUG
        assert(ctxdest->credset != NULL);
#endif

        kcdb_credset_flush(ctxdest->credset);
        
        kcdb_credset_extract_filtered(ctxdest->credset,
                                      ctxsrc->credset,
                                      khuiint_filter_selected,
                                      NULL);

        kcdb_credset_get_size(ctxdest->credset,
                              &ctxdest->n_sel_creds);
    } else {
        if (ctxdest->credset != NULL)
            kcdb_credset_flush(ctxdest->credset);
        ctxdest->n_sel_creds = 0;
    }

    /* For now, we simply transfer the vparam buffer into the new
       context.  If we are copying, we also need to modify
       khui_context_release() to free the allocated buffer */
#if 0
    if (ctxsrc->vparam && ctxsrc->cb_vparam) {
        ctxdest->vparam = PMALLOC(ctxsrc->cb_vparam);
#ifdef DEBUG
        assert(ctxdest->vparam);
#endif
        memcpy(ctxdest->vparam, ctxsrc->vparam, ctxsrc->cb_vparam);
        ctxdest->cb_vparam = ctxsrc->cb_vparam;
    } else {
#endif
        ctxdest->vparam = ctxsrc->vparam;
        ctxdest->cb_vparam = ctxsrc->cb_vparam;
#if 0
    }
#endif
}

static void 
khuiint_context_init(khui_action_context * ctx) {
    ctx->magic = KHUI_ACTION_CONTEXT_MAGIC;
    ctx->scope = KHUI_SCOPE_NONE;
    ctx->identity = NULL;
    ctx->cred_type = KCDB_CREDTYPE_INVALID;
    ctx->cred = NULL;
    ZeroMemory(ctx->headers, sizeof(ctx->headers));
    ctx->n_headers = 0;
    ctx->credset = NULL;
    ctx->n_sel_creds = 0;
    ctx->int_buf = NULL;
    ctx->int_cb_buf = 0;
    ctx->int_cb_used = 0;
    ctx->vparam = NULL;
    ctx->cb_vparam = 0;
}

khui_action_context khui_ctx = {
    KHUI_ACTION_CONTEXT_MAGIC,
    KHUI_SCOPE_NONE,
    NULL, 
    KCDB_CREDTYPE_INVALID, 
    NULL,
    {
        {KCDB_ATTR_INVALID,NULL,0},
        {KCDB_ATTR_INVALID,NULL,0},
        {KCDB_ATTR_INVALID,NULL,0},
        {KCDB_ATTR_INVALID,NULL,0},
        {KCDB_ATTR_INVALID,NULL,0},
        {KCDB_ATTR_INVALID,NULL,0}
    },
    0,
    NULL,
    0,
    NULL,
    0,
    0,
    NULL,
    0};

khm_int32 KHMAPI
set_cred_select_flag(khm_handle cred, void * rock) {
    kcdb_cred_set_flags(cred, KCDB_CRED_FLAG_SELECTED,
                        KCDB_CRED_FLAG_SELECTED);
    return KHM_ERROR_SUCCESS;
}

KHMEXP void KHMAPI
khui_context_create(khui_action_context * ctx,
                    khui_scope scope,
                    khm_handle identity,
                    khm_int32 cred_type,
                    khm_handle cred)
{
    khui_action_context tctx;

    khuiint_context_init(&tctx);
    khuiint_context_init(ctx);

    tctx.scope = scope;
    tctx.identity = identity;
    tctx.cred_type = cred_type;
    tctx.cred = cred;

    /* fill up the credset based on the scope */
    if (scope != KHUI_SCOPE_NONE) {
        if (tctx.credset == NULL)
            kcdb_credset_create(&tctx.credset);
        else
            kcdb_credset_flush(tctx.credset);

        if (scope == KHUI_SCOPE_IDENT) {
            kcdb_credset_extract(tctx.credset,
                                 NULL,
                                 tctx.identity,
                                 KCDB_CREDTYPE_INVALID);
        } else if (scope == KHUI_SCOPE_CREDTYPE) {
            kcdb_credset_extract(tctx.credset,
                                 NULL,
                                 tctx.identity,
                                 tctx.cred_type);
        } else if (scope == KHUI_SCOPE_CRED) {
            khm_handle dupcred = NULL;
            kcdb_cred_dup(cred, &dupcred);

            kcdb_credset_add_cred(tctx.credset, dupcred, -1);
        } else {
#ifdef DEBUG
            /* KHUI_SCOPE_GROUP is not used with
               khui_context_create() */
            assert(FALSE);
#endif
        }

        kcdb_credset_apply(tctx.credset, set_cred_select_flag,
                           NULL);

        kcdb_credset_seal(tctx.credset);
    }

    khuiint_copy_context(ctx, &tctx);
}

KHMEXP void KHMAPI 
khui_context_set(khui_scope scope, 
                 khm_handle identity, 
                 khm_int32 cred_type, 
                 khm_handle cred,
                 khui_header *headers,
                 khm_size n_headers,
                 khm_handle cs_src) {

    khui_context_set_ex(scope,
                        identity,
                        cred_type,
                        cred,
                        headers,
                        n_headers,
                        cs_src,
                        NULL,
                        0);
}

KHMEXP void KHMAPI 
khui_context_set_ex(khui_scope scope, 
                    khm_handle identity, 
                    khm_int32 cred_type, 
                    khm_handle cred,
                    khui_header *headers,
                    khm_size n_headers,
                    khm_handle cs_src,
                    void * vparam,
                    khm_size cb_vparam)
{
    khui_action_context tctx;

    EnterCriticalSection(&cs_actions);

    khuiint_context_release(&khui_ctx);

    khuiint_context_init(&tctx);

    tctx.scope = scope;
    tctx.identity = identity;
    tctx.cred_type = cred_type;
    tctx.cred = cred;
    if (headers) {
        tctx.n_headers = n_headers;
        memcpy(tctx.headers,
               headers,
               sizeof(*headers) * n_headers);
    } else {
        tctx.n_headers = 0;
    }
    tctx.credset = cs_src;
    tctx.n_sel_creds = 0;       /* ignored */
    tctx.vparam = vparam;
    tctx.cb_vparam = cb_vparam;
    tctx.int_buf = NULL;
    tctx.int_cb_buf = 0;
    tctx.int_cb_used = 0;

    khuiint_copy_context(&khui_ctx, &tctx);

    khui_context_refresh();

    LeaveCriticalSection(&cs_actions);
}

KHMEXP void KHMAPI
khui_context_set_indirect(khui_action_context * ctx)
{
    EnterCriticalSection(&cs_actions);

    khuiint_context_release(&khui_ctx);

    khuiint_copy_context(&khui_ctx, ctx);

    khui_context_refresh();

    LeaveCriticalSection(&cs_actions);
}

KHMEXP void KHMAPI 
khui_context_refresh(void) {
    khm_int32 flags;

    EnterCriticalSection(&cs_actions);
    if (khui_ctx.identity) {
        /* an identity is selected */

        if (KHM_SUCCEEDED(kcdb_identity_get_flags(khui_ctx.identity,
                                                  &flags)) &&
            (flags & KCDB_IDENT_FLAG_DEFAULT)) {
            khui_check_action(KHUI_ACTION_SET_DEF_ID, TRUE);
            khui_enable_action(KHUI_ACTION_SET_DEF_ID, FALSE);
        } else {
            khui_check_action(KHUI_ACTION_SET_DEF_ID, FALSE);
            khui_enable_action(KHUI_ACTION_SET_DEF_ID, TRUE);
        }
    } else {
        khui_check_action(KHUI_ACTION_SET_DEF_ID, FALSE);
        khui_enable_action(KHUI_ACTION_SET_DEF_ID, FALSE);
    }

    if (khui_ctx.scope != KHUI_SCOPE_NONE) {
        khui_enable_action(KHUI_ACTION_PROPERTIES, TRUE);
    } else {
        khui_enable_action(KHUI_ACTION_PROPERTIES, FALSE);
    }

    LeaveCriticalSection(&cs_actions);

    kmq_post_message(KMSG_ACT, KMSG_ACT_REFRESH, 0, 0);
}

KHMEXP void KHMAPI 
khui_context_get(khui_action_context * ctx)
{
    EnterCriticalSection(&cs_actions);

    khuiint_context_init(ctx);
    khuiint_copy_context(ctx, &khui_ctx);

    if (ctx->credset) {
        kcdb_credset_seal(ctx->credset);
    }

    LeaveCriticalSection(&cs_actions);
}

KHMEXP void KHMAPI 
khui_context_release(khui_action_context * ctx)
{
#ifdef DEBUG
    assert(ctx->magic == KHUI_ACTION_CONTEXT_MAGIC);
#endif

    khuiint_context_release(ctx);
    if (ctx->credset) {
        kcdb_credset_unseal(ctx->credset);
        kcdb_credset_delete(ctx->credset);
    }
    ctx->credset = NULL;
    if (ctx->int_buf)
        PFREE(ctx->int_buf);
    ctx->int_buf = NULL;
#if 0
    if (ctx->vparam && ctx->cb_vparam > 0) {
        PFREE(ctx->vparam);
        ctx->vparam = NULL;
    }
    ctx->cb_vparam = 0;
#else
    ctx->vparam = 0;
    ctx->cb_vparam = 0;
#endif
}

KHMEXP void KHMAPI 
khui_context_reset(void)
{
    EnterCriticalSection(&cs_actions);

    khuiint_context_release(&khui_ctx);

    khui_context_refresh();

    LeaveCriticalSection(&cs_actions);
}

KHMEXP khm_int32 KHMAPI
khui_context_cursor_filter(khm_handle cred,
                           khm_int32 flags,
                           void * rock) {
    khui_action_context * ctx = (khui_action_context *) rock;
    khm_int32 rv;

    if (ctx->scope == KHUI_SCOPE_NONE)
        return 0;
    else if (ctx->scope == KHUI_SCOPE_IDENT) {
        khm_handle c_ident;

        if (KHM_FAILED(kcdb_cred_get_identity(cred, &c_ident)))
            return 0;

        rv = (c_ident == ctx->identity);

        kcdb_identity_release(c_ident);

        return rv;
    } else if (ctx->scope == KHUI_SCOPE_CREDTYPE) {
        khm_handle c_ident;
        khm_int32 c_type;

        if (KHM_FAILED(kcdb_cred_get_type(cred, &c_type)) ||
            c_type != ctx->cred_type)
            return 0;

        if (ctx->identity == NULL)
            return 1;

        if (KHM_FAILED(kcdb_cred_get_identity(cred, &c_ident)))
            return 0;

        rv = (c_ident == ctx->identity);

        kcdb_identity_release(c_ident);

        return rv;
    } else if (ctx->scope == KHUI_SCOPE_CRED) {
        return kcdb_creds_is_equal(cred, ctx->cred);
    } else if (ctx->scope == KHUI_SCOPE_GROUP) {
        int i;

        rv = 1;

        for (i=0; i < (int) ctx->n_headers && rv; i++) {
            kcdb_attrib * pattr;
            kcdb_type * ptype;
            DWORD buffer[1024]; /* 4096 bytes */
            khm_size cb;

            if (kcdb_cred_get_attr(cred, ctx->headers[i].attr_id,
                                   NULL,
                                   NULL,
                                   &cb) != KHM_ERROR_TOO_LONG) {
                /* the header doesn't exist anyway */
                rv = (ctx->headers[i].cb_data == 0);
                continue;
            }
#ifdef DEBUG
            assert(cb <= sizeof(buffer));
#endif
            cb = sizeof(buffer);

            if (KHM_FAILED(kcdb_cred_get_attr(cred,
                                              ctx->headers[i].attr_id,
                                              NULL,
                                              (void *) buffer,
                                              &cb))) {
                rv = 0;
                continue;
            }

            if (KHM_FAILED(kcdb_attrib_get_info(ctx->headers[i].attr_id,
                                                &pattr))) {
                rv = 0;
                continue;
            }

            if (KHM_FAILED(kcdb_type_get_info(pattr->type, &ptype))) {
                rv = 0;
                kcdb_attrib_release_info(pattr);
                continue;
            }

            if ((*ptype->comp)(ctx->headers[i].data,
                               ctx->headers[i].cb_data,
                               (void *) buffer,
                               cb) != 0)
                rv = 1;

            kcdb_type_release_info(ptype);
            kcdb_attrib_release_info(pattr);
        }

        return rv;
    } else
        return 0;
}

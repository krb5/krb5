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

#ifndef __KHIMAIRA_ACTIONDEF_H
#define __KHIMAIRA_ACTIONDEF_H

/*! \ingroup khui_actions
  @{*/
/*! \defgroup khui_std_actions Standard Actions
@{ */

/*!\name Standard actions
  @{*/
#define KHUI_ACTION_BASE 50000

#define KHUI_ACTION_PROPERTIES  (KHUI_ACTION_BASE + 0)
#define KHUI_ACTION_EXIT        (KHUI_ACTION_BASE + 1)
#define KHUI_ACTION_SET_DEF_ID  (KHUI_ACTION_BASE + 3)
#define KHUI_ACTION_SET_SRCH_ID (KHUI_ACTION_BASE + 4)
#define KHUI_ACTION_PASSWD_ID   (KHUI_ACTION_BASE + 7)
#define KHUI_ACTION_NEW_CRED    (KHUI_ACTION_BASE + 8)
#define KHUI_ACTION_DEBUG_WINDOW    (KHUI_ACTION_BASE + 10)
#define KHUI_ACTION_VIEW_REFRESH    (KHUI_ACTION_BASE + 11)
#define KHUI_ACTION_LAYOUT_ID   (KHUI_ACTION_BASE + 12)
#define KHUI_ACTION_LAYOUT_TYPE (KHUI_ACTION_BASE + 13)
#define KHUI_ACTION_LAYOUT_LOC  (KHUI_ACTION_BASE + 14)
#define KHUI_ACTION_TB_STANDARD (KHUI_ACTION_BASE + 15)
#define KHUI_ACTION_OPT_KHIM    (KHUI_ACTION_BASE + 16)
#define KHUI_ACTION_OPT_IDENTS  (KHUI_ACTION_BASE + 17)
#define KHUI_ACTION_OPT_NOTIF   (KHUI_ACTION_BASE + 18)
#define KHUI_ACTION_HELP_CTX    (KHUI_ACTION_BASE + 19)
#define KHUI_ACTION_HELP_CONTENTS   (KHUI_ACTION_BASE + 20)
#define KHUI_ACTION_HELP_INDEX  (KHUI_ACTION_BASE + 21)
#define KHUI_ACTION_HELP_ABOUT  (KHUI_ACTION_BASE + 22)
#define KHUI_ACTION_DESTROY_CRED    (KHUI_ACTION_BASE + 23)
#define KHUI_ACTION_RENEW_CRED  (KHUI_ACTION_BASE + 24)
#define KHUI_ACTION_OPEN_APP    (KHUI_ACTION_BASE + 25)
#define KHUI_ACTION_MENU_ACTIVATE   (KHUI_ACTION_BASE + 26)
#define KHUI_ACTION_CLOSE_APP   (KHUI_ACTION_BASE + 27)
#define KHUI_ACTION_IMPORT      (KHUI_ACTION_BASE + 28)
#define KHUI_ACTION_OPT_PLUGINS (KHUI_ACTION_BASE + 29)
#define KHUI_ACTION_LAYOUT_CUST (KHUI_ACTION_BASE + 30)
#define KHUI_ACTION_OPT_APPEAR  (KHUI_ACTION_BASE + 31)
#define KHUI_ACTION_LAYOUT_RELOAD (KHUI_ACTION_BASE + 32)
#define KHUI_ACTION_RENEW_ALL   (KHUI_ACTION_BASE + 33)
#define KHUI_ACTION_DESTROY_ALL (KHUI_ACTION_BASE + 34)
#define KHUI_ACTION_UICB        (KHUI_ACTION_BASE + 35)
#define KHUI_ACTION_LAYOUT_MINI (KHUI_ACTION_BASE + 36)
#define KHUI_ACTION_VIEW_ALL_IDS (KHUI_ACTION_BASE + 37)
/*@}*/

/*! \name Pseudo actions 

Pseudo actions do not trigger any specific function, but acts as a
signal of some generic event which will be interpreted based on
context.

@{*/
#define KHUI_PACTION_BASE   (KHUI_ACTION_BASE + 500)

#define KHUI_PACTION_MENU   (KHUI_PACTION_BASE + 0)
#define KHUI_PACTION_UP     (KHUI_PACTION_BASE + 1)
#define KHUI_PACTION_DOWN   (KHUI_PACTION_BASE + 2)
#define KHUI_PACTION_LEFT   (KHUI_PACTION_BASE + 3)
#define KHUI_PACTION_RIGHT  (KHUI_PACTION_BASE + 4)
#define KHUI_PACTION_ENTER  (KHUI_PACTION_BASE + 5)
#define KHUI_PACTION_ESC    (KHUI_PACTION_BASE + 6)
#define KHUI_PACTION_OK     (KHUI_PACTION_BASE + 7)
#define KHUI_PACTION_CANCEL (KHUI_PACTION_BASE + 8)
#define KHUI_PACTION_CLOSE  (KHUI_PACTION_BASE + 9)
#define KHUI_PACTION_DELETE (KHUI_PACTION_BASE + 10)
#define KHUI_PACTION_UP_EXTEND (KHUI_PACTION_BASE + 11)
#define KHUI_PACTION_UP_TOGGLE (KHUI_PACTION_BASE + 12)
#define KHUI_PACTION_DOWN_EXTEND (KHUI_PACTION_BASE + 13)
#define KHUI_PACTION_DOWN_TOGGLE (KHUI_PACTION_BASE + 14)
#define KHUI_PACTION_BLANK  (KHUI_PACTION_BASE + 15)
#define KHUI_PACTION_NEXT   (KHUI_PACTION_BASE + 16)
#define KHUI_PACTION_SELALL (KHUI_PACTION_BASE + 17)
#define KHUI_PACTION_YES    (KHUI_PACTION_BASE + 18)
#define KHUI_PACTION_NO     (KHUI_PACTION_BASE + 19)
#define KHUI_PACTION_YESALL (KHUI_PACTION_BASE + 20)
#define KHUI_PACTION_NOALL  (KHUI_PACTION_BASE + 21)
#define KHUI_PACTION_REMOVE (KHUI_PACTION_BASE + 22)
#define KHUI_PACTION_KEEP   (KHUI_PACTION_BASE + 23)
#define KHUI_PACTION_DISCARD (KHUI_PACTION_BASE + 24)
#define KHUI_PACTION_PGDN   (KHUI_PACTION_BASE + 25)
#define KHUI_PACTION_PGUP   (KHUI_PACTION_BASE + 26)
#define KHUI_PACTION_PGUP_EXTEND (KHUI_PACTION_BASE + 27)
#define KHUI_PACTION_PGDN_EXTEND (KHUI_PACTION_BASE + 28)

/*@}*/

/*! \name Menus

Stock menus.

@{*/
#define KHUI_MENU_BASE      (KHUI_ACTION_BASE + 1000)

#define KHUI_MENU_MAIN      (KHUI_MENU_BASE + 0)
#define KHUI_MENU_FILE      (KHUI_MENU_BASE + 1)
#define KHUI_MENU_CRED      (KHUI_MENU_BASE + 2)
#define KHUI_MENU_VIEW      (KHUI_MENU_BASE + 3)
#define KHUI_MENU_OPTIONS   (KHUI_MENU_BASE + 4)
#define KHUI_MENU_HELP      (KHUI_MENU_BASE + 5)

#define KHUI_MENU_LAYOUT    (KHUI_MENU_BASE + 6)
#define KHUI_MENU_TOOLBARS  (KHUI_MENU_BASE + 7)

#define KHUI_MENU_IDENT_CTX (KHUI_MENU_BASE + 8)
#define KHUI_MENU_TOK_CTX   (KHUI_MENU_BASE + 9)
#define KHUI_MENU_ICO_CTX_MIN    (KHUI_MENU_BASE + 12)
#define KHUI_MENU_ICO_CTX_NORMAL (KHUI_MENU_BASE + 13)
#define KHUI_MENU_CWHEADER_CTX   (KHUI_MENU_BASE + 14)

#define KHUI_MENU_COLUMNS   (KHUI_MENU_BASE + 15)

#define KHUI_PMENU_TOK_SEL  (KHUI_MENU_BASE + 10)
#define KHUI_PMENU_ID_SEL   (KHUI_MENU_BASE + 11)

#define KHUI_MENU_DESTROY_CRED (KHUI_MENU_BASE + 16)
#define KHUI_MENU_RENEW_CRED (KHUI_MENU_BASE + 17)
#define KHUI_MENU_SETDEF    (KHUI_MENU_BASE + 18)

/*@}*/

/*! \name Toolbars
@{*/
#define KHUI_TOOLBAR_BASE   (KHUI_ACTION_BASE + 2000)

#define KHUI_TOOLBAR_STANDARD   (KHUI_TOOLBAR_BASE + 0)
/*@}*/

/*! \brief Base for user actions

    When creating new actions, the UI library will allocate command
    identifiers starting with this one.
*/
#define KHUI_USERACTION_BASE    (KHUI_ACTION_BASE + 10000)

/*! \brief Does this command represent a user action? */
#define IS_USERACTION(cmd) ((cmd) >= KHUI_USERACTION_BASE)
/*@}*/
/*@}*/

#endif

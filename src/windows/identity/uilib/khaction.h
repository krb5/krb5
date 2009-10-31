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

#ifndef __KHIMAIRA_ACTION_H
#define __KHIMAIRA_ACTION_H

/*! \addtogroup khui
  @{*/
/*! \defgroup khui_actions Actions
  @{*/

struct tag_khui_action;
typedef struct tag_khui_action khui_action;

/*! \brief Unknown action type

    Unknown action type.
 */
#define KHUI_ACTIONTYPE_NONE    0

/*! \brief A trigger type action

    A trigger action usually triggers some event, which is what pretty
    much every action does.
*/
#define KHUI_ACTIONTYPE_TRIGGER 1

/*! \brief A toggle type action

    A toggle type action typically changes the CHECKED state of the
    action each time it is invoked.
 */
#define KHUI_ACTIONTYPE_TOGGLE  2

/*! \brief The action is enabled

    This is the default if no other state is specified.  Just means
    not-disabled.
*/
#define KHUI_ACTIONSTATE_ENABLED    0

/*! \brief The action is diabled */
#define KHUI_ACTIONSTATE_DISABLED   1

/*! \brief For toggle type actions, the action is checked */
#define KHUI_ACTIONSTATE_CHECKED    2

/*! \brief The action is hot

    Typically this means that the user is hovering the pointing device
    over a UI element representing the action.
 */
#define KHUI_ACTIONSTATE_HOT        4

/*! \brief The action has been marked for deletion

    For custom actions, this means that the custom action was deleted.
    The contents of the custom action fields are no longer valid.
 */
#define KHUI_ACTIONSTATE_DELETED    8

#ifdef NOEXPORT
#define ACTION_SIMPLE(c,cap,des,top) \
    {c,KHUI_ACTIONTYPE_TRIGGER,NULL,0,0,0,0,0,cap,des,top,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0}

#define ACTION_FULL(cmd,type,name,inormal,ihot,idis,isml,ismld,capt,toolt,topic,state) \
    {cmd,type,name,inormal,ihot,idis,isml,ismld,capt,toolt,topic,NULL,NULL,NULL,NULL,NULL,NULL,NULL,state}

#define ACTION_SIMPLE_IMAGE(c,inormal, ihot, idis, isml, ismld,cap, des, top) \
    {c,KHUI_ACTIONTYPE_TRIGGER,NULL,inormal,ihot,idis,isml,ismld,cap,des,top,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0}
#endif

/*! \brief A reference to an action

    If the \a flags member has the KHUI_ACTIONREF_PACTION bit set,
    then the action is referenced by the \a p_action member of the
    union.  Otherwise the identifier for the action is specified by \a
    action member.
*/
typedef struct tag_khui_action_ref {
    int flags;                  /*!< A combination of KHUI_ACTIONREF_* */
    union {
        khm_int32     action;   /*!< The action identifier for the
                                  action that is being referrred to.
                                  Only valid if
                                  ::KHUI_ACTIONREF_PACTION is not set
                                  in \a flags. */
        khui_action * p_action; /*!< A pointer to the ::khui_action
                                  structure that describes the action
                                  that is being referred to.  Only
                                  valid if ::KHUI_ACTIONREF_PACTION is
                                  set. */
    };
} khui_action_ref;

/*! \brief A submenu

    There should exist a menu associated with the action that is being
    referred.  When displaying this action in a menu, the contents of
    the associated menu will appear as a submenu.
 */
#define KHUI_ACTIONREF_SUBMENU      0x01

/*! \brief Separator

    This is not an actual action, but represents a separator between
    actions.  When displaying this action in a menu or a toolbar, a
    separating line will be drawn in place of this action.  The \a
    action and \a p_action members of the structures are unused if
    this flag is set.
 */
#define KHUI_ACTIONREF_SEP          0x02

/*! \brief Action by reference

    The \a p_action member of the structure points to the
    ::khui_action structure that describes the action.
 */
#define KHUI_ACTIONREF_PACTION      0x04

#ifdef NOEXPORT
/*! \brief Action should be freed

    \note This flag is reserved for internal use in the NetIDMgr
    application.  Do not use.
 */
#define KHUI_ACTIONREF_FREE_PACTION 0x08

/*! \brief Marks the end of an action sequence

    \note THis flag is reserved for internal use in the NetIDMgr
    application. Do not use.
 */
#define KHUI_ACTIONREF_END          0x10
#endif

/*! \brief The default action

    When this bit is set in an action reference that describes a menu,
    the menu item will be the default item and will be rendered
    differently from other menu items.  Only useful when defining
    context menus.  In general, it is good practice to place the
    default item at the top of a menu, although the UI library does
    not enforce this.  This is purely meant as a rendering hint.

    Only one action is allowed to have this flag set.  When an action
    is added to a menu using khui_menu_insert_action() or
    khui_menu_insert_paction() and this flag is set, all other menu
    items will be stripped of this flag.
 */
#define KHUI_ACTIONREF_DEFAULT      0x20

#ifdef NOEXPORT
#define MENU_ACTION(c) {0,c}
#define MENU_DEFACTION(c) {KHUI_ACTIONREF_DEFAULT, c}
#define MENU_SUBMENU(s) {KHUI_ACTIONREF_SUBMENU,s}
#define MENU_SEP() {KHUI_ACTIONREF_SEP,KHUI_MENU_SEP}
#define MENU_END() {KHUI_ACTIONREF_END,KHUI_MENU_END}
#endif

/*! \brief Menu definition

    Use the khui_menu_create(), khui_menu_insert_action(),
    khui_menu_insert_paction(), khui_menu_get_size(),
    khui_menu_get_action() functions to create and manipulate custom
    menus.  Do not manipulate this structure directly as doing so may
    cause inconsistencies in the UI library.
*/
typedef struct tag_khui_menu_def {
    khm_int32 cmd;          /*!< Action associated with menu */
    khm_int32 state;        /*!< combination of KHUI_MENUSTATE_* */
    khm_size  n_items;      /*!< The number of actions in the \a items
                              list.  If this is a custom menu, the
                              ::KHUI_MENUSTATE_ALLOCD bit will be set,
                              and the contents of this field will be
                              valid.  Otherwise, the contents of this
                              field is ignored and the list of actions
                              must be terminated with a
                              ACTION_LIST_END action. */
    khm_size  nc_items;     /*!< max number of items in the buffer
			      alocated for items.  Ignored if
			      ::KHUI_MENUSTATE_ALLOCD is not set in \a
			      state. */
    khui_action_ref *items; /*!< Action list terminated by,
			      ACTION_LIST_END.  If \a n_items is set
			      to a value other than -1, the list
			      doesn't necessarily have to end with a
			      ACTION_LIST_END.  When constructing a
			      menu using khui_menu_* functions, they
			      will set the size of this list in the \a
			      n_items member, and there will be no
			      ACTION_LIST_END action to terminate the
			      list. */
} khui_menu_def;

#ifdef NOEXPORT
#define CONSTMENU(c,s,i) {c,s,(khm_size)-1,(khm_size)-1,i}
#endif

/*! \brief Unspecified menu

    Used when there is no single command associated with the entire
    menu, such as for ad-hoc context menus.
 */
#define KHUI_MENU_NONE -3

/*! \brief Menu end indicator

    For static or constant menus this indicates that this action marks
    the end of the list of actions which defined the menu.  This is
    invalid if used in a dynamic menu (a menu with the
    ::KHUI_MENUSTATE_ALLOCD bit set).
 */
#define KHUI_MENU_END -2

/*! \brief Menu separator

    A separator for actions.  When displaying a menu or showing a
    toolbar based on a menu definition, a separator is rendered as a
    bar separating the user interface elements for the actions on
    either side of this.
*/
#define KHUI_MENU_SEP -1

/*! \brief Constant menu

    The contents of the menu cannot be modified (individual actions in
    the menu may be modified, but the order and the contents of the
    menu itself cannot be modified.

    This is the default if ::KHUI_MENUSTATE_ALLOCD is not specified.
 */
#define KHUI_MENUSTATE_CONSTANT 0

/*! \brief Variable menu

    The menu is dnamically allocated.  The list of actions contained
    in the menu can be modified.
*/
#define KHUI_MENUSTATE_ALLOCD   1

#ifdef NOEXPORT
/* predefined system menu */
#define KHUI_MENUSTATE_SYSTEM   2
#endif

#ifdef NOEXPORT

/*! \brief Accelerator definition */
typedef struct tag_khui_accel_def {
    int cmd;
    int mod;
    int key;
    int scope;
} khui_accel_def;

#define KHUI_ACCEL_SCOPE_GLOBAL 0

extern khui_accel_def khui_accel_global[];
extern int khui_n_accel_global;

extern khui_action khui_actions[];
extern int khui_n_actions;

extern khui_menu_def khui_all_menus[];
extern int khui_n_all_menus;

#endif /* NOEXPORT */

/* functions */

/*! \brief Refresh the global action table

    Changes to system menus and toolbars may not be immediately
    reflected in the user interface.  Calling this function forces the
    UI to reparse the action tables and menus and refresh the
    application menu bar and toolbars.

 */
KHMEXP void KHMAPI
khui_refresh_actions(void);

/*! \brief Lock the action and menu tables

    This function, along with khui_action_unlock() is used to prevent
    changes from being made to shared menus and actions while they are
    being updated.  In particular, changes to shared menus usually
    need to be done in a batch and may suffer corruption of other
    threads access or modify the menu while one thread is updating it.
    Operations on shared menus should always be done with the actions
    locked.
*/
KHMEXP void KHMAPI
khui_action_lock(void);

/*! \brief Unlock the action and menu tables

    Unlocks the action and menu tables after a call to
    khui_action_lock().

    \see khui_action_lock()
 */
KHMEXP void KHMAPI
khui_action_unlock(void);

/*! \brief Create a new menu

    Creates a new menu.  The returned data structure must be freed by
    a call to khui_menu_delete().  Custom menus that are created this
    way are not reference counted or maintained by the UI library.
    The caller is responsible for calling khui_menu_delete() when the
    data is no longer needed.

    Specifiying an action in the \a action parameter will associate
    the menu with the specified action.  In this case, if the action
    is added to another menu with the ::KHUI_ACTIONREF_SUBMENU flag,
    this menu will appear as a submenu within that menu.  Only one
    menu can be associated with any given action.  Custom menus can
    not be associated with standard actions.
 */
KHMEXP khui_menu_def * KHMAPI
khui_menu_create(khm_int32 action);

/*! \brief Duplicate a menu

    Creates a copy of the specified menu.  The returned data structure
    must be freed by a call to khui_menu_delete().  Custom menus are
    not reference counted or maintained by the UI library.  The caller
    is responsible for calling khui_menu_delete() when the data is no
    longer needed.

    Note that even if the original menu was associated with an action,
    the duplicate will not be.  Modifying the duplicate will not
    modify the original menu.  Only one menu can be associated with an
    action.
 */
KHMEXP khui_menu_def * KHMAPI
khui_menu_dup(khui_menu_def * src);

/*! \brief Delete a menu

    Deletes a menu created by a call to khui_menu_create() or
    khui_menu_dup().  This frees up the memory and associated
    resources used by the menu definition.  The pointer that is passed
    in will no longer be valid.
 */
KHMEXP void KHMAPI
khui_menu_delete(khui_menu_def * d);

/*! \brief Insert an action into a menu

    The action specified by \a cmd will be inserted in to the menu \a
    d at index \a idx.

    \param[in] d The menu to insert the action into

    \param[in] idx The index at which to insert the action.  The index
        is zero based.  If \a idx is (-1) or larger than the largest
        index in the menu, the item is appended to the menu.

    \param[in] cmd The command representing the action to insert into
        the menu.  This should be either a standard action, a user
        action created with khui_action_create(), or certain pseudo
        actions.  Not all pseudo actions can be placed on a menu.

    \param[in] flags Flags for the action.  This is a combination of
        KHUI_ACTIONREF_* constants.  Currently, the only constants
        that are valid for this function are: ::KHUI_ACTIONREF_SEP,
        ::KHUI_ACTIONREF_SUBMENU, ::KHUI_ACTIONREF_DEFAULT.
        ::KHUI_ACTIONREF_SEP will be automatically added if the
        command is ::KHUI_MENU_SEP.  If ::KHUI_ACTIONREF_DEFAULT is
        specified, then all other items in the menu will be stripped
        of that flag leaving this action as the only one with that
        flag set.
 */
KHMEXP void KHMAPI
khui_menu_insert_action(khui_menu_def * d, khm_size idx, khm_int32 cmd, khm_int32 flags);

#define khui_menu_add_action(d,c) khui_menu_insert_action((d),-1,(c),0)
#pragma deprecated(khui_menu_add_action)

#ifdef NOEXPORT

/*! \brief Insert an action by reference into a menu

    The action specified by \a act will be inserted into the menu \a d
    at index \a idx.

    \param[in] d The menu to inser the action into.

    \param[in] idx The index at which to insert the action.  The index
        is zero based.  If the index is (-1) or is larger than the
        largest index in the menu, then the action is appended to the
        menu.

    \param[in] act The action to insert.  This is added by reference.
        It is the callers reponsibility to ensure that the structure
        pointed to by \a act is available throughout the lifetime of
        the menu.

    \param[in] flags Flags for the action.  This is a combination of
        KHUI_ACTIONREF_* constants.  Currently, the only constants
        that are valid for this function are: ::KHUI_ACTIONREF_SEP,
        ::KHUI_ACTIONREF_SUBMENU, ::KHUI_ACTIONREF_DEFAULT.  For this
        function, ::KHUI_ACTIONREF_PACTION will automatically be aded
        when adding the action.  ::KHUI_ACTIONREF_SEP will be
        automatically added if the command is ::KHUI_MENU_SEP.  If
        ::KHUI_ACTIONREF_DEFAULT is specified, then all other items in
        the menu will be stripped of that flag leaving this action as
        the only one with that flag set.
*/
KHMEXP void KHMAPI
khui_menu_insert_paction(khui_menu_def * d, khm_size idx, khui_action * act, khm_int32 flags);

#define khui_menu_add_paction(d,a,f) khui_menu_insert_paction((d),-1,(a),(f))
#pragma deprecated(khui_menu_add_paction)

#endif

/*! \brief Remove an action from a menu

    The action at the specified index will be removed from the menu.
  */
KHMEXP void KHMAPI
khui_menu_remove_action(khui_menu_def * d, khm_size idx);

/*! \brief Get the number of items in the menu

    Note that the count includes menu separators.  The indices of the
    menu items range from 0 to one less than the value returned by
    this function.
 */
KHMEXP khm_size KHMAPI
khui_menu_get_size(khui_menu_def * d);

/*! \brief Get the menu item at a specified index

    The returned reference is only valid while the ::khui_menu_def
    structure is valid.  In addition, the reference becomes invalid if
    the list of actions in the menu data structure is modified in any
    way.

    If the specified index is out of bounds, then the function returns
    NULL.

 */
KHMEXP khui_action_ref *
khui_menu_get_action(khui_menu_def * d, khm_size idx);

/*! \brief Action scope identifiers

    The scope identifier is a value which describes the scope of the
    cursor context.  See documentation on individual scope identifiers
    for details.

    The role of the scope identifier is to provide a summary of the
    current cursor context.  Specifically, these identify several
    special cases of credential selection, such as the selection of an
    entire identity, a credential type or a single credential.  If
    none of these are applicable, then the generic scope identifier
    ::KHUI_SCOPE_GROUP is set or ::KHUI_SCOPE_NONE if there is nothing
    selected.

    Note that the scope typically only apply to cursor contexts and
    not the selection context.  Please see
    \ref khui_context "UI Contexts" for more information.

    \see \ref khui_context "UI Contexts"
*/
typedef enum tag_khui_scope {
    KHUI_SCOPE_NONE,
    /*!< No context.  Nothing is selected. */

    KHUI_SCOPE_IDENT,
    /*!< Identity.  The selection is the entire identity specified in
      the \a identity field of the context. */

    KHUI_SCOPE_CREDTYPE,
    /*!< A credentials type.  The selection is an entire credentials
      type.  If \a identity is non-NULL, then the scope is all the
      credentials of type \a cred_type which belong to \a identity.
      Otherwise, the selection is all credentials of type \a
      cred_type.

      \note The \a identity can be non-NULL even for the case where
      all credentials of type \a cred_type under \a identity is the
      same scope as all credentials of type \a cred_type under all
      identities. */

    KHUI_SCOPE_GROUP,
    /*!< A grouping of credentials.  The scope is a group of
      credentials which can not be simplified using one of the other
      context identifiers.  The \a headers array contains \a n_headers
      elements describing the outline level that has been selected.

      \see ::khui_header
      \see \ref khui_context_sel_ctx_grp "KHUI_SCOPE_GROUP description" */

    KHUI_SCOPE_CRED
    /*!< A single credential.  Only a single credential was
      selected. The \a cred field of the context specifies the
      credential.  The \a identity and \a cred_type fields specify the
      identity and the credential type respectively. */
} khui_scope;


/*! \brief Outline header

    Describes an outline header in the user interface.

    \see \ref khui_context_sel_ctx_grp "KHUI_SCOPE_GROUP description"
 */
typedef struct tag_khui_header {
    khm_int32 attr_id;          /*!< Attribute ID */
    void *    data;             /*!< Value of attribute */
    khm_size  cb_data;          /*!< Size of the value */
} khui_header;

/*! \brief Maximum number of outline headers

    This is the maximum number of fields that the credentials view can
    be grouped by.
 */
#define KHUI_MAX_HEADERS  6

/*! \brief Action context

    Represents the UI context for an action.
 */
typedef struct tag_khui_action_context {
    khm_int32   magic;          /*!< Internal. */
    khui_scope  scope;          /*!< Context scope.  One of ::khui_scope*/
    khm_handle  identity;       /*!< Identity */
    khm_int32   cred_type;      /*!< Credential type ID */
    khm_handle  cred;           /*!< Credential */

    khui_header headers[KHUI_MAX_HEADERS];
                                /*!< The ordered set of outline
                                  headers which define the current
                                  cursor location. */

    khm_size    n_headers;      /*!< Number of actual headers defined
                                  above */

    khm_handle  credset;        /*!< Handle to a credential set
                                  containing the currently selected
                                  credentials.  When the context is
                                  obtained through khui_context_get(),
                                  this credential is returned in a
                                  sealed state. */

    khm_size    n_sel_creds;    /*!< Number of selected credentials */

    void *      int_buf;        /*!< Internal.  Do not use. */
    khm_size    int_cb_buf;     /*!< Internal.  Do not use. */
    khm_size    int_cb_used;    /*!< Internal.  Do not use. */

    void *      vparam;         /*!< Optional data */
    khm_size    cb_vparam;      /*!< Size of optional data */
} khui_action_context;

/*! \brief Set the current context

    Changes the UI context to that represented by the parameters to
    the function.  Note that specifying a valid \a identity or \a cred
    parameter will result in an automatic hold on the respective
    object.  The hold will stay until another call to
    khui_context_set() overwrites the identity or credential handle or
    a call to khui_context_reset() is made.

    While this API is available, it is only called from the main
    NetIDMgr application.  Plugins do not have a good reason to call
    this API directly and should not do so.

    \param[in] scope The new context scope

    \param[in] identity A handle to an identity.  If this is not NULL,
        then it should be a valid handle to an identity.  Required if
        \a scope specifies ::KHUI_SCOPE_IDENT.  Optional if \a scope
        specifies ::KHUI_SCOPE_CREDTYPE.  Ignored otherwise.

    \param[in] cred_type A credentials type.  Specify
        ::KCDB_CREDTYPE_INVALID if this parameter is not given or not
        relevant.  Required if \a scope specifies
        ::KHUI_SCOPE_CREDTYPE.  Ignored otherwise.

    \param[in] cred A handle to a credential.  If this parameter is
        not NULL it is expected to be a valid handle to a credential.
        Required if \a scope specifies ::KHUI_SCOPE_CRED.  Ignored
        otherwise.

    \param[in] headers An array of headers.  The \a n_headers
        parameter specifies the number of elements in the array.  Set
        to NULL if not specified.  Required if \a scope specifies
        ::KHUI_SCOPE_GROUP.

    \param[in] n_headers Number of elements in \a headers.  Must be
        less than or equal to ::KHUI_MAX_HEADERS.  Required if \a
        headers is not NULL. Ignored otherwise.

    \param[in] cs_src A handle to a credential set from which the
        selected credentials will be extracted.  The credentials that
        are selected must have the ::KCDB_CRED_FLAG_SELECTED flag set.

    \note This function should only be called from the UI thread.
 */
KHMEXP void KHMAPI
khui_context_set(khui_scope  scope,
                 khm_handle  identity,
                 khm_int32   cred_type,
                 khm_handle  cred,
                 khui_header *headers,
                 khm_size    n_headers,
                 khm_handle  cs_src);

/*! \brief Set the current context

    Changes the UI context to that represented by the parameters to
    the function.  Note that specifying a valid \a identity or \a cred
    parameter will result in an automatic hold on the respective
    object.  The hold will stay until another call to
    khui_context_set() overwrites the identity or credential handle or
    a call to khui_context_reset() is made.

    While this API is available, it is only called from the main
    NetIDMgr application.  Plugins do not have a good reason to call
    this API directly and should not do so.

    \param[in] scope The new context scope

    \param[in] identity A handle to an identity.  If this is not NULL,
        then it should be a valid handle to an identity.  Required if
        \a scope specifies ::KHUI_SCOPE_IDENT.  Optional if \a scope
        specifies ::KHUI_SCOPE_CREDTYPE.  Ignored otherwise.

    \param[in] cred_type A credentials type.  Specify
        ::KCDB_CREDTYPE_INVALID if this parameter is not given or not
        relevant.  Required if \a scope specifies
        ::KHUI_SCOPE_CREDTYPE.  Ignored otherwise.

    \param[in] cred A handle to a credential.  If this parameter is
        not NULL it is expected to be a valid handle to a credential.
        Required if \a scope specifies ::KHUI_SCOPE_CRED.  Ignored
        otherwise.

    \param[in] headers An array of headers.  The \a n_headers
        parameter specifies the number of elements in the array.  Set
        to NULL if not specified.  Required if \a scope specifies
        ::KHUI_SCOPE_GROUP.

    \param[in] n_headers Number of elements in \a headers.  Must be
        less than or equal to ::KHUI_MAX_HEADERS.  Required if \a
        headers is not NULL. Ignored otherwise.

    \param[in] cs_src A handle to a credential set from which the
        selected credentials will be extracted.  The credentials that
        are selected must have the ::KCDB_CRED_FLAG_SELECTED flag set.

    \param[in] vparam Optional parameter blob

    \param[in] cb_vparam Size of parameter blob

    \note This function should only be called from the UI thread.
 */
KHMEXP void KHMAPI
khui_context_set_ex(khui_scope scope,
                    khm_handle identity,
                    khm_int32 cred_type,
                    khm_handle cred,
                    khui_header *headers,
                    khm_size n_headers,
                    khm_handle cs_src,
                    void * vparam,
                    khm_size cb_vparam);

/*! \brief Set the current UI context using an existing context

    Copies the context specified in \a ctx into the active UI context.

    \param[in] ctx A pointer to a ::khui_action_context structure that
        specifies the new UI context.  Cannot be NULL.
*/
KHMEXP void KHMAPI
khui_context_set_indirect(khui_action_context * ctx);

/*! \brief Obtain the current UI context

    The parameter specified by \a ctx will receive the current UI
    context.  If the context contains an identity or a credential
    handle, a hold will be obtained on the relevant object.  Use
    khui_context_release() to release the holds obtained in a prior
    call to khui_context_get().

    \note The returned context should not be modified prior to calling
    khui_context_release().
*/
KHMEXP void KHMAPI
khui_context_get(khui_action_context * ctx);

/*! \brief Create a new UI context

    The created context does not have any relation to the current UI
    context.  This function is provided for use in situations where an
    application needs to provide a scope description through a
    ::khui_action_context structure.

    Once the application is done with the context, it should call
    khui_context_release() to release the created context.
 */
KHMEXP void KHMAPI
khui_context_create(khui_action_context * ctx,
                    khui_scope scope,
                    khm_handle identity,
                    khm_int32 cred_type,
                    khm_handle cred);

/*! \brief Release a context obtained using khui_context_get()

    Releases all holds obtained on related objects in a prior call to
    khui_context_get() and nullifies the context.

    \note The context should not have been modified between calling
    khui_context_get() and khui_context_release()
 */
KHMEXP void KHMAPI
khui_context_release(khui_action_context * ctx);

/*! \brief Reset the UI context

    Nullifies the current UI context and releases any holds obtained
    on objects related to the previous context.
*/
KHMEXP void KHMAPI
khui_context_reset(void);

/*! \brief Refresh context data

    Setting the UI context involves other side effects such as
    activation of or disabling certain actions based on the selection.
    If an operation is performed which may affect the side effects,
    khui_context_refresh() is called to refresh them.

    An example is when setting the default identity.  The state of the
    action ::KHUI_ACTION_SET_DEF_ID depends on whether the currently
    selected identity is the default.  However, if the currently
    selected identity becomes the default after selection, then
    khui_context_refresh() should be called to adjust the state of the
    ::KHUI_ACTION_SET_DEF_ID action.
 */
KHMEXP void KHMAPI
khui_context_refresh(void);

/*! \brief A filter function that filters for credentials in the cursor context

    This is a function of type ::kcdb_cred_filter_func which can be
    used to filter for credentials that are included in the cursor
    context.

    The \a rock parameter should be a pointer to a
    ::khui_action_context structure which will be used as the filter.

    For example, the following code will extract the cursor context
    credentials into the credential set \a my_credset based on the UI
    context \a my context:

    \code
    kcdb_credset_extract_filtered(my_credset,
                                  NULL,
                                  khui_context_cursor_filter,
                                  (void *) my_context);
    \endcode
*/
KHMEXP khm_int32 KHMAPI
khui_context_cursor_filter(khm_handle cred,
                           khm_int32 flags,
                           void * rock);

/*! \brief Get a string representation of an accelerator

    \param[in] cmd Command for which to obtain the accelerator string for
    \param[out] buf Buffer to receive the accelerator string
    \param[in] bufsiz Size of the buffer in bytes.  Note that the size of the
        buffer must be sufficient to hold at least one character and a
        NULL terminator.

    \return TRUE if the operation was successful. FALSE otherwise.
 */
KHMEXP khm_boolean KHMAPI khui_get_cmd_accel_string(khm_int32 cmd, wchar_t * buf, khm_size bufsiz);

#ifdef NOEXPORT
/*! \brief Initializes the global accelerator table
 */
KHMEXP HACCEL KHMAPI khui_create_global_accel_table(void);
#endif

/*! \brief Find a menu by id

    Finds the menu that is associated with the specified action.
 */
KHMEXP khui_menu_def * KHMAPI khui_find_menu(khm_int32 action);

#ifdef NOEXPORT

/* internal */
KHMEXP void KHMAPI
khui_set_main_window(HWND hwnd);

#endif

/*! \brief Trigger an action

    Triggers the specified action using the specified UI context.

    This function does not return until the specified action has been
    processed.  Many standard actions are asynchronous and they will
    return before processing will complete.

    Pseudo actions should not be triggered using khui_action_trigger()
    as they only carry meaning when invoked from specific windows or
    contexts.

    \param[in] action Action.  Should be one of the standard actions
        or an action created by khui_action_create()

    \param[in] ctx The UI context to use for the action.  If this is
        NULL, the action will be triggered under the current UI context.
 */
KHMEXP void KHMAPI
khui_action_trigger(khm_int32 action, khui_action_context * ctx);

/*! \brief Find an action by id

    \note This function should not be used by plugins.  It is there
        for use by the NetIDMgr application.
*/
KHMEXP khui_action * KHMAPI khui_find_action(khm_int32 action);

#ifdef NOEXPORT
/*! \brief Get the length of the action list */
KHMEXP size_t KHMAPI khui_action_list_length(khui_action_ref * ref);
#endif

/*! \brief Create a new action

    Creates a new custom action.  The created custom action can be
    added to menus, toolbars and can be triggered by
    khui_action_trigger().

    When the action is triggered as a result of the user selecting a
    menu item, a toolbar item or as a result of calling
    khui_action_trigger(), the subscription identified by \a hsub will
    received a message of type ::KMSG_ACT, subtype
    ::KMSG_ACT_ACTIVATE.  The \a uparam for the message will be the
    action identifier that was returned by khui_action_create().  The
    \a vparam of the message will currently be set to \a NULL.

    Actions can optionally be named.  The name is not actively used by
    the Network Identity Manager framework, but can be used to label
    actions so that they can be looked up later using
    khui_find_named_action().

    \param[in] name Name for a named action.  The name must be unique
        among all registered actions. (limited by KHUI_MAXCCH_NAME).
        (Optional. Set to NULL if the action is not a named action.)
        See \a note below for additional restrictions on the name of
        the action.

    \param[in] caption The localized caption for the action.  This
        will be shown in menus, toolbars and buttons when the action
        needs to be represented. (limited by KHUI_MAXCCH_SHORT_DESC)
        (Required)

    \param[in] tooltip The localized tooltip for the action. (limited
        by KHUI_MAXCCH_SHORT_DESC) (Optional, set to NULL if there is
        no tooltip associated with the action)

    \param[in] userdata A custom value.

    \param[in] type The type of the action.  Currently it should be
        set to either ::KHUI_ACTIONTYPE_TRIGGER or
        ::KHUI_ACTIONTYPE_TOGGLE.  For ::KHUI_ACTIONTYPE_TOGGLE, the
        initial state will be unchecked.  Use khui_check_action()
        function to change the checked state of the action.

    \param[in] hsub The subscription that is notified when the action
        is triggered. (Optional) The subscription must be created with
        kmq_create_subscription().  The handle will be released when
        it is no longer needed.  Hence, the caller should not release
        it.

    \return The identifier of the new action or zero if the action
        could not be created.

    \note For named custom actions, the name of the action can not be
        the same as the name of a configuration node.  See
        khui_cfg_register_node().
 */
KHMEXP khm_int32 KHMAPI
khui_action_create(const wchar_t * name,
                   const wchar_t * caption,
                   const wchar_t * tooltip,
                   void * userdata,
                   khm_int32 type,
                   khm_handle hsub);

/* \brief Delete a custom action

   Deletes a custom action created by a call to khui_action_create().
   Custom actions should only be deleted when unloading a plugin.
 */
KHMEXP void KHMAPI
khui_action_delete(khm_int32 action);

/*! \brief Get the user data associated with a custom action

    This function returns the user data that was specified when the
    custom action was created usng khui_action_create().  If the
    custom action identifier is invalid or if the custom action does
    not contain any user data, this function will return NULL.
 */
KHMEXP void * KHMAPI
khui_action_get_data(khm_int32 action);

/*! \brief Find an action by name */
KHMEXP khui_action * KHMAPI khui_find_named_action(const wchar_t * name);

/*! \brief Enables or disables a group of actions

    The group of actions are specified by the menu definition.  All
    valid action entries in the menu are marked as enabled or disabled
    according to the value of \a enable.
 */
KHMEXP void KHMAPI khui_enable_actions(khui_menu_def * d, khm_boolean enable);

/*! \brief Enables or disables an action

    The action designated by the command \a action will either be enabled
    or disabled depending on the \a enable parameter.  If \a enable is
    TRUE then the action is enabled.
 */
KHMEXP void KHMAPI khui_enable_action(khm_int32 action, khm_boolean enable);

/*! \brief Check an action in an action group

    Marks the action denoted by \a action as checked and resets the
    checked bit in all other actions.

    \param[in] d A menu definition.

    \param[in] action A command identifier.  Setting this to -1 will
        reset the checked bit in all the actions in the menu
        definition.
 */
KHMEXP void KHMAPI khui_check_radio_action(khui_menu_def * d, khm_int32 action);

/*! \brief Check an action

    For toggle typed actions, this sets or resets the check.
 */
KHMEXP void KHMAPI khui_check_action(khm_int32 cmd, khm_boolean check);

#ifdef NOEXPORT
/*!\cond INTERNAL */

/*! \brief Initialize actions

    \note Only called by the NetIDMgr application
 */
KHMEXP void KHMAPI khui_init_actions(void);

/*! \brief Exit actions

    \note Only called by the NetIDMgr application
 */
KHMEXP void KHMAPI khui_exit_actions(void);

/*! \endcond */
#endif

/*@}*/
/*@}*/
#endif

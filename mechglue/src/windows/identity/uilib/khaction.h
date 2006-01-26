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

/*! \brief An action */
typedef struct tag_khui_action {
    int cmd;            /*!< command id */
    int type;           /*!< combination of KHUI_ACTIONTYPE_* */
    wchar_t * name;     /*!< name for named actions.  NULL if not named. */

    /* normal, hot and disabled are toolbar sized bitmaps */
    int ib_normal;      /*!< normal bitmap (index) */
    int ib_hot;         /*!< hot bitmap (index) */
    int ib_disabled;    /*!< disabled bitmap (index) */

    int ib_icon;        /*!< index of small (16x16) icon (for menu) */
    int ib_icon_dis;    /*!< index of disabled (greyed) icon */

    int is_caption;     /*!< index of string resource for caption */
    int is_tooltip;     /*!< same for description / tooltip */
    int ih_topic;       /*!< help topic */
    int state;          /*!< current state. combination of KHUI_ACTIONSTATE_* */
} khui_action;

/*! \brief Unknown action type */
#define KHUI_ACTIONTYPE_NONE    0

/*! \brief A trigger type action */
#define KHUI_ACTIONTYPE_TRIGGER 1

/*! \brief A toggle type action

    A toggle type action typically changes the CHECKED state of the
    action each time it is invoked.
 */
#define KHUI_ACTIONTYPE_TOGGLE  2

/*! \brief The action is enabled */
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

#ifdef NOEXPORT
#define ACTION_SIMPLE(c,cap,des,top) \
    {c,KHUI_ACTIONTYPE_TRIGGER,0,0,0,0,0,cap,des,top,0}

#define ACTION_FULL(cmd,type,inormal,ihot,idis,isml,ismld,capt,toolt,topic,state) \
    {cmd,type,inormal,ihot,idis,isml,ismld,capt,toolt,topic,state}

#define ACTION_SIMPLE_IMAGE(c,inormal, ihot, idis, isml, ismld,cap, des, top) \
    {c,KHUI_ACTIONTYPE_TRIGGER,inormal,ihot,idis,isml,ismld,cap,des,top,0}
#endif

/*! \brief A reference to an action */
typedef struct tag_khui_action_ref {
    int flags;
    union {
        int action;
        khui_action * p_action;
    };
} khui_action_ref;

#define KHUI_ACTIONREF_SUBMENU      0x01
#define KHUI_ACTIONREF_SEP          0x02
#define KHUI_ACTIONREF_PACTION      0x04
#define KHUI_ACTIONREF_FREE_PACTION 0x08
#define KHUI_ACTIONREF_END          0x10
#define KHUI_ACTIONREF_DEFAULT      0x20

#ifdef NOEXPORT
#define MENU_ACTION(c) {0,c}
#define MENU_DEFACTION(c) {KHUI_ACTIONREF_DEFAULT, c}
#define MENU_SUBMENU(s) {KHUI_ACTIONREF_SUBMENU,s}
#define MENU_SEP() {KHUI_ACTIONREF_SEP,KHUI_MENU_SEP}
#define MENU_END() {KHUI_ACTIONREF_END,KHUI_MENU_END}
#endif

/*! \brief Menu definition */
typedef struct tag_khui_menu_def {
    int cmd;                /*!< Action associated with menu */
    int state;              /*!< combination of KHUI_MENUSTATE_* */
    size_t n_items;         /*!< total number of items or -1 if not
			      set.  If this is -1, then the list of
			      actions must be terminated with a
			      ACTION_LIST_END entry. */
    size_t nc_items;        /*!< max number of items in the buffer
			      alocated for items.  Ignored if
			      KHUI_MENUSTATE_CONSTANT is set in \a
			      state.*/
    khui_action_ref *items; /*!< Action list terminated by,
			      ACTION_LIST_END.  If \a n_items is set
			      to a value other than -1, the list
			      doesn't necessarily have to end with a
			      ACTION_LIST_END. */
} khui_menu_def;

#ifdef NOEXPORT
#define CONSTMENU(c,s,i) {c,s,-1,-1,i}
#endif

#define KHUI_MENU_END -2
#define KHUI_MENU_SEP -1

#define KHUI_MENUSTATE_CONSTANT 0
#define KHUI_MENUSTATE_ALLOCD   1

/*! \brief Accelerator definition */
typedef struct tag_khui_accel_def {
    int cmd;
    int mod;
    int key;
    int scope;
} khui_accel_def;

#define KHUI_ACCEL_SCOPE_GLOBAL 0

#ifdef NOEXPORT

extern khui_accel_def khui_accel_global[];
extern int khui_n_accel_global;

extern khui_action khui_actions[];
extern int khui_n_actions;

extern khui_menu_def khui_all_menus[];
extern int khui_n_all_menus;

#endif /* NOEXPORT */

/* functions */

KHMEXP khui_menu_def * KHMAPI khui_menu_create(int cmd);
KHMEXP khui_menu_def * KHMAPI khui_menu_dup(khui_menu_def * src);
KHMEXP void KHMAPI khui_menu_delete(khui_menu_def * d);
KHMEXP void KHMAPI khui_menu_add_action(khui_menu_def * d, int id);
KHMEXP void KHMAPI khui_menu_add_paction(khui_menu_def * d, khui_action * act, int flags);

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
KHMEXP khm_boolean KHMAPI khui_get_cmd_accel_string(int cmd, wchar_t * buf, size_t bufsiz);

KHMEXP HACCEL KHMAPI khui_create_global_accel_table(void);

/*! \brief Find a menu by id */
KHMEXP khui_menu_def * KHMAPI khui_find_menu(int id);

/*! \brief Find an action by id */
KHMEXP khui_action * KHMAPI khui_find_action(int id);

/*! \brief Get the length of the action list */
KHMEXP size_t KHMAPI khui_action_list_length(khui_action_ref * ref);

/*! \brief Find an action by name */
KHMEXP khui_action * KHMAPI khui_find_named_action(wchar_t * name);

/*! \brief Enables or disables a group of actions

    The group of actions are specified by the menu definition.  All
    valid action entries in the menu are marked as enabled or disabled
    according to the value of \a enable.
 */
KHMEXP void KHMAPI khui_enable_actions(khui_menu_def * d, khm_boolean enable);

/*! \brief Enables or disables an action

    The action designated by the command \a cmd will either be enabled
    or disabled depending on the \a enable parameter.  If \a enable is
    TRUE then the action is enabled.
 */
KHMEXP void KHMAPI khui_enable_action(int cmd, khm_boolean enable);

/*! \brief Check an action in an action group

    Marks the action denoted by \a cmd as checked and resets the
    checked bit in all other actions.

    \param[in] d A menu definition.
    \param[in] cmd A command identifier.  Setting this to -1 will
        reset the checked bit in all the actions in the menu
        definition.
 */
KHMEXP void KHMAPI khui_check_radio_action(khui_menu_def * d, khm_int32 cmd);

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

/*@}*/
/*@}*/
#endif

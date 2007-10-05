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

/*! \page khui_context Contexts

    \section khui_context_contents Contents

    - \ref khui_context_intro "Introduction"
    - \subpage khui_context_using

    \section khui_context_intro Introduction

    Several ::KMSG_CRED messages and many messages depend on the
    selections that the user has made on the user interface.  The UI
    context functions and data structures provide access to this
    information.

    The Network Identity Manager user interface presents an outline view of all the
    credentials that were provided by credentials providers.  This
    view consists of headers representing the outline levels and rows
    representing individual credentials.

    Users can make multiple selections of credentials or headers from
    this view.  If all the credentials and subheaders under a
    particular outline level are selected, then the header itself is
    automatically selected.  There may be multiple disjointed
    selections of headers and credentials.

    In addition, the current cursor position also acts as a selector.
    The credential or header under the cursor may not actually be
    selected.  The cursor is not the mouse pointer, but the focus
    rectangle that may be moved either using the keyboard or by
    clicking on a credential or header.

    Thus there are two independent groups of selections:

    - Credentials and headers which are in a selected state at some
      specific point in time (the <b>current selection</b>).

    - The current credential or selection which the cursor is on (the
      <b>cursor selection</b>).

    There are a few notes on how credentials are selected:

    - An "empty" header (a header that does not contain any credential
      rows) does not appear in a UI context.  However they can appear
      as the current cursor context.

    - At its current implementation, cursor selections of identity,
      credential type, and individual credentials are treated as
      special cases since they are the most common.

    How the UI context is used when processing a specific action or
    message depends on the action or message.  If an action operates
    on a group of credentials, then the current selection may be used,
    and on the other hand if an action or message relates to just one
    credential, identity or credential type is invoked, then the
    cursor selection is invoked.

    For example, double-clicking a credential, or right clicking and
    selecting 'Properties' from the context menu launches the property
    window for a credential.  This operates on the cursor selection
    since that reflects where the user double clicked.  However,
    choosing 'Destroy' from the context menu invokes a command that
    can be applied to a group of credential, and hence uses the
    current selection.

    Next: \ref khui_context_using "Using Contexts"
 */

/*! \page khui_context_using Using Contexts 

    \section khui_context_using_1 Obtaining the context

    Typically, messages sent by actions that rely on UI context will
    obtain and store the context in a location that is accessible to
    the handlers of the message.

    If a plug-in needs to obtain the UI context, it should do so by
    calling khui_context_get() and passing in a pointer to a
    ::khui_action_context structure.

    Once obtained, the contents of the ::khui_action_context structure
    should be considered read-only.  When the plug-in is done with the
    structure, it should call ::khui_context_release().  This cleans
    up any additional memory allocated for storing the context as well
    as releasing all the objects that were referenced from the
    context.

    \section khui_context_sel_ctx Selection context

    The selection context is specified in the ::khui_action_context
    structure in the \a sel_creds and \a n_sel_creds fields.  These
    combined provide an array of handles to credentials which are
    selected.

    \note If \a n_sel_creds is zero, then \a sel_creds may be NULL.

    \section khui_context_cur_ctx Cursor context

    The scope of the cursor context is specified in the \a scope field
    of the ::khui_action_context strucutre.  The scope can be one of:

    - ::KHUI_SCOPE_NONE
    - ::KHUI_SCOPE_IDENT
    - ::KHUI_SCOPE_CREDTYPE
    - ::KHUI_SCOPE_GROUP
    - ::KHUI_SCOPE_CRED

    Depending on the scope, several other members of the strucre may
    also be set.

    In general, the cursor context can be a single credential or an
    entire outline level.  Unlike the selection context, since this
    specifies a single point of selection it can not be disjointed.

    The contents of the \a identity, \a cred_type, \a cred, \a headers
    and \a n_headers are described in the documentation of each of the
    scope values above.

    \subsection khui_context_sel_ctx_grp KHUI_SCOPE_GROUP

    The ::KHUI_SCOPE_GROUP scope is the generic scope which describes
    a cursor selection that can not be simplified into any other
    scope.

    In this case, the selection is described by an array of
    ::khui_header elements each of which specify a criterion for
    narrowing down the selection of credentials.  The ::khui_header
    structure specifies an attribute in the \a attr_id field and a
    value in the \a data and \a cb_data fields.  The credentials that
    are selected are those in the root credential set whose repective
    attributes contain the values specified in each of the
    ::khui_header elements.

    For example, the following selection:

    \image html credview-select-outline.jpg

    will result in the following header specification:

    \code
    ctx.n_headers = 3;

    ctx.headers[0].attr_id = KCDB_ATTR_LOCATION;
    ctx.headers[0].data = L"grailauth@KHMTEST";
    ctx.headers[0].cb_data = sizeof(L"grailauth@KHMTEST");

    ctx.headers[1].attr_id = KCDB_ATTR_ID;
    ctx.headers[1].data = &handle_to_identity;
    ctx.headers[1].cb_data = sizeof(khm_handle);

    ctx.headers[2].attr_id = KCDB_ATTR_TYPE;
    ctx.headers[2].data = &kerberos_5_credtype;
    ctx.headers[2].cb_data = sizeof(khm_int32);
    \endcode

    \note The attribute that is used to specify the header is not the
        display attribute, but the canonical attribute.  For example,
        in the above, the second header was actually
        KCDB_ATTR_ID_NAME.  But KCDB_ATTR_ID was used since that is
        the canonical source for KCDB_ATTR_ID_NAME.  See ::kcdb_attrib
        for more information on canonical attributes.
*/

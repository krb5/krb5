/*
 * Copyright (c) 2006 Secure Endpoints Inc.
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

#include "credprov.h"
#include<assert.h>

/* This file provides handlers for the credentials acquisition
   messages including handling the user interface for the new
   credentials dialogs. */

/*********************************************************************

These are stubs for the Window message for the dialog panel.  This
dialog panel is the one that is added to the new credentials window
for obtaining new credentials.

Note that all the UI callbacks run under the UI thread.

 *********************************************************************/

/* This structure will hold all the state information we will need to
   access from the new credentials panel for our credentials type. */
struct nc_dialog_data {
    khui_new_creds * nc;
    khui_new_creds_by_type * nct;

    /* TODO: add any other state information here */
};

/* Note: This callback runs under the UI thread */
INT_PTR
handle_wm_initdialog(HWND hwnd, WPARAM wParam, LPARAM lParam) {
    khui_new_creds * nc = NULL;
    khui_new_creds_by_type * nct = NULL;
    struct nc_dialog_data * d = NULL;

    nc = (khui_new_creds *) lParam;
    khui_cw_find_type(nc, credtype_id, &nct);

    assert(nct);

    d = malloc(sizeof(*d));
    ZeroMemory(d, sizeof(*d));

    d->nc = nc;
    d->nct = nct;

#pragma warning(push)
#pragma warning(disable: 4244)
    SetWindowLongPtr(hwnd, DWLP_USER, (LPARAM) d);
#pragma warning(pop)

    nct->aux = (LPARAM) d;      /* we can use the auxiliary field to
                                   hold a pointer to d */

    /* TODO: Perform any additional initialization here */

    return FALSE;
}

/* Note: This callback runs under the UI thread */
INT_PTR
handle_khui_wm_nc_notify(HWND hwnd, WPARAM wParam, LPARAM lParam) {

    struct nc_dialog_data * d;

    /* Refer to the khui_wm_nc_notifications enumeration in the
       NetIDMgr SDK for the full list of notification messages that
       can be sent. */

    d = (struct nc_dialog_data *) GetWindowLongPtr(hwnd, DWLP_USER);

    if (!d)
        return TRUE;

    /* these should be set by now */
    assert(d->nc);
    assert(d->nct);

    switch (HIWORD(wParam)) {
    case WMNC_UPDATE_CREDTEXT:
        {
            wchar_t fmt[KHUI_MAXCCH_LONG_DESC];
            wchar_t tbuf[256];

            /* we are being requested to update the credentials
               text. We already allocated a buffer when we created the
               nct structure.  So we can just set the text here.*/

            /* TODO: The credtext should reflect the credentials that
               will be obtained when the new credentials operation
               completes. */

            LoadString(hResModule, IDS_NC_CT_TEMPLATE,
                       fmt, ARRAYLENGTH(fmt));

            LoadString(hResModule, IDS_GEN_NONE,
                       tbuf, ARRAYLENGTH(tbuf));

            assert(d->nct->credtext);

            StringCbPrintf(d->nct->credtext, KHUI_MAXCB_LONG_DESC,
                           fmt, tbuf);
        }
        break;

    case WMNC_CREDTEXT_LINK:
        break;

    case WMNC_IDENTITY_CHANGE:
        break;

    case WMNC_DIALOG_PREPROCESS:
        break;
    }

    return TRUE;
}

/* Note: This callback runs under the UI thread */
INT_PTR
handle_wm_command(HWND hwnd, WPARAM wParam, LPARAM lParam) {

    struct nc_dialog_data * d;

    d = (struct nc_dialog_data *) GetWindowLongPtr(hwnd, DWLP_USER);
    if (d == NULL)
        return FALSE;

    /* TODO: handle WM_COMMAND */
    return FALSE;
}

/* Note: This callback runs under the UI thread */
INT_PTR
handle_wm_destroy(HWND hwnd, WPARAM wParam, LPARAM lParam) {

    struct nc_dialog_data * d;

    d = (struct nc_dialog_data *) GetWindowLongPtr(hwnd, DWLP_USER);

    if (d) {
        d->nc = NULL;
        d->nct = NULL;

        free(d);
        SetWindowLongPtr(hwnd, DWLP_USER, 0);
    }

    /* TODO: Perform any additional uninitialization */

    return FALSE;
}

/* Dialog procedure for the new credentials panel for our credentials
   type.  We just dispatch messages here to other functions here.

   Note that this procedure runs under the UI thread.
 */
INT_PTR CALLBACK
nc_dlg_proc(HWND hwnd,
            UINT uMsg,
            WPARAM wParam,
            LPARAM lParam) {

    switch (uMsg) {
    case WM_INITDIALOG:
        return handle_wm_initdialog(hwnd, wParam, lParam);

    case WM_COMMAND:
        return handle_wm_command(hwnd, wParam, lParam);

    case KHUI_WM_NC_NOTIFY:
        return handle_khui_wm_nc_notify(hwnd, wParam, lParam);

    case WM_DESTROY:
        return handle_wm_destroy(hwnd, wParam, lParam);

        /* TODO: add code for handling other windows messages here. */
    }

    return FALSE;
}

/*******************************************************************

The following section contains function stubs for each of the
credentials messages that a credentials provider is likely to want to
handle.  It doesn't include a few messages, but they should be easy to
add.  Please see the documentation for each of the KMSG_CRED_*
messages for documentation on how to handle each of the messages.

********************************************************************/


/* Handler for KMSG_CRED_NEW_CREDS */
khm_int32
handle_kmsg_cred_new_creds(khui_new_creds * nc) {

    wchar_t wshortdesc[KHUI_MAXCCH_SHORT_DESC];
    size_t cb = 0;
    khui_new_creds_by_type * nct = NULL;

    /* This is a minimal handler that just adds a dialog pane to the
       new credentials window to handle new credentials acquisition
       for this credentials type. */

    /* TODO: add additional initialization etc. as needed */

    nct = malloc(sizeof(*nct));
    ZeroMemory(nct, sizeof(*nct));

    nct->type = credtype_id;
    nct->ordinal = -1;

    LoadString(hResModule, IDS_CT_SHORT_DESC,
               wshortdesc, ARRAYLENGTH(wshortdesc));
    StringCbLength(wshortdesc, sizeof(wshortdesc), &cb);
#ifdef DEBUG
    assert(cb > 0);
#endif
    cb += sizeof(wchar_t);

    nct->name = malloc(cb);
    StringCbCopy(nct->name, cb, wshortdesc);

    /* while we are at it, we should also allocate space for the
       credential text. */
    nct->credtext = malloc(KHUI_MAXCB_LONG_DESC);
    ZeroMemory(nct->credtext, KHUI_MAXCB_LONG_DESC);

    nct->h_module = hResModule;
    nct->dlg_proc = nc_dlg_proc;
    nct->dlg_template = MAKEINTRESOURCE(IDD_NEW_CREDS);

    khui_cw_add_type(nc, nct);

    return KHM_ERROR_SUCCESS;
}

/* Handler for KMSG_CRED_RENEW_CREDS */
khm_int32
handle_kmsg_cred_renew_creds(khui_new_creds * nc) {

    khui_new_creds_by_type * nct;

    /* This is a minimal handler that just adds this credential type
       to the list of credential types that are participating in this
       renewal operation. */

    /* TODO: add additional initialization etc. as needed */

    nct = malloc(sizeof(*nct));
    ZeroMemory(nct, sizeof(*nct));

    nct->type = credtype_id;

    khui_cw_add_type(nc, nct);

    return KHM_ERROR_SUCCESS;
}

/* Handler for KMSG_CRED_DIALOG_PRESTART */
khm_int32
handle_kmsg_cred_dialog_prestart(khui_new_creds * nc) {
    /* TODO: Handle this message */

    /* The message is sent after the dialog has been created.  The
       window handle for the created dialog can be accessed through
       the hwnd_panel member of the khui_new_creds_by_type structure
       that was added for this credentials type. */
    return KHM_ERROR_SUCCESS;
}

/* Handler for KMSG_CRED_DIALOG_NEW_IDENTITY */
/* Not a message sent out by NetIDMgr.  See documentation of
   KMSG_CRED_DIALOG_NEW_IDENTITY  */
khm_int32
handle_kmsg_cred_dialog_new_identity(khm_ui_4 uparam,
                                     void *   vparam) {
    /* TODO: Handle this message */
    return KHM_ERROR_SUCCESS;
}

/* Handler for KMSG_CRED_DIALOG_NEW_OPTIONS */
/* Not a message sent out by NetIDMgr.  See documentation of
   KMSG_CRED_DIALOG_NEW_OPTIONS */
khm_int32
handle_kmsg_cred_dialog_new_options(khm_ui_4 uparam,
                                    void *   vparam) {
    /* TODO: Handle this message */
    return KHM_ERROR_SUCCESS;
}

/* Handler for KMSG_CRED_PROCESS */
khm_int32
handle_kmsg_cred_process(khui_new_creds * nc) {
    /* TODO: Handle this message */

    /* This is where the credentials acquisition should be performed
       as determined by the UI.  Note that this message is sent even
       when the user clicks 'cancel'.  The value of nc->result should
       be checked before performing any credentials acquisition.  If
       the value is KHUI_NC_RESULT_CANCEL, then no credentials should
       be acquired.  Otherwise, the value would be
       KHUI_NC_RESULT_PROCESS. */

    return KHM_ERROR_SUCCESS;
}

/* Handler for KMSG_CRED_END */
khm_int32
handle_kmsg_cred_end(khui_new_creds * nc) {

    khui_new_creds_by_type * nct = NULL;

    /* TODO: Perform any additional uninitialization as needed. */

    khui_cw_find_type(nc, credtype_id, &nct);

    if (nct) {

        khui_cw_del_type(nc, credtype_id);

        if (nct->name)
            free(nct->name);
        if (nct->credtext)
            free(nct->credtext);

        free(nct);

    }

    return KHM_ERROR_SUCCESS;
}

/* Handler for KMSG_CRED_IMPORT */
khm_int32
handle_kmsg_cred_import(void) {

    /* TODO: Handle this message */

    return KHM_ERROR_SUCCESS;
}


/******************************************************
 Dispatch each message to individual handlers above.
 */
khm_int32 KHMAPI
handle_cred_acq_msg(khm_int32 msg_type,
                    khm_int32 msg_subtype,
                    khm_ui_4  uparam,
                    void *    vparam) {

    khm_int32 rv = KHM_ERROR_SUCCESS;

    switch(msg_subtype) {
    case KMSG_CRED_NEW_CREDS:
        return handle_kmsg_cred_new_creds((khui_new_creds *) vparam);

    case KMSG_CRED_RENEW_CREDS:
        return handle_kmsg_cred_renew_creds((khui_new_creds *) vparam);

    case KMSG_CRED_DIALOG_PRESTART:
        return handle_kmsg_cred_dialog_prestart((khui_new_creds *) vparam);

    case KMSG_CRED_PROCESS:
        return handle_kmsg_cred_process((khui_new_creds *) vparam);

    case KMSG_CRED_DIALOG_NEW_IDENTITY:
        return handle_kmsg_cred_dialog_new_identity(uparam, vparam);

    case KMSG_CRED_DIALOG_NEW_OPTIONS:
        return handle_kmsg_cred_dialog_new_options(uparam, vparam);

    case KMSG_CRED_END:
        return handle_kmsg_cred_end((khui_new_creds *) vparam);

    case KMSG_CRED_IMPORT:
        return handle_kmsg_cred_import();
    }

    return rv;
}

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

#define _NIMLIB_

#include<khuidefs.h>
#include<utils.h>
#include<intalert.h>
#include<assert.h>

#include<strsafe.h>

/***********************************************************************
  Alerter
***********************************************************************/


khui_alert * kh_alerts = NULL;
CRITICAL_SECTION cs_alerts;

void 
alert_init(void)
{
    InitializeCriticalSection(&cs_alerts);
}

void 
alert_exit(void)
{
    DeleteCriticalSection(&cs_alerts);
}

KHMEXP khm_int32 KHMAPI 
khui_alert_create_empty(khui_alert ** result)
{
    khui_alert * a;

    a = PMALLOC(sizeof(*a));
    ZeroMemory(a, sizeof(*a));

    a->magic = KHUI_ALERT_MAGIC;

    /* set defaults */
    a->severity = KHERR_INFO;
    a->flags = KHUI_ALERT_FLAG_FREE_STRUCT;
    a->alert_type = KHUI_ALERTTYPE_NONE;
    khui_context_create(&a->ctx, KHUI_SCOPE_NONE,
                        NULL, KCDB_CREDTYPE_INVALID,
                        NULL);

    khui_alert_hold(a);
    EnterCriticalSection(&cs_alerts);
    LPUSH(&kh_alerts, a);
    LeaveCriticalSection(&cs_alerts);

    *result = a;

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_alert_create_simple(const wchar_t * title, 
                         const wchar_t * message, 
                         khm_int32 severity, 
                         khui_alert ** result)
{
    khui_alert * a;

    khui_alert_create_empty(&a);
    khui_alert_set_title(a, title);
    khui_alert_set_message(a, message);
    khui_alert_set_severity(a, severity);

    *result = a;

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_alert_set_title(khui_alert * alert, const wchar_t * title)
{
    size_t cb = 0;

    assert(alert->magic == KHUI_ALERT_MAGIC);

    if(title) {
        if(FAILED(StringCbLength(title, 
                                 KHUI_MAXCB_TITLE, 
                                 &cb))) {
            return KHM_ERROR_INVALID_PARAM;
        }
        cb += sizeof(wchar_t);
    }

    EnterCriticalSection(&cs_alerts);
    if(alert->title && (alert->flags & KHUI_ALERT_FLAG_FREE_TITLE)) {
        PFREE(alert->title);
        alert->title = NULL;
        alert->flags &= ~KHUI_ALERT_FLAG_FREE_TITLE;
    }
    if(title) {
        alert->title = PMALLOC(cb);
        StringCbCopy(alert->title, cb, title);
        alert->flags |= KHUI_ALERT_FLAG_FREE_TITLE;
    }
    LeaveCriticalSection(&cs_alerts);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI
khui_alert_set_flags(khui_alert * alert, khm_int32 mask, khm_int32 flags) 
{
    assert(alert->magic == KHUI_ALERT_MAGIC);

    if (mask & ~KHUI_ALERT_FLAGMASK_RDWR)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_alerts);
    alert->flags = 
        (alert->flags & ~mask) |
        (flags & mask);
    LeaveCriticalSection(&cs_alerts);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_alert_set_severity(khui_alert * alert, khm_int32 severity)
{

    assert(alert->magic == KHUI_ALERT_MAGIC);

    EnterCriticalSection(&cs_alerts);
    alert->severity = severity;
    LeaveCriticalSection(&cs_alerts);
    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_alert_set_suggestion(khui_alert * alert,
                          const wchar_t * suggestion) {
    size_t cb = 0;

    assert(alert->magic == KHUI_ALERT_MAGIC);

    if(suggestion) {
        if(FAILED(StringCbLength(suggestion, 
                                 KHUI_MAXCB_MESSAGE - sizeof(wchar_t), 
                                 &cb))) {
            return KHM_ERROR_INVALID_PARAM;
        }
        cb += sizeof(wchar_t);
    }

    EnterCriticalSection(&cs_alerts);
    if(alert->suggestion && 
       (alert->flags & KHUI_ALERT_FLAG_FREE_SUGGEST)) {

        PFREE(alert->suggestion);
        alert->suggestion = NULL;
        alert->flags &= ~KHUI_ALERT_FLAG_FREE_SUGGEST;

    }

    if(suggestion) {
        alert->suggestion = PMALLOC(cb);
        StringCbCopy(alert->suggestion, cb, suggestion);
        alert->flags |= KHUI_ALERT_FLAG_FREE_SUGGEST;
    }
    LeaveCriticalSection(&cs_alerts);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_alert_set_message(khui_alert * alert, const wchar_t * message)
{
    size_t cb = 0;

    assert(alert->magic == KHUI_ALERT_MAGIC);

    if(message) {
        if(FAILED(StringCbLength(message, 
                                 KHUI_MAXCB_MESSAGE - sizeof(wchar_t), 
                                 &cb))) {
            return KHM_ERROR_INVALID_PARAM;
        }
        cb += sizeof(wchar_t);
    }

    EnterCriticalSection(&cs_alerts);
    if(alert->message && 
       (alert->flags & KHUI_ALERT_FLAG_FREE_MESSAGE)) {

        PFREE(alert->message);
        alert->flags &= ~KHUI_ALERT_FLAG_FREE_MESSAGE;
    }

    alert->message = NULL;

    if(message) {
        alert->message = PMALLOC(cb);
        StringCbCopy(alert->message, cb, message);
        alert->flags |= KHUI_ALERT_FLAG_FREE_MESSAGE;
    }
    LeaveCriticalSection(&cs_alerts);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_alert_clear_commands(khui_alert * alert)
{
    assert(alert->magic == KHUI_ALERT_MAGIC);

    EnterCriticalSection(&cs_alerts);
    alert->n_alert_commands = 0;
    LeaveCriticalSection(&cs_alerts);
    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_alert_add_command(khui_alert * alert, khm_int32 command_id)
{
    khm_int32 rv = KHM_ERROR_SUCCESS;

    assert(alert->magic == KHUI_ALERT_MAGIC);

    EnterCriticalSection(&cs_alerts);
    if(alert->n_alert_commands >= KHUI_MAX_ALERT_COMMANDS)
        rv = KHM_ERROR_NO_RESOURCES;
    else {
        alert->alert_commands[alert->n_alert_commands++] = command_id;
    }
    LeaveCriticalSection(&cs_alerts);

    return rv;
}

KHMEXP khm_int32 KHMAPI
khui_alert_set_type(khui_alert * alert, khui_alert_type alert_type)
{
    khm_int32 rv = KHM_ERROR_SUCCESS;

    assert(alert->magic == KHUI_ALERT_MAGIC);

    EnterCriticalSection(&cs_alerts);
    alert->alert_type = alert_type;
    LeaveCriticalSection(&cs_alerts);

    return rv;
}

KHMEXP khm_int32 KHMAPI
khui_alert_set_ctx(khui_alert * alert,
                   khui_scope scope,
                   khm_handle identity,
                   khm_int32 cred_type,
                   khm_handle cred)
{
    khm_int32 rv = KHM_ERROR_SUCCESS;

    assert(alert->magic == KHUI_ALERT_MAGIC);

    EnterCriticalSection(&cs_alerts);
    khui_context_release(&alert->ctx);
    khui_context_create(&alert->ctx,
                        scope,
                        identity,
                        cred_type,
                        cred);
    LeaveCriticalSection(&cs_alerts);

    return rv;
}

KHMEXP khm_int32 KHMAPI
khui_alert_get_response(khui_alert * alert)
{
    khm_int32 response = 0;

    assert(alert->magic == KHUI_ALERT_MAGIC);

    EnterCriticalSection(&cs_alerts);
    response = alert->response;
    LeaveCriticalSection(&cs_alerts);

    return response;
}

KHMEXP khm_int32 KHMAPI 
khui_alert_show(khui_alert * alert)
{
    assert(alert->magic == KHUI_ALERT_MAGIC);

    khui_alert_hold(alert);
    /* the alert will be released when the message is processed */
    kmq_post_message(KMSG_ALERT, KMSG_ALERT_SHOW, 0, (void *) alert);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI
khui_alert_show_modal(khui_alert * alert)
{
    khm_int32 rv;

    assert(alert->magic == KHUI_ALERT_MAGIC);

    khui_alert_hold(alert);
    rv = kmq_send_message(KMSG_ALERT, KMSG_ALERT_SHOW_MODAL, 0,
                          (void *) alert);

    return rv;
}

KHMEXP khm_int32 KHMAPI
khui_alert_queue(khui_alert * alert)
{
    assert(alert->magic == KHUI_ALERT_MAGIC);

    khui_alert_hold(alert);
    kmq_post_message(KMSG_ALERT, KMSG_ALERT_QUEUE, 0, (void *) alert);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_alert_show_simple(const wchar_t * title, 
                       const wchar_t * message, 
                       khm_int32 severity)
{
    khui_alert * a = NULL;
    khm_int32 rv;

    rv = khui_alert_create_simple(title, message, severity, &a);

    if(KHM_FAILED(rv))
        return rv;

    rv = khui_alert_show(a);

    khui_alert_release(a);

    return rv;
}

KHMEXP khm_int32 KHMAPI 
khui_alert_hold(khui_alert * alert) 
{
    assert(alert->magic == KHUI_ALERT_MAGIC);

    EnterCriticalSection(&cs_alerts);
    alert->refcount++;
    LeaveCriticalSection(&cs_alerts);
    return KHM_ERROR_SUCCESS;
}

/* called with cs_alert held */
static void 
free_alert(khui_alert * alert)
{
    assert(alert->magic == KHUI_ALERT_MAGIC);

    LDELETE(&kh_alerts, alert);

    if(alert->flags & KHUI_ALERT_FLAG_FREE_TITLE) {
        assert(alert->title);
        PFREE(alert->title);
        alert->title = NULL;
        alert->flags &= ~KHUI_ALERT_FLAG_FREE_TITLE;
    }
    if(alert->flags & KHUI_ALERT_FLAG_FREE_MESSAGE) {
        assert(alert->message);
        PFREE(alert->message);
        alert->message = NULL;
        alert->flags &= ~KHUI_ALERT_FLAG_FREE_MESSAGE;
    }
    if(alert->flags & KHUI_ALERT_FLAG_FREE_SUGGEST) {
        assert(alert->suggestion);
        PFREE(alert->suggestion);
        alert->suggestion = NULL;
        alert->flags &= ~KHUI_ALERT_FLAG_FREE_SUGGEST;
    }

    khui_context_release(&alert->ctx);

    if(alert->flags & KHUI_ALERT_FLAG_FREE_STRUCT) {
        alert->flags &= ~KHUI_ALERT_FLAG_FREE_STRUCT;
        alert->magic = 0;
        PFREE(alert);
    }
}

KHMEXP khm_int32 KHMAPI 
khui_alert_release(khui_alert * alert) 
{
    assert(alert->magic == KHUI_ALERT_MAGIC);

    EnterCriticalSection(&cs_alerts);
    if((--(alert->refcount)) == 0) {
        free_alert(alert);
    }
    LeaveCriticalSection(&cs_alerts);
    return KHM_ERROR_SUCCESS;
}

KHMEXP void KHMAPI khui_alert_lock(khui_alert * alert)
{
    EnterCriticalSection(&cs_alerts);
}

KHMEXP void KHMAPI khui_alert_unlock(khui_alert * alert)
{
    LeaveCriticalSection(&cs_alerts);
}

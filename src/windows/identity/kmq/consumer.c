/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
 * 
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

#include<kmqinternal.h>
#include<assert.h>

DWORD kmq_tls_queue;

CRITICAL_SECTION cs_kmq_msg_ref;

kmq_message_ref * kmq_msg_ref_free = NULL;

/* ad-hoc subscriptions */
kmq_msg_subscription * kmq_adhoc_subs = NULL;

#ifdef DEBUG

#include<stdio.h>

void
kmqint_dump_consumer(FILE * f) {
    kmq_message_ref * r;
    kmq_msg_subscription * s;

    int n_free = 0;
    int n_adhoc = 0;

    EnterCriticalSection(&cs_kmq_msg_ref);

    fprintf(f, "qc0\t*** Free Message References ***\n");

    fprintf(f, "qc1\tAddress\n");

    r = kmq_msg_ref_free;
    while(r) {
        n_free ++;

        fprintf(f, "qc2\t0x%p\n", r);

        r = LNEXT(r);
    }

    fprintf(f, "qc3\tTotal free message references : %d\n", n_free);

    fprintf(f, "qc4\t--- End ---\n");

    LeaveCriticalSection(&cs_kmq_msg_ref);

    EnterCriticalSection(&cs_kmq_global);

    fprintf(f, "qc5\t*** Adhoc Message Subscriptions ***\n");

    fprintf(f, "qc6\tAddress\tMsg Type\tRcpt Type\tRcpt\tQueue\n");

    s = kmq_adhoc_subs;

    while(s) {
        n_adhoc ++;

        fprintf(f, "qc7\t0x%p\t%d\t%s\t0x%p\t0x%p\n",
                s,
                s->type,
                (s->rcpt_type == KMQ_RCPTTYPE_CB)?"CALLBACK":"HWND",
                (s->rcpt_type == KMQ_RCPTTYPE_CB)? s->recipient.cb: (void *) s->recipient.hwnd,
                s->queue);

        s = LNEXT(s);
    }

    fprintf(f, "qc8\tTotal ad-hoc subscriptions : %d\n", n_adhoc);

    fprintf(f, "qc9\t--- End ---\n");

    LeaveCriticalSection(&cs_kmq_global);

}

#endif

/*! \internal
    \brief Get a message ref object
    \note called with cs_kmq_msg_ref held */
kmq_message_ref * kmqint_get_message_ref(void) {
    kmq_message_ref * r;

    LPOP(&kmq_msg_ref_free, &r);
    if(!r) {
        r = PMALLOC(sizeof(kmq_message_ref));
    }
    ZeroMemory(r, sizeof(kmq_message_ref));

    r->msg = NULL;
    r->recipient = NULL;

    return r;
}

/*! \internal
    \brief Free a message ref object
    \note called with cs_kmq_msg_ref and cs_kmq_msg held */
void kmqint_put_message_ref(kmq_message_ref * r) {
    if(!r)
        return;
    if(r->msg) {
        r->msg->refcount--;
        r->msg = NULL;
    }
    LPUSH(&kmq_msg_ref_free, r);
}

/*! \internal
    \brief Get the queue associated with the current thread
    \note Obtains ::cs_kmq_global
    */
kmq_queue * kmqint_get_thread_queue(void) {
    kmq_queue * q;

    q = (kmq_queue *) TlsGetValue(kmq_tls_queue);
    if(!q) {
        kmqint_attach_this_thread();
        q = (kmq_queue *) TlsGetValue(kmq_tls_queue);
    }

    return q;
}

/*! \internal
    \brief Get the topmost message ref for a queue
    \note Obtains kmq_queue::cs
    */
void kmqint_get_queue_message_ref(kmq_queue * q, kmq_message_ref ** r) {
    EnterCriticalSection(&q->cs);

    if (q->flags & KMQ_QUEUE_FLAG_DELETED) {
        *r = NULL;
    } else {
        QGET(q,r);
        if(QTOP(q))
            SetEvent(q->wait_o);
    }

    LeaveCriticalSection(&q->cs);
}

/*! \internal
    \brief Post a message to a queue
    \note Obtains ::cs_kmq_msg_ref, ::cs_kmq_msg, kmq_queue::cs
    */
void kmqint_post_queue(kmq_queue * q, kmq_message *m) {
    kmq_message_ref *r;

    EnterCriticalSection(&q->cs);
    if (q->flags & KMQ_QUEUE_FLAG_DELETED) {
        LeaveCriticalSection(&q->cs);
        return;
    }
    LeaveCriticalSection(&q->cs);

    EnterCriticalSection(&cs_kmq_msg_ref);
    r = kmqint_get_message_ref();
    LeaveCriticalSection(&cs_kmq_msg_ref);

    r->msg = m;
    r->recipient = NULL;

    EnterCriticalSection(&cs_kmq_msg);
    m->refcount++;
    m->nSent++;
    LeaveCriticalSection(&cs_kmq_msg);

    EnterCriticalSection(&q->cs);
    QPUT(q,r);
    SetEvent(q->wait_o);
    LeaveCriticalSection(&q->cs);
}

/*! \internal
    \brief Post a message to a subscriber
    \note Obtains ::cs_kmq_msg_ref, ::cs_kmq_msg, kmq_queue::cs
    \note Should be called with ::cs_kmq_msg held
    \note Should be called with ::cs_kmq_types held if try_send is true
    */
void kmqint_post(kmq_msg_subscription * s, kmq_message * m, khm_boolean try_send) {
    if(s->rcpt_type == KMQ_RCPTTYPE_CB) {
        kmq_queue *q;
        kmq_message_ref *r;

        q = s->queue;

        if(try_send && q->thread == GetCurrentThreadId()) {
            khm_int32 rv;
            /* we are sending a message from this thread to this
               thread.  just call the recipient directly, bypassing
               the message queue. */
            m->refcount++;
            m->nSent++;
            rv = s->recipient.cb(m->type, m->subtype, 
                                 m->uparam, m->vparam);
            m->refcount--;
            if(KHM_SUCCEEDED(rv))
                m->nCompleted++;
            else
                m->nFailed++;
        } else {

            EnterCriticalSection(&q->cs);
            if (q->flags & KMQ_QUEUE_FLAG_DELETED) {
                LeaveCriticalSection(&q->cs);
                return;
            }
            LeaveCriticalSection(&q->cs);

            EnterCriticalSection(&cs_kmq_msg_ref);
            r = kmqint_get_message_ref();
            LeaveCriticalSection(&cs_kmq_msg_ref);

            r->msg = m;
            r->recipient = s->recipient.cb;

            m->refcount++;
            m->nSent++;

            EnterCriticalSection(&q->cs);
            QPUT(q,r);
            SetEvent(q->wait_o);
            LeaveCriticalSection(&q->cs);
        }
    }

#ifdef _WIN32
    else if(s->rcpt_type == KMQ_RCPTTYPE_HWND) {
        if(try_send && 
           GetCurrentThreadId() == GetWindowThreadProcessId(s->recipient.hwnd, 
                                                            NULL)) {
            /* kmqint_post does not know whether there are any other
               messages waiting to be posted at this point.  Hence,
               simply sending the message is not the right thing to do
               as the recipient may incorrectly assume that the
               message has completed when (m->nCompleted + m->nFailed
               == m->nSent).  Therefore, we only increment nSent after
               the message is sent. */

            m->refcount++;

            /* the kmq_wm_begin()/kmq_wm_end() and kmq_wm_dispatch()
               handlers decrement the reference count on the message
               when they are done. */
            SendMessage(s->recipient.hwnd, KMQ_WM_DISPATCH, 
                        m->type, (LPARAM) m);

            m->nSent++;

        } else {
            m->nSent++;
            m->refcount++;

            /* the kmq_wm_begin()/kmq_wm_end() and kmq_wm_dispatch()
               handlers decrement the reference count on the message
               when they are done. */
            PostMessage(s->recipient.hwnd, KMQ_WM_DISPATCH, 
                        m->type, (LPARAM) m);
        }
    }
#endif

    else {
        /* This could either be because we were passed in an invalid
           subscription or because we lost a race to a thread that
           deleted an ad-hoc subscription. */
#ifdef DEBUG
        assert(FALSE);
#endif
    }
}

/*! \internal
    \brief Subscribes a window to a message type
    \note Obtains ::cs_kmq_types
    */
KHMEXP khm_int32 KHMAPI kmq_subscribe_hwnd(khm_int32 type, HWND hwnd) {
    kmq_msg_subscription * s;

    s = PMALLOC(sizeof(kmq_msg_subscription));
    ZeroMemory(s, sizeof(*s));
    s->magic = KMQ_MSG_SUB_MAGIC;
    LINIT(s);
    s->queue = NULL;
    s->rcpt_type = KMQ_RCPTTYPE_HWND;
    s->recipient.hwnd = hwnd;
    kmqint_msg_type_add_sub(type, s);

    return KHM_ERROR_SUCCESS;
}

/*! \internal
    \note Obtains ::cs_kmq_types, ::cs_kmq_global
    */
KHMEXP khm_int32 KHMAPI kmq_subscribe(khm_int32 type, kmq_callback_t cb) {
    kmq_msg_subscription * s;

    s = PMALLOC(sizeof(kmq_msg_subscription));
    ZeroMemory(s, sizeof(*s));
    s->magic = KMQ_MSG_SUB_MAGIC;
    LINIT(s);
    s->queue = kmqint_get_thread_queue();
    s->rcpt_type = KMQ_RCPTTYPE_CB;
    s->recipient.cb = cb;
    kmqint_msg_type_add_sub(type, s);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI kmq_create_hwnd_subscription(HWND hw,
                                                     khm_handle * result)
{
    kmq_msg_subscription * s;

    s = PMALLOC(sizeof(kmq_msg_subscription));
    ZeroMemory(s, sizeof(*s));
    s->magic = KMQ_MSG_SUB_MAGIC;
    LINIT(s);
    s->queue = NULL;
    s->rcpt_type = KMQ_RCPTTYPE_HWND;
    s->recipient.hwnd = hw;

    EnterCriticalSection(&cs_kmq_global);
    LPUSH(&kmq_adhoc_subs, s);
    LeaveCriticalSection(&cs_kmq_global);

    *result = (khm_handle) s;

    return KHM_ERROR_SUCCESS;
}

/*! \internal
    \note Obtains ::cs_kmq_global
*/
KHMEXP khm_int32 KHMAPI kmq_create_subscription(kmq_callback_t cb, 
                                                khm_handle * result)
{
    kmq_msg_subscription * s;

    s = PMALLOC(sizeof(kmq_msg_subscription));
    ZeroMemory(s, sizeof(*s));
    s->magic = KMQ_MSG_SUB_MAGIC;
    LINIT(s);
    s->queue = kmqint_get_thread_queue();
    s->rcpt_type = KMQ_RCPTTYPE_CB;
    s->recipient.cb = cb;

    EnterCriticalSection(&cs_kmq_global);
    LPUSH(&kmq_adhoc_subs, s);
    LeaveCriticalSection(&cs_kmq_global);

    *result = (khm_handle) s;

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI kmq_delete_subscription(khm_handle sub)
{
    kmq_msg_subscription * s;

    s = (kmq_msg_subscription *) sub;

    assert(s->magic == KMQ_MSG_SUB_MAGIC);

    s->type = 0;

    EnterCriticalSection(&cs_kmq_global);
    LDELETE(&kmq_adhoc_subs, s);
    LeaveCriticalSection(&cs_kmq_global);

    PFREE(s);

    return KHM_ERROR_SUCCESS;
}

/*! \internal
    \brief Unsubscribes a window from a message type
    \note Obtains ::cs_kmq_types
    */
KHMEXP khm_int32 KHMAPI kmq_unsubscribe_hwnd(khm_int32 type, HWND hwnd) {
    kmq_msg_subscription * s;

    s = kmqint_msg_type_del_sub_hwnd(type, hwnd);
    if(s)
        PFREE(s);
    return (s)?KHM_ERROR_SUCCESS:KHM_ERROR_NOT_FOUND;
}

/*! \internal
    \brief Unsubscribe a callback from a message type
    \note Obtains ::cs_kmq_types, ::cs_kmq_global
    */
KHMEXP khm_int32 KHMAPI kmq_unsubscribe(khm_int32 type, kmq_callback_t cb) {
    kmq_msg_subscription * s;

    s = kmqint_msg_type_del_sub_cb(type,cb);
    if(s)
        PFREE(s);

    return (s)?KHM_ERROR_SUCCESS:KHM_ERROR_NOT_FOUND;
}

KHMEXP LRESULT KHMAPI kmq_wm_begin(LPARAM lparm, kmq_message ** m) {
    *m = (kmq_message *) lparm;
    if ((*m)->err_ctx) {
        kherr_push_context((*m)->err_ctx);
    }
    return TRUE;
}

/*! \internal
    \note Obtains ::cs_kmq_msg
    */
KHMEXP LRESULT KHMAPI kmq_wm_end(kmq_message *m, khm_int32 rv) {
    if (m->err_ctx)
        kherr_pop_context();

    EnterCriticalSection(&cs_kmq_msg);
    m->refcount--;
    if(KHM_SUCCEEDED(rv))
        m->nCompleted++;
    else
        m->nFailed++;

    if(m->nCompleted + m->nFailed == m->nSent) {
        kmqint_put_message(m);
    }
    LeaveCriticalSection(&cs_kmq_msg);

    return TRUE;
}

/*! \internal
    \note Obtains ::cs_kmq_msg
    */
KHMEXP LRESULT KHMAPI kmq_wm_dispatch(LPARAM lparm, kmq_callback_t cb) {
    kmq_message *m;
    khm_int32 rv;

    m = (kmq_message *) lparm;

    if (m->err_ctx)
        kherr_push_context(m->err_ctx);

    rv = cb(m->type, m->subtype, m->uparam, m->vparam);

    if (m->err_ctx)
        kherr_pop_context();

    EnterCriticalSection(&cs_kmq_msg);

    m->refcount--;
    if(KHM_SUCCEEDED(rv))
        m->nCompleted++;
    else
        m->nFailed++;

    if(m->nCompleted + m->nFailed == m->nSent) {
        kmqint_put_message(m);
    }
    LeaveCriticalSection(&cs_kmq_msg);

    return TRUE;
}

KHMEXP khm_boolean KHMAPI kmq_is_call_aborted(void) {
    /* TODO: Implement this */
    return FALSE;
}

/*! \internal

    \note Obtains ::cs_kmq_global, kmq_queue::cs, ::cs_kmq_msg_ref, ::cs_kmq_msg, 
*/
KHMEXP khm_int32 KHMAPI kmq_dispatch(kmq_timer timeout) {
    kmq_queue * q;
    kmq_message_ref * r;
    kmq_message *m;
    DWORD hr;

    q = kmqint_get_thread_queue();

    assert(q->wait_o);

    hr = WaitForSingleObject(q->wait_o, timeout);
    if(hr == WAIT_OBJECT_0) {
        /* signalled */
        kmqint_get_queue_message_ref(q, &r);

        m = r->msg;

        if(m->type != KMSG_SYSTEM || m->subtype != KMSG_SYSTEM_EXIT) {
            khm_boolean rv;

            if (m->err_ctx)
                kherr_push_context(m->err_ctx);

            /* TODO: before dispatching the message, the message being
               dispatched for this thread needs to be stored so that
               it can be looked up in kmq_is_call_aborted(). This
               needs to happen in kmq_wm_dispatch() and
               kmq_wm_begin() as well. */

            /* dispatch */
            rv = r->recipient(m->type, m->subtype, m->uparam, m->vparam);

            if (m->err_ctx)
                kherr_pop_context();

            EnterCriticalSection(&cs_kmq_msg);
            EnterCriticalSection(&cs_kmq_msg_ref);
            kmqint_put_message_ref(r);
            LeaveCriticalSection(&cs_kmq_msg_ref);

            if(KHM_SUCCEEDED(rv))
                m->nCompleted++;
            else
                m->nFailed++;

            if(m->nCompleted + m->nFailed == m->nSent) {
                kmqint_put_message(m);
            }
            LeaveCriticalSection(&cs_kmq_msg);

            return KHM_ERROR_SUCCESS;
        } else {
            EnterCriticalSection(&cs_kmq_msg);
            EnterCriticalSection(&cs_kmq_msg_ref);
            kmqint_put_message_ref(r);
            LeaveCriticalSection(&cs_kmq_msg_ref);
            m->nCompleted++;
            if(m->nCompleted + m->nFailed == m->nSent) {
                kmqint_put_message(m);
            }
            LeaveCriticalSection(&cs_kmq_msg);

            return KHM_ERROR_EXIT;
        }
    } else {
        return KHM_ERROR_TIMEOUT;
    }
}

/* TODO: rename this file to subscriber.c */

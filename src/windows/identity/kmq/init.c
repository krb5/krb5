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

#include<kmqinternal.h>
#include<kconfig.h>
#include<assert.h>

CRITICAL_SECTION cs_kmq_global;
kmq_timer kmq_queue_dead_timeout;
kmq_timer kmq_call_dead_timeout;

kmq_queue * queues;

LONG kmq_init_once = 0;

void kmqint_init(void) {
    khm_handle hconfig = NULL;

    queues = NULL;

    InitializeCriticalSection(&cs_kmq_global);
    InitializeCriticalSection(&cs_kmq_msg);
    InitializeCriticalSection(&cs_kmq_msg_ref);

    EnterCriticalSection(&cs_kmq_global);
    khc_load_schema(NULL, schema_kmqconfig);
    khc_open_space(NULL, KMQ_CONF_SPACE_NAME, KHM_PERM_READ, &hconfig);
    if(hconfig) {
        khm_int32 t = 0;

        khc_read_int32(hconfig, KMQ_CONF_QUEUE_DEAD_TIMEOUT_NAME, &t);
        kmq_queue_dead_timeout = t;

        khc_read_int32(hconfig, KMQ_CONF_CALL_DEAD_TIMEOUT_NAME, &t);
        kmq_call_dead_timeout = t;

        khc_close_space(hconfig);
    }
    kmqint_init_msg_types();
    LeaveCriticalSection(&cs_kmq_global);

    kmq_tls_queue = TlsAlloc();
}

void kmqint_exit(void) {
    EnterCriticalSection(&cs_kmq_global);
    kmqint_exit_msg_types();
    LeaveCriticalSection(&cs_kmq_global);
    DeleteCriticalSection(&cs_kmq_msg);
    DeleteCriticalSection(&cs_kmq_msg_ref);
    DeleteCriticalSection(&cs_kmq_global);

    TlsFree(kmq_tls_queue);
}

/*! \internal
    \brief Preps a thread for use with kmq
    \note Obtains ::cs_kmq_global
    */
void kmqint_attach_this_thread(void) {
    kmq_queue * q;

    EnterCriticalSection(&cs_kmq_global);

    q = (kmq_queue *) TlsGetValue(kmq_tls_queue);
    if(!q) {
        q = PMALLOC(sizeof(kmq_queue));

        InitializeCriticalSection(&q->cs);
        q->thread = GetCurrentThreadId();
        QINIT(q);
        LINIT(q);
        q->wait_o = CreateEvent(NULL, FALSE, FALSE, NULL);
        q->load = 0;
        q->last_post = 0;
        q->flags = 0;

        LPUSH(&queues, q);

        TlsSetValue(kmq_tls_queue, (LPVOID) q);
    }

    LeaveCriticalSection(&cs_kmq_global);
}

/*! \internal
    \brief Detaches the current thread from kmq
    \note Obtains ::cs_kmq_global
    */
void kmqint_detach_this_thread(void) {
    kmq_queue * q;

    q = (kmq_queue *) TlsGetValue(kmq_tls_queue);
    if(q) {
        kmq_message_ref * r;
        kmq_message * m;

        EnterCriticalSection(&q->cs);

        if (q->flags & KMQ_QUEUE_FLAG_DETACHING) {
#ifdef DEBUG
            assert(FALSE);
#endif
            LeaveCriticalSection(&q->cs);
            return;
        }

        q->flags |= KMQ_QUEUE_FLAG_DELETED | KMQ_QUEUE_FLAG_DETACHING;

        QGET(q, &r);
        while(r) {

            m = r->msg;

            LeaveCriticalSection(&q->cs);

            EnterCriticalSection(&cs_kmq_msg);
            EnterCriticalSection(&cs_kmq_msg_ref);
            kmqint_put_message_ref(r);
            LeaveCriticalSection(&cs_kmq_msg_ref);

            m->nFailed++;
            if(m->nCompleted + m->nFailed == m->nSent) {
                kmqint_put_message(m);
            }
            LeaveCriticalSection(&cs_kmq_msg);

            EnterCriticalSection(&q->cs);

            QGET(q, &r);
        }

        CloseHandle(q->wait_o);

        q->wait_o = NULL;

        q->flags &= ~KMQ_QUEUE_FLAG_DETACHING;
        
        LeaveCriticalSection(&q->cs);

        /* For now, we don't free the queue. */

        /* TODO: before we can free the queue, we have to go through
           all the message type subscriptions and ad-hoc subscriptions
           and make sure no subscriptions exist which refer to this
           message queue. */
    }
}

HANDLE kmq_h_compl = NULL;
kmq_thread_id kmq_tid_compl;

/* Message transfer */
struct tag_kmq_msg_xfer {
    QDCL(kmq_message);
} kmq_completion_xfer;

HANDLE compl_wx;
BOOL compl_continue;
CRITICAL_SECTION cs_compl;

DWORD WINAPI kmqint_completion_thread_proc(LPVOID p) {
    kmq_message * m;
    kherr_context * ctx;

    PDESCTHREAD(L"Msg completion thread", L"KMQ");

    EnterCriticalSection(&cs_compl);
    do {
       
        if (QTOP(&kmq_completion_xfer) == NULL) {
            LeaveCriticalSection(&cs_compl);
            WaitForSingleObject(compl_wx, INFINITE);
            EnterCriticalSection(&cs_compl);
            /* go through the loop again before checking the queue */
        } else {
            QGET(&kmq_completion_xfer, &m);
            LeaveCriticalSection(&cs_compl);
            EnterCriticalSection(&cs_kmq_msg);

            ctx = m->err_ctx;

            if (ctx)
                kherr_push_context(ctx);

            kmqint_put_message(m);

            if (ctx)
                kherr_pop_context();

            LeaveCriticalSection(&cs_kmq_msg);
            EnterCriticalSection(&cs_compl);
        }

    } while(compl_continue);

    LeaveCriticalSection(&cs_compl);

    ExitThread(0);

    /* not reached */
    return 0;
}

int kmqint_call_completion_handler(kmq_msg_completion_handler h,
                                    kmq_message * m) {
    if (h == NULL)
        return 0;

    /* We only dispatch to the completion thread if we are not the
       completion thread.  If calling the completion handler results
       in more messages completing, then we just call the completion
       handler directly.  We also make an exception for completions
       that happen before the message queue is properly intiailized. */

    if (kmq_tid_compl != GetCurrentThreadId() &&
        kmq_h_compl != NULL) {

        EnterCriticalSection(&cs_compl);
        QPUT(&kmq_completion_xfer, m);
        SetEvent(compl_wx);
        LeaveCriticalSection(&cs_compl);

        return 1;

    } else {
        h(m);

        return 0;
    }
}

KHMEXP khm_int32 KHMAPI kmq_init(void) {
    if (InterlockedIncrement(&kmq_init_once) == 1) {
        EnterCriticalSection(&cs_kmq_global);

        InitializeCriticalSection(&cs_compl);
        compl_wx = CreateEvent(NULL, FALSE, FALSE, NULL);
        compl_continue = TRUE;
        QINIT(&kmq_completion_xfer);

        kmq_h_compl = CreateThread(NULL,
                                   0,
                                   kmqint_completion_thread_proc,
                                   NULL,
                                   0,
                                   &kmq_tid_compl);

        assert(kmq_h_compl != NULL);

        LeaveCriticalSection(&cs_kmq_global);
    }

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI kmq_exit(void) {
    if (InterlockedDecrement(&kmq_init_once) == 0) {

        EnterCriticalSection(&cs_compl);
        compl_continue = FALSE;
        SetEvent(compl_wx);
        LeaveCriticalSection(&cs_compl);

        WaitForSingleObject(kmq_h_compl, INFINITE);

        EnterCriticalSection(&cs_kmq_global);
        CloseHandle(kmq_h_compl);
        kmq_h_compl = NULL;
        kmq_tid_compl = 0;
        CloseHandle(compl_wx);
        DeleteCriticalSection(&cs_compl);
        LeaveCriticalSection(&cs_kmq_global);
    }

    return KHM_ERROR_SUCCESS;
}

#ifdef DEBUG

void kmqint_dump_consumer(FILE * f);
void kmqint_dump_publisher(FILE * f);


KHMEXP void KHMAPI kmqint_dump(FILE * f) {
    kmqint_dump_consumer(f);
    kmqint_dump_publisher(f);
}

#endif

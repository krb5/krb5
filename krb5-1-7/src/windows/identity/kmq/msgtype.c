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

CRITICAL_SECTION cs_kmq_types;

kmq_msg_type *msg_types[KMQ_MSG_TYPE_MAX + 1];
kmq_msg_type *all_msg_types = NULL;

/*! \internal
    \brief Initializes the message type data structures
    \note called with cs_mkq_global held */
void kmqint_init_msg_types(void) {
    ZeroMemory(msg_types, sizeof(kmq_msg_type *) * (KMQ_MSG_TYPE_MAX + 1));
    InitializeCriticalSection(&cs_kmq_types);
}

/*! \internal
    \brief Frees up the message type data structures
    \note called with cs_mkq_global held */
void kmqint_exit_msg_types(void) {
    int i;

    EnterCriticalSection(&cs_kmq_types);
    for(i=0;i<KMQ_MSG_TYPE_MAX;i++) {
        if(msg_types[i])
            kmqint_free_msg_type(i);
    }
    LeaveCriticalSection(&cs_kmq_types);
    DeleteCriticalSection(&cs_kmq_types);
}

/*! \internal
    \brief Notifies that the message has completed

    \return Zero if the completion handling is done.  Nonzero if the
    handling is queued.
    */
int kmqint_notify_msg_completion(kmq_message * m) {
    kmq_msg_type * mt;
    kmq_msg_completion_handler h;

    /* doing it this way to elude race conditions without
       obtaining a lock */

    mt = msg_types[m->type];
    if(mt == NULL)
        return 0;
    h = mt->completion_handler;

    /* handler is set to NULL before freeing type */
    if(h == NULL || msg_types[m->type] == NULL)
        return 0;

    return kmqint_call_completion_handler(h,m);
}

/* called with cs_mkq_global && cs_kmq_types held */
void kmqint_free_msg_type(int t) {
    kmq_msg_type * pt;
    kmq_msg_subscription * s;

    pt = msg_types[t];

    msg_types[t] = NULL;

    if (pt == NULL)
        return;

    /* all the subscriptions attached to a message type are owned by
       the message type */
    LPOP(&pt->subs, &s);
    while(s) {
        s->magic = 0;

        PFREE(s);

        LPOP(&pt->subs, &s);
    }

    pt->completion_handler = NULL;

    LDELETE(&all_msg_types, pt);

    PFREE(pt);
}

/*! \internal
    \brief Create a message type
    \note Obtains ::cs_kmq_types
    */
void kmqint_msg_type_create(int t) {
    if(t < 0 || t > KMQ_MSG_TYPE_MAX)
        return;

    EnterCriticalSection(&cs_kmq_types);
    if(!msg_types[t]) {
        kmq_msg_type * mt;
        mt = PMALLOC(sizeof(kmq_msg_type));
        ZeroMemory(mt, sizeof(kmq_msg_type));
        mt->id = t;
        LINIT(mt);
        mt->subs = NULL;
        msg_types[t] = mt;

        LPUSH(&all_msg_types, mt);
    }
    LeaveCriticalSection(&cs_kmq_types);
}

KHMEXP khm_int32 KHMAPI kmq_register_type(wchar_t * name, 
                                          khm_int32 * new_id)
{
    int i;
    khm_int32 rv = KHM_ERROR_SUCCESS;
    BOOL registered = FALSE;
    int first_free = 0;
    size_t sz;

    if(FAILED(StringCbLength(name, KMQ_MAXCB_TYPE_NAME, &sz)) ||
       sz == 0)
        return KHM_ERROR_INVALID_PARAM;
    sz += sizeof(wchar_t);

    EnterCriticalSection(&cs_kmq_types);
    for(i=KMSGBASE_USER; i <= KMQ_MSG_TYPE_MAX; i++) {
        if(msg_types[i] == NULL) {
            if(first_free == 0)
                first_free = i;
            /* continue searching since we might find that this type
               is already registered. */
        } else {
            if(msg_types[i]->name != NULL && 
               !wcscmp(msg_types[i]->name, name)) {

                registered = TRUE;
                if (new_id)
                    *new_id = i;
                break;
            }
        }
    }

    if(registered) {
        rv = KHM_ERROR_EXISTS;
    } else if(first_free == 0) {
        rv = KHM_ERROR_NO_RESOURCES;
    } else {
        kmqint_msg_type_create(first_free);
        msg_types[first_free]->name = PMALLOC(sz);
        StringCbCopy(msg_types[first_free]->name, sz, name);

        if(new_id != NULL)
            *new_id = first_free;
    }
    LeaveCriticalSection(&cs_kmq_types);

    return rv;
}

KHMEXP khm_int32 KHMAPI kmq_find_type(wchar_t * name, khm_int32 * id)
{
    int i;

    EnterCriticalSection(&cs_kmq_types);
    for(i=KMSGBASE_USER; i <= KMQ_MSG_TYPE_MAX; i++) {
        if(msg_types[i] != NULL && msg_types[i]->name != NULL) {
            if(!wcscmp(msg_types[i]->name, name))
                break;
        }
    }
    LeaveCriticalSection(&cs_kmq_types);

    if(i <= KMQ_MSG_TYPE_MAX) {
        if(id != NULL)
            *id = i;
        return KHM_ERROR_SUCCESS;
    }

    return KHM_ERROR_NOT_FOUND;
}

KHMEXP khm_int32 KHMAPI kmq_unregister_type(khm_int32 id)
{
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if(id < KMSGBASE_USER || id > KMQ_MSG_TYPE_MAX)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_kmq_types);
    if(msg_types[id] != NULL) {
        EnterCriticalSection(&cs_kmq_global);
        kmqint_free_msg_type(id);
        LeaveCriticalSection(&cs_kmq_global);
    } else {
        rv = KHM_ERROR_NOT_FOUND;
    }
    LeaveCriticalSection(&cs_kmq_types);

    return rv;
}

/*! \internal
    \brief Adds a subscription to a message type
    \note Obtains ::cs_kmq_types
    */
void kmqint_msg_type_add_sub(int t, kmq_msg_subscription *s) {
    kmq_msg_subscription * ts;

    if(t < 0 || t > KMQ_MSG_TYPE_MAX)
        return;

    if(!msg_types[t])
        kmqint_msg_type_create(t);

    EnterCriticalSection(&cs_kmq_types);
    s->type = t;
    /* check if we already have this subscription */
    ts = msg_types[t]->subs;
    while(ts) {
        if((ts->rcpt_type == s->rcpt_type) &&
            (((ts->rcpt_type == KMQ_RCPTTYPE_CB) && (ts->recipient.cb == s->recipient.cb)) ||
             ((ts->rcpt_type == KMQ_RCPTTYPE_HWND) && (ts->recipient.hwnd == s->recipient.hwnd))))
            break;
        ts = LNEXT(ts);
    }
    /* add it if we didn't find it */
    if(!ts) {
        LPUSH(&msg_types[t]->subs, s);
    }
    LeaveCriticalSection(&cs_kmq_types);
}

/*! \internal
    \brief Delete a subscription
    \note Obtains ::cs_kmq_types
    */
void kmqint_msg_type_del_sub(kmq_msg_subscription *s) {
    int t = s->type;

    EnterCriticalSection(&cs_kmq_types);
    if(msg_types[t]) {
        LDELETE(&msg_types[t]->subs,s);
    }
    LeaveCriticalSection(&cs_kmq_types);
}


/*! \internal
    \brief Deletes a window subscription from a message type
    \note Obtains ::cs_kmq_types
*/
kmq_msg_subscription * kmqint_msg_type_del_sub_hwnd(khm_int32 t, HWND hwnd) {
    kmq_msg_subscription *s = NULL;

    if(t < 0 || t > KMQ_MSG_TYPE_MAX)
        return NULL;

    EnterCriticalSection(&cs_kmq_types);
    if(msg_types[t]) {
        s = msg_types[t]->subs;
        while(s) {
            kmq_msg_subscription * n = LNEXT(s);
            if(s->rcpt_type == KMQ_RCPTTYPE_HWND && s->recipient.hwnd == hwnd) {
                /*TODO: do more here? */
                LDELETE(&msg_types[t]->subs, s);
                break;
            }
            s = n;
        }
    }
    LeaveCriticalSection(&cs_kmq_types);

    return s;
}

/*! \internal
    \brief Delete a callback from a message type
    \note Obtains ::cs_kmq_types, ::cs_kmq_global
    */
kmq_msg_subscription * kmqint_msg_type_del_sub_cb(khm_int32 t, kmq_callback_t cb) {
    kmq_msg_subscription *s;
    kmq_queue *q;

    if(t < 0 || t > KMQ_MSG_TYPE_MAX)
        return NULL;

    if(!msg_types[t])
        return NULL;

    q = kmqint_get_thread_queue();

    EnterCriticalSection(&cs_kmq_types);
    s = msg_types[t]->subs;
    while(s) {
        kmq_msg_subscription * n = LNEXT(s);
        if(s->rcpt_type == KMQ_RCPTTYPE_CB && 
           s->recipient.cb == cb && 
           s->queue == q) {
            /*TODO: do more here? */
            LDELETE(&msg_types[t]->subs, s);
            break;
        }
        s = n;
    }
    LeaveCriticalSection(&cs_kmq_types);

    return s;
}

/*! \internal
    \brief Publish a message
    \note Obtains ::cs_kmq_types, ::cs_kmq_msg_ref, kmq_queue::cs, ::cs_kmq_msg
    */
khm_int32 kmqint_msg_publish(kmq_message * m, khm_boolean try_send) {
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if(msg_types[m->type]) {
        kmq_msg_type *t;
        kmq_msg_subscription * s;

        EnterCriticalSection(&cs_kmq_types);
        EnterCriticalSection(&cs_kmq_msg);
        t = msg_types[m->type];
        s = t->subs;
        while(s) {
            kmqint_post(s, m, try_send);
            s = LNEXT(s);
        }

        if(m->nCompleted + m->nFailed == m->nSent) {
            kmqint_put_message(m);
        }

        LeaveCriticalSection(&cs_kmq_msg);
        LeaveCriticalSection(&cs_kmq_types);

    } else {
        EnterCriticalSection(&cs_kmq_msg);
        kmqint_put_message(m);
        LeaveCriticalSection(&cs_kmq_msg);
    }
    return rv;
}

/*! \internal
    \brief Sets the completion handler for a message type
    \note Obtains ::cs_kmq_types
    */
khm_int32 kmqint_msg_type_set_handler(khm_int32 type, kmq_msg_completion_handler handler) {

    if (type == KMSG_SYSTEM)
        return KHM_ERROR_INVALID_PARAM;

    if(!msg_types[type]) {
        if (handler)
            kmqint_msg_type_create(type);
        else
            return KHM_ERROR_SUCCESS;
    }

    if(!msg_types[type])
        return KHM_ERROR_NO_RESOURCES;

    EnterCriticalSection(&cs_kmq_types);
    msg_types[type]->completion_handler = handler;
    LeaveCriticalSection(&cs_kmq_types);

    return KHM_ERROR_SUCCESS;
}

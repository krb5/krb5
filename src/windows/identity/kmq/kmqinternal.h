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

#ifndef __KHIMAIRA_KMQINTERNAL_H
#define __KHIMAIRA_KMQINTERNAL_H

#include<windows.h>
#include<kmq.h>
#include<khlist.h>
#include<kherror.h>
#include<khmsgtypes.h>
#include<kconfig.h>

#define NOEXPORT

#include<utils.h>
#include<strsafe.h>




/*! \brief Message reference */
typedef struct tag_kmq_message_ref {
    kmq_message * msg;          /*!< Message that we are referring
                                  to */
    kmq_callback_t recipient;   /*!< The recipient of the message */

    LDCL(struct tag_kmq_message_ref);
} kmq_message_ref;




/*! \brief Message queue

    Each thread gets its own message queue.  When a message is
    broadcast to which there is a subscriber in a particular thread, a
    reference to the message is placed in the message queue of the
    thread.  The dispatch procedure then dispatches the message as
    described in the message reference.
*/
typedef struct tag_kmq_queue {
    kmq_thread_id thread;       /*!< The thread id  */

    CRITICAL_SECTION cs;
    HANDLE wait_o;

    khm_int32 load;             /*!< Number of messages waiting to be
                                  processed on this message queue.  */
    kmq_timer last_post;        /*!< Time the last message was
                                  received */

    khm_int32 flags;            /*!< Flags.  Currently, it's just KMQ_QUEUE_FLAG_DELETED */

    /*Q*/
    QDCL(kmq_message_ref);      /*!< Queue of message references  */

    /*Lnode*/
    LDCL(struct tag_kmq_queue);
} kmq_queue;

#define KMQ_QUEUE_FLAG_DELETED   0x00000008
#define KMQ_QUEUE_FLAG_DETACHING 0x00000010

/*! \brief Message subscription

    A subscription binds a recipient with a message type.  These are
    specific to a thread. I.e. a subscription that was made in one
    thread will not receive messages in the context of another thread.
*/
typedef struct tag_kmq_msg_subscription {
    khm_int32 magic;            /*!< Magic number.  Should always be
                                  ::KMQ_MSG_SUB_MAGIC */
    khm_int32 type;             /*!< Type of message */
    khm_int32 rcpt_type;        /*!< Type of recipient.  One of
                                  ::KMQ_RCPTTYPE_CB or
                                  ::KMQ_RCPTTYPE_HWND  */
    union {
        kmq_callback_t cb;      /*!< Callback if the subscription is
                                  of callback type */
        HWND hwnd;              /*!< Window handle if the subscription
                                  is a windows message type */
    } recipient;

    kmq_queue * queue;          /*!< Associated queue */

    /*lnode*/
    LDCL(struct tag_kmq_msg_subscription);
} kmq_msg_subscription;

#define KMQ_MSG_SUB_MAGIC 0x3821b58e

/*! \brief Callback recipient type

    The recipient is a callback function */
#define KMQ_RCPTTYPE_CB     1

/*! \brief Windows recipient type

    The recipient is a window */
#define KMQ_RCPTTYPE_HWND   2




/*! \brief A message type
 */
typedef struct tag_kmq_msg_type {
    khm_int32 id;               /*!< Identifier for the message
                                  type. */
    kmq_msg_subscription * subs; /*!< The list of subscriptions */
    kmq_msg_completion_handler completion_handler; /*!< Completion
                                  handler for the message type */

    wchar_t * name;             /*!< Name of the message type for
                                  named types.  Message type names are
                                  language independant. */

    /*Lnode*/
    LDCL(struct tag_kmq_msg_type);
} kmq_msg_type;

/*! \brief The maximum number of message types
 */
#define KMQ_MSG_TYPE_MAX 255

/*! \brief Maximum number of characters in a message type name

    The count includes the terminating NULL
 */
#define KMQ_MAXCCH_TYPE_NAME 256

/*! \brief Maximum number of bytes in a message type name

    Type count includes the terminating NULL
 */
#define KMQ_MAXCB_TYPE_NAME (KMQ_MAXCCH_TYPE_NAME * sizeof(wchar_t))




#define KMQ_CONF_SPACE_NAME L"KMQ"
#define KMQ_CONF_QUEUE_DEAD_TIMEOUT_NAME L"QueueDeadTimeout"
#define KMQ_CONF_CALL_DEAD_TIMEOUT_NAME L"CallDeadTimeout"

extern CRITICAL_SECTION cs_kmq_global;
extern kmq_timer kmq_queue_dead_timeout;
extern kmq_timer kmq_call_dead_timeout;

extern kmq_queue * queues;

/* message type */
extern CRITICAL_SECTION cs_kmq_types;
extern kmq_msg_type *msg_types[KMQ_MSG_TYPE_MAX+1];

void kmqint_init_msg_types(void);
void kmqint_exit_msg_types(void);
void kmqint_free_msg_type(int t);
void kmqint_msg_type_create(int t);
void kmqint_msg_type_add_sub(int t, kmq_msg_subscription *s);
void kmqint_msg_type_del_sub(kmq_msg_subscription *s);
kmq_msg_subscription * kmqint_msg_type_del_sub_hwnd(khm_int32 t, HWND hwnd);
kmq_msg_subscription * kmqint_msg_type_del_sub_cb(khm_int32 t, kmq_callback_t cb);
khm_int32 kmqint_msg_publish(kmq_message * m, khm_boolean try_send);
khm_int32 kmqint_msg_type_set_handler(khm_int32 type, kmq_msg_completion_handler handler);
int kmqint_notify_msg_completion(kmq_message * m);

/* consumer */
extern DWORD kmq_tls_queue;

void kmqint_post_queue(kmq_queue * q, kmq_message *m);
void kmqint_post(kmq_msg_subscription * s, kmq_message * m, khm_boolean try_send);
kmq_queue * kmqint_get_thread_queue(void);
void kmqint_get_queue_message_ref(kmq_queue * q, kmq_message_ref ** r);
void kmqint_put_message_ref(kmq_message_ref * r);

/* publisher */
extern CRITICAL_SECTION cs_kmq_msg;
extern CRITICAL_SECTION cs_kmq_msg_ref;

kmq_message * kmqint_get_message(void);
void kmqint_put_message(kmq_message *m);

void kmqint_init(void);
void kmqint_exit(void);
void kmqint_attach_this_thread(void);
void kmqint_detach_this_thread(void);

khm_int32 kmqint_post_message_ex(
    khm_int32 type, 
    khm_int32 subtype, 
    khm_ui_4 uparam, 
    void * blob, 
    kmq_call * call,
    khm_boolean try_send);

int kmqint_call_completion_handler(kmq_msg_completion_handler h,
                                   kmq_message * m);

/* global */
extern kconf_schema schema_kmqconfig[];

/* Lock hiearchy :

    cs_kmq_types
    cs_kmq_msg
    cs_kmq_msg_ref
    cs_compl
    cs_kmq_global
    kmq_queue::cs

    If you have a level 'x' lock, you can obtain a level 'x+n' lock.
    You can't obtain a 'x-n' lock if you already have a level 'x' lock.
    If you don't have any locks, you can obtain any lock.
 */
#endif

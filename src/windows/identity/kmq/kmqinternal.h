/*
 * Copyright (c) 2004 Massachusetts Institute of Technology
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
#include<strsafe.h>

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

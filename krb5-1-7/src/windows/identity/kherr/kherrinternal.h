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

#ifndef __KHIMAIRA_KHERRORINTERNAL_H
#define __KHIMAIRA_KHERRORINTERNAL_H

#define _NIMLIB_

#include<windows.h>
#include<kherr.h>
#include<utils.h>
#include<strsafe.h>

#define IS_KHERR_CTX(c) ((c) && (c)->magic == KHERR_CONTEXT_MAGIC)
#define IS_KHERR_EVENT(e) ((e) && (e)->magic == KHERR_EVENT_MAGIC)

typedef struct tag_kherr_thread {
    khm_size nc_ctx;
    khm_size n_ctx;
    kherr_context ** ctx;
} kherr_thread;

#define THREAD_STACK_SIZE 8

typedef struct tag_kherr_handler_node {
    khm_int32         filter;
    kherr_ctx_handler h;
    kherr_serial      serial;
} kherr_handler_node;

#define CTX_ALLOC_INCR 4

#define EVENT_MASK_UNRESOLVED \
    (KHERR_RF_RES_SHORT_DESC|KHERR_RF_MSG_SHORT_DESC| \
    KHERR_RF_RES_LONG_DESC|KHERR_RF_MSG_LONG_DESC| \
    KHERR_RF_RES_SUGGEST|KHERR_RF_MSG_SUGGEST)

extern CRITICAL_SECTION cs_error;
extern DWORD tls_error;
extern kherr_context * ctx_free_list;
extern kherr_event * evt_free_list;
extern kherr_handler_node * ctx_handlers;
extern khm_size n_ctx_handlers;

#define parm_type(p) ((p).type)
#define parm_data(p) ((p).data)

void resolve_event_strings(kherr_event *);
void attach_this_thread(void);
void detach_this_thread(void);
#endif

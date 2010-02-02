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

#include<kcreddbinternal.h>

/* set to TRUE when the configuration is loaded */
static int kcdb_config_loaded = 0;

/* global state cs */
static CRITICAL_SECTION cs_kcdb_global;

/* forward dcl */
void KHMAPI kcdb_msg_completion(kmq_message * m);

void kcdb_init(void) {
    /* setup the critical sections */
    InitializeCriticalSection(&cs_kcdb_global);

    kmq_set_completion_handler(KMSG_KCDB, kcdb_msg_completion);

    kcdb_credtype_init();
    kcdbint_ident_init();
    kcdb_credset_init();
    kcdb_cred_init();
    kcdb_type_init();
    kcdb_attrib_init();
}

void kcdb_exit(void) {

    kcdb_attrib_exit();
    kcdb_type_exit();
    kcdb_cred_exit();
    kcdb_credset_exit();
    kcdbint_ident_exit();
    kcdb_credtype_exit();

    kmq_set_completion_handler(KMSG_KCDB, NULL);

    DeleteCriticalSection(&cs_kcdb_global);
}

khm_handle kcdb_get_config(void) {
    khm_handle space = NULL;

    EnterCriticalSection(&cs_kcdb_global);
    if(!kcdb_config_loaded) {
        khc_load_schema(NULL, schema_kcdbconfig);
        kcdb_config_loaded = 1;
    }
    khc_open_space(NULL, L"KCDB", 0, &space);
    LeaveCriticalSection(&cs_kcdb_global);

    return space;
}

void KHMAPI kcdb_msg_completion(kmq_message * m) {
    if(!m)
        return;
    if(m->subtype == KMSG_KCDB_IDENT)
        kcdbint_ident_msg_completion(m);
    else if(m->subtype == KMSG_KCDB_ATTRIB)
        kcdb_attrib_msg_completion(m);
    else if(m->subtype == KMSG_KCDB_TYPE)
        kcdb_type_msg_completion(m);
    else if(m->subtype == KMSG_KCDB_CREDTYPE)
        kcdb_credtype_msg_completion(m);
}

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

#include<kmminternal.h>

kmm_module_i * kmm_all_modules = NULL;
kmm_plugin_i * kmm_listed_plugins = NULL;

HANDLE ht_registrar = NULL;
DWORD tid_registrar = 0;
DWORD tls_kmm = 0;

#define KMM_HASH_SIZE 31
hashtable * hash_plugins = NULL;
hashtable * hash_modules = NULL;

CRITICAL_SECTION cs_kmm;
HANDLE evt_startup = NULL;
HANDLE evt_exit = NULL;
int ready = 0;

HINSTANCE kmm_hInstance;
const wchar_t * kmm_facility = L"KMM";

KHMEXP void KHMAPI kmm_init(void)
{
    DWORD dummy;

    EnterCriticalSection(&cs_kmm);
    kmm_all_modules = NULL;
    kmm_listed_plugins = NULL;

    tls_kmm = TlsAlloc();

    hash_plugins = hash_new_hashtable(
        KMM_HASH_SIZE, 
        hash_string, 
        hash_string_comp, 
        NULL, 
        NULL);

    hash_modules = hash_new_hashtable(
        KMM_HASH_SIZE,
        hash_string,
        hash_string_comp,
        NULL,
        NULL);

    ht_registrar = CreateThread(
        NULL,
        0,
        kmmint_registrar,
        NULL,
        0,
        &dummy);

    _WAIT_FOR_START;

    khc_load_schema(NULL, schema_kmmconfig);

    LeaveCriticalSection(&cs_kmm);
}

KHMEXP void KHMAPI kmm_exit(void)
{
    kmm_module_i * m;
    kmm_plugin_i * p;

    EnterCriticalSection(&cs_kmm);

    p = kmm_listed_plugins;
    while(p) {
        kmm_plugin_i * pn;

        pn = LNEXT(p);
        /* plugins that were never resolved should be kicked off the
           list.  Flipping the refcount will do that if no other
           references exist for the plugin.  The plugins that were
           waiting for unresolved dependencies will automatically get
           freed when the placeholders and other plugins get freed. */
        if(p->state == KMM_PLUGIN_STATE_PLACEHOLDER) {
            kmm_hold_plugin(kmm_handle_from_plugin(p));
            kmm_release_plugin(kmm_handle_from_plugin(p));
        }

        p = pn;
    }

    m = kmm_all_modules;
    while(m) {
        kmm_unload_module(kmm_handle_from_module(m));
        m = LNEXT(m);
    }

    LeaveCriticalSection(&cs_kmm);
    WaitForSingleObject(evt_exit, INFINITE);

    kmq_send_thread_quit_message(tid_registrar, 0);

    EnterCriticalSection(&cs_kmm);

    hash_del_hashtable(hash_plugins);
    hash_del_hashtable(hash_modules);

    LeaveCriticalSection(&cs_kmm);

    TlsFree(tls_kmm);

    tls_kmm = 0;
}

void kmm_dll_init(void)
{
    InitializeCriticalSection(&cs_kmm);
    evt_startup = CreateEvent(NULL, TRUE, FALSE, NULL);
    evt_exit = CreateEvent(NULL, TRUE, TRUE, NULL);
}

void kmm_dll_exit(void)
{
    DeleteCriticalSection(&cs_kmm);
    if(evt_startup)
        CloseHandle(evt_startup);
    evt_startup = NULL;
}

void 
kmm_process_attach(HINSTANCE hinstDLL) {
    kmm_hInstance = hinstDLL;
    kmm_dll_init();
}

void
kmm_process_detach(void) {
    kmm_dll_exit();
}


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

#include<windows.h>

/* forward dcls */
void
kherr_process_attach(void);

void
kherr_process_detach(void);

void
kherr_thread_attach(void);

void
kherr_thread_detach(void);

void
kconfig_process_attach(void);

void
kconfig_process_detach(void);

void
kmq_process_attach(void);

void
kmq_process_detach(void);

void
kmq_thread_attach(void);

void
kmq_thread_detach(void);

void
kcdb_process_attach(HINSTANCE);

void
kcdb_process_detach(void);

void
kmm_process_attach(HINSTANCE);

void
kmm_process_detach(void);

void
uilib_process_attach(void);

void
uilib_process_detach(void);


BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved )  // reserved
{
    switch(fdwReason) {
    case DLL_PROCESS_ATTACH:
        kherr_process_attach();
        kconfig_process_attach();
        kmq_process_attach();
        kcdb_process_attach(hinstDLL);
        kmm_process_attach(hinstDLL);
        uilib_process_attach();
        break;

    case DLL_PROCESS_DETACH:
        kherr_process_detach();
        kconfig_process_detach();
        kmq_process_detach();
        kcdb_process_detach();
        kmm_process_detach();
        uilib_process_detach();
        break;

    case DLL_THREAD_ATTACH:
        kherr_thread_attach();
        kmq_thread_attach();
        break;

    case DLL_THREAD_DETACH:
        kherr_thread_detach();
        kmq_thread_detach();
        break;
    }
    return TRUE;
}

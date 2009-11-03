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

#include<khmapp.h>
#include<iphlpapi.h>

static HANDLE evt_terminate = NULL;
static HANDLE h_thread = NULL;

DWORD WINAPI
addr_change_thread(LPVOID dummy) {

    HANDLE h_waits[2];
    HANDLE h_notify;

    OVERLAPPED overlap;
    DWORD ret;

    PDESCTHREAD(L"Address change waiter", L"App");

    ZeroMemory(&overlap, sizeof(overlap));

    h_notify = NULL;
    overlap.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    do {
        ret = NotifyAddrChange(&h_notify, &overlap);

        if (ret != ERROR_IO_PENDING) {
            goto _end_thread;   /* some error */
        }

        h_waits[0] = overlap.hEvent;
        h_waits[1] = evt_terminate;

        ret = WaitForMultipleObjects(2, h_waits, FALSE, INFINITE);

        if ( ret == WAIT_OBJECT_0 ) {
            Sleep(3000);        /* wait for things to settle down */
            kmq_post_message(KMSG_CRED, KMSG_CRED_ADDR_CHANGE, 0, 0);
        } else {
            goto _end_thread;
        }
    } while(TRUE);

 _end_thread:
    ExitThread(0);
}

void
khm_addr_change_notifier_init(void) {
    evt_terminate = CreateEvent(NULL, FALSE, FALSE, NULL);
    h_thread = CreateThread(NULL,
                            64 * 4096,
                            addr_change_thread,
                            NULL,
                            0,
                            NULL);
}

void
khm_addr_change_notifier_exit(void) {
    if (h_thread && evt_terminate) {
        SetEvent(evt_terminate);
        WaitForSingleObject(h_thread, INFINITE);

        CloseHandle(h_thread);
        CloseHandle(evt_terminate);
    }
}

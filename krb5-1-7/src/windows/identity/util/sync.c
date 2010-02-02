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

#define _NIMLIB_

#include<windows.h>
#include<sync.h>
#include<assert.h>

#define LOCK_OPEN 0
#define LOCK_READING 1
#define LOCK_WRITING 2

KHMEXP void KHMAPI InitializeRwLock(PRWLOCK pLock)
{
    pLock->locks = 0;
    pLock->status = LOCK_OPEN;
    InitializeCriticalSection(&(pLock->cs));
    pLock->writewx = CreateEvent(NULL, 
                                 FALSE, /* Manual reset */
                                 TRUE,  /* Initial state */
                                 NULL);
    pLock->readwx = CreateEvent(NULL,
                                TRUE, /* Manual reset */
                                TRUE, /* Initial state */
                                NULL);
}

KHMEXP void KHMAPI DeleteRwLock(PRWLOCK pLock)
{
    EnterCriticalSection(&pLock->cs);

    CloseHandle(pLock->readwx);
    CloseHandle(pLock->writewx);
    pLock->readwx = NULL;
    pLock->writewx = NULL;

    LeaveCriticalSection(&pLock->cs);
    DeleteCriticalSection(&(pLock->cs));
}

KHMEXP void KHMAPI LockObtainRead(PRWLOCK pLock)
{
    while(1) {
        WaitForSingleObject(pLock->readwx, INFINITE);
        EnterCriticalSection(&pLock->cs);
        if(pLock->status == LOCK_WRITING) {
            LeaveCriticalSection(&(pLock->cs));
            continue;
        } else
            break;
    }
    pLock->locks ++;
    pLock->status = LOCK_READING;
    ResetEvent(pLock->writewx);
    LeaveCriticalSection(&(pLock->cs));
}

KHMEXP void KHMAPI LockReleaseRead(PRWLOCK pLock)
{
    EnterCriticalSection(&(pLock->cs));
    assert(pLock->status == LOCK_READING);
    pLock->locks--;
    if(!pLock->locks) {
        pLock->status = LOCK_OPEN;
        SetEvent(pLock->readwx);
        SetEvent(pLock->writewx);
    }
    LeaveCriticalSection(&(pLock->cs));
}

KHMEXP void KHMAPI LockObtainWrite(PRWLOCK pLock)
{
    EnterCriticalSection(&(pLock->cs));
    if(pLock->status == LOCK_WRITING && 
       pLock->writer == GetCurrentThreadId()) {
        pLock->locks++;
        LeaveCriticalSection(&(pLock->cs));
        return;
    }
    LeaveCriticalSection(&(pLock->cs));
    while(1) {
        WaitForSingleObject(pLock->writewx, INFINITE);
        EnterCriticalSection(&(pLock->cs));
        if(pLock->status == LOCK_OPEN)
            break;
        LeaveCriticalSection(&(pLock->cs));
    }
    pLock->status = LOCK_WRITING;
    pLock->locks++;
    pLock->writer = GetCurrentThreadId();
    ResetEvent(pLock->readwx);
    ResetEvent(pLock->writewx);
    LeaveCriticalSection(&(pLock->cs));
}

KHMEXP void KHMAPI LockReleaseWrite(PRWLOCK pLock)
{
    EnterCriticalSection(&(pLock->cs));
    assert(pLock->status == LOCK_WRITING);
    pLock->locks--;
    if(!pLock->locks) {
        pLock->status = LOCK_OPEN;
        pLock->writer = 0;
        SetEvent(pLock->readwx);
        SetEvent(pLock->writewx);
    }
    LeaveCriticalSection(&(pLock->cs));
}

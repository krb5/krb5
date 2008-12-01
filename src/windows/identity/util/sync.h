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

#ifndef __KHIMAIRA_SYNC_H
#define __KHIMAIRA_SYNC_H

#include<khdefs.h>

/*! \addtogroup util
    @{ */

/*! \defgroup util_sync Synchronization
    @{*/

/*! \brief A read/write lock

    A classic read/write lock.  Allows multiple readers or a single
    writer to access a protected object.  Readers will wait for any
    pending writer to release the lock, while a writer will wait for
    any pending readers to release the lock.
*/
typedef struct tag_rwlock {
    int locks;
    int status;
    CRITICAL_SECTION cs;
    HANDLE readwx;
    HANDLE writewx;

    DWORD writer;               /* TID of writer thread */
} rw_lock_t;

typedef rw_lock_t RWLOCK, *PRWLOCK;

/*! \brief Initialize a read/write lock.

    A lock <b>must</b> be initialized before it can be used.
    Initializing the lock does not grant the caller any locks on the
    object.
*/
KHMEXP void KHMAPI InitializeRwLock(PRWLOCK pLock);

/*! \brief Delete a read/write lock

    Once the application is done using the read/write lock, it must be
    deleted with a call to DeleteRwLock()
*/
KHMEXP void KHMAPI DeleteRwLock(PRWLOCK pLock);

/*! \brief Obtains a read lock on the read/write lock

    Multiple readers can obtain read locks on the same r/w lock.
    However, if any thread attempts to obtain a write lock on the
    object, it will wait until all readers have released the read
    locks.

    Call LockReleaseRead() to release the read lock.  While the same
    thread may obtain multiple read locks on the same object, each
    call to LockObtainRead() must have a corresponding call to
    LockReleaseRead() to properly relinquish the lock.

    \see LockReleaseRead()
*/
KHMEXP void KHMAPI LockObtainRead(PRWLOCK pLock);

/*! \brief Relase a read lock obtained on a read/write lock

    Each call to LockObtainRead() must have a corresponding call to
    LockReleaseRead().  Once all read locks are released, any threads
    waiting on write locks on the object will be woken and assigned a
    write lock.

    \see LockObtainRead()
*/
KHMEXP void KHMAPI LockReleaseRead(PRWLOCK pLock);

/*! \brief Obtains a write lock on the read/write lock

    Only a single writer is allowed to lock a single r/w lock.
    However, if any thread attempts to obtain a read lock on the
    object, it will wait until the writer has released the lock.

    Call LockReleaseWrite() to release the write lock.  While the same
    thread may obtain multiple write locks on the same object, each
    call to LockObtainWrite() must have a corresponding call to
    LockReleaseWrite() to properly relinquish the lock.

    \see LockReleaseWrite()
*/
KHMEXP void KHMAPI LockObtainWrite(PRWLOCK pLock);

/*! \brief Relase a write lock obtained on a read/write lock

    Each call to LockObtainWrite() must have a corresponding call to
    LockReleaseWrite().  Once the write lock is released, any threads
    waiting for read or write locks on the object will be woken and
    assigned the proper lock.

    \see LockObtainWrite()
*/
KHMEXP void KHMAPI LockReleaseWrite(PRWLOCK pLock);

/*@}*/
/*@}*/

#endif

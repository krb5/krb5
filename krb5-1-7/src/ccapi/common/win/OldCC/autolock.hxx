/*

   Copyright (C) 1998 Danilo Almeida.  All rights reserved.

   automatic stack-based locking object

   This file is part of FIFS (Framework for Implementing File Systems). 

   This software is distributed with NO WARRANTY OF ANY KIND.  No
   author or distributor accepts any responsibility for the
   consequences of using it, or for whether it serves any particular
   purpose or works at all, unless he or she says so in writing.
   Refer to the included modified Alladin Free Public License (the
   "License") for full details.

   Every copy of this software must include a copy of the License, in
   a plain ASCII text file named COPYING.  The License grants you the
   right to copy, modify and redistribute this software, but only
   under certain conditions described in the License.  Among other
   things, the License requires that the copyright notice and this
   notice be preserved on all copies.

*/

#ifndef __AUTOLOCK_HXX__
#define __AUTOLOCK_HXX__

#include <windows.h>

class CcOsLock {
    CRITICAL_SECTION cs;
    bool valid;
public:
    CcOsLock()      {InitializeCriticalSection(&cs);   valid = true; }
    ~CcOsLock()     {DeleteCriticalSection(&cs);       valid = false;}
    void lock()     {if (valid) EnterCriticalSection(&cs);}
    void unlock()   {if (valid) LeaveCriticalSection(&cs);}
#if 0
    bool trylock()  {return valid ? (TryEnterCriticalSection(&cs) ? true : false)
                                  : false; }
#endif
};

class CcAutoLock {
    CcOsLock& m_lock;
public:
    static void Start(CcAutoLock*& a, CcOsLock& lock) { a = new CcAutoLock(lock); };
    static void Stop (CcAutoLock*& a) { delete a; a = 0; };
    CcAutoLock(CcOsLock& lock):m_lock(lock) { m_lock.lock(); }
    ~CcAutoLock() { m_lock.unlock(); }
};

#endif /* __AUTOLOCK_HXX */

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

/* Not exported */
#ifndef __KHIMAIRA_KTHREAD_H
#define __KHIMAIRA_KTHREAD_H

#ifdef _WIN32
#define khm_mutex CRITICAL_SECTION

#define khp_mutex_init(pcs) InitializeCriticalSection(pcs)
#define khp_mutex_destroy(pcs) DeleteCriticalSection(pcs)
#define khp_mutex_lock(pcs) EnterCriticalSection(pcs)
#define khp_mutex_unlock(pcs) LeaveCriticalSection(pcs)
#define khp_mutex_trylock(pcs) (!TryEnterCriticalSection(pcs))

#endif

#endif
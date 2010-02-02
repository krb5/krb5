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

#ifndef __KHIMAIRA_PERFSTAT_H
#define __KHIMAIRA_PERFSTAT_H

#include<khdefs.h>

#ifdef DEBUG
#define PMALLOC(s) perf_malloc(__FILE__,__LINE__,s)
#define PCALLOC(n,s) perf_calloc(__FILE__,__LINE__,n,s)
#define PREALLOC(d,s) perf_realloc(__FILE__,__LINE__,d,s)
#define PFREE(p)   perf_free(p)
#define PDUMP(f)   perf_dump(f)
#define PWCSDUP(s) perf_wcsdup(__FILE__,__LINE__,s)
#define PSTRDUP(s) perf_strdup(__FILE__,__LINE__,s)
#define PDESCTHREAD(n,c) perf_set_thread_desc(__FILE__,__LINE__,n,c);
#else
#define PMALLOC(s) malloc(s)
#define PCALLOC(n,s) calloc(n,s)
#define PREALLOC(d,s) realloc(d,s)
#define PFREE(p)   free(p)
#define PDUMP(f)   ((void) 0)
#define PWCSDUP(s) _wcsdup(s)
#define PSTRDUP(s) strdup(s)
#define PDESCTHREAD(n,c)
#endif

KHMEXP void *
perf_malloc(const char * file, int line, size_t s);

KHMEXP void *
perf_realloc(const char * file, int line, void * data, size_t s);

KHMEXP void
perf_free  (void * b);

KHMEXP wchar_t *
perf_wcsdup(const char * file, int line, const wchar_t * str);

KHMEXP char *
perf_strdup(const char * file, int line, const char * str);

KHMEXP void *
perf_calloc(const char * file, int line, size_t num, size_t size);

KHMEXP void
perf_set_thread_desc(const char * file, int line,
                     const wchar_t * name, const wchar_t * creator);

#endif

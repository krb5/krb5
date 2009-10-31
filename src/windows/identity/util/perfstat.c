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
#include<utils.h>
#include<crtdbg.h>
#include<malloc.h>
#include<stdio.h>
#include<strsafe.h>
#include<assert.h>

#define HASHSIZE 1151
#define ALLOCBLOCK 1024

#define HASHPTR(p) (((size_t) (p)) % HASHSIZE)

typedef struct tag_allocation {
    const char * file;
    int    line;
    size_t size;
    void * ptr;
#ifdef _WIN32
    DWORD  thread;
#endif

    LDCL(struct tag_allocation);
} allocation;

static allocation * ht[HASHSIZE];

static allocation * next_alloc = NULL;
static size_t       idx_next_alloc = 0;
static allocation * free_alloc = NULL;

typedef struct tag_thread_info {
#ifdef _WIN32
    DWORD thread;
#else
#error Unsupported platform
#endif
    wchar_t name[128];
    wchar_t creator[128];

    const char * file;
    int line;

    LDCL(struct tag_thread_info);
} thread_info;

static thread_info * threads = NULL;

static hashtable fn_hash;

static CRITICAL_SECTION cs_alloc;
static LONG ctr = 0;
static int  perf_ready = 0;

static DWORD init_thread = 0;

#ifdef _DEBUG
/*  */
#define OPS_TILL_MEM_CHECK 1024
static int ops_till_mem_check = OPS_TILL_MEM_CHECK;
#endif

#define _PERF_BLOCK_TYPE(t) (_CLIENT_BLOCK | ((t) << 16))
#define _RMEM_BLOCK         _PERF_BLOCK_TYPE(0)
#define _PERF_BLOCK         _PERF_BLOCK_TYPE(1)

static khm_int32 hash_stringA(const void * vs) {
    /* DJB algorithm */

    khm_int32 hv = 13331;
    char * c;

    for (c = (char *) vs; *c; c++) {
        hv = ((hv << 5) + hv) + (khm_int32) *c;
    }

    return (hv & KHM_INT32_MAX);
}

static khm_int32 hash_string_compA(const void * vs1,
                                   const void * vs2) {
    return strcmp((const char *) vs1, (const char *) vs2);
}

static void perf_once(void) {
    if (InterlockedIncrement(&ctr) == 1) {
        InitializeCriticalSection(&cs_alloc);
        ZeroMemory(ht, sizeof(ht));

        next_alloc = _malloc_dbg(sizeof(allocation) * ALLOCBLOCK, _PERF_BLOCK,
                                __FILE__, __LINE__);
        assert(next_alloc);
        idx_next_alloc = 0;
        free_alloc = NULL;

        ZeroMemory(&fn_hash, sizeof(fn_hash));
        fn_hash.n = 13;
        fn_hash.hash = hash_stringA;
        fn_hash.comp = hash_string_compA;
        fn_hash.bins = _calloc_dbg(fn_hash.n, sizeof(hash_bin *),
                                   _PERF_BLOCK, __FILE__, __LINE__);

        perf_ready = 1;
    } else {
        DWORD this_thread = GetCurrentThreadId();

        while(!perf_ready &&
              init_thread != this_thread) {
            Sleep(0);           /* relinquish control to the thread
                                   that is initializing the alloc
                                   data. */
        }
    }
}

static allocation * get_allocation(void) {
    allocation * a;

    LPOP(&free_alloc, &a);
    if (!a) {
        if (idx_next_alloc == ALLOCBLOCK) {
            next_alloc = _malloc_dbg(sizeof(allocation) * ALLOCBLOCK,
                                     _PERF_BLOCK,
                                     __FILE__, __LINE__);
            assert(next_alloc);
            idx_next_alloc = 0;
        }

        a = &next_alloc[idx_next_alloc];
        idx_next_alloc++;
    }

    return a;
}

#define MAXCB_STR 32768

KHMEXP wchar_t *
perf_wcsdup(const char * file, int line, const wchar_t * str) {
    size_t cb;
    wchar_t * dest;

    if (FAILED(StringCbLength(str, MAXCB_STR, &cb)))
        return NULL;
    cb += sizeof(wchar_t);

    dest = (wchar_t *) perf_malloc(file, line, cb);
    StringCbCopy(dest, cb, str);

    return dest;
}

KHMEXP char *
perf_strdup(const char * file, int line, const char * str) {
    size_t cb;
    char * dest;

    if (FAILED(StringCbLengthA(str, MAXCB_STR, &cb)))
        return NULL;
    cb += sizeof(char);

    dest = (char *) perf_malloc(file, line, cb);
    StringCbCopyA(dest, cb, str);

    return dest;
}

KHMEXP void *
perf_calloc(const char * file, int line, size_t num, size_t size) {
    void * ptr;
    size_t tsize;

    tsize = num * size;

    ptr = perf_malloc(file,line,tsize);

    if (ptr) {
        ZeroMemory(ptr, tsize);
    }

    return ptr;
}

KHMEXP void *
perf_malloc(const char * file, int line, size_t s) {
    allocation * a;
    void * ptr;
    size_t h;
    char * fn_copy = NULL;

    perf_once();

    assert(s > 0);

    EnterCriticalSection(&cs_alloc);
    a = get_allocation();

    ptr = _malloc_dbg(s, _RMEM_BLOCK, file, line);

    assert(ptr);                /* TODO: handle this gracefully */

    if (file[0] == '.' && file[1] == '\\')
        file += 2;

    fn_copy = hash_lookup(&fn_hash, file);
    if (fn_copy == NULL) {

        size_t cblen = 0;
        if (FAILED(StringCbLengthA(file, MAX_PATH * sizeof(char),
                                   &cblen)))
            fn_copy = NULL;
        else {
            fn_copy = _malloc_dbg(cblen + sizeof(char), _PERF_BLOCK,
                                  __FILE__, __LINE__);
            if (fn_copy) {
                hash_bin * b;
                int hv;

                StringCbCopyA(fn_copy, cblen + sizeof(char), file);

                hv = fn_hash.hash(fn_copy) % fn_hash.n;

                b = _malloc_dbg(sizeof(*b), _PERF_BLOCK,
                                __FILE__, __LINE__);
                b->data = fn_copy;
                b->key = fn_copy;
                LINIT(b);
                LPUSH(&fn_hash.bins[hv], b);
            }
        }
    }

    a->file = fn_copy;
    a->line = line;
    a->size = s;
    a->ptr = ptr;
#ifdef _WIN32
    a->thread = GetCurrentThreadId();
#endif

    h = HASHPTR(ptr);

    LPUSH(&ht[h], a);

#ifdef _DEBUG
    if (-- ops_till_mem_check <= 0) {
        assert(_CrtCheckMemory());
        ops_till_mem_check = OPS_TILL_MEM_CHECK;
    }
#endif

    LeaveCriticalSection(&cs_alloc);

    return ptr;
}

KHMEXP void *
perf_realloc(const char * file, int line, void * data, size_t s) {
    void * n_data;
    allocation * a;
    size_t h;

    if (data == NULL)
        return perf_malloc(file, line, s);

    perf_once();
    h = HASHPTR(data);

    n_data = _realloc_dbg(data, s, _RMEM_BLOCK,
                          __FILE__, __LINE__);

    assert(n_data);

    EnterCriticalSection(&cs_alloc);
    for (a = ht[h]; a; a = LNEXT(a)) {
        if (a->ptr == data)
            break;
    }

    assert(a);

    LDELETE(&ht[h], a);

    a->size = s;
    a->ptr = n_data;

    h = HASHPTR(n_data);
    LPUSH(&ht[h], a);

#ifdef _DEBUG
    if (-- ops_till_mem_check <= 0) {
        assert(_CrtCheckMemory());
        ops_till_mem_check = OPS_TILL_MEM_CHECK;
    }
#endif

    LeaveCriticalSection(&cs_alloc);

    return n_data;
}

KHMEXP void
perf_free  (void * b) {
    size_t h;
    allocation * a;

    perf_once();
    h = HASHPTR(b);

    EnterCriticalSection(&cs_alloc);
    for(a = ht[h]; a; a = LNEXT(a)) {
        if (a->ptr == b)
            break;
    }

    assert(a);

    if (a) {
        LDELETE(&ht[h], a);
        LPUSH(&free_alloc, a);

        _free_dbg(b, _RMEM_BLOCK);
    }

#ifdef _DEBUG
    if (-- ops_till_mem_check <= 0) {
        assert(_CrtCheckMemory());
        ops_till_mem_check = OPS_TILL_MEM_CHECK;
    }
#endif

    LeaveCriticalSection(&cs_alloc);
}

KHMEXP void KHMAPI
perf_dump(FILE * f) {
    size_t i;
    allocation * a;
    size_t total = 0;
    thread_info * t;

    perf_once();

    EnterCriticalSection(&cs_alloc);

    fprintf(f, "p00\t*** Threads ***\n");
    fprintf(f, "p00\tFile\tLine\tThread\tName\tCreated by\n");

    for (t = threads; t; t = LNEXT(t)) {
        fprintf(f, "p01\t%s\t%6d\t%6d\t%S\t%S\n",
                t->file, t->line, t->thread,
                t->name, t->creator);
    }

    fprintf(f, "p02\t--- End Threads ---\n");

    fprintf(f, "p10\t*** Leaked allocations list ***\n");
    fprintf(f, "p11\tFile\tLine\tThread\tSize\tAddress\n");

    for (i=0; i < HASHSIZE; i++) {
        for (a = ht[i]; a; a = LNEXT(a)) {
            fprintf(f, "p12\t%s\t%6d\t%6d\t%6d\t0x%p\n", a->file, a->line,
		    a->thread, a->size, a->ptr);
            total += a->size;
        }
    }

    fprintf(f, "p20\t----------------------------------------\n");
    fprintf(f, "p21\tTotal\t\t%d\n", total);
    fprintf(f, "p22\t----------------- End ------------------\n");

    LeaveCriticalSection(&cs_alloc);
}

KHMEXP void
perf_set_thread_desc(const char * file, int line,
                     const wchar_t * name, const wchar_t * creator) {
    thread_info * t;
    char * fn_copy;

    perf_once();

    t = malloc(sizeof(*t));
    ZeroMemory(t, sizeof(*t));

#ifdef _WIN32
    t->thread = GetCurrentThreadId();
#else
#error Unsupported platform
#endif

    StringCbCopy(t->name, sizeof(t->name), name);
    if (creator)
        StringCbCopy(t->creator, sizeof(t->creator), creator);

    if (file[0] == '.' && file[1] == '\\')
        file += 2;

    EnterCriticalSection(&cs_alloc);

    fn_copy = hash_lookup(&fn_hash, file);
    if (fn_copy == NULL) {
        size_t cblen = 0;
        if (FAILED(StringCbLengthA(file, MAX_PATH * sizeof(char),
                                   &cblen)))
            fn_copy = NULL;
        else {
            fn_copy = malloc(cblen + sizeof(char));
            if (fn_copy) {
                hash_bin * b;
                int hv;

                StringCbCopyA(fn_copy, cblen + sizeof(char), file);

                hv = fn_hash.hash(fn_copy) % fn_hash.n;

                b = malloc(sizeof(*b));
                b->data = fn_copy;
                b->key = fn_copy;
                LINIT(b);
                LPUSH(&fn_hash.bins[hv], b);
            }
        }
    }

    t->file = fn_copy;
    t->line = line;

    LPUSH(&threads, t);
    LeaveCriticalSection(&cs_alloc);
}

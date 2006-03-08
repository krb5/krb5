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
#include<utils.h>
#include<malloc.h>
#include<stdio.h>
#include<strsafe.h>
#include<assert.h>

#define HASHSIZE 1151
#define ALLOCBLOCK 1024

#define HASHPTR(p) (((size_t) (p)) % HASHSIZE)

typedef struct tag_allocation {
    char   file[8];
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

static CRITICAL_SECTION cs_alloc;
static LONG ctr = 0;
static int  perf_ready = 0;

static void perf_once(void) {
    if (InterlockedIncrement(&ctr) == 1) {
        InitializeCriticalSection(&cs_alloc);
        ZeroMemory(ht, sizeof(ht));

        next_alloc = malloc(sizeof(allocation) * ALLOCBLOCK);
        assert(next_alloc);
        idx_next_alloc = 0;
        free_alloc = NULL;

        perf_ready = 1;
    } else {
        while(!perf_ready) {
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
            next_alloc = malloc(sizeof(allocation) * ALLOCBLOCK);
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
perf_wcsdup(char * file, int line, const wchar_t * str) {
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
perf_strdup(char * file, int line, const char * str) {
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
perf_calloc(char * file, int line, size_t num, size_t size) {
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
perf_malloc(char * file, int line, size_t s) {
    allocation * a;
    void * ptr;
    size_t h;

    perf_once();

    assert(s > 0);

    EnterCriticalSection(&cs_alloc);
    a = get_allocation();

    ptr = malloc(s);

    assert(ptr);                /* TODO: handle this gracefully */

    if (file[0] == '.' && file[1] == '\\')
        file += 2;

    StringCbCopyA(a->file, sizeof(a->file), file);
    a->line = line;
    a->size = s;
    a->ptr = ptr;
#ifdef _WIN32
    a->thread = GetCurrentThreadId();
#endif

    h = HASHPTR(ptr);

    LPUSH(&ht[h], a);
    LeaveCriticalSection(&cs_alloc);

    return ptr;
}

KHMEXP void *
perf_realloc(char * file, int line, void * data, size_t s) {
    void * n_data;
    allocation * a;
    size_t h;

    if (data == NULL)
        return perf_malloc(file, line, s);

    perf_once();
    h = HASHPTR(data);

    n_data = realloc(data, s);

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

    LDELETE(&ht[h], a);
    LPUSH(&free_alloc, a);
    LeaveCriticalSection(&cs_alloc);
}

KHMEXP void
perf_dump(char * file) {
    FILE * f;
    size_t i;
    allocation * a;
    size_t total = 0;

    perf_once();

    EnterCriticalSection(&cs_alloc);
    f = fopen(file, "w");
    if (!f)
        return;

    fprintf(f, "Leaked allocations list ....\n");
    fprintf(f, "File\tLine\tThread\tSize\n");

    for (i=0; i < HASHSIZE; i++) {
        for (a = ht[i]; a; a = LNEXT(a)) {
            fprintf(f, "%s\t%6d\t%6d\t%6d\n", a->file, a->line,
		    a->thread, a->size);
            total += a->size;
        }
    }

    fprintf(f, "----------------------------------------\n");
    fprintf(f, "Total\t\t%d\n", total);
    fprintf(f, "----------------- End ------------------\n");

    fclose(f);

    LeaveCriticalSection(&cs_alloc);
}

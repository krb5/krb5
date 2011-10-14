/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* To the extent possible under law, Painless Security, LLC has waived
 * all copyright and related or neighboring rights to GSS-API Memory
 * Management Header. This work is published from: United States.
 */

#ifndef GSSAPI_ALLOC_H
#define GSSAPI_ALLOC_H

#ifdef _WIN32
#include "winbase.h"
#endif
#include <string.h>

static inline void
gssalloc_free(void * value)
{
    if (value) {
#if _WIN32
        HeapFree(GetProcessHeap(), 0, value);
#else
        free(value);
#endif
    }
}

static inline void *
gssalloc_malloc(size_t size)
{
#if _WIN32
    return HeapAlloc(GetProcessHeap(), 0, size);
#else
    return malloc(size);
#endif
}

static inline void *
gssalloc_calloc(size_t count, size_t size)
{
#if _WIN32
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, count * size);
#else
    return calloc(count, size);
#endif
}

static inline void *
gssalloc_realloc(void *value, size_t size)
{
#if _WIN32
    return HeapReAlloc(GetProcessHeap(), 0, value, size);
#else
    return realloc(value, size);
#endif
}

static inline char *
gssalloc_strdup(const char *str)
{
    size_t size = strlen(str)+1;
    char *copy = gssalloc_malloc(size);
    if (copy) {
        memcpy(copy, str, size);
        copy[size-1] = '\0';
    }
    return copy;
}

#endif

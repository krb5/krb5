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

#include<mstring.h>
#include<kherror.h>
#include<strsafe.h>
#include<stdlib.h>

#define TRUE    1
#define FALSE   0

KHMEXP khm_int32 KHMAPI
multi_string_init(wchar_t * ms,
                  khm_size cb_ms) {
    if (!ms || cb_ms < sizeof(wchar_t) * 2)
        return KHM_ERROR_INVALID_PARAM;

    memset(ms, 0, cb_ms);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
multi_string_append(wchar_t * ms,
                    khm_size * pcb_ms,
                    const wchar_t * str)
{
    wchar_t * s;
    size_t cch_s;
    size_t cch_t;
    size_t cch_r;

    if(!ms || !pcb_ms || !str)
        return KHM_ERROR_INVALID_PARAM;

    if(FAILED(StringCchLength(str, KHM_MAXCCH_STRING, &cch_s)) || cch_s == 0)
        return KHM_ERROR_INVALID_PARAM;
    cch_s++;

    s = ms;

    while(*s && ((s - ms) < KHM_MAXCCH_STRING)) {
        if(FAILED(StringCchLength(s, KHM_MAXCB_STRING, &cch_t)))
            return KHM_ERROR_INVALID_PARAM;
        s += cch_t + 1;
    }

    if(*s || (s - ms) >= KHM_MAXCCH_STRING) {
        return KHM_ERROR_INVALID_PARAM;
    }

    /* now s points to the second NULL of the terminating double NULL */

    cch_r = ((s - ms) + cch_s + 1) * sizeof(wchar_t);
    if(*pcb_ms < cch_r) {
        *pcb_ms = cch_r;
        return KHM_ERROR_TOO_LONG;
    }

    *pcb_ms = cch_r;

    StringCchCopy(s, cch_s, str);
    s += cch_s;
    *s = 0;

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
multi_string_prepend(wchar_t * ms,
                     khm_size * pcb_ms,
                     const wchar_t * str)
{
    size_t cch_s;
    size_t cch_t;
    size_t cch_r;
    khm_size cb_r;

    if(!ms || !pcb_ms || !str)
        return KHM_ERROR_INVALID_PARAM;

    if(FAILED(StringCchLength(str, KHM_MAXCCH_STRING, &cch_s)) || cch_s == 0)
        return KHM_ERROR_INVALID_PARAM;
    cch_s++;

    if(KHM_FAILED(multi_string_length_cch(ms,
                                              KHM_MAXCCH_STRING,
                                              &cch_r)))
        return KHM_ERROR_INVALID_PARAM;

    cch_t = cch_s + cch_r;
    cb_r = cch_t * sizeof(wchar_t);

    if (*pcb_ms < cb_r) {
        *pcb_ms = cb_r;
        return KHM_ERROR_TOO_LONG;
    }

    memmove(ms + cch_s, ms, cch_r * sizeof(wchar_t));
    memcpy(ms, str, cch_s * sizeof(wchar_t));

    *pcb_ms = cb_r;

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
multi_string_delete(wchar_t * ms,
                    const wchar_t * str,
                    const khm_int32 flags)
{
    wchar_t * s;
    wchar_t * n;
    wchar_t * e;
    size_t cch;

    if(!ms || !str)
        return KHM_ERROR_INVALID_PARAM;

    s = multi_string_find(ms, str, flags);
    if(!s)
        return KHM_ERROR_NOT_FOUND;

    e = s;
    n = NULL;
    while(*e && (e - s) < KHM_MAXCCH_STRING) {
        if(FAILED(StringCchLength(e, KHM_MAXCCH_STRING, &cch)))
            return KHM_ERROR_INVALID_PARAM;
        e += cch + 1;

        if(!n)
            n = e;
    }

    if(*e || (e - s) >= KHM_MAXCCH_STRING)
        return KHM_ERROR_INVALID_PARAM;

    if(e == s)
        return KHM_ERROR_SUCCESS;

    memmove((void *) s, (void *) n, ((e - n) + 1) * sizeof(wchar_t));

    return KHM_ERROR_SUCCESS;
}

KHMEXP wchar_t * KHMAPI 
multi_string_find(const wchar_t * ms,
                  const wchar_t * str,
                  const khm_int32 flags)
{
    const wchar_t *s;
    size_t cch;
    size_t cch_s;

    if(!ms || !str)
        return NULL;

    if(FAILED(StringCchLength(str, KHM_MAXCCH_STRING, &cch_s)))
        return NULL;

    s = ms;

    while(*s && (s - ms) < KHM_MAXCCH_STRING) {
        if(FAILED(StringCchLength(s, KHM_MAXCCH_STRING, &cch)))
            return NULL;
        /* cch++ at end */

        if(flags & KHM_PREFIX) {
            if(((flags & KHM_CASE_SENSITIVE) && !wcsncmp(s, str, cch_s)) ||
                (!(flags & KHM_CASE_SENSITIVE) && !_wcsnicmp(s, str, cch_s)))
                return (wchar_t *) s;
        } else {
            if((cch == cch_s) &&
				((flags & KHM_CASE_SENSITIVE) && !wcsncmp(s, str, cch)) ||
                (!(flags & KHM_CASE_SENSITIVE) && !_wcsnicmp(s, str, cch)))
                return (wchar_t *) s;
        }

        s += cch + 1;
    }

    return NULL;
}

KHMEXP khm_int32 KHMAPI 
multi_string_to_csv(wchar_t * csvbuf,
                    khm_size * pcb_csvbuf,
                    const wchar_t * ms)
{
    size_t cb;
    size_t cbt;
    const wchar_t * t;
    wchar_t * d;

    if(!pcb_csvbuf || !ms)
        return KHM_ERROR_INVALID_PARAM;

    /* dry run */
    cbt = 0;
    t = ms;
    while(*t && cbt <= KHM_MAXCB_STRING) {
        khm_boolean quotes = FALSE;

        if(FAILED(StringCbLength(t, KHM_MAXCB_STRING, &cb)))
            return KHM_ERROR_INVALID_PARAM;
        cb += sizeof(wchar_t);

        cbt += cb;

        if(wcschr(t, L','))
            quotes = TRUE;

        d = (wchar_t *) t;
        while(d = wcschr(d, L'"')) {
            cbt += sizeof(wchar_t); /* '"'-> '""' */
            d++;
            quotes = TRUE;
        }

        if(quotes)
            cbt += 2*sizeof(wchar_t); /* make room for quotes */

        t += cb / sizeof(wchar_t);
    }

    if(cbt > KHM_MAXCB_STRING)
        return KHM_ERROR_INVALID_PARAM;

    /* happens if the multi string contained no strings */
    if(cbt == 0)
        cbt = sizeof(wchar_t);

    if(!csvbuf || *pcb_csvbuf < cbt)
    {
        *pcb_csvbuf = cbt;
        return KHM_ERROR_TOO_LONG;
    }

    *pcb_csvbuf = cbt;

    /* wet run */
    t = ms;
    d = csvbuf;
    *csvbuf = 0;
    while(*t) {
        const wchar_t * s;

        StringCbLength(t, KHM_MAXCB_STRING, &cb);
        cb += sizeof(wchar_t);

        if(d != csvbuf)
            *d++ = L',';
        if(wcschr(t, L',') || wcschr(t, L'"')) {
            *d++ = L'"';
            s = t;
            while(*s) {
                if(*s == L'"') {
                    *d++ = L'"';
                    *d++ = L'"';
                } else
                    *d++ = *s;
                s++;
            }
            *d++ = L'"';
            *d = 0;
        } else {
            StringCbCopy(d, cbt - ((d - csvbuf) * sizeof(wchar_t)), t);
            d += cb / sizeof(wchar_t) - 1;
        }
        t += cb / sizeof(wchar_t);
    }

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
csv_to_multi_string(wchar_t * ms,
                    khm_size * pcb_ms,
                    const wchar_t * csv)
{
    const wchar_t * t;
    wchar_t * p;
    size_t cchr;
    int field = 1;


    if(!pcb_ms || !csv)
        return KHM_ERROR_INVALID_PARAM;

    cchr = 0;

    /* dry run */
    t = csv;
    while(*t && (t - csv) < KHM_MAXCCH_STRING) {
        if(field && *t == L'"') {
            t++;
            while(*t && (t - csv) < KHM_MAXCCH_STRING) {
                if(*t == L'"') {
                    t++;
                    if(*t != L'"')
                        break;
                }
                cchr++;
                t++;
            }
        }

        if(*t) {
            cchr++;
            if(*t == L',')
                field = 1;
            else
                field = 0;

            t++;
        }
    }

    if((t - csv) >= KHM_MAXCCH_STRING)
        return KHM_ERROR_INVALID_PARAM;

    cchr++; /* last string ends */
    cchr++; /* double NULL */

    if(!ms || *pcb_ms < (cchr * sizeof(wchar_t))) {
        *pcb_ms = cchr * sizeof(wchar_t);
        return KHM_ERROR_TOO_LONG;
    }

    /* wet run */
    t = csv;
    p = ms;
    field = 1;
    while(*t) {
        if(field && *t == L'"') {
            t++;
            while(*t) {
                if(*t == L'"') {
                    t++;
                    if(*t != L'"')
                        break;
                }
                *p++ = *t;
                t++;
            }
        }

        if(*t == L',') {
            *p++ = 0;
            field = 1;
            t++;
        } else if(*t) {
            *p++ = *t;
            field = 0;
            t++;
        }
    }

    *p++ = 0; /* last string ends */
    *p++ = 0; /* double NULL */

    *pcb_ms = (p - ms) * sizeof(wchar_t);

    return KHM_ERROR_SUCCESS;
}

KHMEXP wchar_t * KHMAPI 
multi_string_next(const wchar_t * str)
{
    size_t cch;

    if(*str) {
        if(FAILED(StringCchLength(str, KHM_MAXCCH_STRING, &cch)))
            return NULL;
        str += cch + 1;
        if(*str)
            return (wchar_t *) str;
        else
            return NULL;
    } else {
        return NULL;
    }
}

KHMEXP khm_size KHMAPI 
multi_string_length_n(const wchar_t * str)
{
    size_t n = 0;
    const wchar_t * c = str;

    while(c) {
        n++;
        c = multi_string_next(c);
    }

    return n;
}

KHMEXP khm_int32 KHMAPI 
multi_string_length_cb(const wchar_t * str, 
                       khm_size max_cb, 
                       khm_size * len_cb)
{
    khm_size cch;
    khm_int32 rv;

    rv = multi_string_length_cch(str, max_cb / sizeof(wchar_t), &cch);
    
    if(KHM_FAILED(rv))
        return rv;
    
    if(len_cb)
        *len_cb = cch * sizeof(wchar_t);

    return rv;
}

KHMEXP khm_int32 KHMAPI 
multi_string_length_cch(const wchar_t * str, 
                        khm_size max_cch, 
                        khm_size * len_cch)
{
    const wchar_t * s;
    khm_size cch;
    size_t tcch;

    if(!str)
        return KHM_ERROR_INVALID_PARAM;

    s = str;
    cch = 0;
    while(*s && (cch < max_cch)) {
        if(FAILED(StringCchLength(s, max_cch, &tcch)))
            return KHM_ERROR_TOO_LONG;
        cch += ++tcch;
        s += tcch;
    }

    if(cch >= max_cch)
        return KHM_ERROR_TOO_LONG;

    if(len_cch) {
        *len_cch = ++cch;
    }

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
multi_string_copy_cb(wchar_t * s_dest, 
                         khm_size max_cb_dest, 
                         const wchar_t * src)
{
    khm_size cb_dest;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if(!s_dest)
        return KHM_ERROR_INVALID_PARAM;

    rv = multi_string_length_cb(src, max_cb_dest, &cb_dest);
    if(KHM_FAILED(rv))
        return rv;

    memmove(s_dest, src, cb_dest);

    return rv;
}

KHMEXP khm_int32 KHMAPI 
multi_string_copy_cch(wchar_t * s_dest, 
                      khm_size max_cch_dest, 
                      const wchar_t * src)
{
    khm_size cch_dest;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if(!s_dest)
        return KHM_ERROR_INVALID_PARAM;

    rv = multi_string_length_cch(src, max_cch_dest, &cch_dest);
    if(KHM_FAILED(rv))
        return rv;

    memmove(s_dest, src, cch_dest * sizeof(wchar_t));

    return rv;
}

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

#include<kcreddbinternal.h>
#include<limits.h>

CRITICAL_SECTION cs_type;
hashtable * kcdb_type_namemap;
kcdb_type_i ** kcdb_type_tbl;
kcdb_type_i * kcdb_types = NULL;

/* Void */

#define GENERIC_VOID_STR L"(Void)"

khm_int32 KHMAPI kcdb_type_void_toString(
    const void * d, 
    khm_size cbd, 
    wchar_t * buffer, 
    khm_size * cb_buf, 
    khm_int32 flags)
{
    size_t cbsize;

    if(!cb_buf)
        return KHM_ERROR_INVALID_PARAM;

    cbsize = sizeof(GENERIC_VOID_STR);

    if(!buffer || *cb_buf < cbsize) {
        *cb_buf = cbsize;
        return KHM_ERROR_TOO_LONG;
    }

    StringCbCopy(buffer, *cb_buf, GENERIC_VOID_STR);

    *cb_buf = cbsize;

    return KHM_ERROR_SUCCESS;
}

khm_boolean KHMAPI kcdb_type_void_isValid(
    const void * d,
    khm_size cbd)
{
    /* void is always valid, even if d is NULL */
    return TRUE;
}

khm_int32 KHMAPI kcdb_type_void_comp(
    const void * d1,
    khm_size cbd1,
    const void * d2,
    khm_size cbd2)
{
    /* voids can not be compared */
    return 0;
}

khm_int32 KHMAPI kcdb_type_void_dup(
    const void * d_src,
    khm_size cbd_src,
    void * d_dst,
    khm_size * cbd_dst)
{
    if(!cbd_dst)
        return KHM_ERROR_INVALID_PARAM;

    *cbd_dst = 0;

    /* copying a void doesn't do much */
    return KHM_ERROR_SUCCESS;
}


/* String */
khm_int32 KHMAPI kcdb_type_string_toString(
    const void * d, 
    khm_size cbd, 
    wchar_t * buffer, 
    khm_size * cb_buf, 
    khm_int32 flags)
{
    size_t cbsize;
    wchar_t * sd;

    if(!cb_buf)
        return KHM_ERROR_INVALID_PARAM;

    sd = (wchar_t *) d;

    if(FAILED(StringCbLength(sd, KCDB_TYPE_MAXCB, &cbsize)))
        return KHM_ERROR_INVALID_PARAM;

    cbsize += sizeof(wchar_t);

    if(!buffer || *cb_buf < cbsize) {
        *cb_buf = cbsize;
        return KHM_ERROR_TOO_LONG;
    }

    StringCbCopy(buffer, *cb_buf, sd);

    *cb_buf = cbsize;

    return KHM_ERROR_SUCCESS;
}

khm_boolean KHMAPI kcdb_type_string_isValid(
    const void * d,
    khm_size cbd)
{
    size_t cbsize;

    if(cbd == KCDB_CBSIZE_AUTO)
        cbd = KCDB_TYPE_MAXCB;

    if(FAILED(StringCbLength((wchar_t *) d, cbd, &cbsize)))
        return FALSE;
    else
        return TRUE;
}

khm_int32 KHMAPI kcdb_type_string_comp(
    const void * d1,
    khm_size cbd1,
    const void * d2,
    khm_size cbd2)
{
    return wcscmp((const wchar_t *) d1, (const wchar_t *) d2);
}

khm_int32 KHMAPI kcdb_type_string_dup(
    const void * d_src,
    khm_size cbd_src,
    void * d_dst,
    khm_size * cbd_dst)
{
    size_t cbsize;

    if(!cbd_dst)
        return KHM_ERROR_INVALID_PARAM;

    if(cbd_src == KCDB_CBSIZE_AUTO) {
        cbd_src = KCDB_TYPE_MAXCB;
    }

    if(FAILED(StringCbLength((const wchar_t *) d_src, cbd_src, &cbsize))) {
        return KHM_ERROR_UNKNOWN;
    }

    cbsize += sizeof(wchar_t);

    if(!d_dst || *cbd_dst < cbsize) {
        *cbd_dst = cbsize;
        return KHM_ERROR_TOO_LONG;
    }

    StringCbCopy((wchar_t *) d_dst, *cbd_dst, (const wchar_t *) d_src);
    *cbd_dst = cbsize;

    return KHM_ERROR_SUCCESS;
}

/* Date and time */


khm_int32 KHMAPI kcdb_type_date_toString(
    const void * d, 
    khm_size cbd, 
    wchar_t * buffer, 
    khm_size * cb_buf, 
    khm_int32 flags)
{
    size_t cbsize;
    size_t cchsize;
    wchar_t * bufend;
    SYSTEMTIME st_now;
    SYSTEMTIME st_d;
    SYSTEMTIME st_dl;
    FILETIME *ft;
    int today = 0;

    if(!cb_buf)
        return KHM_ERROR_INVALID_PARAM;

    ft = (FILETIME *) d;

    GetLocalTime(&st_now);
    FileTimeToSystemTime(ft, &st_d);
    SystemTimeToTzSpecificLocalTime(NULL, &st_d, &st_dl);
    if (st_now.wYear == st_dl.wYear &&
        st_now.wMonth == st_dl.wMonth &&
        st_now.wDay == st_dl.wDay)
        today = 1;

    if(today && (flags & KCDB_TS_SHORT)) {
        cbsize = 0;
    } else {
        cbsize = GetDateFormat(
            LOCALE_USER_DEFAULT,
            DATE_SHORTDATE,
            &st_dl,
            NULL,
            NULL,
            0) * sizeof(wchar_t);
    }

    cbsize += GetTimeFormat(
        LOCALE_USER_DEFAULT,
        0,
        &st_dl,
        NULL,
        NULL,
        0) * sizeof(wchar_t);

    if(!buffer || *cb_buf < cbsize) {
        *cb_buf = cbsize;
        return KHM_ERROR_TOO_LONG;
    }

    cchsize = cbsize / sizeof(wchar_t);

    if(!today || !(flags & KCDB_TS_SHORT)) {
        size_t cch_buf_len;

        GetDateFormat(
            LOCALE_USER_DEFAULT,
            DATE_SHORTDATE,
            &st_dl,
            NULL,
            buffer,
            (int) cchsize);

        StringCchCat(buffer, cchsize, L" ");

        StringCchLength(buffer, cchsize, &cch_buf_len);

        bufend = buffer + cch_buf_len;
        cchsize -= cch_buf_len;
    } else {
        bufend = buffer;
    }

    GetTimeFormat(
        LOCALE_USER_DEFAULT,
        0,
        &st_dl,
        NULL,
        bufend,
        (int) cchsize);

    *cb_buf = cbsize;

    return KHM_ERROR_SUCCESS;
}

khm_boolean KHMAPI kcdb_type_date_isValid(
    const void * d,
    khm_size cbd)
{
    return (d && (cbd == KCDB_CBSIZE_AUTO || cbd == sizeof(FILETIME)));
}

khm_int32 KHMAPI kcdb_type_date_comp(
    const void * d1,
    khm_size cbd1,
    const void * d2,
    khm_size cbd2)
{
    return (khm_int32) CompareFileTime((CONST FILETIME *) d1, (CONST FILETIME *) d2);
}

khm_int32 KHMAPI kcdb_type_date_dup(
    const void * d_src,
    khm_size cbd_src,
    void * d_dst,
    khm_size * cbd_dst)
{
    if(d_dst && *cbd_dst >= sizeof(FILETIME)) {
        *cbd_dst = sizeof(FILETIME);
        *((FILETIME *) d_dst) = *((FILETIME *) d_src);
        return KHM_ERROR_SUCCESS;
    } else {
        *cbd_dst = sizeof(FILETIME);
        return KHM_ERROR_TOO_LONG;
    }
}

/* Interval */

/* returns the number of milliseconds that must elapse away from the
   interval specified in pft for the representation of pft to change
   from whatever it is right now */
KHMEXP long KHMAPI 
FtIntervalMsToRepChange(LPFILETIME pft)
{
    __int64 ms,s,m,h,d;
    __int64 ift;
    long l;

    ift = FtToInt(pft);
    ms = ift / 10000i64;
    
    if(ms < 0 || ift == _I64_MAX)
        return -1;

    s = ms / 1000i64;
    m = s / 60;
    h = s / 3600;
    d = s / (3600*24);

    if (d > 0) {
        /* rep change at next hour change */
        l = (long) (ms % (3600*1000i64));
    } else if (h > 0) {
        /* rep change at next minute change */
        l = (long) (ms % (60*1000i64));
    } else if (m > 5) {
        /* rep change at next minute change */
        l = (long) (ms % (60*1000i64));
    } else {
        /* rep change at next second change */
        l = (long) (ms % 1000);
    }

    return l;
}

KHMEXP khm_int32 KHMAPI 
FtIntervalToString(LPFILETIME data, wchar_t * buffer, khm_size * cb_buf)
{
    size_t cbsize;
    __int64 s,m,h,d;
    __int64 ift;
    wchar_t ibuf[256];
    wchar_t fbuf[256];
    wchar_t * t;

    if(!cb_buf)
        return KHM_ERROR_INVALID_PARAM;

    ift = FtToInt(data);
    s = ift / 10000000i64;

    m = s / 60;
    h = s / 3600;
    d = s / (3600*24);

    if(ift == _I64_MAX) {
#ifdef INDICATE_UNKNOWN_EXPIRY_TIMES
        LoadString(hinst_kcreddb, IDS_IVL_UNKNOWN, ibuf, sizeof(ibuf)/sizeof(wchar_t));
#else
        StringCbCopy(ibuf, sizeof(ibuf), L"");
#endif
    } else if(s < 0) {
        LoadString(hinst_kcreddb, IDS_IVL_EXPIRED, ibuf, sizeof(ibuf)/sizeof(wchar_t));
    } else if(d > 0) {
        h = (s - (d * 3600 * 24)) / 3600;
        if(d == 1) {
            LoadString(hinst_kcreddb, IDS_IVL_1D, ibuf, ARRAYLENGTH(ibuf));
        } else {
            LoadString(hinst_kcreddb, IDS_IVL_D, fbuf, ARRAYLENGTH(fbuf));
            StringCbPrintf(ibuf, sizeof(ibuf), fbuf, d);
        }
        if(h > 0) {
            StringCbCat(ibuf, sizeof(ibuf), L" ");
            t = ibuf + wcslen(ibuf);
            if(h == 1)
            {
                LoadString(hinst_kcreddb, IDS_IVL_1H, t,
                           (int) (ARRAYLENGTH(ibuf) - wcslen(ibuf)));
            } else {
                LoadString(hinst_kcreddb, IDS_IVL_H, fbuf,
                           (int) ARRAYLENGTH(fbuf));
                StringCbPrintf(t, sizeof(ibuf) - wcslen(ibuf)*sizeof(wchar_t), fbuf, h);
            }
        }
    } else if(h > 0 || m > 5) {
        m = (s - (h * 3600)) / 60;
        if(h == 1) {
            LoadString(hinst_kcreddb, IDS_IVL_1H, ibuf, ARRAYLENGTH(ibuf));
        } else if (h > 1) {
            LoadString(hinst_kcreddb, IDS_IVL_H, fbuf, ARRAYLENGTH(fbuf));
            StringCbPrintf(ibuf, sizeof(ibuf), fbuf, h);
        } else {
            *ibuf = L'\0';
        }

        if(m > 0 || h == 0) {
            if (h >= 1)
                StringCbCat(ibuf, sizeof(ibuf), L" ");

            t = ibuf + wcslen(ibuf);
            if(m == 1)
            {
                LoadString(hinst_kcreddb, IDS_IVL_1M, t,
                           (int) (ARRAYLENGTH(ibuf) - wcslen(ibuf)));
            } else {
                LoadString(hinst_kcreddb, IDS_IVL_M, fbuf,
                           (int) ARRAYLENGTH(fbuf));
                StringCbPrintf(t, sizeof(ibuf) - wcslen(ibuf)*sizeof(wchar_t), fbuf, m);
            }
        }
    } else if(m > 0) {
        s -= m * 60;
        if(m == 1) {
            LoadString(hinst_kcreddb, IDS_IVL_1M, ibuf, ARRAYLENGTH(ibuf));
        } else {
            LoadString(hinst_kcreddb, IDS_IVL_M, fbuf, ARRAYLENGTH(fbuf));
            StringCbPrintf(ibuf, sizeof(ibuf), fbuf, m);
        }
        if(s > 0) {
            StringCbCat(ibuf, sizeof(ibuf), L" ");
            t = ibuf + wcslen(ibuf);
            if(s == 1)
            {
                LoadString(hinst_kcreddb, IDS_IVL_1S, t,
                           (int) (ARRAYLENGTH(ibuf) - wcslen(ibuf)));
            } else {
                LoadString(hinst_kcreddb, IDS_IVL_S, fbuf,
                           (int) ARRAYLENGTH(fbuf));
                StringCbPrintf(t, sizeof(ibuf) - wcslen(ibuf)*sizeof(wchar_t), fbuf, s);
            }
        }
    } else {
        if(s == 1) {
            LoadString(hinst_kcreddb, IDS_IVL_1S, ibuf, ARRAYLENGTH(ibuf));
        } else {
            LoadString(hinst_kcreddb, IDS_IVL_S, fbuf, sizeof(fbuf)/sizeof(wchar_t));
            StringCbPrintf(ibuf, sizeof(ibuf), fbuf, s);
        }
    }

    StringCbLength(ibuf, sizeof(ibuf), &cbsize);
    cbsize += sizeof(wchar_t);

    if(!buffer || *cb_buf < cbsize) {
        *cb_buf = cbsize;
        return KHM_ERROR_TOO_LONG;
    }

    StringCbCopy(buffer, *cb_buf, ibuf);
    *cb_buf = cbsize;

    return KHM_ERROR_SUCCESS;
}

khm_int32 KHMAPI 
kcdb_type_interval_toString(const void * data, 
                            khm_size cbd, 
                            wchar_t * buffer, 
                            khm_size * cb_buf, 
                            khm_int32 flags)
{
    return FtIntervalToString((LPFILETIME) data, buffer, cb_buf);
}

khm_boolean KHMAPI kcdb_type_interval_isValid(
    const void * d,
    khm_size cbd)
{
    return (d && (cbd == sizeof(FILETIME) || cbd == KCDB_CBSIZE_AUTO));
}

khm_int32 KHMAPI kcdb_type_interval_comp(
    const void * d1,
    khm_size cbd1,
    const void * d2,
    khm_size cbd2)
{
    __int64 i1, i2;

    i1 = FtToInt((FILETIME *) d1);
    i2 = FtToInt((FILETIME *) d2);

    if(i1 < i2)
        return -1;
    else if(i1 > i2)
        return 1;
    else
        return 0;
}

khm_int32 KHMAPI kcdb_type_interval_dup(
    const void * d_src,
    khm_size cbd_src,
    void * d_dst,
    khm_size * cbd_dst)
{
    if(d_dst && *cbd_dst >= sizeof(FILETIME)) {
        *cbd_dst = sizeof(FILETIME);
        *((FILETIME *) d_dst) = *((FILETIME *) d_src);
        return KHM_ERROR_SUCCESS;
    } else {
        *cbd_dst = sizeof(FILETIME);
        return KHM_ERROR_TOO_LONG;
    }
}

/* Int32 */

khm_int32 KHMAPI kcdb_type_int32_toString(
    const void * d, 
    khm_size cbd, 
    wchar_t * buffer, 
    khm_size * cb_buf, 
    khm_int32 flags)
{
    size_t cbsize;
    wchar_t ibuf[12];

    if(!cb_buf)
        return KHM_ERROR_INVALID_PARAM;

    StringCbPrintf(ibuf, sizeof(ibuf), L"%d", *((khm_int32 *) d));
    StringCbLength(ibuf, sizeof(ibuf), &cbsize);
    cbsize += sizeof(wchar_t);

    if(!buffer || *cb_buf < cbsize) {
        *cb_buf = cbsize;
        return KHM_ERROR_TOO_LONG;
    }

    StringCbCopy((wchar_t *) buffer, *cb_buf, ibuf);
    *cb_buf = cbsize;

    return KHM_ERROR_SUCCESS;
}

khm_boolean KHMAPI kcdb_type_int32_isValid(
    const void * d,
    khm_size cbd)
{
    return (d && (cbd == KCDB_CBSIZE_AUTO || cbd == sizeof(khm_int32)));
}

khm_int32 KHMAPI kcdb_type_int32_comp(
    const void * d1,
    khm_size cbd1,
    const void * d2,
    khm_size cbd2)
{
    return *((khm_int32 *) d1) - *((khm_int32 *) d2);
}

khm_int32 KHMAPI kcdb_type_int32_dup(
    const void * d_src,
    khm_size cbd_src,
    void * d_dst,
    khm_size * cbd_dst)
{
    if(d_dst && (*cbd_dst >= sizeof(khm_int32))) {
        *cbd_dst = sizeof(khm_int32);
        *((khm_int32 *) d_dst) = *((khm_int32 *) d_src);
        return KHM_ERROR_SUCCESS;
    } else {
        *cbd_dst = sizeof(khm_int32);
        return KHM_ERROR_TOO_LONG;
    }
}

/* Int64 */

khm_int32 KHMAPI kcdb_type_int64_toString(
    const void * d, 
    khm_size cbd, 
    wchar_t * buffer, 
    khm_size * cb_buf, 
    khm_int32 flags)
{
    size_t cbsize;
    wchar_t ibuf[22];

    if(!cb_buf)
        return KHM_ERROR_INVALID_PARAM;

    StringCbPrintf(ibuf, sizeof(ibuf), L"%I64d", *((__int64 *) d));
    StringCbLength(ibuf, sizeof(ibuf), &cbsize);
    cbsize += sizeof(wchar_t);

    if(!buffer || *cb_buf < cbsize) {
        *cb_buf = cbsize;
        return KHM_ERROR_TOO_LONG;
    }

    StringCbCopy((wchar_t *) buffer, *cb_buf, ibuf);
    *cb_buf = cbsize;

    return KHM_ERROR_SUCCESS;
}

khm_boolean KHMAPI kcdb_type_int64_isValid(
    const void * d,
    khm_size cbd)
{
    return (d && (cbd == KCDB_CBSIZE_AUTO || cbd == sizeof(__int64)));
}

khm_int32 KHMAPI kcdb_type_int64_comp(
    const void * d1,
    khm_size cbd1,
    const void * d2,
    khm_size cbd2)
{
    __int64 r = *((__int64 *) d1) - *((__int64 *) d2);
    return (r==0i64)?0:((r>0i64)?1:-1);
}

khm_int32 KHMAPI kcdb_type_int64_dup(
    const void * d_src,
    khm_size cbd_src,
    void * d_dst,
    khm_size * cbd_dst)
{
    if(d_dst && (*cbd_dst >= sizeof(__int64))) {
        *cbd_dst = sizeof(__int64);
        *((__int64 *) d_dst) = *((__int64 *) d_src);
        return KHM_ERROR_SUCCESS;
    } else {
        *cbd_dst = sizeof(__int64);
        return KHM_ERROR_TOO_LONG;
    }
}

/* Data */
#define GENERIC_DATA_STR L"(Data)"

khm_int32 KHMAPI kcdb_type_data_toString(
    const void * d, 
    khm_size cbd, 
    wchar_t * buffer, 
    khm_size * cb_buf, 
    khm_int32 flags)
{
    size_t cbsize;

    if(!cb_buf)
        return KHM_ERROR_INVALID_PARAM;

    cbsize = sizeof(GENERIC_DATA_STR);

    if(!buffer || *cb_buf < cbsize) {
        *cb_buf = cbsize;
        return KHM_ERROR_TOO_LONG;
    }

    StringCbCopy(buffer, *cb_buf, GENERIC_DATA_STR);

    *cb_buf = cbsize;

    return KHM_ERROR_SUCCESS;
}

khm_boolean KHMAPI kcdb_type_data_isValid(
    const void * d,
    khm_size cbd)
{
    /* data is always valid */
    if (cbd != 0 && d == NULL)
        return FALSE;
    else
        return TRUE;
}

khm_int32 KHMAPI kcdb_type_data_comp(
    const void * d1,
    khm_size cbd1,
    const void * d2,
    khm_size cbd2)
{
    khm_size pref;
    khm_int32 rv = 0;

    pref = min(cbd1, cbd2);

    if (pref == 0)
        return (cbd1 < cbd2)? -1 : ((cbd1 > cbd2)? 1 : 0);

    rv = memcmp(d1, d2, pref);

    if (rv == 0) {
        return (cbd1 < cbd2)? -1 : ((cbd1 > cbd2)? 1 : 0);
    } else {
        return rv;
    }
}

khm_int32 KHMAPI kcdb_type_data_dup(
    const void * d_src,
    khm_size cbd_src,
    void * d_dst,
    khm_size * cbd_dst)
{
    if(!cbd_dst || cbd_src == KCDB_CBSIZE_AUTO)
        return KHM_ERROR_INVALID_PARAM;

    if(!d_dst || *cbd_dst < cbd_src) {
        *cbd_dst = cbd_src;
        return KHM_ERROR_TOO_LONG;
    } else {
        *cbd_dst = cbd_src;
        memcpy(d_dst, d_src, cbd_src);
        return KHM_ERROR_SUCCESS;
    }
}


void kcdb_type_msg_completion(kmq_message * m) 
{
    kcdb_type_release((kcdb_type_i *) m->vparam);
}

void kcdb_type_post_message(khm_int32 op, kcdb_type_i * t)
{
    kcdb_type_hold(t);
    kmq_post_message(KMSG_KCDB, KMSG_KCDB_TYPE, op, (void *) t);
}

void kcdb_type_init(void)
{
    kcdb_type type;

    InitializeCriticalSection(&cs_type);
    kcdb_type_namemap = hash_new_hashtable(
        KCDB_TYPE_HASH_SIZE,
        hash_string,
        hash_string_comp,
        kcdb_type_add_ref,
        kcdb_type_del_ref);
    kcdb_type_tbl = PMALLOC(sizeof(kcdb_type_i *) * (KCDB_TYPE_MAX_ID + 1));
    ZeroMemory(kcdb_type_tbl, sizeof(kcdb_type_i *) * (KCDB_TYPE_MAX_ID + 1));
    kcdb_types = NULL;

    /*TODO: register standard data types */

    ZeroMemory(&type, sizeof(type));
    type.comp = kcdb_type_void_comp;
    type.dup = kcdb_type_void_dup;
    type.isValid = kcdb_type_void_isValid;
    type.toString = kcdb_type_void_toString;
    type.name = KCDB_TYPENAME_VOID;
    type.id = KCDB_TYPE_VOID;

    kcdb_type_register(&type, NULL);

    ZeroMemory(&type, sizeof(type));
    type.comp = kcdb_type_string_comp;
    type.dup = kcdb_type_string_dup;
    type.isValid = kcdb_type_string_isValid;
    type.toString = kcdb_type_string_toString;
    type.name = KCDB_TYPENAME_STRING;
    type.id = KCDB_TYPE_STRING;
    type.flags = KCDB_TYPE_FLAG_CB_AUTO;

    kcdb_type_register(&type, NULL);

    ZeroMemory(&type, sizeof(type));
    type.comp = kcdb_type_date_comp;
    type.dup = kcdb_type_date_dup;
    type.isValid = kcdb_type_date_isValid;
    type.toString = kcdb_type_date_toString;
    type.name = KCDB_TYPENAME_DATE;
    type.id = KCDB_TYPE_DATE;
    type.cb_max = sizeof(FILETIME);
    type.cb_min = sizeof(FILETIME);
    type.flags = KCDB_TYPE_FLAG_CB_FIXED;

    kcdb_type_register(&type, NULL);

    ZeroMemory(&type, sizeof(type));
    type.comp = kcdb_type_interval_comp;
    type.dup = kcdb_type_interval_dup;
    type.isValid = kcdb_type_interval_isValid;
    type.toString = kcdb_type_interval_toString;
    type.name = KCDB_TYPENAME_INTERVAL;
    type.id = KCDB_TYPE_INTERVAL;
    type.cb_max = sizeof(FILETIME);
    type.cb_min = sizeof(FILETIME);
    type.flags = KCDB_TYPE_FLAG_CB_FIXED;

    kcdb_type_register(&type, NULL);

    ZeroMemory(&type, sizeof(type));
    type.comp = kcdb_type_int32_comp;
    type.dup = kcdb_type_int32_dup;
    type.isValid = kcdb_type_int32_isValid;
    type.toString = kcdb_type_int32_toString;
    type.name = KCDB_TYPENAME_INT32;
    type.id = KCDB_TYPE_INT32;
    type.cb_max = sizeof(khm_int32);
    type.cb_min = sizeof(khm_int32);
    type.flags = KCDB_TYPE_FLAG_CB_FIXED;

    kcdb_type_register(&type, NULL);

    ZeroMemory(&type, sizeof(type));
    type.comp = kcdb_type_int64_comp;
    type.dup = kcdb_type_int64_dup;
    type.isValid = kcdb_type_int64_isValid;
    type.toString = kcdb_type_int64_toString;
    type.name = KCDB_TYPENAME_INT64;
    type.id = KCDB_TYPE_INT64;
    type.cb_max = sizeof(__int64);
    type.cb_min = sizeof(__int64);
    type.flags = KCDB_TYPE_FLAG_CB_FIXED;

    kcdb_type_register(&type, NULL);

    ZeroMemory(&type, sizeof(type));
    type.comp = kcdb_type_data_comp;
    type.dup = kcdb_type_data_dup;
    type.isValid = kcdb_type_data_isValid;
    type.toString = kcdb_type_data_toString;
    type.name = KCDB_TYPENAME_DATA;
    type.id = KCDB_TYPE_DATA;

    kcdb_type_register(&type, NULL);
}

void kcdb_type_add_ref(const void *key, void *vt)
{
    kcdb_type_hold((kcdb_type_i *) vt);
}

void kcdb_type_del_ref(const void *key, void *vt)
{
    kcdb_type_release((kcdb_type_i *) vt);
}

khm_int32 kcdb_type_hold(kcdb_type_i * t)
{
    if(!t)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_type);
    t->refcount++;
    LeaveCriticalSection(&cs_type);

    return KHM_ERROR_SUCCESS;
}

khm_int32 kcdb_type_release(kcdb_type_i * t)
{
    if(!t)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_type);
    t->refcount--;
    kcdb_type_check_and_delete(t->type.id);
    LeaveCriticalSection(&cs_type);

    return KHM_ERROR_SUCCESS;
}

void kcdb_type_exit(void)
{
    EnterCriticalSection(&cs_type);
    PFREE(kcdb_type_tbl);
    /*TODO: free up the individual types */
    LeaveCriticalSection(&cs_type);
    DeleteCriticalSection(&cs_type);
}

void kcdb_type_check_and_delete(khm_int32 id)
{
    kcdb_type_i * t;

    if(id < 0 || id > KCDB_TYPE_MAX_ID)
        return;

    EnterCriticalSection(&cs_type);
    t = kcdb_type_tbl[id];
    if(t && !t->refcount) {
        kcdb_type_tbl[id] = NULL;
        LDELETE(&kcdb_types, t);
        /* must already be out of the hash-table, otherwise refcount should not
            be zero */
        PFREE(t->type.name);
        PFREE(t);
    }
    LeaveCriticalSection(&cs_type);
}

KHMEXP khm_int32 KHMAPI kcdb_type_get_id(const wchar_t *name, khm_int32 * id)
{
    kcdb_type_i * t;
    size_t cbsize;

    if(FAILED(StringCbLength(name, KCDB_MAXCB_NAME, &cbsize))) {
        /* also fails of name is NULL */
        return KHM_ERROR_INVALID_PARAM;
    }

    EnterCriticalSection(&cs_type);
    t = hash_lookup(kcdb_type_namemap, (void*) name);
    LeaveCriticalSection(&cs_type);

    if(!t) {
        *id = KCDB_TYPE_INVALID;
        return KHM_ERROR_NOT_FOUND;
    } else {
        *id = t->type.id;
        return KHM_ERROR_SUCCESS;
    }
}

KHMEXP khm_int32 KHMAPI kcdb_type_get_info(khm_int32 id, kcdb_type ** info)
{
    kcdb_type_i * t;

    if(id < 0 || id > KCDB_TYPE_MAX_ID)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_type);
    t = kcdb_type_tbl[id];

    if (t)
        kcdb_type_hold(t);
    LeaveCriticalSection(&cs_type);

    if(info)
        *info = (kcdb_type *) t;
    else if (t)
        kcdb_type_release(t);

    return (t)? KHM_ERROR_SUCCESS : KHM_ERROR_NOT_FOUND;
}

KHMEXP khm_int32 KHMAPI kcdb_type_release_info(kcdb_type * info)
{
    return kcdb_type_release((kcdb_type_i *) info);
}

KHMEXP khm_int32 KHMAPI kcdb_type_get_name(khm_int32 id, wchar_t * buffer, khm_size * cbbuf)
{
    size_t cbsize;
    kcdb_type_i * t;

    if(id < 0 || id > KCDB_TYPE_MAX_ID || !cbbuf)
        return KHM_ERROR_INVALID_PARAM;

    t = kcdb_type_tbl[id];

    if(!t)
        return KHM_ERROR_NOT_FOUND;

    if(FAILED(StringCbLength(t->type.name, KCDB_MAXCB_NAME, &cbsize)))
        return KHM_ERROR_UNKNOWN;

    cbsize += sizeof(wchar_t);

    if(!buffer || *cbbuf < cbsize) {
        *cbbuf = cbsize;
        return KHM_ERROR_TOO_LONG;
    }

    StringCbCopy(buffer, *cbbuf, t->type.name);
    *cbbuf = cbsize;

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI kcdb_type_register(const kcdb_type * type, khm_int32 * new_id)
{
    kcdb_type_i *t;
    size_t cbsize;
    khm_int32 type_id;

    if(!type || 
        !type->comp || 
        !type->dup || 
        !type->isValid || 
        !type->toString || 
        !type->name)
        return KHM_ERROR_INVALID_PARAM;

    if((type->flags & KCDB_TYPE_FLAG_CB_MIN) &&
        (type->cb_min < 0 || type->cb_min > KCDB_TYPE_MAXCB))
    {
        return KHM_ERROR_INVALID_PARAM;
    }

    if((type->flags & KCDB_TYPE_FLAG_CB_MAX) &&
        (type->cb_max < 0 || type->cb_max > KCDB_TYPE_MAXCB))
    {
        return KHM_ERROR_INVALID_PARAM;
    }

    if((type->flags & KCDB_TYPE_FLAG_CB_MIN) &&
        (type->flags & KCDB_TYPE_FLAG_CB_MAX) &&
        (type->cb_max < type->cb_min))
    {
        return KHM_ERROR_INVALID_PARAM;
    }

    if(FAILED(StringCbLength(type->name, KCDB_MAXCB_NAME, &cbsize)))
        return KHM_ERROR_TOO_LONG;

    cbsize += sizeof(wchar_t);

    EnterCriticalSection(&cs_type);
    if(type->id == KCDB_TYPE_INVALID) {
        kcdb_type_get_next_free(&type_id);
    } else if(type->id < 0 || type->id > KCDB_TYPE_MAX_ID) {
        LeaveCriticalSection(&cs_type);
        return KHM_ERROR_INVALID_PARAM;
    } else if(kcdb_type_tbl[type->id]) {
        LeaveCriticalSection(&cs_type);
        return KHM_ERROR_DUPLICATE;
    } else {
        type_id = type->id;
    }

    if(type_id == KCDB_TYPE_INVALID) {
        LeaveCriticalSection(&cs_type);
        return KHM_ERROR_NO_RESOURCES;
    }

    t = PMALLOC(sizeof(kcdb_type_i));
    ZeroMemory(t, sizeof(kcdb_type_i));

    t->type.name = PMALLOC(cbsize);
    StringCbCopy(t->type.name, cbsize, type->name);

    t->type.comp = type->comp;
    t->type.dup = type->dup;
    t->type.flags = type->flags;
    t->type.id = type_id;
    t->type.isValid = type->isValid;
    t->type.toString = type->toString;

    LINIT(t);

    kcdb_type_tbl[type_id] = t;
    LPUSH(&kcdb_types, t);

    hash_add(kcdb_type_namemap, (void *) t->type.name, (void *) t);

    LeaveCriticalSection(&cs_type);

    if(new_id)
        *new_id = type_id;

    kcdb_type_post_message(KCDB_OP_INSERT, t);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI kcdb_type_unregister(khm_int32 id)
{
    kcdb_type_i * t;

    if(id < 0 || id > KCDB_TYPE_MAX_ID)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_type);
    t = kcdb_type_tbl[id];
    if(t) {
        kcdb_type_post_message(KCDB_OP_DELETE, t);
        /* we are going to remove t from the hash table.  If no one is holding
            a reference to it, then we can free it (actually, the del_ref code
            will take care of that anyway).  If there is a hold, then it will
            get freed when they release it. 
            
            Actually, the post_message call above pretty much guarantees that
            the type has a hold on it.*/
        t->type.flags |= KCDB_TYPE_FLAG_DELETED;
        hash_del(kcdb_type_namemap, t->type.name);
    }
    LeaveCriticalSection(&cs_type);

    if(t)
        return KHM_ERROR_SUCCESS;
    else
        return KHM_ERROR_NOT_FOUND;
}

KHMEXP khm_int32 KHMAPI kcdb_type_get_next_free(khm_int32 * id)
{
    int i;

    if(!id)
        return KHM_ERROR_INVALID_PARAM;

    /* do a linear search because this function only gets called a few times */
    EnterCriticalSection(&cs_type);
    for(i=0; i <= KCDB_TYPE_MAX_ID; i++) {
        if(!kcdb_type_tbl[i])
            break;
    }
    LeaveCriticalSection(&cs_type);

    if(i <= KCDB_TYPE_MAX_ID) {
        *id = i;
        return KHM_ERROR_SUCCESS;
    } else {
        *id = KCDB_TYPE_INVALID;
        return KHM_ERROR_NO_RESOURCES;
    }
}

/* Conversion functions */

KHMEXP void KHMAPI TimetToFileTime( time_t t, LPFILETIME pft )
{
    LONGLONG ll;

    if ( sizeof(time_t) == 4 )
	ll = Int32x32To64(t, 10000000) + 116444736000000000i64;
    else {
	ll = t * 10000000i64 + 116444736000000000i64;
    }
    pft->dwLowDateTime = (DWORD) ll;
    pft->dwHighDateTime = (DWORD) (ll >> 32);
}

KHMEXP void KHMAPI TimetToFileTimeInterval(time_t t, LPFILETIME pft)
{
    LONGLONG ll;
    
    if ( sizeof(time_t) == 4 )
	ll = Int32x32To64(t, 10000000);
    else {
	ll = t * 10000000i64;
    }
    pft->dwLowDateTime = (DWORD) ll;
    pft->dwHighDateTime = (DWORD) (ll >> 32);
}

KHMEXP long KHMAPI FtIntervalToSeconds(LPFILETIME pft)
{
    __int64 i = FtToInt(pft);
    return (long) (i / 10000000i64);
}

KHMEXP long KHMAPI FtIntervalToMilliseconds(LPFILETIME pft)
{
    __int64 i = FtToInt(pft);
    return (long) (i / 10000i64);
}

KHMEXP khm_int64 KHMAPI FtToInt(LPFILETIME pft) {
    LARGE_INTEGER ll;
    ll.LowPart = pft->dwLowDateTime;
    ll.HighPart = pft->dwHighDateTime;
    return ll.QuadPart;
}

KHMEXP FILETIME KHMAPI IntToFt(khm_int64 i) {
    LARGE_INTEGER ll;
    FILETIME ft;

    ll.QuadPart = i;
    ft.dwLowDateTime = ll.LowPart;
    ft.dwHighDateTime = ll.HighPart;

    return ft;
}

KHMEXP FILETIME KHMAPI FtSub(LPFILETIME ft1, LPFILETIME ft2) {
    FILETIME d;
    LARGE_INTEGER l1, l2;

    l1.LowPart = ft1->dwLowDateTime;
    l1.HighPart = ft1->dwHighDateTime;
    l2.LowPart = ft2->dwLowDateTime;
    l2.HighPart = ft2->dwHighDateTime;

    l1.QuadPart -= l2.QuadPart;

    d.dwLowDateTime = l1.LowPart;
    d.dwHighDateTime = l1.HighPart;

    return d;
}

KHMEXP FILETIME KHMAPI FtAdd(LPFILETIME ft1, LPFILETIME ft2) {
    FILETIME d;
    LARGE_INTEGER l1, l2;

    l1.LowPart = ft1->dwLowDateTime;
    l1.HighPart = ft1->dwHighDateTime;
    l2.LowPart = ft2->dwLowDateTime;
    l2.HighPart = ft2->dwHighDateTime;

    l1.QuadPart += l2.QuadPart;

    d.dwLowDateTime = l1.LowPart;
    d.dwHighDateTime = l1.HighPart;

    return d;
}

KHMEXP int KHMAPI AnsiStrToUnicode( wchar_t * wstr, size_t cbwstr, const char * astr)
{
    size_t nc;

    if(cbwstr == 0)
        return 0;

    nc = strlen(astr);
    if(nc == MultiByteToWideChar(
        CP_ACP, 
        0, 
        astr, 
        (int) nc, 
        wstr, 
        (int)(cbwstr / sizeof(wchar_t) - 1))) {
        wstr[nc] = L'\0';
    } else {
        wstr[0] = L'\0';
        nc = 0;
    }

    return (int) nc;
}

KHMEXP int KHMAPI UnicodeStrToAnsi( char * dest, size_t cbdest, const wchar_t * src)
{
    size_t nc;

    if(cbdest == 0)
        return 0;

    dest[0] = 0;

    if(FAILED(StringCchLength(src, cbdest, &nc)) || nc*sizeof(char) >= cbdest)
        // note that cbdest counts the terminating NULL, while nc doesn't
        return 0;

    nc = WideCharToMultiByte(
        CP_ACP, 
        WC_NO_BEST_FIT_CHARS, 
        src, 
        (int) nc, 
        dest, 
        (int) cbdest, 
        NULL, 
        NULL);

    dest[nc] = 0;

    return (int) nc;
}

#define MAX_IVL_SPECLIST_LEN 256
#define MAX_IVL_UNITS 5

enum _ivl_indices {
    IVL_SECONDS = 0,
    IVL_MINUTES,
    IVL_HOURS,
    IVL_DAYS,
    IVL_WEEKS
};

typedef struct ivspec_t {
    wchar_t str[MAX_IVL_SPECLIST_LEN];
    __int64 mul;
} ivspec;

static ivspec ivspecs[MAX_IVL_UNITS];
static BOOL ivspecs_loaded = FALSE;

int _iv_is_in_spec(wchar_t *s, int n, wchar_t * spec)
{
    /* spec strigns are comma separated */
    wchar_t *b, *e;

    b = spec;
    while(*b) {
        e = wcschr(b, L',');
        if(!e)
            e = b + wcslen(b);
    
        if((e - b) == n  && !_wcsnicmp(b, s, n)) {
            return TRUE;
        }

        if(*e)
            b = e+1;
        else
            break;
    }

    return FALSE;
}

KHMEXP khm_int32 KHMAPI IntervalStringToFt(FILETIME * pft, wchar_t * str)
{
    size_t cb;
    wchar_t * b;
    __int64 t;

    *pft = IntToFt(0);

    /* ideally we should synchronize this, but it doesn't hurt if two
       threads do this at the same time, because we only set the ivspecs_loaded
       flag when we are done */
    if(!ivspecs_loaded) {
        LoadString(hinst_kcreddb, IDS_IVL_S_SPEC, ivspecs[IVL_SECONDS].str, MAX_IVL_SPECLIST_LEN);
        ivspecs[IVL_SECONDS].mul = 10000000i64;
        LoadString(hinst_kcreddb, IDS_IVL_M_SPEC, ivspecs[IVL_MINUTES].str, MAX_IVL_SPECLIST_LEN);
        ivspecs[IVL_MINUTES].mul = ivspecs[IVL_SECONDS].mul * 60;
        LoadString(hinst_kcreddb, IDS_IVL_H_SPEC, ivspecs[2].str, MAX_IVL_SPECLIST_LEN);
        ivspecs[IVL_HOURS].mul = ivspecs[IVL_MINUTES].mul * 60;
        LoadString(hinst_kcreddb, IDS_IVL_D_SPEC, ivspecs[3].str, MAX_IVL_SPECLIST_LEN);
        ivspecs[IVL_DAYS].mul = ivspecs[IVL_HOURS].mul * 24;
        LoadString(hinst_kcreddb, IDS_IVL_W_SPEC, ivspecs[4].str, MAX_IVL_SPECLIST_LEN);
        ivspecs[IVL_WEEKS].mul = ivspecs[IVL_DAYS].mul * 7;

        ivspecs_loaded = TRUE;
    }

    if(!str || FAILED(StringCbLength(str, MAX_IVL_SPECLIST_LEN, &cb)))
        return KHM_ERROR_INVALID_PARAM;

    b = str;
    t = 0;
    while(*b) {
        __int64 f = 1;
        wchar_t *e;
        int i;

        while(*b && iswspace(*b))
            b++;

        if(*b && iswdigit(*b)) {
            f = _wtoi64(b);

            while(*b && iswdigit(*b))
                b++;
        }

        while(*b && iswspace(*b))
            b++;

        if(!*b) /* no unit specified */
            return KHM_ERROR_INVALID_PARAM;

        e = b;

        while(*e && !iswspace(*e))
            e++;

        for(i=0; i < MAX_IVL_UNITS; i++) {
            if(_iv_is_in_spec(b, (int)(e-b), ivspecs[i].str))
                break;
        }

        if(i==MAX_IVL_UNITS)
            return KHM_ERROR_INVALID_PARAM;

        t += f * ivspecs[i].mul;

        b = e;
    }

    *pft = IntToFt(t);

    return KHM_ERROR_SUCCESS;
}

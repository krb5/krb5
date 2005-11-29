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

/* Data representation and related functions */

#include<krbcred.h>
#include<krb5.h>
#include<kherror.h>
#include<strsafe.h>

khm_int32 KHMAPI enctype_toString(const void * data, khm_size cbdata, wchar_t *destbuf, khm_size *pcbdestbuf, khm_int32 flags)
{
    int resid = 0;
    int etype;
    wchar_t buf[256];
    size_t cblength;

    if(cbdata != sizeof(khm_int32))
        return KHM_ERROR_INVALID_PARAM;

    etype = *((khm_int32 *) data);

    switch(etype) {
    case ENCTYPE_NULL:
        resid = IDS_ETYPE_NULL;
        break;

    case ENCTYPE_DES_CBC_CRC:
        resid = IDS_ETYPE_DES_CBC_CRC;
        break;

    case ENCTYPE_DES_CBC_MD4:
        resid = IDS_ETYPE_DES_CBC_MD4;
        break;

    case ENCTYPE_DES_CBC_MD5:
        resid = IDS_ETYPE_DES_CBC_MD5;
        break;

    case ENCTYPE_DES_CBC_RAW:
        resid = IDS_ETYPE_DES_CBC_RAW;
        break;

    case ENCTYPE_DES3_CBC_SHA:
        resid = IDS_ETYPE_DES3_CBC_SHA;
        break;

    case ENCTYPE_DES3_CBC_RAW:
        resid = IDS_ETYPE_DES3_CBC_RAW;
        break;

    case ENCTYPE_DES_HMAC_SHA1:
        resid = IDS_ETYPE_DES_HMAC_SHA1;
        break;

    case ENCTYPE_DES3_CBC_SHA1:
        resid = IDS_ETYPE_DES3_CBC_SHA1;
        break;

    case ENCTYPE_AES128_CTS_HMAC_SHA1_96:
        resid = IDS_ETYPE_AES128_CTS_HMAC_SHA1_96;
        break;

    case ENCTYPE_AES256_CTS_HMAC_SHA1_96:
        resid = IDS_ETYPE_AES256_CTS_HMAC_SHA1_96;
        break;

    case ENCTYPE_ARCFOUR_HMAC:
        resid = IDS_ETYPE_ARCFOUR_HMAC;
        break;

    case ENCTYPE_ARCFOUR_HMAC_EXP:
        resid = IDS_ETYPE_ARCFOUR_HMAC_EXP;
        break;

    case ENCTYPE_UNKNOWN:
        resid = IDS_ETYPE_UNKNOWN;
        break;

#if 0
    case ENCTYPE_LOCAL_DES3_HMAC_SHA1:
        resid = IDS_ETYPE_LOCAL_DES3_HMAC_SHA1;
        break;

    case ENCTYPE_LOCAL_RC4_MD4:
        resid = IDS_ETYPE_LOCAL_RC4_MD4;
        break;
#endif
    }

    if(resid != 0) {
        LoadString(hResModule, (UINT) resid, buf, ARRAYLENGTH(buf));
    } else {
        StringCbPrintf(buf, sizeof(buf), L"#%d", etype);
    }

    StringCbLength(buf, ARRAYLENGTH(buf), &cblength);
    cblength += sizeof(wchar_t);

    if(!destbuf || *pcbdestbuf < cblength) {
        *pcbdestbuf = cblength;
        return KHM_ERROR_TOO_LONG;
    } else {
        StringCbCopy(destbuf, *pcbdestbuf, buf);
        *pcbdestbuf = cblength;
        return KHM_ERROR_SUCCESS;
    }
}

khm_int32 KHMAPI addr_list_toString(const void *d, khm_size cb_d, wchar_t *buf, khm_size *pcb_buf, khm_int32 flags)
{
    /*TODO: implement this */
    return KHM_ERROR_NOT_IMPLEMENTED;
}

khm_int32 KHMAPI krb5flags_toString(const void *d, 
                                    khm_size cb_d, 
                                    wchar_t *buf, 
                                    khm_size *pcb_buf, 
                                    khm_int32 f)
{
    wchar_t sbuf[32];
    int i = 0;
    khm_size cb;
    khm_int32 flags;

    flags = *((khm_int32 *) d);

    if (flags & TKT_FLG_FORWARDABLE)
        sbuf[i++] = L'F';

    if (flags & TKT_FLG_FORWARDED)
        sbuf[i++] = L'f';

    if (flags & TKT_FLG_PROXIABLE)
        sbuf[i++] = L'P';

    if (flags & TKT_FLG_PROXY)
        sbuf[i++] = L'p';

    if (flags & TKT_FLG_MAY_POSTDATE)
        sbuf[i++] = L'D';

    if (flags & TKT_FLG_POSTDATED)
        sbuf[i++] = L'd';

    if (flags & TKT_FLG_INVALID)
        sbuf[i++] = L'i';

    if (flags & TKT_FLG_RENEWABLE)
        sbuf[i++] = L'R';

    if (flags & TKT_FLG_INITIAL)
        sbuf[i++] = L'I';

    if (flags & TKT_FLG_HW_AUTH)
        sbuf[i++] = L'H';

    if (flags & TKT_FLG_PRE_AUTH)
        sbuf[i++] = L'A';

    sbuf[i++] = L'\0';

    cb = i * sizeof(wchar_t);

    if (!buf || *pcb_buf < cb) {
        *pcb_buf = cb;
        return KHM_ERROR_TOO_LONG;
    } else {
        StringCbCopy(buf, *pcb_buf, sbuf);
        *pcb_buf = cb;
        return KHM_ERROR_SUCCESS;
    }
}

khm_int32 serialize_krb5_addresses(krb5_address ** a, void ** buf, size_t * pcbbuf)
{
    /*TODO: implement this */
    return KHM_ERROR_NOT_IMPLEMENTED;
}

#if 0

wchar_t * 
one_addr(krb5_address *a)
{
    static wchar_t retstr[256];
    struct hostent *h;
    int no_resolve = 1;

    retstr[0] = L'\0';

    if ((a->addrtype == ADDRTYPE_INET && a->length == 4)
#ifdef AF_INET6
        || (a->addrtype == ADDRTYPE_INET6 && a->length == 16)
#endif
        ) 
    {
        int af = AF_INET;
#ifdef AF_INET6
        if (a->addrtype == ADDRTYPE_INET6)
            af = AF_INET6;
#endif
        if (!no_resolve) {
#ifdef HAVE_GETIPNODEBYADDR
            int err;
            h = getipnodebyaddr(a->contents, a->length, af, &err);
            if (h) {
                StringCbPrintf(retstr, sizeof(retstr), L"%S", h->h_name);
                freehostent(h);
            }
#else
            h = gethostbyaddr(a->contents, a->length, af);
            if (h) {
                StringCbPrintf(retstr, sizeof(retstr), L"%S", h->h_name);
            }
#endif
            if (h)
                return(retstr);
        }
        if (no_resolve || !h) {
#ifdef HAVE_INET_NTOP
            char buf[46];
            const char *name = inet_ntop(a->addrtype, a->contents, buf, sizeof(buf));
            if (name) {
                StringCbPrintf(retstr, sizeof(retstr), L"%S", name);
                return;
            }
#else
            if (a->addrtype == ADDRTYPE_INET) {
                StringCbPrintf(retstr, sizeof(retstr),
                    L"%d.%d.%d.%d", a->contents[0], a->contents[1],
                    a->contents[2], a->contents[3]);
                return(retstr);
            }
#endif
        }
    }
    {
        wchar_t tmpfmt[128];
        LoadString(hResModule, IDS_UNK_ADDR_FMT, tmpfmt, sizeof(tmpfmt)/sizeof(wchar_t));
        StringCbPrintf(retstr, sizeof(retstr), tmpfmt, a->addrtype);
    }
    return(retstr);
}
#endif

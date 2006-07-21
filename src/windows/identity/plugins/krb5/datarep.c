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

#include<winsock2.h>
#include<krbcred.h>
#include<krb5.h>
#include<kherror.h>
#include<strsafe.h>
#include<assert.h>

khm_int32 KHMAPI 
enctype_toString(const void * data, khm_size cbdata,
		 wchar_t *destbuf, khm_size *pcbdestbuf,
		 khm_int32 flags)
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

khm_int32 KHMAPI
addr_list_comp(const void *d1, khm_size cb_d1,
	       const void *d2, khm_size cb_d2)
{
    if (cb_d1 < cb_d2)
	return -1;
    if (cb_d1 > cb_d2)
	return 1;
    return memcmp(d1, d2, cb_d1);
}

khm_int32 KHMAPI
addr_list_toString(const void *d, khm_size cb_d,
		   wchar_t *buf, khm_size *pcb_buf,
		   khm_int32 flags)
{
    wchar_t tbuf[2048];
    wchar_t * strpos;
    khm_size cbleft;
    size_t t;
    k5_serial_address * addrs;

    if (cb_d == 0 || d == NULL) {
        tbuf[0] = L'\0';
    } else {
        addrs = (k5_serial_address *) d;

        strpos = tbuf;
        cbleft = sizeof(tbuf);
        tbuf[0] = L'\0';

        while (TRUE) {
            if (cb_d < sizeof(*addrs) ||
                addrs->magic != K5_SERIAL_ADDRESS_MAGIC ||
                cb_d < sizeof(*addrs) + addrs->length - sizeof(khm_int32))
                break;

            if (strpos != tbuf) {
                if (FAILED(StringCbCatEx(strpos, cbleft, L"  ",
                                         &strpos, &cbleft,
                                         0)))
                    break;
            }

#ifdef DEBUG
            assert(*strpos == L'\0');
#endif

            one_addr(addrs, strpos, cbleft);

	    t = 0;
	    if (FAILED(StringCchLength(strpos,
				       cbleft / sizeof(wchar_t),
				       &t)))
		break;

	    strpos += t;
	    cbleft -= t * sizeof(wchar_t);

            t = sizeof(*addrs) + addrs->length - sizeof(khm_int32);
            addrs = (k5_serial_address *) BYTEOFFSET(addrs, t);
            cb_d -= t;
        }
    }

    StringCbLength(tbuf, sizeof(tbuf), &t);

    if (!buf || *pcb_buf < t) {
        *pcb_buf = t;
        return KHM_ERROR_TOO_LONG;
    }

    StringCbCopy(buf, *pcb_buf, tbuf);
    *pcb_buf = t;

    return KHM_ERROR_SUCCESS;
}

khm_int32 KHMAPI
krb5flags_toString(const void *d, 
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

khm_int32 KHMAPI
kvno_toString(const void * data, khm_size cbdata,
              wchar_t *destbuf, khm_size *pcbdestbuf,
              khm_int32 flags)
{
    int resid = 0;
    int kvno;
    wchar_t buf[256];
    size_t cblength;

    if (cbdata != sizeof(khm_int32))
        return KHM_ERROR_INVALID_PARAM;

    kvno = *((khm_int32 *) data);

    StringCbPrintf(buf, sizeof(buf), L"#%d", kvno);

    StringCbLength(buf, ARRAYLENGTH(buf), &cblength);
    cblength += sizeof(wchar_t);

    if (!destbuf || *pcbdestbuf < cblength) {
        *pcbdestbuf = cblength;
        return KHM_ERROR_TOO_LONG;
    } else {
        StringCbCopy(destbuf, *pcbdestbuf, buf);
        *pcbdestbuf = cblength;
        return KHM_ERROR_SUCCESS;
    }
}

khm_int32
serialize_krb5_addresses(krb5_address ** a, void * buf, size_t * pcbbuf)
{
    k5_serial_address * addr;
    khm_size cb_req;
    khm_size t;
    khm_boolean overflow = FALSE;

    addr = (k5_serial_address *) buf;
    cb_req = 0;

    for(; *a; a++) {
        t = sizeof(k5_serial_address) + (*a)->length - sizeof(khm_int32);
        cb_req += t;
        if (cb_req < *pcbbuf) {
            addr->magic = K5_SERIAL_ADDRESS_MAGIC;
            addr->addrtype = (*a)->addrtype;
            addr->length = (*a)->length;
            memcpy(&addr->data, (*a)->contents, (*a)->length);

            addr = (k5_serial_address *) BYTEOFFSET(addr, t);
        } else {
            overflow = TRUE;
        }
    }

    *pcbbuf = cb_req;

    return (overflow)?KHM_ERROR_TOO_LONG: KHM_ERROR_SUCCESS;
}

void
one_addr(k5_serial_address *a, wchar_t * buf, khm_size cbbuf)
{
    wchar_t retstr[256];
    struct hostent *h = NULL;
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
            h = getipnodebyaddr(&a->data, a->length, af, &err);
            if (h) {
                StringCbPrintf(retstr, sizeof(retstr), L"%S", h->h_name);
                freehostent(h);
            }
            else
                h = gethostbyaddr(&a->data, a->length, af);
            if (h) {
                StringCbPrintf(retstr, sizeof(retstr), L"%S", h->h_name);
            }
#endif
            if (h)
                goto _copy_string;
        }
        if (no_resolve || !h) {
#ifdef HAVE_INET_NTOP
            char buf[46];
            const char *name = inet_ntop(a->addrtype, &a->data, buf, sizeof(buf));
            if (name) {
                StringCbPrintf(retstr, sizeof(retstr), L"%S", name);
                goto _copy_string;
            }
#else
            if (a->addrtype == ADDRTYPE_INET) {
                khm_ui_4 addr = a->data;
                StringCbPrintf(retstr, sizeof(retstr),
                               L"%d.%d.%d.%d",
                               (int) (addr & 0xff),
                               (int) ((addr >> 8) & 0xff),
                               (int) ((addr >> 16)& 0xff),
                               (int) ((addr >> 24)& 0xff));
                goto _copy_string;
            }
#endif
        }
    }

    {
        wchar_t tmpfmt[128];
        LoadString(hResModule, IDS_UNK_ADDR_FMT, tmpfmt, sizeof(tmpfmt)/sizeof(wchar_t));
        StringCbPrintf(retstr, sizeof(retstr), tmpfmt, a->addrtype);
    }

 _copy_string:
    StringCbCopy(buf, cbbuf, retstr);
}


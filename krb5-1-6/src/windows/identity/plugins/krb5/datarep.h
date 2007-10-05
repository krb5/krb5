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

#ifndef __KHIMAIRA_KRB_DATAREP_H
#define __KHIMAIRA_KRB_DATAREP_H

typedef struct tag_k5_serial_address {
    khm_int32     magic;        /* should be K5_SERIAL_ADDRESS_MAGIC */
    khm_int32     addrtype;     /* Address type. We only know what to
                                   do with ADDRTYPE_INET and
                                   ADDRTYPE_INET6 */
    khm_size      length;       /* number of bytes of data in [data].
                                   This should always be greater than
                                   sizeof(khm_int32) */
    khm_int32     data;         /* actually, &data is the beginning of
                                   the data buffer that is [length]
                                   bytes long. */
} k5_serial_address;

#define K5_SERIAL_ADDRESS_MAGIC 0x44ce832d

khm_int32 KHMAPI
enctype_toString(const void * data, khm_size cbdata,
                 wchar_t *destbuf, khm_size *pcbdestbuf,
                 khm_int32 flags);

khm_int32 KHMAPI
addr_list_comp(const void *d1, khm_size cb_d1,
	       const void *d2, khm_size cb_d2);

khm_int32 KHMAPI
addr_list_toString(const void *, khm_size, wchar_t *,
                   khm_size *, khm_int32);

khm_int32 KHMAPI
krb5flags_toString(const void *, khm_size, wchar_t *,
                   khm_size *, khm_int32);

khm_int32 KHMAPI
kvno_toString(const void * data, khm_size cbdata,
              wchar_t *destbuf, khm_size *pcbdestbuf,
              khm_int32 flags);

khm_int32 KHMAPI
renew_for_cb(khm_handle cred, khm_int32 id, void * buffer,
             khm_size * pcbsize);

khm_int32
serialize_krb5_addresses(krb5_address ** a, void * buf, size_t * pcbbuf);

void
one_addr(k5_serial_address *a, wchar_t * buf, khm_size cbbuf);
#endif

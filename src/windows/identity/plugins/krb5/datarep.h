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

#ifndef __KHIMAIRA_KRB_DATAREP_H
#define __KHIMAIRA_KRB_DATAREP_H


khm_int32 KHMAPI enctype_toString(const void * data, khm_size cbdata, wchar_t *destbuf, khm_size *pcbdestbuf, khm_int32 flags);
khm_int32 KHMAPI addr_list_toString(const void *, khm_size, wchar_t *, khm_size *, khm_int32);
khm_int32 KHMAPI krb5flags_toString(const void *, khm_size, wchar_t *, khm_size *, khm_int32);
khm_int32 KHMAPI renew_for_cb(khm_handle cred, khm_int32 id, void * buffer, khm_size * pcbsize);


#endif
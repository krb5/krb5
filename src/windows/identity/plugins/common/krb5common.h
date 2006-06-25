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

/* Adapted from multiple Leash header files */

#ifndef __KHIMAIRA_KRB5COMMON_H
#define __KHIMAIRA_KRB5COMMON_H

#include<krb5.h>

#ifndef NO_KRB5
int khm_krb5_error(krb5_error_code rc, LPCSTR FailedFunctionName, 
                   int FreeContextFlag, krb5_context *ctx,
                   krb5_ccache *cache);

int
khm_krb5_get_error_string(krb5_error_code rc,
                          wchar_t * buffer,
                          khm_size cb_buffer);

int khm_krb5_initialize(khm_handle ident, krb5_context *, krb5_ccache *);

khm_int32 KHMAPI
khm_krb5_find_ccache_for_identity(khm_handle ident, krb5_context *pctx,
                                  void * buffer, khm_size * pcbbuf);

khm_int32 KHMAPI
khm_get_identity_expiration_time(krb5_context ctx, krb5_ccache cc, 
                                 khm_handle ident, 
                                 krb5_timestamp * pexpiration);
#endif /* NO_KRB5 */

#endif

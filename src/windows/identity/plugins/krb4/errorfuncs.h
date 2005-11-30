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

#ifndef __KHIMAIRA_ERR_H
#define __KHIMAIRA_ERR_H

/* All error handling and reporting related functions for the krb4/5
   and AFS plugins */

#include <errno.h>
#include <com_err.h>
/*
 * This is a hack needed because the real com_err.h does
 * not define err_func.  We need it in the case where
 * we pull in the real com_err instead of the krb4 
 * impostor.
 */
#ifndef _DCNS_MIT_COM_ERR_H
typedef LPSTR (*err_func)(int, long);
#endif

#include <krberr.h>
#include <kadm_err.h>

#define kadm_err_base ERROR_TABLE_BASE_kadm

#include <stdarg.h>

#ifndef KRBERR
#define KRBERR(code) (code + krb_err_base)
#endif

LPSTR err_describe(LPSTR buf, size_t len, long code);


/* */
khm_int32 init_error_funcs();

khm_int32 exit_error_funcs();


#endif

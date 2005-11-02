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
extern void Leash_initialize_krb_error_func(err_func func,struct et_list **);
#undef init_krb_err_func
#define init_krb_err_func(erf) Leash_initialize_krb_error_func(erf,&_et_list)

#include <kadm_err.h>

extern void Leash_initialize_kadm_error_table(struct et_list **);
#undef init_kadm_err_tbl
#define init_kadm_err_tbl() Leash_initialize_kadm_error_table(&_et_list)
#define kadm_err_base ERROR_TABLE_BASE_kadm

#define krb_err_func Leash_krb_err_func

#include <stdarg.h>
int lsh_com_err_proc (LPSTR whoami, long code,
		      LPSTR fmt, va_list args);
void FAR Leash_load_com_err_callback(FARPROC,FARPROC,FARPROC);

#ifndef KRBERR
#define KRBERR(code) (code + krb_err_base)
#endif

int lsh_com_err_proc (LPSTR whoami, long code, LPSTR fmt, va_list args);
int DoNiftyErrorReport(long errnum, LPSTR what);

LPSTR err_describe(LPSTR buf, long code);


/* */
khm_int32 init_error_funcs();

khm_int32 exit_error_funcs();


#endif

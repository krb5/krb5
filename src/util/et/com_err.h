/*
 * Header file for common error description library.
 *
 * Copyright 1988, Student Information Processing Board of the
 * Massachusetts Institute of Technology.
 *
 * Copyright 1995 by Cygnus Support.
 *
 * For copyright and distribution info, see the documentation supplied
 * with this package.
 */

#ifndef __COM_ERR_H

/* This should be part of k5-config.h but many application
 * programs are not including that file. We probably want to
 * come up with a better way of handling this problem.
 */
#if defined(_MSDOS) || defined (_WIN32)
#include <win-mac.h>
#endif

#ifndef KRB5_CALLCONV
#define KRB5_CALLCONV
#define KRB5_CALLCONV_C
#define KRB5_DLLIMP
#define KRB5_EXPORTVAR
#endif

#ifndef FAR
#define FAR
#define NEAR
#endif

#if defined(__STDC__) || defined(_MSDOS) || defined(_WIN32) || defined(_MACINTOSH)

/* End-user programs may need this -- oh well */
#ifndef HAVE_STDARG_H
#define HAVE_STDARG_H 1
#endif

#define ET_P(x) x

#else
#define ET_P(x) ()
#endif /* __STDC__ */

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#define	ET_STDARG_P(x) x
#else
#include <varargs.h>
#define ET_STDARG_P(x) ()
#define ET_VARARGS
#endif

typedef long errcode_t;

typedef void (*et_old_error_hook_func) ET_P((const char FAR *, errcode_t,
					     const char FAR *, va_list ap));
	
KRB5_DLLIMP extern void KRB5_CALLCONV_C com_err
	ET_STDARG_P((const char FAR *, errcode_t, const char FAR *, ...));
KRB5_DLLIMP extern void KRB5_CALLCONV_C com_err_va
	ET_STDARG_P((const char FAR *, errcode_t, const char FAR *, va_list));

KRB5_DLLIMP extern const char FAR * KRB5_CALLCONV error_message
	ET_P((errcode_t));

KRB5_DLLIMP extern et_old_error_hook_func KRB5_EXPORTVAR com_err_hook;
KRB5_DLLIMP extern et_old_error_hook_func KRB5_CALLCONV set_com_err_hook
	ET_P((et_old_error_hook_func));
KRB5_DLLIMP extern et_old_error_hook_func KRB5_CALLCONV reset_com_err_hook
	ET_P((void));
KRB5_DLLIMP extern void KRB5_CALLCONV com_err_va
	ET_P((const char FAR *whoami, errcode_t code, const char FAR *fmt,
	      va_list ap));

/*
 * The experimental com_err API...
 */
typedef struct et_context FAR *et_ctx;
typedef void (KRB5_CALLCONV *et_error_hook_func)
	ET_P((et_ctx, void FAR *, const char FAR *, errcode_t,
	      const char FAR *, va_list ap));

struct error_table {
	char const FAR * const FAR * msgs;
	long base;
	int n_msgs;
};

struct et_hook {
	et_error_hook_func	func;
	void			FAR *data;
};

KRB5_DLLIMP extern errcode_t KRB5_CALLCONV et_init ET_P((et_ctx FAR *));
KRB5_DLLIMP extern void KRB5_CALLCONV et_shutdown ET_P((et_ctx));

KRB5_DLLIMP extern errcode_t KRB5_CALLCONV et_add_error_table
	ET_P((et_ctx, struct error_table FAR *));

KRB5_DLLIMP extern const char FAR * KRB5_CALLCONV et_error_message
	ET_P((et_ctx, errcode_t));

KRB5_DLLIMP extern void KRB5_CALLCONV_C et_com_err
	ET_STDARG_P((et_ctx, const char FAR *, errcode_t,
		     const char FAR *, ...));

KRB5_DLLIMP extern void KRB5_CALLCONV_C et_com_err_va
	ET_STDARG_P((et_ctx, const char FAR *, errcode_t,
		     const char FAR *, va_list ap));

KRB5_DLLIMP errcode_t KRB5_CALLCONV et_set_hook
	ET_P((et_ctx, struct et_hook FAR *, struct et_hook FAR *));
			
#define __COM_ERR_H
#endif /* ! defined(__COM_ERR_H) */

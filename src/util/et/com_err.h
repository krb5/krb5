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

/* This should be part of k5-config.h but many application
 * programs are not including that file. We probably want to
 * come up with a better way of handling this problem.
 */
#if defined(_MSDOS) || defined (_WIN32)
#ifdef _MSDOS
        /* Windows 16 specific */
#ifndef KRB5_CALLCONV
#define KRB5_CALLCONV __far __export __pascal 
#define KRB5_CALLCONV_C __far __export __cdecl
#define KRB5_DLLIMP
#define INTERFACE   KRB5_CALLCONV
#define INTERFACE_C KRB5_CALLCONV_C
#endif /* !KRB5_CALLCONV */
#ifndef FAR
#define FAR __far
#define NEAR __near
#endif
#else
        /* Windows 32 specific */
#ifndef KRB5_CALLCONV
#ifdef KRB5_DLL_FILE
#define KRB5_DECLSPEC dllexport
#else
#define KRB5_DECLSPEC dllimport
#endif
#define KRB5_DLLIMP __declspec(KRB5_DECLSPEC)
#define KRB5_CALLCONV __stdcall
#define KRB5_CALLCONV_C __cdecl
#define INTERFACE   KRB5_DLLIMP KRB5_CALLCONV
#define INTERFACE_C KRB5_DLLIMP KRB5_CALLCONV_C
#endif /* !KRB5_CALLCONV */

#include <windows.h>
	
#endif  /* Win 16 vs Win 32 */
#else /* Windows stuff */
#ifndef KRB5_CALLCONV
#define KRB5_CALLCONV
#define KRB5_CALLCONV_C
#define KRB5_DLLIMP
#define INTERFACE
#define INTERFACE_C
#endif
#endif /* Windows stuff */

#ifndef FAR
#define FAR
#define NEAR
#endif

typedef long errcode_t;

typedef void (*et_old_error_hook_func) ET_P((const char FAR *, errcode_t,
					     const char FAR *, va_list ap));
	
KRB5_DLLIMP extern void KRB5_CALLCONV_C com_err
	ET_STDARG_P((const char FAR *, errcode_t, const char FAR *, ...));

KRB5_DLLIMP extern const char FAR * KRB5_CALLCONV error_message
	ET_P((errcode_t));

KRB5_DLLIMP extern et_old_error_hook_func KRB5_CALLCONV com_err_hook;

KRB5_DLLIMP extern et_old_error_hook_func KRB5_CALLCONV set_com_err_hook
	ET_P((et_old_error_hook_func));

KRB5_DLLIMP extern et_old_error_hook_func KRB5_CALLCONV reset_com_err_hook
	ET_P((void));

/*
 * The the new com_err API...
 */
typedef struct et_context FAR *et_ctx;
typedef void (* KRB5_CALLCONV et_error_hook_func)
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
	ET_STDARG_P((et_ctx, void FAR *, const char FAR *, errcode_t,
		     const char FAR *, ...));

KRB5_DLLIMP extern void KRB5_CALLCONV_C et_com_err_va
	ET_STDARG_P((et_ctx, void FAR *, const char FAR *, errcode_t,
		     const char FAR *, va_list ap));

KRB5_DLLIMP errcode_t KRB5_CALLCONV et_set_hook
	ET_P((et_ctx, struct et_hook FAR *, struct et_hook FAR *));
			
#define __COM_ERR_H
#endif /* ! defined(__COM_ERR_H) */

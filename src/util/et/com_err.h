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

#if defined(_MSDOS) || defined(_WIN32) || defined(macintosh)
#include <win-mac.h>
#endif

#ifndef KRB5_CALLCONV
#define KRB5_CALLCONV
#define KRB5_CALLCONV_C
/* We don't use this, but since we're using the Kerberos ones, we
   need to either provide all the ones the Kerberos headers
   will use, or not define KRB5_CALLCONV, since that's the only one
   they test.  */
#define KRB5_EXPORTVAR
#endif

#ifndef FAR
#define FAR
#define NEAR
#endif

#include <stdarg.h>

typedef long errcode_t;
typedef void (*et_old_error_hook_func) (const char FAR *, errcode_t,
					const char FAR *, va_list ap);
	
struct error_table {
	/*@shared@*/ char const FAR * const FAR * msgs;
        long base;
	unsigned int n_msgs;
};

#ifdef __cplusplus
extern "C" {
#endif

/* Public interfaces */
extern void KRB5_CALLCONV_C com_err
	(const char FAR *, errcode_t, const char FAR *, ...);
extern void KRB5_CALLCONV com_err_va
	(const char FAR *whoami, errcode_t code, const char FAR *fmt,
	 va_list ap);
extern /*@observer@*//*@dependent@*/ const char FAR * KRB5_CALLCONV error_message
	(errcode_t)
       /*@modifies internalState@*/;
extern errcode_t KRB5_CALLCONV add_error_table
	(/*@dependent@*/ const struct error_table FAR *)
       /*@modifies internalState@*/;
extern errcode_t KRB5_CALLCONV remove_error_table
	(const struct error_table FAR *)
       /*@modifies internalState@*/;

#if !defined(_MSDOS) && !defined(_WIN32) && !defined(macintosh)
/*
 * The display routine should be application specific.  A global hook,
 * may cause inappropriate display procedures to be called between
 * applications under non-Unix environments.
 */

extern et_old_error_hook_func set_com_err_hook (et_old_error_hook_func);
extern et_old_error_hook_func reset_com_err_hook (void);
#endif

#ifdef __cplusplus
}
#endif

#define __COM_ERR_H
#endif /* ! defined(__COM_ERR_H) */

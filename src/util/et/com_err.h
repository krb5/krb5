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

#ifndef HAVE_STDARG_H
/* End-user programs may need this -- oh well */
#if defined(__STDC__) || defined(_WINDOWS) || defined(_MACINTOSH)
#define HAVE_STDARG_H 1
#endif
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
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

#if defined(__STDC__) || defined(_MSDOS) || defined(_WIN32)
/* ANSI C -- use prototypes etc */
KRB5_DLLIMP extern void KRB5_CALLCONV_C com_err
	(const char FAR *, long, const char FAR *, ...);
KRB5_DLLIMP extern const char  FAR * KRB5_CALLCONV error_message (long);
extern void (*com_err_hook) (const char *, long, const char *, va_list);
extern void (*set_com_err_hook (void (*) (const char *, long, const char *, va_list)))
    (const char *, long, const char *, va_list);
extern void (*reset_com_err_hook ()) (const char *, long, const char *, va_list);
#else
/* no prototypes */
extern void com_err ();
extern const char * error_message ();
extern void (*com_err_hook) ();
extern void (*set_com_err_hook ()) ();
extern void (*reset_com_err_hook ()) ();
#endif

#define __COM_ERR_H
#endif /* ! defined(__COM_ERR_H) */

/*
 * Header file for common error description library.
 *
 * Copyright 1988, Student Information Processing Board of the
 * Massachusetts Institute of Technology.
 *
 * For copyright and distribution info, see the documentation supplied
 * with this package.
 */

#ifndef __COM_ERR_H

#ifndef STDARG_PROTOTYPES
/* Imake needs this -- oh well */
#ifdef __STDC__
#define STDARG_PROTOTYPES
#endif
#endif

#ifdef STDARG_PROTOTYPES
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#ifdef __STDC__
/* ANSI C -- use prototypes etc */
extern void INTERFACE_C com_err (const char *, long, const char *, ...);
extern char const * INTERFACE error_message (long);
extern void (*com_err_hook) (const char *, long, const char *, va_list);
extern void (*set_com_err_hook (void (*) (const char *, long, const char *, va_list)))
    (const char *, long, const char *, va_list);
extern void (*reset_com_err_hook ()) (const char *, long, const char *, va_list);
#else
/* no prototypes */
extern void INTERFACE_C com_err ();
extern char * INTERFACE error_message ();
extern void (*com_err_hook) ();
extern void (*set_com_err_hook ()) ();
extern void (*reset_com_err_hook ()) ();
#endif

#define __COM_ERR_H
#endif /* ! defined(__COM_ERR_H) */

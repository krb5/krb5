/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Basic definitions for Kerberos V5 library
 */


#ifndef KRB5_BASE_DEFS__
#define KRB5_BASE_DEFS__

#include <krb5/wordsize.h>

#ifndef FALSE
#define	FALSE	0
#endif
#ifndef TRUE
#define	TRUE	1
#endif

typedef krb5_octet	krb5_boolean;
typedef	krb5_octet	krb5_msgtype;
typedef	krb5_octet	krb5_kvno;

typedef	krb5_ui_2	krb5_addrtype;
typedef krb5_ui_2	krb5_keytype;
typedef krb5_ui_2	krb5_enctype;
typedef krb5_ui_2	krb5_cksumtype;
typedef krb5_ui_2	krb5_authdatatype;

typedef	krb5_int32	krb5_flags;
typedef krb5_int32	krb5_timestamp;
typedef	krb5_int32	krb5_error_code;
typedef krb5_int32	krb5_deltat;

typedef struct _krb5_data {
    int length;
    char *data;
} krb5_data;

/* make const & volatile available without effect */

#if !defined(__STDC__) && !defined(HAS_ANSI_CONST)
#define const
#endif
#if !defined(__STDC__) && !defined(HAS_ANSI_VOLATILE)
#define volatile
#endif

#if defined(__STDC__) || defined(HAS_VOID_TYPE)
typedef	void * krb5_pointer;
typedef void const * krb5_const_pointer;
#else
typedef char * krb5_pointer;
typedef char const * krb5_const_pointer;
#endif

#if defined(__STDC__) || defined(KRB5_PROVIDE_PROTOTYPES)
#define PROTOTYPE(x) x
#if defined(__STDC__) || defined(STDARG_PROTOTYPES)
#define	STDARG_P(x) x
#else
#define STDARG_P(x) ()
#endif /* defined(__STDC__) || defined(STDARG_PROTOTYPES) */
#ifdef NARROW_PROTOTYPES
#define DECLARG(type, val) type val
#define OLDDECLARG(type, val)
#else
#define DECLARG(type, val) val
#define OLDDECLARG(type, val) type val;
#endif /* NARROW_PROTOTYPES */
#else
#define PROTOTYPE(x) ()
#define STDARG_P(x) ()
#define DECLARG(type, val) val
#define OLDDECLARG(type, val) type val;
#endif /* STDC or PROTOTYPES */

typedef	krb5_data **	krb5_principal;	/* array of strings */
					/* CONVENTION: realm is first elem. */
/* constant version thereof: */
typedef krb5_data * const *  krb5_const_principal;

#define krb5_princ_realm(princ) ((princ)[0])

#endif /* KRB5_BASE_DEFS__ */

/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
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

typedef krb5_int32	krb5_preauthtype; /* This may change, later on */
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

#ifdef NO_NESTED_PROTOTYPES
#define	NPROTOTYPE(x) ()
#else
#define	NPROTOTYPE(x) PROTOTYPE(x)
#endif

typedef struct krb5_principal_data {
    krb5_data realm;
    krb5_data *data;		/* An array of strings */
    krb5_int32 length;
    krb5_int32 type;
} krb5_principal_data;

typedef	krb5_principal_data *krb5_principal;

/*
 * Per V5 spec on definition of principal types
 */

/* Name type not known */
#define KRB5_NT_UNKNOWN		0
/* Just the name of the principal as in DCE, or for users */
#define KRB5_NT_PRINCIPAL	1
/* Service and other unique instance (krbtgt) */
#define KRB5_NT_SRV_INST	2
/* Service with host name as instance (telnet, rcommands) */
#define KRB5_NT_SRV_HST		3
/* Service with host as remaining components */
#define KRB5_NT_SRV_XHST	4
/* Unique ID */
#define KRB5_NT_UID		5

/* constant version thereof: */
typedef const krb5_principal_data *krb5_const_principal;

#define krb5_princ_realm(princ) (&(princ)->realm)
#define krb5_princ_set_realm(princ,value) ((princ)->realm = *(value))
#define krb5_princ_set_realm_length(princ,value) (princ)->realm.length = (value)
#define krb5_princ_set_realm_data(princ,value) (princ)->realm.data = (value)
#define	krb5_princ_size(princ) (princ)->length
#define	krb5_princ_type(princ) (princ)->type
#define	krb5_princ_name(princ) (princ)->data
#define	krb5_princ_component(princ,i) ((princ)->data + i)

/* The name of the Kerberos ticket granting service... and its size */
#define	KRB5_TGS_NAME		"krbtgt"
#define KRB5_TGS_NAME_SIZE	6

#endif /* KRB5_BASE_DEFS__ */

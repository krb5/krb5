/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Basic definitions for Kerberos V5 library
 */

#include <krb5/copyright.h>

#ifndef __KRB5_BASE_DEFS__
#define __KRB5_BASE_DEFS__

#include <krb5/wordsize.h>

typedef krb5_octet	krb5_ui_1;
typedef krb5_int16	krb5_ui_2;
typedef krb5_int32	krb5_ui_4;
typedef krb5_octet	krb5_boolean;

#ifndef FALSE
#define	FALSE	0
#endif
#ifndef TRUE
#define	TRUE	1
#endif

typedef krb5_int32	krb5_timestamp;
typedef krb5_ui_2	krb5_confounder;
typedef	krb5_octet	krb5_msgtype;
typedef	krb5_octet	krb5_kvno;
typedef	krb5_int32	krb5_flags;

typedef	krb5_ui_2	krb5_addrtype;
typedef krb5_ui_2	krb5_keytype;
typedef krb5_ui_2	krb5_enctype;
typedef krb5_ui_2	krb5_cksumtype;
typedef krb5_ui_2	krb5_authdatatype;

typedef	krb5_int32	krb5_error_code;
typedef krb5_int32	krb5_deltat;

typedef struct _krb5_data {
    int length;
    char *data;
} krb5_data;


typedef	krb5_data **	krb5_principal;	/* array of strings */
					/* CONVENTION: realm is first elem. */
#ifdef __STDC__
typedef	void * krb5_pointer;
#define PROTOTYPE(x) x
#else
/* make const & volatile available without effect */
#define const
#define volatile
typedef char * krb5_pointer;
#define PROTOTYPE(x) ()
#endif /* __STDC__ */

#endif /* __KRB5_BASE_DEFS__ */

/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * <<< Description >>>
 */

#include <krb5/copyright.h>

#ifndef __KRB5_BASE_DEFS__
#define __KRB5_BASE_DEFS__

#include <krb5/wordsize.h>

typedef krb5_octet	krb5_ui_1;
typedef krb5_int16	krb5_ui_2;
typedef krb5_int32	krb5_ui_4;
typedef krb5_octet	krb5_boolean;


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

typedef struct _krb5_data {
    int length;
    char *data;
} krb5_data;


typedef	krb5_data **	krb5_principal;	/* array of strings */
					/* CONVENTION: realm is first elem. */
#ifdef __STDC__
typedef	void * krb5_pointer;
#else
typedef char * krb5_pointer;
#endif /* __STDC__ */

#endif /* __KRB5_BASE_DEFS__ */

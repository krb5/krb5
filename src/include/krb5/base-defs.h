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

typedef octet		krb5_ui_1;
typedef int16		krb5_ui_2;
typedef int32		krb5_ui_4;
typedef octet		krb5_boolean;


typedef int32		krb5_timestamp;
typedef krb5_ui_2	krb5_confounder;
typedef	octet		krb5_msgtype;
typedef	octet		krb5_kvno;
typedef	int32		krb5_flags;

typedef	krb5_ui_2	krb5_addrtype;
typedef krb5_ui_2	krb5_keytype;
typedef krb5_ui_2	krb5_enctype;
typedef krb5_ui_2	krb5_cksumtype;
typedef krb5_ui_2	krb5_authdatatype;

typedef struct _krb5_data {
    int length;
    char *data;
} krb5_data;

#endif /* __KRB5_BASE_DEFS__ */

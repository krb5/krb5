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

#include <krb5/mit-copyright.h>

#ifndef __KRB5_TYPEDEFS__
#define __KRB5_TYPEDEFS__

#include <krb5/wordsize.h>

typedef octet		krb5_ui_1;
typedef int16		krb5_ui_2;
typedef int32		krb5_ui_4;

typedef int32		krb5_timestamp;
typedef krb5_ui_2	confounder;
typedef	octet		krb5_msgtype;
typedef	octet		krb5_kvno;
typedef	int32		krb5_flags;

typedef	krb5_ui_2	krb5_addr_type;
typedef krb5_ui_2	krb5_keytype;
typedef krb5_ui_2	krb5_enctype;
typedef krb5_ui_2	krb5_cksumtype;

#endif /* __KRB5_TYPEDEFS__ */

/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * macros used in Kerberos code.
 */


#ifndef KRB5_MACROS__
#define KRB5_MACROS__

#define krb5_princ_aref(princ, n, plen) (char *)(*plen = princ[n]->length, princ[n]->data)

#endif /* KRB5_MACROS__ */

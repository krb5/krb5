/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * LIBOS internal function prototypes.
 */

#include <krb5/copyright.h>

#ifndef KRB5_LIBOS_INT_PROTO__
#define KRB5_LIBOS_INT_PROTO__

#ifdef SOCK_DGRAM			/* XXX hack... */
krb5_error_code krb5_locate_kdc
    PROTOTYPE((krb5_data *,
	       struct sockaddr **,
	       int *));
#endif

#endif /* KRB5_LIBOS_INT_PROTO__ */

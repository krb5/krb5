/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * LIBOS internal function prototypes.
 */

#ifndef KRB5_LIBOS_INT_PROTO__
#define KRB5_LIBOS_INT_PROTO__

#ifdef SOCK_DGRAM			/* XXX hack... */
krb5_error_code krb5_locate_kdc
    PROTOTYPE((const krb5_data *,
	       struct sockaddr **,
	       int *));
#endif

#ifdef KRB5_USE_INET
krb5_error_code krb5_unpack_full_ipaddr
    PROTOTYPE((krb5_address *,
	       krb5_int32 *,
	       krb5_int16 *));

#ifdef NARROW_PROTOTYPES
krb5_error_code krb5_make_full_ipaddr
    PROTOTYPE((krb5_int32,
	       krb5_int16,
	       krb5_address **));
#else
krb5_error_code krb5_make_full_ipaddr
    PROTOTYPE((krb5_int32,
	       int,			/* unsigned short promotes to signed
					   int */
	       krb5_address **));
#endif /* NARROW_PROTOTYPES */
#endif /* KRB5_USE_INET */

#endif /* KRB5_LIBOS_INT_PROTO__ */

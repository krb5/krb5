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
 * Function prototypes for Kerberos V5 library (libos)
 */

#ifndef KRB5_LIBOS_PROTO__
#define KRB5_LIBOS_PROTO__

#include <stdio.h>

/* libos.spec */
krb5_error_code krb5_read_password
	PROTOTYPE((char *,
		   char *,
		   char *,
		   int * ));
krb5_error_code krb5_lock_file
	PROTOTYPE((FILE *,
		   char *,
		   int  ));
krb5_error_code krb5_unlock_file
	PROTOTYPE((FILE *,
		   char * ));
krb5_error_code krb5_timeofday
	PROTOTYPE((krb5_int32 * ));
krb5_error_code krb5_us_timeofday
	PROTOTYPE((krb5_int32 *,
		   krb5_int32 * ));
int krb5_net_read
	PROTOTYPE((int ,
		   char *,
		   int  ));
int krb5_net_write
	PROTOTYPE((int ,
		   char *,
		   int  ));
		 /* get all the addresses of this host */
krb5_error_code krb5_os_localaddr
	PROTOTYPE((krb5_address ***));
krb5_error_code krb5_sendto_kdc
	PROTOTYPE((const krb5_data *,
		   const krb5_data *,
		   krb5_data * ));
krb5_error_code krb5_get_krbhst
	PROTOTYPE((const krb5_data *,
		   char *** ));
krb5_error_code krb5_free_krbhst
	PROTOTYPE((char * const * ));
krb5_error_code krb5_aname_to_localname
	PROTOTYPE((krb5_const_principal,
		   const int,
		   char * ));
krb5_error_code krb5_get_default_realm
	PROTOTYPE(( char ** ));
krb5_error_code krb5_get_host_realm
	PROTOTYPE((const char *,
		   char *** ));
krb5_error_code krb5_free_host_realm
	PROTOTYPE((char * const * ));
krb5_boolean krb5_kuserok
	PROTOTYPE((krb5_principal, const char *));
krb5_error_code krb5_random_confounder
	PROTOTYPE((int,
		   krb5_pointer ));
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
#endif /* not NARROW_PROTOTYPES */

#endif /* KRB5_LIBOS_PROTO__ */

/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Function prototypes for Kerberos V5 library (libos)
 */

#include <krb5/copyright.h>

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
krb5_error_code krb5_ms_timeofday
	PROTOTYPE((krb5_int32 *,
		   krb5_ui_2 * ));
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
	PROTOTYPE((const krb5_principal,
		   const int,
		   char * ));
krb5_error_code krb5_get_default_realm
	PROTOTYPE((const int,
		   char * ));
krb5_error_code krb5_get_host_realm
	PROTOTYPE((const char *,
		   char *** ));
krb5_error_code krb5_free_host_realm
	PROTOTYPE((char * const * ));
krb5_boolean krb5_kuserok
	PROTOTYPE((krb5_principal, const char *));
krb5_confounder krb5_random_confounder PROTOTYPE((void));

#endif /* KRB5_LIBOS_PROTO__ */

/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
		   const char *,
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
krb5_error_code krb5_get_realm_domain
	PROTOTYPE((const char *,
		   char ** ));
krb5_boolean krb5_kuserok
	PROTOTYPE((krb5_principal, const char *));
krb5_error_code krb5_random_confounder
	PROTOTYPE((int,
		   krb5_pointer ));
krb5_error_code krb5_gen_replay_name
    PROTOTYPE((const krb5_address *,
	       const char *,
	       char **));
krb5_error_code krb5_gen_portaddr
    PROTOTYPE((const krb5_address *,
	       krb5_const_pointer,
	       krb5_address **));
krb5_error_code krb5_create_secure_file
	PROTOTYPE((const char * pathname));
krb5_error_code krb5_sync_disk_file
	PROTOTYPE((FILE *fp));


krb5_error_code krb5_read_message PROTOTYPE((krb5_pointer, krb5_data *));
krb5_error_code krb5_write_message PROTOTYPE((krb5_pointer, krb5_data *));

#include <krb5/widen.h>
krb5_error_code krb5_sname_to_principal
    PROTOTYPE((const char *,
	       const char *,
	       krb5_int32,
	       krb5_principal *));
#include <krb5/narrow.h>

#endif /* KRB5_LIBOS_PROTO__ */

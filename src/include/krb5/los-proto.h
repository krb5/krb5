/*
 * include/krb5/los-proto.h
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
	KRB5_PROTOTYPE((krb5_context,
		   const char *,
		   const char *,
		   char *,
		   int * ));
krb5_error_code krb5_lock_file
	KRB5_PROTOTYPE((krb5_context,
		   FILE *,
		   char *,
		   int  ));
krb5_error_code krb5_unlock_file
	KRB5_PROTOTYPE((krb5_context,
		   FILE *,
		   char * ));
int krb5_net_read
	KRB5_PROTOTYPE((krb5_context,
		   int ,
		   char *,
		   int  ));
int krb5_net_write
	KRB5_PROTOTYPE((krb5_context,
		   int ,
		   const char *,
		   int  ));
krb5_error_code krb5_sendto_kdc
	KRB5_PROTOTYPE((krb5_context,
		   const krb5_data *,
		   const krb5_data *,
		   krb5_data * ));
krb5_error_code krb5_get_krbhst
	KRB5_PROTOTYPE((krb5_context,
		   const krb5_data *,
		   char *** ));
krb5_error_code krb5_free_krbhst
	KRB5_PROTOTYPE((krb5_context,
		   char * const * ));
krb5_error_code krb5_aname_to_localname
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const_principal,
		   const int,
		   char * ));
krb5_error_code krb5_get_host_realm
	KRB5_PROTOTYPE((krb5_context,
		   const char *,
		   char *** ));
krb5_error_code krb5_free_host_realm
	KRB5_PROTOTYPE((krb5_context,
		   char * const * ));
krb5_error_code krb5_get_realm_domain
	KRB5_PROTOTYPE((krb5_context,
		   const char *,
		   char ** ));
krb5_boolean krb5_kuserok
	KRB5_PROTOTYPE((krb5_context,
		   krb5_principal, const char *));
krb5_error_code krb5_random_confounder
	KRB5_PROTOTYPE((int,
		   krb5_pointer ));
krb5_error_code krb5_gen_replay_name
    KRB5_PROTOTYPE((krb5_context,
		   const krb5_address *,
	       const char *,
	       char **));
krb5_error_code INTERFACE krb5_auth_con_genaddrs
    KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
	       int, int));
krb5_error_code krb5_gen_portaddr
    KRB5_PROTOTYPE((krb5_context,
		   const krb5_address *,
	       krb5_const_pointer,
	       krb5_address **));
krb5_error_code krb5_create_secure_file
	KRB5_PROTOTYPE((krb5_context,
		   const char * pathname));
krb5_error_code krb5_sync_disk_file
	KRB5_PROTOTYPE((krb5_context,
		   FILE *fp));


krb5_error_code krb5_read_message 
	KRB5_PROTOTYPE((krb5_context,
		   krb5_pointer, 
		   krb5_data *));
krb5_error_code krb5_write_message 
	KRB5_PROTOTYPE((krb5_context,
		   krb5_pointer, 
		   krb5_data *));

krb5_error_code krb5_os_init_context
        KRB5_PROTOTYPE((krb5_context));

void krb5_os_free_context
        KRB5_PROTOTYPE((krb5_context));

krb5_error_code krb5_find_config_files
        KRB5_PROTOTYPE(());

krb5_error_code krb5_make_fulladdr
    KRB5_PROTOTYPE((krb5_context,
	       krb5_address *,
	       krb5_address *,
	       krb5_address *));

time_t gmt_mktime KRB5_PROTOTYPE((struct tm *));

#endif /* KRB5_LIBOS_PROTO__ */

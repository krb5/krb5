/*
 * lib/krb5/rcache/rc_dfl.h
 *
 * This file of the Kerberos V5 software is derived from public-domain code
 * contributed by Daniel J. Bernstein, <brnstnd@acf10.nyu.edu>.
 *
 */

/*
 * Declarations for the default replay cache implementation.
 */

#ifndef KRB5_RC_DFL_H
#define KRB5_RC_DFL_H

extern krb5_rc_ops krb5_rc_dfl_ops; /* initialized to the following */

krb5_error_code KRB5_CALLCONV krb5_rc_dfl_init 
    	PROTOTYPE((krb5_context,
		   krb5_rcache,
		   krb5_deltat));
krb5_error_code KRB5_CALLCONV krb5_rc_dfl_recover 
	PROTOTYPE((krb5_context,
		   krb5_rcache)); 
krb5_error_code KRB5_CALLCONV krb5_rc_dfl_destroy 
	PROTOTYPE((krb5_context,
		   krb5_rcache));
krb5_error_code KRB5_CALLCONV krb5_rc_dfl_close 
	PROTOTYPE((krb5_context,
		   krb5_rcache));
krb5_error_code KRB5_CALLCONV krb5_rc_dfl_store 
	PROTOTYPE((krb5_context,
		   krb5_rcache,
		   krb5_donot_replay *));
krb5_error_code KRB5_CALLCONV krb5_rc_dfl_expunge 
	PROTOTYPE((krb5_context,
		   krb5_rcache));
krb5_error_code KRB5_CALLCONV krb5_rc_dfl_get_span 
	PROTOTYPE((krb5_context,
		   krb5_rcache,
		   krb5_deltat *));
char * KRB5_CALLCONV krb5_rc_dfl_get_name 
	PROTOTYPE((krb5_context,
		   krb5_rcache));
krb5_error_code KRB5_CALLCONV krb5_rc_dfl_resolve 
	PROTOTYPE((krb5_context,
		   krb5_rcache,
		   char *));
krb5_error_code krb5_rc_dfl_close_no_free
	PROTOTYPE((krb5_context,
		   krb5_rcache));
void krb5_rc_free_entry 
	PROTOTYPE((krb5_context,
		   krb5_donot_replay **));
#endif


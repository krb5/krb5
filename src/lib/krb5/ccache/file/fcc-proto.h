/*
 * lib/krb5/ccache/file/fcc-proto.h
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
 * Prototypes for File-based credentials cache
 */


#ifndef KRB5_FCC_PROTO__
#define KRB5_FCC_PROTO__

/* fcc_close.c */
krb5_error_code INTERFACE krb5_fcc_close
	PROTOTYPE((krb5_context, krb5_ccache id ));

/* fcc_defnam.c */
char * krb5_fcc_default_name 
	PROTOTYPE((krb5_context));

/* fcc_destry.c */
krb5_error_code INTERFACE krb5_fcc_destroy 
	PROTOTYPE((krb5_context, krb5_ccache id ));

/* fcc_eseq.c */
krb5_error_code INTERFACE krb5_fcc_end_seq_get 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_cc_cursor *cursor ));

/* fcc_gennew.c */
krb5_error_code INTERFACE krb5_fcc_generate_new 
	PROTOTYPE((krb5_context, krb5_ccache *id ));

/* fcc_getnam.c */
char * INTERFACE krb5_fcc_get_name 
	PROTOTYPE((krb5_context, krb5_ccache id ));

/* fcc_gprin.c */
krb5_error_code INTERFACE krb5_fcc_get_principal 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_principal *princ ));

/* fcc_init.c */
krb5_error_code INTERFACE krb5_fcc_initialize 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_principal princ ));

/* fcc_nseq.c */
krb5_error_code INTERFACE krb5_fcc_next_cred 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_cc_cursor *cursor , 
		   krb5_creds *creds ));

/* fcc_read.c */
krb5_error_code krb5_fcc_read
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_pointer buf,
		   int len));
krb5_error_code krb5_fcc_read_principal 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_principal *princ ));
krb5_error_code krb5_fcc_read_keyblock 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_keyblock *keyblock ));
krb5_error_code krb5_fcc_read_data 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_data *data ));
krb5_error_code krb5_fcc_read_int32 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_int32 *i ));
krb5_error_code krb5_fcc_read_ui_2 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_ui_2 *i ));
krb5_error_code krb5_fcc_read_octet 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_octet *i ));
krb5_error_code krb5_fcc_read_times 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_ticket_times *t ));
krb5_error_code krb5_fcc_read_addrs 
	PROTOTYPE((krb5_context, krb5_ccache, krb5_address ***));
krb5_error_code krb5_fcc_read_addr 
	PROTOTYPE((krb5_context, krb5_ccache, krb5_address *));
krb5_error_code krb5_fcc_read_authdata 
	PROTOTYPE((krb5_context, krb5_ccache , krb5_authdata ***));
krb5_error_code krb5_fcc_read_authdatum 
	PROTOTYPE((krb5_context, krb5_ccache , krb5_authdata *));

/* fcc_reslv.c */
krb5_error_code INTERFACE krb5_fcc_resolve 
	PROTOTYPE((krb5_context, krb5_ccache *id , char *residual ));

/* fcc_retrv.c */
krb5_error_code INTERFACE krb5_fcc_retrieve 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_flags whichfields , 
		   krb5_creds *mcreds , 
		   krb5_creds *creds ));

/* fcc_sseq.c */
krb5_error_code INTERFACE krb5_fcc_start_seq_get 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_cc_cursor *cursor ));

/* fcc_store.c */
krb5_error_code INTERFACE krb5_fcc_store 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_creds *creds ));

/* fcc_skip.c */
krb5_error_code krb5_fcc_skip_principal 
	PROTOTYPE((krb5_context, krb5_ccache id ));

/* fcc_sflags.c */
krb5_error_code INTERFACE krb5_fcc_set_flags 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_flags flags ));

/* fcc_ops.c */
extern krb5_cc_ops krb5_cc_file_ops;
krb5_error_code krb5_change_cache
   PROTOTYPE((void));


/* fcc_write.c */
krb5_error_code krb5_fcc_write 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_pointer buf , int len ));
krb5_error_code krb5_fcc_store_principal 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_principal princ ));
krb5_error_code krb5_fcc_store_keyblock 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_keyblock *keyblock ));
krb5_error_code krb5_fcc_store_data 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_data *data ));
krb5_error_code krb5_fcc_store_int32 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_int32 i ));
krb5_error_code krb5_fcc_store_ui_2 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_int32 i ));
krb5_error_code krb5_fcc_store_octet 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_int32 i ));
krb5_error_code krb5_fcc_store_times 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_ticket_times *t ));
krb5_error_code krb5_fcc_store_addrs 
	PROTOTYPE((krb5_context, krb5_ccache , krb5_address ** ));
krb5_error_code krb5_fcc_store_addr 
	PROTOTYPE((krb5_context, krb5_ccache , krb5_address * ));
krb5_error_code krb5_fcc_store_authdata 
	PROTOTYPE((krb5_context, krb5_ccache , krb5_authdata **));
krb5_error_code krb5_fcc_store_authdatum 
	PROTOTYPE((krb5_context, krb5_ccache , krb5_authdata *));

/* fcc_errs.c */
krb5_error_code krb5_fcc_interpret 
	PROTOTYPE((krb5_context, int ));

/* fcc_maybe.c */
krb5_error_code krb5_fcc_close_file 
	PROTOTYPE((krb5_context, krb5_ccache));
krb5_error_code krb5_fcc_open_file 
	PROTOTYPE((krb5_context, krb5_ccache, int));

#endif /* KRB5_FCC_PROTO__ */

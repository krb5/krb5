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
 * Prototypes for File-based credentials cache
 */

#include <krb5/copyright.h>

#ifndef KRB5_SCC_PROTO__
#define KRB5_SCC_PROTO__

/* scc_close.c */
krb5_error_code krb5_scc_close PROTOTYPE((krb5_ccache id ));

/* scc_defnam.c */
char *krb5_scc_default_name PROTOTYPE((void ));

/* scc_destry.c */
krb5_error_code krb5_scc_destroy PROTOTYPE((krb5_ccache id ));

/* scc_eseq.c */
krb5_error_code krb5_scc_end_seq_get PROTOTYPE((krb5_ccache id , krb5_cc_cursor *cursor ));

/* scc_gennew.c */
krb5_error_code krb5_scc_generate_new PROTOTYPE((krb5_ccache *id ));

/* scc_getnam.c */
char *krb5_scc_get_name PROTOTYPE((krb5_ccache id ));

/* scc_gprin.c */
krb5_error_code krb5_scc_get_principal PROTOTYPE((krb5_ccache id , krb5_principal *princ ));

/* scc_init.c */
krb5_error_code krb5_scc_initialize PROTOTYPE((krb5_ccache id , krb5_principal princ ));

/* scc_nseq.c */
krb5_error_code krb5_scc_next_cred PROTOTYPE((krb5_ccache id , krb5_cc_cursor *cursor , krb5_creds *creds ));

/* scc_read.c */
krb5_error_code krb5_scc_read_principal PROTOTYPE((krb5_ccache id , krb5_principal *princ ));
krb5_error_code krb5_scc_read_keyblock PROTOTYPE((krb5_ccache id , krb5_keyblock *keyblock ));
krb5_error_code krb5_scc_read_data PROTOTYPE((krb5_ccache id , krb5_data *data ));
krb5_error_code krb5_scc_read_int32 PROTOTYPE((krb5_ccache id , krb5_int32 *i ));
krb5_error_code krb5_scc_read_ui_2 PROTOTYPE((krb5_ccache id , krb5_ui_2 *i ));
krb5_error_code krb5_scc_read_keytype PROTOTYPE((krb5_ccache id , krb5_keytype *k ));
krb5_error_code krb5_scc_read_int PROTOTYPE((krb5_ccache id , int *i ));
krb5_error_code krb5_scc_read_bool PROTOTYPE((krb5_ccache id , krb5_boolean *b ));
krb5_error_code krb5_scc_read_times PROTOTYPE((krb5_ccache id , krb5_ticket_times *t ));
krb5_error_code krb5_scc_read_flags PROTOTYPE((krb5_ccache id , krb5_flags *f ));
krb5_error_code krb5_scc_read_addrs PROTOTYPE((krb5_ccache, krb5_address ***));
krb5_error_code krb5_scc_read_addr PROTOTYPE((krb5_ccache, krb5_address *));

/* scc_reslv.c */
krb5_error_code krb5_scc_resolve PROTOTYPE((krb5_ccache *id , char *residual ));

/* scc_retrv.c */
krb5_error_code krb5_scc_retrieve PROTOTYPE((krb5_ccache id , krb5_flags whichfields , krb5_creds *mcreds , krb5_creds *creds ));

/* scc_sseq.c */
krb5_error_code krb5_scc_start_seq_get PROTOTYPE((krb5_ccache id , krb5_cc_cursor *cursor ));

/* scc_store.c */
krb5_error_code krb5_scc_store PROTOTYPE((krb5_ccache id , krb5_creds *creds ));

/* scc_skip.c */
krb5_error_code krb5_scc_skip_principal PROTOTYPE((krb5_ccache id ));

/* scc_sflags.c */
krb5_error_code krb5_scc_set_flags PROTOTYPE((krb5_ccache id , krb5_flags flags ));

/* scc_ops.c */

/* scc_write.c */
krb5_error_code krb5_scc_write PROTOTYPE((krb5_ccache id , krb5_pointer buf , int len ));
krb5_error_code krb5_scc_store_principal PROTOTYPE((krb5_ccache id , krb5_principal princ ));
krb5_error_code krb5_scc_store_keyblock PROTOTYPE((krb5_ccache id , krb5_keyblock *keyblock ));
krb5_error_code krb5_scc_store_data PROTOTYPE((krb5_ccache id , krb5_data *data ));
krb5_error_code krb5_scc_store_int32 PROTOTYPE((krb5_ccache id , krb5_int32 *i ));
krb5_error_code krb5_scc_store_ui_2 PROTOTYPE((krb5_ccache id , krb5_ui_2 *i ));
krb5_error_code krb5_scc_store_keytype PROTOTYPE((krb5_ccache id , krb5_keytype *k ));
krb5_error_code krb5_scc_store_int PROTOTYPE((krb5_ccache id , int *i ));
krb5_error_code krb5_scc_store_bool PROTOTYPE((krb5_ccache id , krb5_boolean *b ));
krb5_error_code krb5_scc_store_times PROTOTYPE((krb5_ccache id , krb5_ticket_times *t ));
krb5_error_code krb5_scc_store_flags PROTOTYPE((krb5_ccache id , krb5_flags *f ));
krb5_error_code krb5_scc_store_addrs PROTOTYPE((krb5_ccache , krb5_address ** ));
krb5_error_code krb5_scc_store_addr PROTOTYPE((krb5_ccache , krb5_address * ));

/* scc_errs.c */
krb5_error_code krb5_scc_interpret PROTOTYPE((int ));

#endif /* KRB5_SCC_PROTO__ */

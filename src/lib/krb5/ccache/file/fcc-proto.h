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

#ifndef KRB5_FCC_PROTO__
#define KRB5_FCC_PROTO__

/* fcc_close.c */
krb5_error_code krb5_fcc_close PROTOTYPE((krb5_ccache id ));

/* fcc_defnam.c */
char *krb5_fcc_default_name PROTOTYPE((void ));

/* fcc_destry.c */
krb5_error_code krb5_fcc_destroy PROTOTYPE((krb5_ccache id ));

/* fcc_eseq.c */
krb5_error_code krb5_fcc_end_seq_get PROTOTYPE((krb5_ccache id , krb5_cc_cursor *cursor ));

/* fcc_gennew.c */
krb5_error_code krb5_fcc_generate_new PROTOTYPE((krb5_ccache *id ));

/* fcc_getnam.c */
char *krb5_fcc_get_name PROTOTYPE((krb5_ccache id ));

/* fcc_gprin.c */
krb5_error_code krb5_fcc_get_principal PROTOTYPE((krb5_ccache id , krb5_principal *princ ));

/* fcc_init.c */
krb5_error_code krb5_fcc_initialize PROTOTYPE((krb5_ccache id , krb5_principal princ ));

/* fcc_nseq.c */
krb5_error_code krb5_fcc_next_cred PROTOTYPE((krb5_ccache id , krb5_cc_cursor *cursor , krb5_creds *creds ));

/* fcc_read.c */
krb5_error_code krb5_fcc_read_principal PROTOTYPE((krb5_ccache id , krb5_principal *princ ));
krb5_error_code krb5_fcc_read_keyblock PROTOTYPE((krb5_ccache id , krb5_keyblock *keyblock ));
krb5_error_code krb5_fcc_read_data PROTOTYPE((krb5_ccache id , krb5_data *data ));
krb5_error_code krb5_fcc_read_int32 PROTOTYPE((krb5_ccache id , krb5_int32 *i ));
krb5_error_code krb5_fcc_read_keytype PROTOTYPE((krb5_ccache id , krb5_keytype *k ));
krb5_error_code krb5_fcc_read_int PROTOTYPE((krb5_ccache id , int *i ));
krb5_error_code krb5_fcc_read_bool PROTOTYPE((krb5_ccache id , krb5_boolean *b ));
krb5_error_code krb5_fcc_read_times PROTOTYPE((krb5_ccache id , krb5_ticket_times *t ));
krb5_error_code krb5_fcc_read_flags PROTOTYPE((krb5_ccache id , krb5_flags *f ));

/* fcc_reslv.c */
krb5_error_code krb5_fcc_resolve PROTOTYPE((krb5_ccache *id , char *residual ));

/* fcc_retrv.c */
krb5_error_code krb5_fcc_retrieve PROTOTYPE((krb5_ccache id , krb5_flags whichfields , krb5_creds *mcreds , krb5_creds *creds ));

/* fcc_sseq.c */
krb5_error_code krb5_fcc_start_seq_get PROTOTYPE((krb5_ccache id , krb5_cc_cursor *cursor ));

/* fcc_store.c */
krb5_error_code krb5_fcc_store PROTOTYPE((krb5_ccache id , krb5_creds *creds ));

/* fcc_skip.c */
krb5_error_code krb5_fcc_skip_principal PROTOTYPE((krb5_ccache id ));

/* fcc_sflags.c */
krb5_error_code krb5_fcc_set_flags PROTOTYPE((krb5_ccache id , krb5_flags flags ));

/* fcc_ops.c */

/* fcc_write.c */
krb5_error_code krb5_fcc_write PROTOTYPE((krb5_ccache id , krb5_pointer buf , int len ));
krb5_error_code krb5_fcc_store_principal PROTOTYPE((krb5_ccache id , krb5_principal princ ));
krb5_error_code krb5_fcc_store_keyblock PROTOTYPE((krb5_ccache id , krb5_keyblock *keyblock ));
krb5_error_code krb5_fcc_store_data PROTOTYPE((krb5_ccache id , krb5_data *data ));
krb5_error_code krb5_fcc_store_int32 PROTOTYPE((krb5_ccache id , krb5_int32 *i ));
krb5_error_code krb5_fcc_store_keytype PROTOTYPE((krb5_ccache id , krb5_keytype *k ));
krb5_error_code krb5_fcc_store_int PROTOTYPE((krb5_ccache id , int *i ));
krb5_error_code krb5_fcc_store_bool PROTOTYPE((krb5_ccache id , krb5_boolean *b ));
krb5_error_code krb5_fcc_store_times PROTOTYPE((krb5_ccache id , krb5_ticket_times *t ));

/* fcc_test.c */
void init_test_cred PROTOTYPE((void ));


#endif /* KRB5_FCC_PROTO__ */

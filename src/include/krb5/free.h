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
 * definitions for free routines
 */

#include <krb5/copyright.h>

#ifndef KRB5_FREE__
#define KRB5_FREE__

/* to keep lint happy */
#define xfree(val) free((char *)(val))

#define krb5_free_data(val) { xfree((val)->data); xfree(val);}

#define krb5_free_ap_rep_enc_part xfree

/* krb5_free.c */
void krb5_free_checksum PROTOTYPE((krb5_checksum *));
void krb5_free_keyblock PROTOTYPE((krb5_keyblock *));
void krb5_free_principal PROTOTYPE((krb5_principal ));
void krb5_free_authenticator PROTOTYPE((krb5_authenticator *));
void krb5_free_address PROTOTYPE((krb5_address **));
void krb5_free_authdata PROTOTYPE((krb5_authdata **));
void krb5_free_enc_tkt_part PROTOTYPE((krb5_enc_tkt_part *));
void krb5_free_ticket PROTOTYPE((krb5_ticket *));
void krb5_free_as_req PROTOTYPE((krb5_as_req *));
void krb5_free_kdc_rep PROTOTYPE((krb5_kdc_rep *));
void krb5_free_last_req PROTOTYPE((krb5_last_req_entry **));
void krb5_free_enc_kdc_rep_part PROTOTYPE((krb5_enc_kdc_rep_part *));
void krb5_free_error PROTOTYPE((krb5_error *));
void krb5_free_ap_req PROTOTYPE((krb5_ap_req *));
void krb5_free_ap_rep PROTOTYPE((krb5_ap_rep *));
void krb5_free_tgs_req PROTOTYPE((krb5_tgs_req *));
void krb5_free_real_tgs_req PROTOTYPE((krb5_real_tgs_req *));
void krb5_free_tgs_req_enc_part PROTOTYPE((krb5_tgs_req_enc_part *));
void krb5_free_safe PROTOTYPE((krb5_safe *));
void krb5_free_priv PROTOTYPE((krb5_priv *));
void krb5_free_priv_enc_part PROTOTYPE((krb5_priv_enc_part *));
void krb5_free_creds PROTOTYPE((krb5_creds *));

#endif /* KRB5_FREE__ */

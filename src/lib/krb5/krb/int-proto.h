/*
 * lib/krb5/krb/int-proto.h
 *
 * Copyright 1990,1991 the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Function prototypes for Kerberos V5 library internal functions.
 */


#ifndef KRB5_INT_FUNC_PROTO__
#define KRB5_INT_FUNC_PROTO__

krb5_error_code krb5_tgtname
    	(krb5_context context,
	           const krb5_data *,
	           const krb5_data *,
	           krb5_principal *);

krb5_error_code krb5_libdefault_boolean
        (krb5_context, const krb5_data *, const char *,
			int *);

krb5_error_code krb5_ser_authdata_init (krb5_context);
krb5_error_code krb5_ser_address_init (krb5_context);
krb5_error_code krb5_ser_authenticator_init (krb5_context);
krb5_error_code krb5_ser_checksum_init (krb5_context);
krb5_error_code krb5_ser_keyblock_init (krb5_context);
krb5_error_code krb5_ser_principal_init (krb5_context);
krb5_error_code krb5_ser_authdata_context_init (krb5_context);

krb5_error_code
krb5_preauth_supply_preauth_data(krb5_context context,
				 krb5_gic_opt_ext *opte,
				 const char *attr,
				 const char *value);

krb5_error_code
krb5_get_cred_from_kdc_opt(krb5_context context, krb5_ccache ccache,
			   krb5_creds *in_cred, krb5_creds **out_cred,
			   krb5_creds ***tgts, int kdcopt);

krb5_error_code
krb5_get_credentials_core(krb5_context context, krb5_flags options,
			  krb5_creds *in_creds, krb5_creds *mcreds,
			  krb5_flags *fields);

#define in_clock_skew(date, now) (labs((date)-(now)) < context->clockskew)

#define IS_TGS_PRINC(c, p)						\
    (krb5_princ_size((c), (p)) == 2 &&					\
     data_eq_string(*krb5_princ_component((c), (p), 0), KRB5_TGS_NAME))

krb5_error_code
krb5_get_cred_via_tkt_ext (krb5_context context, krb5_creds *tkt,
			   krb5_flags kdcoptions, krb5_address *const *address,
			   krb5_pa_data **in_padata,
			   krb5_creds *in_cred,
			   krb5_error_code (*gcvt_fct)(krb5_context,
						       krb5_keyblock *,
						       krb5_kdc_req *,
						       void *),
			   void *gcvt_data,
			   krb5_pa_data ***out_padata,
			   krb5_pa_data ***enc_padata,
			   krb5_creds **out_cred,
			   krb5_keyblock **out_subkey);

#endif /* KRB5_INT_FUNC_PROTO__ */


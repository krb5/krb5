/*
 * include/krb5/preauth.h
 *
 * (Originally written by Glen Machin at Sandia Labs.)
 *
 * Copyright 1992, 1995 by the Massachusetts Institute of Technology.
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
 * Sandia National Laboratories also makes no representations about the 
 * suitability of the modifications, or additions to this software for 
 * any purpose.  It is provided "as is" without express or implied warranty.
 * 
 */
#ifndef KRB5_PREAUTH__
#define KRB5_PREAUTH__

#define MAX_PREAUTH_SIZE 20	/* Maximum size of PreAuthenticator.data */

/*
 * Note: these typedefs are subject to change.... [tytso:19920903.1609EDT]
 */
typedef krb5_error_code (krb5_preauth_obtain_proc)
    KRB5_PROTOTYPE((krb5_context, krb5_principal client, krb5_address **src_addr,
	       krb5_pa_data *pa_data));

typedef krb5_error_code (krb5_preauth_verify_proc)
    KRB5_PROTOTYPE((krb5_context, krb5_principal client, krb5_address **src_addr,
	       krb5_data *data));

typedef struct _krb5_preauth_ops {
    krb5_magic magic;
    int     type;
    int	flags;
    krb5_preauth_obtain_proc	*obtain;
    krb5_preauth_verify_proc	*verify;
} krb5_preauth_ops;

/*
 * Preauthentication property flags
 */
#define KRB5_PREAUTH_FLAGS_ENCRYPT	0x00000001
#define KRB5_PREAUTH_FLAGS_HARDWARE	0x00000002

#if 0
krb5_error_code get_random_padata
    KRB5_PROTOTYPE((krb5_principal client, krb5_address **src_addr,
	       krb5_pa_data *data));

krb5_error_code verify_random_padata
    KRB5_PROTOTYPE((krb5_principal client, krb5_address **src_addr,
	       krb5_data *data));
#endif

krb5_error_code get_unixtime_padata
    KRB5_PROTOTYPE((krb5_context, krb5_principal client, 
	       krb5_address **src_addr, krb5_pa_data *data));

krb5_error_code verify_unixtime_padata
    KRB5_PROTOTYPE((krb5_context, krb5_principal client, krb5_address **src_addr,
	       krb5_data *data));

krb5_error_code get_securid_padata
    KRB5_PROTOTYPE((krb5_context, krb5_principal client, krb5_address **src_addr,
	       krb5_pa_data *data));

krb5_error_code verify_securid_padata
    KRB5_PROTOTYPE((krb5_context, krb5_principal client, krb5_address **src_addr,
	       krb5_data *data));

#endif /* KRB5_PREAUTH__ */

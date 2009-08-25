/*
 * lib/krb5/krb/authdata.h
 *
 * Copyright (C) 2009 by the Massachusetts Institute of Technology.
 * All rights reserved.
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
 * <<< Description >>>
 */
#ifndef KRB_AUTHDATA_H

#define KRB_AUTHDATA_H

#include <k5-int.h>

/* authdata.c */
krb5_error_code
krb5int_authdata_verify(krb5_context context,
			krb5_authdata_context,
			krb5_flags usage,
			const krb5_auth_context *auth_context,
			const krb5_keyblock *key,
			const krb5_ap_req *ap_req);

/* pac.c */
extern krb5plugin_authdata_client_ftable_v0 krb5int_mspac_authdata_client_ftable;

#endif /* !KRB_AUTHDATA_H */


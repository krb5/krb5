/*
 * Copyright (C) 2003 by the Massachusetts Institute of Technology.
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
 */

#ifdef _WIN32
#include "krb5.h"

#ifdef krb524_convert_creds_kdc
#undef krb524_convert_creds_kdc
#endif
#ifdef krb524_init_ets
#undef krb524_init_ets
#endif

int KRB5_CALLCONV_WRONG
krb524_convert_creds_kdc(krb5_context context, krb5_creds *v5creds, struct credentials *v4creds)
{
	return(krb5_524_convert_creds(context,v5creds,v4creds));
}

void KRB5_CALLCONV_WRONG
krb524_init_ets(krb5_context context)
{
	/* no-op */
}
#endif /* _WIN32 */

/*
 * lib/krb5/free/f_cred_enc.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * krb5_free_cred_enc_part()
 */

#include "k5-int.h"

KRB5_DLLIMP void KRB5_CALLCONV 
krb5_free_cred_enc_part(context, val)
    krb5_context context;
    register krb5_cred_enc_part FAR *val;
{
    register krb5_cred_info **temp;
    
    if (val->r_address)
      krb5_free_address(context, val->r_address);
    if (val->s_address)
      krb5_free_address(context, val->s_address);

    if (val->ticket_info) {
	for (temp = val->ticket_info; *temp; temp++) {
	    if ((*temp)->session)
		krb5_free_keyblock(context, (*temp)->session);
	    if ((*temp)->client)
		krb5_free_principal(context, (*temp)->client);
	    if ((*temp)->server)
		krb5_free_principal(context, (*temp)->server);
	    if ((*temp)->caddrs)
		krb5_free_addresses(context, (*temp)->caddrs);
	    krb5_xfree((*temp));
	}
	krb5_xfree(val->ticket_info);
    }
    return;
}

/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 * krb5_copy_ticket()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_copy_tick_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>

#include <krb5/ext-proto.h>

static krb5_error_code
krb5_copy_enc_tkt_part(partfrom, partto)
const krb5_enc_tkt_part *partfrom;
krb5_enc_tkt_part **partto;
{
    krb5_error_code retval;
    krb5_enc_tkt_part *tempto;

    if (!(tempto = (krb5_enc_tkt_part *)malloc(sizeof(*tempto))))
	return ENOMEM;
    *tempto = *partfrom;
    if (retval = krb5_copy_keyblock(partfrom->session,
				    &tempto->session)) {
	xfree(tempto->session);
	xfree(tempto);
	return retval;
    }
    if (retval = krb5_copy_principal(partfrom->client, &tempto->client)) {
	krb5_free_keyblock(tempto->session);
	xfree(tempto);
	return retval;
    }
    tempto->transited = partfrom->transited;
    tempto->transited.tr_contents.data =
	malloc(sizeof(partfrom->transited.tr_contents.length));
    if (!tempto->transited.tr_contents.data) {
	krb5_free_principal(tempto->client);
	krb5_free_keyblock(tempto->session);
	xfree(tempto);
	return retval;
    }
    memcpy((char *)tempto->transited.tr_contents.data,
	   (char *)partfrom->transited.tr_contents.data,
	   partfrom->transited.tr_contents.length);
    if (retval = krb5_copy_addresses(partfrom->caddrs, &tempto->caddrs)) {
	xfree(tempto->transited.tr_contents.data);
	krb5_free_principal(tempto->client);
	krb5_free_keyblock(tempto->session);
	xfree(tempto);
	return retval;
    }
    if (partfrom->authorization_data) {
	if (retval = krb5_copy_authdata(partfrom->authorization_data,
					&tempto->authorization_data)) {
	    krb5_free_addresses(tempto->caddrs);
	    xfree(tempto->transited.tr_contents.data);
	    krb5_free_principal(tempto->client);
	    krb5_free_keyblock(tempto->session);
	    xfree(tempto);
	    return retval;
	}
    }
    *partto = tempto;
    return 0;
}

krb5_error_code
krb5_copy_ticket(from, pto)
const krb5_ticket *from;
krb5_ticket **pto;
{
    krb5_error_code retval;
    krb5_ticket *tempto;
    krb5_data *scratch;

    if (!(tempto = (krb5_ticket *)malloc(sizeof(*tempto))))
	return ENOMEM;
    *tempto = *from;
    if (retval = krb5_copy_principal(from->server, &tempto->server))
	return retval;
    if (retval = krb5_copy_data(&from->enc_part.ciphertext, &scratch)) {
	krb5_free_principal(tempto->server);
	xfree(tempto);
	return retval;
    }
    tempto->enc_part.ciphertext = *scratch;
    xfree(scratch);
    if (retval = krb5_copy_enc_tkt_part(from->enc_part2, &tempto->enc_part2)) {
	xfree(tempto->enc_part.ciphertext.data);
	krb5_free_principal(tempto->server);
	xfree(tempto);
	return retval;
    }	
    *pto = tempto;
    return 0;
}

/*
 * $Source$
 * $Author$
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
 * krb5_copy_authenticator()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_copy_authenticator_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>

#include <krb5/ext-proto.h>

krb5_error_code
krb5_copy_authenticator(authfrom, authto)
const krb5_authenticator *authfrom;
krb5_authenticator **authto;
{
    krb5_error_code retval;
    krb5_authenticator *tempto;

    if (!(tempto = (krb5_authenticator *)malloc(sizeof(*tempto))))
	return ENOMEM;
    *tempto = *authfrom;

    retval = krb5_copy_principal(authfrom->client, &tempto->client);
    if (retval) {
	krb5_xfree(tempto);
	return retval;
    }
    
    if (authfrom->checksum &&
	(retval = krb5_copy_checksum(authfrom->checksum, &tempto->checksum))) {
	    krb5_free_principal(tempto->client);    
	    krb5_xfree(tempto);
	    return retval;
    }
    
    if (authfrom->subkey) {
	    retval = krb5_copy_keyblock(authfrom->subkey, &tempto->subkey);
	    if (retval) {
		    krb5_xfree(tempto->subkey);
		    krb5_free_checksum(tempto->checksum);
		    krb5_free_principal(tempto->client);    
		    krb5_xfree(tempto);
		    return retval;
	    }
    }
    
    if (authfrom->authorization_data) {
		retval = krb5_copy_authdata(authfrom->authorization_data,
				    &tempto->authorization_data);
		if (retval) {
		    krb5_xfree(tempto->subkey);
		    krb5_free_checksum(tempto->checksum);
		    krb5_free_principal(tempto->client);    
		    krb5_free_authdata(tempto->authorization_data);
		    krb5_xfree(tempto);
		    return retval;
		}
    }

    *authto = tempto;
    return 0;
}

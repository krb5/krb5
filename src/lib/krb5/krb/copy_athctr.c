/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
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

    if (retval = krb5_copy_principal(authfrom->client, &tempto->client)) {
	xfree(tempto);
	return retval;
    }
    
    if (authfrom->checksum &&
	(retval = krb5_copy_checksum(authfrom->checksum, &tempto->checksum))) {
	    krb5_free_principal(tempto->client);    
	    xfree(tempto);
	    return retval;
    }
    
    if (authfrom->subkey) {
	    if (retval = krb5_copy_keyblock(authfrom->subkey,
					    &tempto->subkey)) {
		    xfree(tempto->subkey);
		    krb5_free_checksum(tempto->checksum);
		    krb5_free_principal(tempto->client);    
		    xfree(tempto);
		    return retval;
	    }
    }
    
    *authto = tempto;
    return 0;
}

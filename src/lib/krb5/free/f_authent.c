/*
 * lib/krb5/free/f_authent.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * krb5_free_authenticator()
 */

#include "k5-int.h"

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_authenticator(context, val)
    krb5_context context;
    krb5_authenticator FAR *val;
{
    if (val->checksum)
	krb5_free_checksum(context, val->checksum);
    if (val->client)
	krb5_free_principal(context, val->client);
    if (val->subkey)
	krb5_free_keyblock(context, val->subkey);
    if (val->authorization_data)        
       krb5_free_authdata(context, val->authorization_data);
    krb5_xfree(val);
    return;
}

/*
 * lib/krb5/free/f_kdc_req.c
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
 * krb5_free_kdc_req()
 */

#include "k5-int.h"

void
krb5_free_kdc_req(context, val)
    krb5_context context;
    krb5_kdc_req *val;
{
    if (val->padata)
	krb5_free_pa_data(context, val->padata);
    if (val->client)
	krb5_free_principal(context, val->client);
    if (val->server)
	krb5_free_principal(context, val->server);
    if (val->etype)
	krb5_xfree(val->etype);
    if (val->addresses)
	krb5_free_addresses(context, val->addresses);
    if (val->authorization_data.ciphertext.data)
	krb5_xfree(val->authorization_data.ciphertext.data);
    if (val->unenc_authdata)
	krb5_free_authdata(context, val->unenc_authdata);
    if (val->second_ticket)
	krb5_free_tickets(context, val->second_ticket);
    krb5_xfree(val);
    return;
}

/*
 * lib/krb5/asn.1/edat2kedat.c
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
 * Glue between Kerberos version and ISODE 6.0 version of structures.
 */


#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_enc_data *
KRB5_EncryptedData2krb5_enc_data(val, error)
register const struct type_KRB5_EncryptedData *val;
register int *error;
{
    register krb5_enc_data *retval;
    krb5_data *temp;

    retval = (krb5_enc_data *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    memset(retval, 0, sizeof(*retval));

    temp = qbuf2krb5_data(val->cipher, error);
    if (temp) {
	retval->ciphertext = *temp;
	krb5_xfree(temp);
    } else {
	krb5_xfree(retval);
	return(0);
    }
    if (val->optionals & opt_KRB5_EncryptedData_kvno)
	retval->kvno = val->kvno;
    retval->etype = val->etype;
    return(retval);
}

/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Glue between Kerberos version and ISODE 6.0 version of structures.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_edat2kedat_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include "KRB5-types.h"
#include "asn1glue.h"
#include "asn1defs.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_enc_data *
KRB5_EncryptedData2krb5_enc_data(val, error)
const register struct type_KRB5_EncryptedData *val;
register int *error;
{
    register krb5_enc_data *retval;
    krb5_data *temp;

    retval = (krb5_enc_data *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    temp = qbuf2krb5_data(val->cipher, error);
    if (temp) {
	retval->ciphertext = *temp;
	xfree(temp);
    } else {
	xfree(retval);
	return(0);
    }
    if (val->optionals & opt_KRB5_EncryptedData_kvno)
	retval->kvno = val->kvno;
    retval->etype = val->etype;
    return(retval);
}

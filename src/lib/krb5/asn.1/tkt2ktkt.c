/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Glue between Kerberos version and ISODE 6.0 version of structures.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_tkt2ktkt_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_ticket *
KRB5_Ticket2krb5_ticket(val, error)
const register struct type_KRB5_Ticket *val;
register int *error;
{
    register krb5_ticket *retval;
    krb5_enc_data *temp;

    retval = (krb5_ticket *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));


    retval->server = KRB5_PrincipalName2krb5_principal(val->sname,
						       val->realm,
						       error);
    if (!retval->server) {
	xfree(retval);
	return(0);
    }

    temp = KRB5_EncryptedData2krb5_enc_data(val->enc__part, error);
    if (temp) {
	retval->enc_part = *temp;
	xfree(temp);
    } else {
	krb5_free_ticket(retval);
	return(0);
    }
    return(retval);
}

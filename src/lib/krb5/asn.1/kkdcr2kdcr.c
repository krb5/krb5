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
static char rcsid_kkdcr2kdcr_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

#include <isode/psap.h>
#include "KRB5-types.h"
#include "asn1glue.h"
#include "asn1defs.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

struct type_KRB5_TGS__REP *
krb5_kdc_rep2KRB5_KDC__REP(DECLARG(const register krb5_kdc_rep *,val),
			   DECLARG(const krb5_msgtype, type),
			   DECLARG(register int *,error))
OLDDECLARG(const register krb5_kdc_rep *,val)
OLDDECLARG(const krb5_msgtype, type)
OLDDECLARG(register int *,error)
{
    register struct type_KRB5_TGS__REP *retval;

    retval = (struct type_KRB5_TGS__REP *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    retval->pvno = KRB5_PVNO;
    retval->msg__type = type;

    retval->crealm = krb5_data2qbuf(val->client[0]);
    if (!retval->crealm) {
	*error = ENOMEM;
    errout:
	free_KRB5_TGS__REP(retval);
	return(0);
    }
    retval->cname = krb5_principal2KRB5_PrincipalName(val->client, error);
    if (!retval->cname) {
	goto errout;
    }
    retval->ticket = krb5_ticket2KRB5_Ticket(val->ticket, error);
    if (!retval->ticket) {
	goto errout;
    }
    retval->enc__part = krb5_enc_data2KRB5_EncryptedData(&(val->enc_part),
							 error);
    if (!retval->enc__part) {
	goto errout;
    }
    return(retval);
}


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
static char rcsid_ktkt2tkt_c[] =
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

struct type_KRB5_Ticket *
krb5_ticket2KRB5_Ticket(val, error)
const register krb5_ticket *val;
register int *error;
{
    register struct type_KRB5_Ticket *retval;

    retval = (struct type_KRB5_Ticket *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    retval->tkt__vno = KRB5_PVNO;
    retval->srealm = krb5_data2qbuf(val->server[0]);
    if (!retval->srealm) {
	*error = ENOMEM;
    errout:
	free_KRB5_Ticket(retval);
	return(0);
    }
    retval->sname = krb5_principal2KRB5_PrincipalName(val->server, error);
    if (!retval->sname) {
	goto errout;
    }

    retval->etype = val->etype;

    retval->skvno = val->skvno;
    retval->enc__part = krb5_data2qbuf(&(val->enc_part));
    if (!retval->enc__part) {
	*error = ENOMEM;
	goto errout;
    }
    return(retval);
}

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
static char rcsid_ktran2tran_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

struct type_KRB5_TransitedEncoding *
krb5_transited2KRB5_TransitedEncoding(val, error)
const register krb5_transited *val;
register int *error;
{
    register struct type_KRB5_TransitedEncoding *retval;

    retval = (struct type_KRB5_TransitedEncoding *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    retval->tr__type = val->tr_type;
    retval->contents = krb5_data2qbuf(&val->tr_contents);
    if (!retval->contents) {
	*error = ENOMEM;
	free_KRB5_TransitedEncoding(retval);
	return(0);
    }
    return(retval);
}

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
static char rcsid_qbuf2data_c[] =
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

krb5_data *
qbuf2krb5_data(val, error)
const struct qbuf *val;
register int *error;
{
    krb5_data *retval;
    if (qb_pullup(val) != OK) {
    nomem:
	*error = ENOMEM;
	return(0);
    }
    retval = (krb5_data *)xmalloc(sizeof(*retval));
    if (!retval) {
	goto nomem;
    }
    retval->length = val->qb_forw->qb_len;
    retval->data = (char *)xmalloc(val->qb_forw->qb_len);
    if (!retval->data) {
	xfree(retval);
	goto nomem;
    }
    xbcopy(val->qb_forw->qb_data, retval->data,
	  val->qb_forw->qb_len);
    return(retval);
}


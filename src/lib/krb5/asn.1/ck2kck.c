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
static char rcsid_ck2kck_c[] =
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

krb5_checksum *
KRB5_Checksum2krb5_checksum(val, error)
const register struct type_KRB5_Checksum *val;
register int *error;
{
    krb5_checksum *retval;

    if (!val->checksum) {
	*error = EINVAL;
	return(0);
    } else
	*error = 0;
    /* pull up, then play with the single string */
    if (qb_pullup(val->checksum) != OK) {
    nomem:
	*error = ENOMEM;
	return(0);
    }
    retval = (krb5_checksum *)xmalloc(sizeof(*retval));
    if (!retval) {
	goto nomem;
    }
    retval->contents = (unsigned char *)xmalloc(val->checksum->qb_forw->qb_len);
    if (!retval->contents) {
	xfree(retval);
	goto nomem;
    }
    retval->checksum_type = val->cksumtype;
    retval->length = val->checksum->qb_forw->qb_len;
    xbcopy(val->checksum->qb_forw->qb_data, retval->contents,
	  val->checksum->qb_forw->qb_len);
    return(retval);
}

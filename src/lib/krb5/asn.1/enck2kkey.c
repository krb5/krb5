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
static char rcsid_enck2kkey_c[] =
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


krb5_keyblock *
KRB5_EncryptionKey2krb5_keyblock(val, error)
const register struct type_KRB5_EncryptionKey *val;
register int *error;
{
    krb5_keyblock *retval;

    if (!val->session) {
	*error = EINVAL;
	return(0);
    } else
	*error = 0;
    /* pull up, then play with the single string */
    if (qb_pullup(val->session) != OK) {
    nomem:
	*error = ENOMEM;
	return(0);
    }
    retval = (krb5_keyblock *)xmalloc(sizeof(*retval));
    if (!retval) {
	goto nomem;
    }
    retval->contents = (unsigned char *) xmalloc(val->session->qb_forw->qb_len);
    if (!retval->contents) {
	xfree(retval);
	goto nomem;
    }
    retval->keytype = val->keytype;
    retval->length = val->session->qb_forw->qb_len;
    xbcopy(val->session->qb_forw->qb_data, retval->contents,
	  val->session->qb_forw->qb_len);
    return(retval);
}


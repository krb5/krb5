/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
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

#if !defined(lint) && !defined(SABER)
static char rcsid_enck2kkey_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */


krb5_keyblock *
KRB5_EncryptionKey2krb5_keyblock(val, error)
const register struct type_KRB5_EncryptionKey *val;
register int *error;
{
    krb5_keyblock *retval;

    if (!val->keyvalue) {
	*error = EINVAL;
	return(0);
    } else
	*error = 0;
    /* pull up, then play with the single string */
    if (qb_pullup(val->keyvalue) != OK) {
    nomem:
	*error = ENOMEM;
	return(0);
    }
    retval = (krb5_keyblock *)xmalloc(sizeof(*retval));
    if (!retval) {
	goto nomem;
    }
    retval->contents = (unsigned char *) xmalloc(val->keyvalue->qb_forw->qb_len);
    if (!retval->contents) {
	xfree(retval);
	goto nomem;
    }
    retval->keytype = val->keytype;
    retval->length = val->keyvalue->qb_forw->qb_len;
    xbcopy(val->keyvalue->qb_forw->qb_data, retval->contents,
	  val->keyvalue->qb_forw->qb_len);
    return(retval);
}


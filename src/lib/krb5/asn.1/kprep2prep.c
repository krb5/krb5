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
static char rcsid_kprep2prep_c[] =
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

struct type_KRB5_EncKrbPrivPart *
krb5_priv_enc_part2KRB5_EncKrbPrivPart(val, error)
const register krb5_priv_enc_part *val;
register int *error;
{
    register struct type_KRB5_EncKrbPrivPart *retval;
 
    retval = (struct type_KRB5_EncKrbPrivPart *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    retval->user__data = krb5_data2qbuf(&(val->user_data));
    if (!retval->user__data) {
	xfree(retval);
	*error = ENOMEM;
	return(0);
    }
    retval->timestamp = unix2gentime(val->timestamp, error);
    if (!retval->timestamp) {
	free_KRB5_EncKrbPrivPart(retval);
	return(0);
    }
    retval->msec = val->msec;
    retval->addresses = krb5_address2KRB5_HostAddresses(val->addresses, error);
    if (!retval->addresses) {
	free_KRB5_EncKrbPrivPart(retval);
	return(0);
    }

    return(retval);
}

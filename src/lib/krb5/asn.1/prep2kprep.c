/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Glue between Kerberos version and ISODE 6.0 version of structures.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_prep2kprep_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_priv_enc_part *
KRB5_EncKrbPrivPart2krb5_priv_enc_part(val, error)
const register struct type_KRB5_EncKrbPrivPart *val;
register int *error;
{
    register krb5_priv_enc_part *retval;
    krb5_data *temp;

    retval = (krb5_priv_enc_part *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    temp = qbuf2krb5_data(val->user__data, error);
    if (temp) {
	retval->user_data = *temp;
	xfree(temp);
    } else {
	xfree(retval);
	return(0);
    }
    if (val->timestamp) {
	if (!(val->optionals & opt_KRB5_EncKrbPrivPart_usec)) {
	    /* must have usec if we have timestamp */
	    *error = ISODE_50_LOCAL_ERR_BADCOMBO;
	    goto errout;
	}

	retval->timestamp = gentime2unix(val->timestamp, error);
	if (*error) {
	errout:
	    krb5_free_priv_enc_part(retval);
	    return(0);
	}
	retval->usec = val->usec;
    }
    retval->s_address = KRB5_HostAddress2krb5_addr(val->s__address, error);
    if (!retval->s_address) {
	goto errout;
    }
    if (val->r__address) {
	retval->r_address = KRB5_HostAddress2krb5_addr(val->r__address, error);
	if (!retval->r_address) {
	    goto errout;
	}
    }
    if (val->optionals & opt_KRB5_EncKrbPrivPart_seq__number) {
	retval->seq_number = val->seq__number;
    }
    return(retval);
}

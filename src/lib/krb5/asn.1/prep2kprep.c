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
    } else {
	retval->timestamp = 0;
	retval->usec = 0;
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
    } else
	retval->seq_number = 0;
    return(retval);
}

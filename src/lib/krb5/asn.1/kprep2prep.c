/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
static char rcsid_kprep2prep_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

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
    if (val->timestamp) {
	retval->timestamp = unix2gentime(val->timestamp, error);
	if (!retval->timestamp) {
	errout:
	    free_KRB5_EncKrbPrivPart(retval);
	    return(0);
	}
	retval->usec = val->usec;
	retval->optionals |= opt_KRB5_EncKrbPrivPart_usec;
    }
    retval->s__address = krb5_addr2KRB5_HostAddress(val->s_address, error);
    if (!retval->s__address) {
	goto errout;
    }
    if (val->r_address) {
	retval->r__address = krb5_addr2KRB5_HostAddress(val->r_address, error);
	if (!retval->r__address) {
	    goto errout;
	}
    }
    if (val->seq_number) {
	retval->seq__number = val->seq_number;
	retval->optionals |= opt_KRB5_EncKrbPrivPart_seq__number;
    }
    return(retval);
}

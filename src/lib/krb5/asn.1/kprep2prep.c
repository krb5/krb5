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

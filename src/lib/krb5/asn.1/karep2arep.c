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
static char rcsid_karep2arep_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

struct type_KRB5_EncAPRepPart *
krb5_ap_rep_enc_part2KRB5_EncAPRepPart(val, error)
const register krb5_ap_rep_enc_part *val;
register int *error;
{
    register struct type_KRB5_EncAPRepPart *retval;
 
    retval = (struct type_KRB5_EncAPRepPart *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    retval->ctime = unix2gentime(val->ctime, error);
    if (!retval->ctime) {
	xfree(retval);
	return(0);
    }

    retval->cusec = val->cusec;
    if (val->subkey) {
	retval->subkey = krb5_keyblock2KRB5_EncryptionKey(val->subkey, error);
	if (!retval->subkey) {
	    free_KRB5_EncAPRepPart(retval);
	    return 0;
	}
    }
    if (val->seq_number) {
	retval->seq__number = val->seq_number;
	retval->optionals |= opt_KRB5_EncAPRepPart_seq__number;
    }
    return(retval);
}

/*
 * lib/krb5/asn.1/karep2arep.c
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


#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

struct type_KRB5_EncAPRepPart *
krb5_ap_rep_enc_part2KRB5_EncAPRepPart(val, error)
register const krb5_ap_rep_enc_part *val;
register int *error;
{
    register struct type_KRB5_EncAPRepPart *retval;
 
    retval = (struct type_KRB5_EncAPRepPart *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    memset(retval, 0, sizeof(*retval));

    retval->ctime = unix2gentime(val->ctime, error);
    if (!retval->ctime) {
	krb5_xfree(retval);
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

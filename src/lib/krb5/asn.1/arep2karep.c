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
static char rcsid_arep2karep_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_ap_rep_enc_part *
KRB5_EncAPRepPart2krb5_ap_rep_enc_part(val, error)
const register struct type_KRB5_EncAPRepPart *val;
register int *error;
{
    register krb5_ap_rep_enc_part *retval;
 
    retval = (krb5_ap_rep_enc_part *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    /* xbzero not needed, since structure is simple */
    /* xbzero(retval, sizeof(*retval)); */

    retval->ctime = gentime2unix(val->ctime, error);
    if (*error) {
	xfree(retval);
	return(0);
    }	
    retval->cmsec = val->cmsec;

    return(retval);
}

/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Given a tgt, and a target cred, get it.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_gcvtgt_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

/*
 * Warning: here lie eggs in search of their chickens, and chickens in
 * search of the eggs they hatched from.
 *
 * This code is incomplete.
 *
 * Don't even think about finishing it until this C&E problem is resolved.
 * 
 */
    

krb5_error_code
krb5_get_cred_via_tgt (tgt, cred)
    krb5_creds *tgt;		/* IN */
    krb5_creds *cred		/* IN OUT */
{
    krb5_tgs_req_enc_part tgs_enc;
    krb5_tgs_req tgs;
    krb5_ap_req ap;
    
    /* tgt->client must be equal to cred->client */
    /* tgt->server must be equal to krbtgt/realmof(cred->client) */

    /*
     * Construct a KRB_TGS_REQ.
     *
     * The first thing is an ap_req
     */
    code = krb5_mk_req_int (/* flags */, /* checksum */, /* times */,
			    /* flags */, &tgt, &ap);
    if (code != 0) goto out;

    abort();
    
out:
    return code;
}

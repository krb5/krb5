/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Get credentials from some KDC somewhere, possibly accumulating tgts
 * along the way.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_gcfkdc_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>

/*
 * Retrieve credentials for principal creds->client,
 * server creds->server, ticket flags creds->ticket_flags, possibly
 * second_ticket if needed by ticket_flags.
 * 
 * Credentials are requested from the KDC for the server's realm.  Any
 * TGT credentials obtained in the process of contacting the KDC are
 * returned in an array of credentials; tgts is filled in to point to an
 * array of pointers to credential structures (if no TGT's were used, the
 * pointer is zeroed).
 * 
 * The returned credentials are NOT cached.
 *
 * This routine should not be called if the credentials are already in
 * the cache.
 * 
 * If credentials are obtained, creds is filled in with the results;
 * creds->ticket and creds->keyblock->key are set to allocated storage,
 * which should be freed by the caller when finished.
 * 
 * returns errors, system errors.
 */

krb5_error_code
krb5_get_cred_from_kdc (ccache, cred, tgts)
    krb5_ccache ccache;
    krb5_creds *cred;
    krb5_creds ***tgts;
{
    krb5_creds tgt, tgtq;
    krb5_error_code retval;
    
    /*
     * we know that the desired credentials aren't in the cache yet.
     *
     * To get them, we first need a tgt for the realm of the server.
     */

    /* first, we see if we have a shortcut path to the server's realm. */
    
    /*
     * look for ticket with:
     * client == cred->client,
     * server == "krbtgt/realmof(cred->server)@realmof(cred->client)"
     */

    /*
     * XXX we're sharing some substructure here, which is
     * probably not safe...
     */
    tgtq.client = cred->client;

    if (retval = krb5_tgtname(cred->server, cred->client, &tgtq.server))
	return retval;
    /* go find it.. */
    retval = krb5_cc_retrieve_cred (ccache,
				    KRB5_CF_CLIENT|KRB5_CF_SERVER,
				    &tgtq,
				    &tgt);
    krb5_free_principal(tgtq.server);

    if (retval != 0) {
	if (retval != KRB5_CC_NOTFOUND)
	    goto out;
	/* nope; attempt to get tgt */
    }
    /* got tgt! */
    retval = krb5_get_cred_via_tgt(&tgt, cred);
out:
    /* XXX what about tgts? */
    return retval;
}

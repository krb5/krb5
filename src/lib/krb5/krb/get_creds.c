/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_get_credentials()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_get_creds_c[] =
"$Id$";
#endif	/* !lint & !SABER */


/*
 Attempts to use the credentials cache or TGS exchange to get an additional
 ticket for the
 client identified by creds->client, the server identified by
 creds->server, with options options, expiration date specified in
 creds->times.endtime (0 means as long as possible), session key type
 specified in creds->keyblock.keytype (if non-zero)

 Any returned ticket and intermediate ticket-granting tickets are
 stored in ccache.

 returns errors from encryption routines, system errors
 */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

krb5_error_code
krb5_get_credentials(options, ccache, creds)
const krb5_flags options;
krb5_ccache ccache;
krb5_creds *creds;
{
    krb5_error_code retval, rv2;
    krb5_creds **tgts;
    krb5_creds mcreds;
    krb5_flags fields;

    memset((char *)&mcreds, 0, sizeof(mcreds));
    mcreds.server = creds->server;
    mcreds.client = creds->client;
    mcreds.times.endtime = creds->times.endtime;
    mcreds.keyblock = creds->keyblock;
    mcreds.authdata = creds->authdata;
    
    fields = KRB5_TC_MATCH_TIMES /*XXX |KRB5_TC_MATCH_SKEY_TYPE */
	| KRB5_TC_MATCH_AUTHDATA;

    if (options & KRB5_GC_USER_USER) {
	/* also match on identical 2nd tkt and tkt encrypted in a
	   session key */
	fields |= KRB5_TC_MATCH_2ND_TKT|KRB5_TC_MATCH_IS_SKEY;
	mcreds.is_skey = TRUE;
    }

    retval = krb5_cc_retrieve_cred(ccache, fields, &mcreds, creds);
    if (retval != KRB5_CC_NOTFOUND || options & KRB5_GC_CACHED)
	return retval;

    if (options & KRB5_GC_USER_USER && !creds->second_ticket.length)
	return KRB5_NO_2ND_TKT;

    retval = krb5_get_cred_from_kdc(ccache, creds, &tgts);
    if (tgts) {
	register int i = 0;
	while (tgts[i]) {
	    if (rv2 = krb5_cc_store_cred(ccache, tgts[i])) {
		retval = rv2;
		break;
	    }
	    i++;
	}
	krb5_free_tgt_creds(tgts);
    }
    if (!retval)
	retval = krb5_cc_store_cred(ccache, creds);
    return retval;
}

/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for krb5_scc_retrieve.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_scc_retrv_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>

#include "scc.h"

#define set(bits) (whichfields & bits)
#define flags_match(a,b) (a & b == a)

static krb5_boolean
times_match(t1, t2)
register const krb5_ticket_times *t1;
register const krb5_ticket_times *t2;
{
    if (t1->renew_till) {
	if (t1->renew_till > t2->renew_till)
	    return FALSE;		/* this one expires too late */
    }
    if (t1->endtime) {
	if (t1->endtime > t2->endtime)
	    return FALSE;		/* this one expires too late */
    }
    /* only care about expiration on a times_match */
    return TRUE;
}

static krb5_boolean
times_match_exact (t1, t2)
    register const krb5_ticket_times *t1, *t2;
{
    return (t1->authtime == t2->authtime
	    && t1->starttime == t2->starttime
	    && t1->endtime == t2->endtime
	    && t1->renew_till == t2->renew_till);
}

static krb5_boolean
standard_fields_match(mcreds, creds)
register const krb5_creds *mcreds, *creds;
{
    return (krb5_principal_compare(mcreds->client,creds->client) &&
	    krb5_principal_compare(mcreds->server,creds->server));
}

static krb5_boolean
authdata_match(mdata, data)
    krb5_authdata *const *mdata, *const *data;
{
    const krb5_authdata *mdatap, *datap;

    if (mdata == data)
	return TRUE;

    if (mdata == NULL)
	return *data == NULL;

    if (data == NULL)
	return *mdata == NULL;

    while ((mdatap = *mdata)
	   && (datap = *data)
	   && mdatap->ad_type == datap->ad_type
	   && mdatap->length == datap->length
	   && !memcmp ((char *) mdatap->contents, (char *) datap->contents,
		       datap->length)) {
	mdata++;
	data++;
    }

    return !*mdata && !*data;
}

/*
 * Effects:
 * Searches the file cred cache is for a credential matching mcreds,
 * with the fields specified by whichfields.  If one if found, it is
 * returned in creds, which should be freed by the caller with
 * krb5_free_credentials().
 * 
 * The fields are interpreted in the following way (all constants are
 * preceded by KRB5_TC_).  MATCH_IS_SKEY requires the is_skey field to
 * match exactly.  MATCH_TIMES requires the requested lifetime to be
 * at least as great as that specified; MATCH_TIMES_EXACT requires the
 * requested lifetime to be exactly that specified.  MATCH_FLAGS
 * requires only the set bits in mcreds be set in creds;
 * MATCH_FLAGS_EXACT requires all bits to match.
 *
 * Errors:
 * system errors
 * permission errors
 * KRB5_CC_NOMEM
 */
krb5_error_code
krb5_scc_retrieve(id, whichfields, mcreds, creds)
   krb5_ccache id;
   krb5_flags whichfields;
   krb5_creds *mcreds;
   krb5_creds *creds;
{
     /* This function could be considerably faster if it kept indexing */
     /* information.. sounds like a "next version" idea to me. :-) */

     krb5_cc_cursor cursor;
     krb5_error_code kret;
     krb5_creds fetchcreds;

     kret = krb5_scc_start_seq_get(id, &cursor);
     if (kret != KRB5_OK)
	  return kret;

     while ((kret = krb5_scc_next_cred(id, &cursor, &fetchcreds)) == KRB5_OK) {
	  if (standard_fields_match(mcreds, &fetchcreds)
	      &&
	      (! set(KRB5_TC_MATCH_IS_SKEY) ||
	       mcreds->is_skey == fetchcreds.is_skey)
	      &&
	      (! set(KRB5_TC_MATCH_FLAGS_EXACT) ||
	       mcreds->ticket_flags == fetchcreds.ticket_flags)
	      &&
	      (! set(KRB5_TC_MATCH_FLAGS) ||
	       flags_match(mcreds->ticket_flags, fetchcreds.ticket_flags))
	      &&
	      (! set(KRB5_TC_MATCH_TIMES_EXACT) ||
	       times_match_exact(&mcreds->times, &fetchcreds.times))
	      &&
	      (! set(KRB5_TC_MATCH_TIMES) ||
	       times_match(&mcreds->times, &fetchcreds.times))
	      &&
	      (! set(KRB5_TC_MATCH_AUTHDATA) ||
	       authdata_match (mcreds->authdata, fetchcreds.authdata))
	      )
	  {
	       krb5_scc_end_seq_get(id, &cursor);
	       *creds = fetchcreds;
	       return KRB5_OK;
	  }

	  /* This one doesn't match */
	  /* XXX krb5_free_credentials(creds); */
     }

     /* If we get here, a match wasn't found */
     krb5_scc_end_seq_get(id, &cursor);
     return KRB5_CC_NOTFOUND;
}

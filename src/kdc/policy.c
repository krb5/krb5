/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Policy decision routines for KDC.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_policy_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>


#include <krb5/krb5.h>
#include <krb5/kdb.h>

#include "kdc_util.h"

/*ARGSUSED*/
krb5_boolean
against_postdate_policy(fromtime)
krb5_timestamp fromtime;
{
    return FALSE;
}

krb5_boolean
against_flag_policy_as(request)
register krb5_as_req *request;
{
    if (isset(request->kdc_options, KDC_OPT_FORWARDED) ||
	isset(request->kdc_options, KDC_OPT_PROXY) ||
	isset(request->kdc_options, KDC_OPT_RENEW) ||
	isset(request->kdc_options, KDC_OPT_VALIDATE) ||
	isset(request->kdc_options, KDC_OPT_REUSE_SKEY) ||
	isset(request->kdc_options, KDC_OPT_ENC_TKT_IN_SKEY))
	return TRUE;			/* against policy */

    return FALSE;			/* not against policy */
}

krb5_boolean
against_flag_policy_tgs(request)
register krb5_tgs_req *request;
{
    if (((isset(request->kdc_options, KDC_OPT_FORWARDED) ||
	  isset(request->kdc_options, KDC_OPT_FORWARDABLE)) &&
	 !isset(request->header->ticket->enc_part2->flags,
		TKT_FLG_FORWARDABLE)) || /* TGS must be forwardable to get
					    forwarded or forwardable ticket */

	((isset(request->kdc_options, KDC_OPT_PROXY) ||
	  isset(request->kdc_options, KDC_OPT_PROXIABLE)) &&
	 !isset(request->header->ticket->enc_part2->flags,
		TKT_FLG_PROXIABLE)) ||	/* TGS must be proxiable to get
					   proxiable ticket */

	((isset(request->kdc_options, KDC_OPT_ALLOW_POSTDATE) ||
	  isset(request->kdc_options, KDC_OPT_POSTDATED)) &&
	 !isset(request->header->ticket->enc_part2->flags,
		TKT_FLG_MAY_POSTDATE)) || /* TGS must allow postdating to get
					   postdated ticket */
	 
	(isset(request->kdc_options, KDC_OPT_VALIDATE) &&
	 !isset(request->header->ticket->enc_part2->flags,
		TKT_FLG_INVALID)) || 	/* can only validate invalid tix */

	((isset(request->kdc_options, KDC_OPT_RENEW) ||
	  isset(request->kdc_options, KDC_OPT_RENEWABLE)) &&
	 !isset(request->header->ticket->enc_part2->flags,
		TKT_FLG_RENEWABLE))) 	/* can only renew renewable tix */

	return TRUE;			/* against policy */

    return FALSE;			/* XXX not against policy */
}

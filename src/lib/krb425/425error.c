/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * convert error codes from v5 to v4
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_425error_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb.h>
#include <krb5/krb5.h>

int
krb425error(e)
krb5_error_code e;
{
	/*
	 * This is not a very good switch.
	 * Probably needs to be rewritten.
	 */
	switch (e) {
	case 0:				/* No error */
		return(KSUCCESS);

	case KDC_ERR_NAME_EXP:		/* Client's entry in DB expired */
		return(KDC_NAME_EXP);

	case KDC_ERR_SERVICE_EXP:	/* Server's entry in DB expired */
		return(KDC_SERVICE_EXP);

	case KDC_ERR_BAD_PVNO:		/* Requested pvno not supported */
		return(KDC_PKT_VER);

	case KDC_ERR_C_OLD_MAST_KVNO:	/* C's key encrypted in old master */
		return(KDC_P_MKEY_VER);

	case KDC_ERR_S_OLD_MAST_KVNO:	/* S's key encrypted in old master */
		return(KDC_S_MKEY_VER);

	case KDC_ERR_C_PRINCIPAL_UNKNOWN:/* Client not found in Kerberos DB */
	case KDC_ERR_S_PRINCIPAL_UNKNOWN:/* Server not found in Kerberos DB */
		return(KDC_PR_UNKNOWN);

	case KDC_ERR_PRINCIPAL_NOT_UNIQUE:/* Multiple entries in Kerberos DB */
		return(KDC_PR_N_UNIQUE);

	case KDC_ERR_NULL_KEY:		/* The C or S has a null key */
		return(KDC_NULL_KEY);

	case KDC_ERR_CANNOT_POSTDATE:	/* Tkt ineligible for postdating */
	case KDC_ERR_NEVER_VALID:	/* Requested starttime > endtime */
	case KDC_ERR_POLICY:		/* KDC policy rejects request */
	case KDC_ERR_BADOPTION:		/* KDC can't do requested opt. */
	case KDC_ERR_ETYPE_NOSUPP:	/* No support for encryption type */
		return(KDC_GEN_ERR);

	case KRB_AP_ERR_BAD_INTEGRITY:	/* Decrypt integrity check failed */
		return(RD_AP_UNDEC);

	case KRB_AP_ERR_TKT_EXPIRED:	/* Ticket expired */
		return(RD_AP_EXP);

	case KRB_AP_ERR_TKT_NYV:	/* Ticket not yet valid */
		return(RD_AP_NYV);

	case KRB_AP_ERR_REPEAT:		/* Request is a replay */
		return(RD_AP_REPEAT);

	case KRB_AP_ERR_NOT_US:		/* The ticket isn't for us */
		return(RD_AP_NOT_US);

	case KRB_AP_ERR_BADMATCH:	/* Ticket/authenticator don't match */
		return(RD_AP_INCON);

	case KRB_AP_ERR_SKEW:		/* Clock skew too great */
		return(RD_AP_TIME);

	case KRB_AP_ERR_BADADDR:	/* Incorrect net address */
		return(RD_AP_BADD);

	case KRB_AP_ERR_BADVERSION:	/* Protocol version mismatch */
		return(RD_AP_VERSION);

	case KRB_AP_ERR_MSG_TYPE:	/* Invalid message type */
		return(RD_AP_MSG_TYPE);

	case KRB_AP_ERR_MODIFIED:	/* Message stream modified */
		return(RD_AP_MODIFIED);

	case KRB_AP_ERR_BADORDER:	/* Message out of order */
		return(RD_AP_ORDER);

	case KRB_AP_ERR_BADKEYVER:	/* Key version is not available */
	case KRB_AP_ERR_NOKEY:		/* Service key not available */
	case KRB_AP_ERR_MUT_FAIL:	/* Mutual authentication failed */
		return(RD_AP_INCON);

	case KRB_ERR_FIELD_TOOLONG:	/* Field is too long for impl. */
	default:
		return(KFAILURE);
	}
}

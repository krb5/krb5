/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * convert error codes from v5 to v4
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_425error_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb.h>
#include <krb5/krb5.h>

int	krb5_425_error;		/* For people who want to know what */
				/* the *real* error was....  */

int
krb425error(e)
krb5_error_code e;
{
	/*
	 * This is not a very good switch.
	 * Probably needs to be rewritten.
	 */
	krb5_425_error = e;
	switch (e) {
	case 0:				/* No error */
		return(KSUCCESS);

	case KRB5KDC_ERR_NAME_EXP:	/* Client's entry in DB expired */
		return(KDC_NAME_EXP);

	case KRB5KDC_ERR_SERVICE_EXP:	/* Server's entry in DB expired */
		return(KDC_SERVICE_EXP);

	case KRB5KDC_ERR_BAD_PVNO:	/* Requested pvno not supported */
		return(KDC_PKT_VER);

	case KRB5KDC_ERR_C_OLD_MAST_KVNO:/* C's key encrypted in old master */
		return(KDC_P_MKEY_VER);

	case KRB5KDC_ERR_S_OLD_MAST_KVNO:/* S's key encrypted in old master */
		return(KDC_S_MKEY_VER);

	case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:/* Client not found in Kerberos DB */
	case KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN:/* Server not found in Kerberos DB */
		return(KDC_PR_UNKNOWN);

	case KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE:/* Multiple entries in Kerberos DB */
		return(KDC_PR_N_UNIQUE);

	case KRB5KDC_ERR_NULL_KEY:	/* The C or S has a null key */
		return(KDC_NULL_KEY);

	case KRB5KDC_ERR_CANNOT_POSTDATE:/* Tkt ineligible for postdating */
	case KRB5KDC_ERR_NEVER_VALID:	/* Requested starttime > endtime */
	case KRB5KDC_ERR_POLICY:	/* KDC policy rejects request */
	case KRB5KDC_ERR_BADOPTION:	/* KDC can't do requested opt. */
	case KRB5KDC_ERR_ETYPE_NOSUPP:	/* No support for encryption type */
	case KRB5_KDCREP_MODIFIED:	/* KDC reply did not match expectations */
		return(KDC_GEN_ERR);
	case KRB5_KDC_UNREACH:		/* Cannot contact any KDC for requested realm */
	case KRB5_REALM_UNKNOWN:	/* Cannot find KDC for requested realm */
		return(SKDC_CANT);

	case KRB5KRB_AP_ERR_BAD_INTEGRITY: /* Decrypt integrity check failed */
	case KRB5KRB_AP_ERR_TKT_INVALID: /* Ticket has invalid flag set */

		return(RD_AP_UNDEC);

	case KRB5KRB_AP_ERR_TKT_EXPIRED:/* Ticket expired */
		return(RD_AP_EXP);

	case KRB5KRB_AP_ERR_TKT_NYV:	/* Ticket not yet valid */
		return(RD_AP_NYV);

	case KRB5KRB_AP_ERR_REPEAT:		/* Request is a replay */
		return(RD_AP_REPEAT);

	case KRB5KRB_AP_ERR_NOT_US:		/* The ticket isn't for us */
		return(RD_AP_NOT_US);

	case KRB5KRB_AP_ERR_BADMATCH:	/* Ticket/authenticator don't match */
		return(RD_AP_INCON);

	case KRB5KRB_AP_ERR_SKEW:		/* Clock skew too great */
		return(RD_AP_TIME);

	case KRB5KRB_AP_ERR_BADADDR:	/* Incorrect net address */
		return(RD_AP_BADD);

	case KRB5KRB_AP_ERR_BADVERSION:	/* Protocol version mismatch */
		return(RD_AP_VERSION);

	case KRB5KRB_AP_ERR_MSG_TYPE:	/* Invalid message type */
	case KRB5_BADMSGTYPE:		/* Invalid message type specified for encoding */
		return(RD_AP_MSG_TYPE);

	case KRB5KRB_AP_ERR_MODIFIED:	/* Message stream modified */
		return(RD_AP_MODIFIED);

	case KRB5KRB_AP_ERR_BADORDER:	/* Message out of order */
	case KRB5KRB_AP_ERR_BADSEQ:	/* Message out of order */
	case KRB5KRB_AP_ERR_BADDIRECTION: /* Incorrect message direction */
		return(RD_AP_ORDER);

	case KRB5KRB_AP_ERR_BADKEYVER:	/* Key version is not available */
	case KRB5KRB_AP_ERR_NOKEY:		/* Service key not available */
	case KRB5KRB_AP_ERR_MUT_FAIL:	/* Mutual authentication failed */
		return(RD_AP_INCON);

	case KRB5_CC_BADNAME:		/* Credential cache name malformed */
	case KRB5_CC_UNKNOWN_TYPE:	/* Unknown credential cache type */
	case KRB5_CC_TYPE_EXISTS:	/* Credentials cache type is already registered */
	case KRB5_CC_IO:		/* Credentials cache I/O operation failedXXX */
	case KRB5_CC_NOMEM:		/* No more memory to allocate (in credentials cache code) */
		return(TKT_FIL_ACC);
	case KRB5_CC_END:		/* End of credential cache reached */
		return(RET_NOTKT);
	case KRB5_CC_NOTFOUND:		/* Matching credential not found */
		return(NO_TKT_FIL);

	case KRB5_NO_TKT_IN_RLM:	/* Cannot find ticket for requested realm */
		return(AD_NOTGT);
	case KRB5KRB_ERR_FIELD_TOOLONG:	/* Field is too long for impl. */
	default:
		return(KFAILURE);
	}
}

/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Dispatch an incoming packet.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_dispatch_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/asn1.h>
#include <krb5/krb5_err.h>
#include <krb5/isode_err.h>
#include <krb5/kdb.h>
#include "kdc_util.h"

krb5_error_code
dispatch(pkt, from, response)
krb5_data *pkt;
krb5_fulladdr *from;
krb5_data **response;
{

    krb5_error_code retval;
    krb5_as_req *as_req;
    krb5_tgs_req *tgs_req;

    /* decode incoming packet, and dispatch */
    if (pkt->data[0] == 4)		/* XXX old version */
	return(process_v4(pkt));

    /* try TGS_REQ first; they are more common! */

    retval = decode_krb5_tgs_req(pkt, &tgs_req);
    switch (retval) {
    case ISODE_50_LOCAL_ERR_BADDECODE:
	retval = decode_krb5_as_req(pkt, &as_req);
	switch (retval) {
	case 0:
	    retval = process_as_req(as_req, from, response);
	    krb5_free_as_req(as_req);
	    break;
	default:
	    return(retval);
	}
    case 0:
	/* it's now decoded, but still has an encrypted part to work on */
	if (!(retval = decrypt_tgs_req(tgs_req, from)))
	    retval = process_tgs_req(tgs_req, from, response);
	krb5_free_tgs_req(tgs_req);
	break;
    }
    return retval;
}

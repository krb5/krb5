/*
 * kdc/dispatch.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Dispatch an incoming packet.
 */

#include "k5-int.h"
#include <syslog.h>
#include "kdc_util.h"
#include "extern.h"
#include "adm_proto.h"

krb5_error_code
dispatch(pkt, from, portnum, response)
    krb5_data *pkt;
    const krb5_fulladdr *from;
    int		portnum;
    krb5_data **response;
{

    krb5_error_code retval;
    krb5_kdc_req *as_req;

    /* decode incoming packet, and dispatch */

#ifndef NOCACHE
    /* try the replay lookaside buffer */
    if (kdc_check_lookaside(pkt, from, response)) {
	/* a hit! */
	char *name = 0;
	char buf[46];
	krb5_address *a = from->address;

#ifdef HAVE_INET_NTOP
	name = inet_ntop (from->address->addrtype, from->address->contents,
			  buf, sizeof (buf));
#else
	if (addrtype == ADDRTYPE_INET) {
	    struct sockaddr_in *sin
		= (struct sockaddr_in *)from->address->contents;
	    strcpy (buf, inet_ntoa (sin->sin_addr));
	    name = buf;
	}
#endif
	if (name == 0)
	    name = "[unknown address type]";
	krb5_klog_syslog(LOG_INFO,
			 "DISPATCH: repeated (retransmitted?) request from %s port %d, resending previous response",
			 name, portnum);
	return 0;
    }
#endif
    /* try TGS_REQ first; they are more common! */

    if (krb5_is_tgs_req(pkt)) {
	retval = process_tgs_req(pkt, from, portnum, response);
    } else if (krb5_is_as_req(pkt)) {
	if (!(retval = decode_krb5_as_req(pkt, &as_req))) {
	    /*
	     * setup_server_realm() sets up the global realm-specific data
	     * pointer.
	     */
	    if (!(retval = setup_server_realm(as_req->server))) {
		retval = process_as_req(as_req, from, portnum, response);
	    }
	    krb5_free_kdc_req(kdc_context, as_req);
	}
    }
#ifdef KRB5_KRB4_COMPAT
    else if (pkt->data[0] == 4)		/* old version */
	retval = process_v4(pkt, from, portnum, response);
#endif
    else
	retval = KRB5KRB_AP_ERR_MSG_TYPE;
#ifndef NOCACHE
    /* put the response into the lookaside buffer */
    if (!retval)
	kdc_insert_lookaside(pkt, from, *response);
#endif

    return retval;
}

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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

static krb5_int32 last_usec = 0, last_os_random = 0;

static krb5_error_code
process_req(krb5_context, krb5_kdc_req *, krb5_data *,
                          const krb5_fulladdr *, krb5_data **);
krb5_error_code
dispatch(krb5_data *pkt, const krb5_fulladdr *from, krb5_data **response,
	int thread_num)
{

    krb5_error_code retval;
    krb5_kdc_req *req;
    krb5_int32 now, now_usec;
    krb5_context kdc_context = NULL;

    /* decode incoming packet, and dispatch */
    retval = krb5_crypto_us_timeofday(&now, &now_usec);
    if (retval == 0) {
      krb5_int32 usec_difference = now_usec-last_usec;
      krb5_data data;
      if(last_os_random == 0)
	last_os_random = now;
      /* Grab random data from OS every hour*/
      if(now-last_os_random >= 60*60) {
	krb5_c_random_os_entropy(def_kdc_context, 0, NULL);
	last_os_random = now;
      }
      
      data.length = sizeof(krb5_int32);
      data.data = (void *) &usec_difference;
      
      krb5_c_random_add_entropy(def_kdc_context,
				KRB5_C_RANDSOURCE_TIMING, &data);
      last_usec = now_usec;
    }
    /* try TGS_REQ first; they are more common! */

    if (krb5_is_tgs_req(pkt)) {
	if (!(retval = decode_krb5_tgs_req(pkt, &req))) {
	    if (!(retval = setup_server_realm(req->server, &kdc_context,
					    thread_num)))
		retval = process_req(kdc_context, req, pkt, from, response);
	    krb5_free_kdc_req(kdc_context, req);
	}
    } else if (krb5_is_as_req(pkt)) {
	if (!(retval = decode_krb5_as_req(pkt, &req))) {
	    /*
	     * setup_server_realm() sets up the global realm-specific data
	     * pointer.
	     */
	    if (!(retval = setup_server_realm(req->server, &kdc_context,
					    thread_num)))
		retval = process_req(kdc_context, req, pkt, from, response);
	    krb5_free_kdc_req(kdc_context, req);
	}
    }
#ifdef KRB5_KRB4_COMPAT
    else if (pkt->data[0] == 4)		/* old version */
	retval = process_v4(kdc_realmlist[0]->realm_context[thread_num], pkt, from, response);
#endif
    else
	retval = KRB5KRB_AP_ERR_MSG_TYPE;

    return retval;
}

static krb5_error_code
process_req(krb5_context kdc_context, krb5_kdc_req *req, krb5_data *pkt,
            const krb5_fulladdr *from, krb5_data **response)
{
    int retval = 0;

#ifndef NOCACHE
    /* try the replay lookaside buffer */
    if (kdc_check_lookaside(kdc_context, pkt, response)) {
        /* a hit! */
        const char *name = 0;
        char buf[46];

        name = inet_ntop (ADDRTYPE2FAMILY (from->address->addrtype),
                          from->address->contents, buf, sizeof (buf));
        if (name == 0)
            name = "[unknown address type]";
        krb5_klog_syslog(LOG_INFO,
                         "DISPATCH: repeated (retransmitted?) request from %s, resending previous response",
                         name);
        return 0;
    }
    kdc_insert_lookaside_1(kdc_context, pkt);
#endif

    if (krb5_is_tgs_req(pkt))
        retval = process_tgs_req(kdc_context, req, pkt, from, response);
    else
        retval = process_as_req(kdc_context, req, pkt, from, response);

#ifndef NOCACHE
    /* put the response into the lookaside buffer */
    if (!retval) {
	kdc_insert_lookaside_2(kdc_context, pkt, *response);
    } else
	kdc_insert_lookaside_2(kdc_context, pkt, NULL);
#endif

    return retval;
}

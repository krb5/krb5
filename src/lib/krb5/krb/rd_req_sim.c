/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_rd_req_simple()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_rd_req_sim_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/asn1.h>
#include <krb5/ext-proto.h>

/*
 *  Parses a KRB_AP_REQ message, returning its contents.
 * 
 *  server specifies the expected server's name for the ticket.
 * 
 *  sender_addr specifies the address(es) expected to be present in the
 *  ticket.
 * 
 *  A replay cache name derived from the first component of the service name
 *  is used.
 * 
 *  The default key store is consulted to find the service key.
 *
 * authdat isset to point at allocated structures; the caller should
 * free it when finished. 
 * 
 *  returns system errors, encryption errors, replay errors
 */

krb5_error_code
krb5_rd_req_simple(inbuf, server, sender_addr, authdat)
const krb5_data *inbuf;
krb5_const_principal server;
const krb5_address *sender_addr;
krb5_tkt_authent **authdat;
{
    krb5_error_code retval;
    krb5_ap_req *request;
    krb5_rcache rcache;

    if (!krb5_is_ap_req(inbuf))
	return KRB5KRB_AP_ERR_MSG_TYPE;
    if (retval = decode_krb5_ap_req(inbuf, &request)) {
    	switch (retval) {
	case ISODE_50_LOCAL_ERR_BADMSGTYPE:
	    return KRB5KRB_AP_ERR_BADVERSION; 
	default:
	    return(retval);
	}
    }
    if (rcache = (krb5_rcache) malloc(sizeof(*rcache))) {
	if (!(retval = krb5_rc_resolve_type(&rcache, "dfl"))) {
	    char *cachename;
	    extern krb5_deltat krb5_clockskew;

	    if (cachename = malloc(server[1]->length+1+3)) {
		strcpy(cachename, "rc_");
		strncat(cachename, server[1]->data, server[1]->length);
		cachename[server[1]->length+3] = '\0';

		if (!(retval = krb5_rc_resolve(rcache, cachename))) {
		    if (!((retval = krb5_rc_recover(rcache)) &&
			  (retval = krb5_rc_initialize(rcache,
						       krb5_clockskew)))) {
			retval = krb5_rd_req_decoded(request, server,
						     sender_addr, 0,
						     0, 0, rcache, authdat);
			krb5_rc_close(rcache);
		    }
		}
		free(cachename);
	    } else
		retval = ENOMEM;
	}
	xfree(rcache);
    } else
	retval = ENOMEM;
    krb5_free_ap_req(request);

    return retval;
}


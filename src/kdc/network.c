/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 * Network code for Kerberos v5 KDC.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_network_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/osconf.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <krb5/kdb.h>
#include <com_err.h>
#include "kdc_util.h"
#include "extern.h"
#include "kdc5_err.h"

#ifdef KRB5_USE_INET
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

extern char *krb5_kdc_udp_portname;
extern int errno;

static int udp_port_fd = -1;

krb5_error_code
setup_network(prog)
const char *prog;
{
    struct servent *sp;
    struct sockaddr_in sin;
    krb5_error_code retval;

    sp = getservbyname(krb5_kdc_udp_portname, "udp");
    if (!sp) {
	com_err(prog, 0, "%s/udp service unknown\n",
		krb5_kdc_udp_portname);
	return KDC5_NOPORT;
    }
    if ((udp_port_fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
	retval = errno;
	com_err(prog, 0, "Cannot create server socket");
	return retval;
    }
    memset((char *)&sin, 0, sizeof(sin));
    sin.sin_port = sp->s_port;
    if (bind(udp_port_fd, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
	retval = errno;
	com_err(prog, 0, "Cannot bind server socket");
	return retval;
    }
    return 0;
}

krb5_error_code
listen_and_process(prog)
const char *prog;
{
    int cc, saddr_len;
    krb5_error_code retval;
    struct sockaddr_in saddr;
    krb5_fulladdr faddr;
    krb5_address addr;
    krb5_data request;
    krb5_data *response;
    char pktbuf[MAX_DGRAM_SIZE];

    if (udp_port_fd == -1)
	return KDC5_NONET;
    
    while (!signal_requests_exit) {
	saddr_len = sizeof(saddr);
	if ((cc = recvfrom(udp_port_fd, pktbuf, sizeof(pktbuf), 0,
			   (struct sockaddr *)&saddr, &saddr_len)) != -1) {
	    if (!cc)
		continue;		/* zero-length packet? */
	    request.length = cc;
	    request.data = pktbuf;
	    faddr.port = ntohs(saddr.sin_port);
	    faddr.address = &addr;
	    addr.addrtype = ADDRTYPE_INET;
	    addr.length = 4;
	    /* this address is in net order */
	    addr.contents = (krb5_octet *) &saddr.sin_addr;
	    if (retval = dispatch(&request, &faddr, &response)) {
		com_err(prog, retval, "while dispatching");
		continue;
	    }
	    if ((cc = sendto(udp_port_fd, response->data, response->length, 0,
			     (struct sockaddr *)&saddr, saddr_len)) != response->length) {
		switch (cc) {
		case -1:
		    com_err(prog, errno, "while sending reply to %s/%d",
			    inet_ntoa(saddr.sin_addr), ntohs(saddr.sin_port));
		    break;
		default:
		    com_err(prog, 0, "short reply write %d vs %d\n",
			    response->length, cc);
		    break;
		}
	    }
	    krb5_free_data(response);
	} else {
	    switch (errno) {
	    case EINTR:
		continue;
	    default:
		com_err(prog, errno, "while receiving from network");
		break;
	    }
	}
	
    }
    return 0;
}

krb5_error_code
closedown_network(prog)
const char *prog;
{
    if (udp_port_fd == -1)
	return KDC5_NONET;

    (void) close(udp_port_fd);
    udp_port_fd = -1;
    return 0;
}

#endif /* INET */

/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
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
#include <stdio.h>
#include <krb5/libos-proto.h>
#include <errno.h>
#include <com_err.h>
#include <krb5/kdb.h>
#include "kdc_util.h"
#include "extern.h"

#ifdef KRB5_USE_INET
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

extern char *krb5_kdc_udp_portname;
extern int errno;

static int udp_port_fd = -1;

void
setup_network()
{
    struct servent *sp;
    struct sockaddr_in sin;

    sp = getservbyname(krb5_kdc_udp_portname, "udp");
    if (!sp) {
	fprintf(stderr, "XXX: %s/udp service unknown\n",
		krb5_kdc_udp_portname);
	return;
    }
    if ((udp_port_fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
	com_err("XXX", errno, "when creating server socket");
	return;
    }
    bzero((char *)&sin, sizeof(sin));
    sin.sin_port = sp->s_port;
    if (bind(udp_port_fd, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
	com_err("XXX", errno, "when binding server socket");
	return;
    }
    return;
}

void
listen_and_process()
{
    int cc, saddr_len;
    krb5_error_code retval;
    struct sockaddr_in saddr;
    krb5_fulladdr faddr;
    krb5_address addr;
    krb5_data request;
    krb5_data *response;
    char pktbuf[MAX_DGRAM_SIZE];

    if (udp_port_fd == -1) {
	fprintf(stderr, "Network not setup\n");
	return;
    }
    
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
	    addr.contents = (krb5_octet *) &saddr.sin_addr; /* XXX net order or host order? */
	    if (retval = dispatch(&request, &faddr, &response)) {
		com_err("XXX", retval, "while dispatching");
		continue;
	    }
	    if ((cc = sendto(udp_port_fd, response->data, response->length, 0,
			     (struct sockaddr *)&saddr, saddr_len)) != response->length) {
		switch (cc) {
		case -1:
		    com_err("XXX", errno, "while sending reply to %s/%d",
			    inet_ntoa(saddr.sin_addr), ntohs(saddr.sin_port));
		    break;
		default:
		    fprintf(stderr, "short reply write %d vs %d\n",
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
		com_err("XXX", errno, "while receiving from network");
		break;
	    }
	}
	
    }
    
}

void
closedown_network()
{
    if (udp_port_fd == -1) {
	fprintf(stderr, "Network not setup\n");
	return;
    }
    (void) close(udp_port_fd);
    udp_port_fd = -1;
    return;
}

#endif /* INET */

/*
 * kdc/network.c
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Network code for Kerberos v5 KDC.
 */

#include "k5-int.h"
#include "com_err.h"
#include "kdc_util.h"
#include "extern.h"
#include "kdc5_err.h"

#include <ctype.h>
#ifdef HAVE_NETINET_IN_H
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <arpa/inet.h>

extern int errno;

static int *udp_port_fds = (int *) NULL;
static u_short *udp_port_nums = (u_short *) NULL;
static int n_udp_ports = 0;
static int max_udp_ports = 0;
static fd_set select_fds;
static int select_nfds;

#define safe_realloc(p,n) ((p)?(realloc(p,n)):(malloc(n)))

static krb5_error_code add_port(port)
     u_short port;
{
    int	i;
    int *new_fds;
    u_short *new_ports;
    int new_max;

    for (i=0; i < n_udp_ports; i++) {
	if (udp_port_nums[i] == port)
	    return 0;
    }
    
    if (n_udp_ports >= max_udp_ports) {
	new_max = max_udp_ports + 10;
	new_fds = safe_realloc(udp_port_fds, new_max * sizeof(int));
	if (new_fds == 0)
	    return ENOMEM;
	udp_port_fds = new_fds;

	new_ports = safe_realloc(udp_port_nums, new_max * sizeof(u_short));
	if (new_ports == 0)
	    return ENOMEM;
	udp_port_nums = new_ports;

	max_udp_ports = new_max;
    }
	
    udp_port_nums[n_udp_ports++] = port;
    return 0;
}
#undef safe_realloc

krb5_error_code
setup_network(prog)
const char *prog;
{
    struct sockaddr_in sin;
    krb5_error_code retval;
    u_short port;
    char *cp;
    int i;

    FD_ZERO(&select_fds);
    select_nfds = 0;
    memset((char *)&sin, 0, sizeof(sin));

    /* Handle each realm's ports */
    for (i=0; i<kdc_numrealms; i++) {
	cp = kdc_realmlist[i]->realm_ports;
	while (cp && *cp) {
	    if (*cp == ',' || isspace(*cp)) {
		cp++;
		continue;
	    }
	    port = strtol(cp, &cp, 10);
	    if (cp == 0)
		break;
	    retval = add_port(port);
	    if (retval)
		return retval;
	}
    }

    for (i=0; i<n_udp_ports; i++) {
	if ((udp_port_fds[i] = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
	    retval = errno;
	    com_err(prog, 0, "Cannot create server socket on port %d",
		    udp_port_nums[i]);
	    return(retval);
	}
	sin.sin_port = htons(udp_port_nums[i]);
	if (bind(udp_port_fds[i], (struct sockaddr *) &sin,
		 sizeof(sin)) == -1) {
	    retval = errno;
	    com_err(prog, 0, "Cannot bind server socket on port %d",
		    udp_port_nums[i]);
	    return(retval);
	}
	FD_SET(udp_port_fds[i], &select_fds);
	if (udp_port_fds[i]+1 > select_nfds)
	    select_nfds = udp_port_fds[i]+1;
    }

    return 0;
}

void process_packet(port_fd, prog, portnum)
    int	port_fd;
    const char	*prog;
    int		portnum;
{
    int cc, saddr_len;
    krb5_fulladdr faddr;
    krb5_error_code retval;
    struct sockaddr_in saddr;
    krb5_address addr;
    krb5_data request;
    krb5_data *response;
    char pktbuf[MAX_DGRAM_SIZE];

    if (port_fd < 0)
	return;
    
    saddr_len = sizeof(saddr);
    cc = recvfrom(port_fd, pktbuf, sizeof(pktbuf), 0,
		  (struct sockaddr *)&saddr, &saddr_len);
    if (cc == -1) {
	if (errno != EINTR)
	    com_err(prog, errno, "while receiving from network");
	return;
    }
    if (!cc)
	return;		/* zero-length packet? */

    request.length = cc;
    request.data = pktbuf;
    faddr.port = ntohs(saddr.sin_port);
    faddr.address = &addr;
    addr.addrtype = ADDRTYPE_INET;
    addr.length = 4;
    /* this address is in net order */
    addr.contents = (krb5_octet *) &saddr.sin_addr;
    if ((retval = dispatch(&request, &faddr, portnum, &response))) {
	com_err(prog, retval, "while dispatching");
	return;
    }
    cc = sendto(port_fd, response->data, response->length, 0,
		(struct sockaddr *)&saddr, saddr_len);
    if (cc == -1) {
        krb5_free_data(kdc_context, response);
	com_err(prog, errno, "while sending reply to %s/%d",
		inet_ntoa(saddr.sin_addr), ntohs(saddr.sin_port));
	return;
    }
    if (cc != response->length) {
	krb5_free_data(kdc_context, response);
	com_err(prog, 0, "short reply write %d vs %d\n",
		response->length, cc);
	return;
    }
    krb5_free_data(kdc_context, response);
    return;
}

krb5_error_code
listen_and_process(prog)
const char *prog;
{
    int			nfound;
    fd_set		readfds;
    int			i;

    if (udp_port_fds == (int *) NULL)
	return KDC5_NONET;
    
    while (!signal_requests_exit) {
	readfds = select_fds;
	nfound = select(select_nfds, &readfds, 0, 0, 0);
	if (nfound == -1) {
	    if (errno == EINTR)
		continue;
	    com_err(prog, errno, "while selecting for network input");
	    continue;
	}
	for (i=0; i<n_udp_ports; i++) {
	    if (FD_ISSET(udp_port_fds[i], &readfds)) {
		process_packet(udp_port_fds[i], prog, udp_port_nums[i]);
		nfound--;
		if (nfound == 0)
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
    int i;

    if (udp_port_fds == (int *) NULL)
	return KDC5_NONET;

    for (i=0; i<n_udp_ports; i++) {
	if (udp_port_fds[i] >= 0)
	    (void) close(udp_port_fds[i]);
    }
    free(udp_port_fds);
    free(udp_port_nums);

    return 0;
}

#endif /* INET */

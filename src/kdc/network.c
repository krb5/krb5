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

#ifdef KRB5_USE_INET
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
static int *sec_udp_port_fds = (int *) NULL;
static u_short *sec_udp_port_nums = (u_short *) NULL;
static int n_sec_udp_ports = 0;
static fd_set select_fds;
static int select_nfds;

krb5_error_code
setup_network(prog, p_ports, s_ports)
const char *prog;
int *p_ports;
int *s_ports;
{
    struct servent *sp;
    struct sockaddr_in sin;
    krb5_error_code retval;
    int i, j, found;
    int npports, nsports;

    FD_ZERO(&select_fds);
    select_nfds = 0;
    memset((char *)&sin, 0, sizeof(sin));

    /*
     * Count the number of primary and secondary ports supplied to us.
     */
    npports = 0;
    if (p_ports)
	for (npports=0; p_ports[npports] > 0; npports++);
    nsports = 0;
    if (s_ports)
	for (nsports=0; s_ports[nsports] > 0; nsports++);

    /*
     * Now handle the primary ports.
     */
    if ((udp_port_fds = (int *) malloc((kdc_numrealms+npports)
				       * sizeof(int))) &&
	(udp_port_nums = (u_short *) malloc((kdc_numrealms+npports)
					    * sizeof(u_short)))) {
	/* Zero it out */
	for (i=0; i<(kdc_numrealms+npports); i++) {
	    udp_port_fds[i] = -1;
	    udp_port_nums[i] = 0;
	}

	/*
	 * First handle any explicitly named primary ports.
	 */
	for (i=0; i<npports; i++) {
	    found = 0;
	    for (j=0; j<i; j++) {
		if (udp_port_nums[j] == p_ports[i]) {
		    found = 1;
		    break;
		}
	    }
	    if (!found) {
		if ((udp_port_fds[i] = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
		    retval = errno;
		    com_err(prog, 0, "Cannot create server socket on port %d",
			    p_ports[i]);
		    return(retval);
		}
		udp_port_nums[i] = p_ports[i];
		sin.sin_port = htons(p_ports[i]);
		if (bind(udp_port_fds[i],
			 (struct sockaddr *) &sin,
			 sizeof(sin)) == -1) {
		    retval = errno;
		    com_err(prog, 0, "Cannot bind server socket on port %d",
			    p_ports[i]);
		    return(retval);
		}
		FD_SET(udp_port_fds[i], &select_fds);
		if (udp_port_fds[i]+1 > select_nfds)
		    select_nfds = udp_port_fds[i]+1;
	    }
	    else {
		udp_port_fds[i] = udp_port_fds[j];
		udp_port_nums[i] = udp_port_nums[j];
	    }
	}

	/* Now handle each realm */
	for (i=0; i<kdc_numrealms; i++) {
	    found = 0;
	    for (j=0; j<(npports+i); j++) {
		if (udp_port_nums[j] == kdc_realmlist[i]->realm_pport) {
		    found = 1;
		    break;
		}
	    }
	    if (!found) {
		if ((udp_port_fds[npports+i] =
		     socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
		    retval = errno;
		    com_err(prog, 0, "Cannot create server socket on port %d",
			    kdc_realmlist[i]->realm_pport);
		    return(retval);
		}
		udp_port_nums[npports+i] = kdc_realmlist[i]->realm_pport;
		sin.sin_port = htons(kdc_realmlist[i]->realm_pport);
		if (bind(udp_port_fds[npports+i],
			 (struct sockaddr *) &sin,
			 sizeof(sin)) == -1) {
		    retval = errno;
		    com_err(prog, 0, "Cannot bind server socket on port %d",
			    kdc_realmlist[i]->realm_pport);
		    return(retval);
		}
		FD_SET(udp_port_fds[npports+i], &select_fds);
		if (udp_port_fds[npports+i]+1 > select_nfds)
		    select_nfds = udp_port_fds[npports+i]+1;
	    }
	    else {
		udp_port_fds[npports+i] = udp_port_fds[j];
		udp_port_nums[npports+i] = udp_port_nums[j];
	    }
	}
	n_udp_ports = kdc_numrealms + npports;
    }

    /*
     * Now we set up the secondary listening ports.  Special case here.
     * If the first secondary port is -1, then we don't listen on secondary
     * ports.
     */
    if ((!s_ports || (s_ports[0] != -1)) &&
	(sec_udp_port_fds = (int *) malloc((kdc_numrealms+nsports)
				       * sizeof(int))) &&
	(sec_udp_port_nums = (u_short *) malloc((kdc_numrealms+nsports)
					    * sizeof(u_short)))) {
	/* Zero it out */
	for (i=0; i<(kdc_numrealms+nsports); i++) {
	    sec_udp_port_fds[i] = -1;
	    sec_udp_port_nums[i] = 0;
	}

	/*
	 * First handle any explicitly named secondary ports.
	 */
	for (i=0; i<nsports; i++) {
	    found = 0;
	    for (j=0; j<i; j++) {
		if (sec_udp_port_nums[j] == s_ports[i]) {
		    found = 1;
		    break;
		}
	    }
	    if (!found) {
		if ((sec_udp_port_fds[i] =
		     socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
		    retval = errno;
		    com_err(prog, 0,
			    "Cannot create secondary server socket on port %d",
			    s_ports[i]);
		    return(retval);
		}
		sec_udp_port_nums[i] = s_ports[i];
		sin.sin_port = htons(s_ports[i]);
		if (bind(sec_udp_port_fds[i],
			 (struct sockaddr *) &sin,
			 sizeof(sin)) == -1) {
		    retval = errno;
		    com_err(prog, 0,
			    "Cannot bind secondary server socket on port %d",
			    s_ports[i]);
		    close(sec_udp_port_fds[i]);
		    sec_udp_port_fds[i] = -1;
		    continue;
		}
		FD_SET(sec_udp_port_fds[i], &select_fds);
		if (sec_udp_port_fds[i]+1 > select_nfds)
		    select_nfds = sec_udp_port_fds[i]+1;
	    }
	    else {
		sec_udp_port_fds[i] = sec_udp_port_fds[j];
		sec_udp_port_nums[i] = sec_udp_port_nums[j];
	    }
	}

	/* Now handle each realm */
	for (i=0; i<kdc_numrealms; i++) {
	    if (kdc_realmlist[i]->realm_sport > 0) {
		found = 0;
		for (j=0; j<(nsports+i); j++) {
		    if (sec_udp_port_nums[j] ==
			kdc_realmlist[i]->realm_sport) {
			found = 1;
			break;
		    }
		}
		if (!found && (kdc_realmlist[i]->realm_sport > 0)) {
		    if ((sec_udp_port_fds[nsports+i] =
			 socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
			retval = errno;
			com_err(prog, 0,
				"Cannot create secondary server socket on port %d",
				kdc_realmlist[i]->realm_sport);
			return(retval);
		    }
		    sec_udp_port_nums[nsports+i] =
			kdc_realmlist[i]->realm_sport;
		    sin.sin_port = htons(kdc_realmlist[i]->realm_sport);
		    if (bind(sec_udp_port_fds[nsports+i],
			     (struct sockaddr *) &sin,
			     sizeof(sin)) == -1) {
			retval = errno;
			com_err(prog, 0,
				"Cannot bind secondary server socket on port %d",
				kdc_realmlist[i]->realm_sport);
			close(sec_udp_port_fds[nsports+i]);
			sec_udp_port_fds[nsports+i] = -1;
			continue;
		    }
		    FD_SET(sec_udp_port_fds[nsports+i], &select_fds);
		    if (sec_udp_port_fds[nsports+i]+1 > select_nfds)
			select_nfds = sec_udp_port_fds[nsports+i]+1;
		}
		else {
		    if (kdc_realmlist[i]->realm_sport > 0) {
			sec_udp_port_fds[nsports+i] = sec_udp_port_fds[j];
			sec_udp_port_nums[nsports+i] = sec_udp_port_nums[j];
		    }
		    else {
			sec_udp_port_fds[nsports+i] = -1;
			sec_udp_port_nums[nsports+i] = -1;
		    }
		}
	    }
	}
	n_sec_udp_ports = kdc_numrealms + nsports;
    }
    return 0;
}

void process_packet(port_fd, prog, is_secondary)
    int	port_fd;
    const char	*prog;
    int		is_secondary;
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
    if ((retval = dispatch(&request, &faddr, is_secondary, &response))) {
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
    int			fdfound;

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
	fdfound = 0;
	for (i=0; i<n_udp_ports; i++) {
	    if (FD_ISSET(udp_port_fds[i], &readfds)) {
		process_packet(udp_port_fds[i], prog, 0);
		fdfound = 1;
		break;
	    }
	}

	if (!fdfound) {
	    for (i=0; i<n_sec_udp_ports; i++) {
		if (FD_ISSET(sec_udp_port_fds[i], &readfds)) {
		    process_packet(sec_udp_port_fds[i], prog, 1);
		    fdfound = 1;
		    break;
		}
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

    for (i=0; i<n_sec_udp_ports; i++) {
	if (sec_udp_port_fds[i] >= 0)
	    (void) close(sec_udp_port_fds[i]);
    }
    free(sec_udp_port_fds);
    free(sec_udp_port_nums);

    return 0;
}

#endif /* INET */

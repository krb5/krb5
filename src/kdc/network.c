/*
 * kdc/network.c
 *
 * Copyright 1990,2000 by the Massachusetts Institute of Technology.
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
 * Network code for Kerberos v5 KDC.
 */

#define NEED_SOCKETS
#include "k5-int.h"
#include "com_err.h"
#include "kdc_util.h"
#include "extern.h"
#include "kdc5_err.h"
#include "adm_proto.h"
#include <sys/ioctl.h>
#include <syslog.h>

#include <stddef.h>
#include <ctype.h>
#ifdef HAVE_NETINET_IN_H
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_SOCKIO_H
/* for SIOCGIFCONF, etc. */
#include <sys/sockio.h>
#endif
#include <sys/time.h>
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <arpa/inet.h>

#ifndef ARPHRD_ETHER /* OpenBSD breaks on multiple inclusions */
#include <net/if.h>
#endif

#include "fake-addrinfo.h"

extern int errno;

static int *udp_port_fds = (int *) NULL;
static u_short *udp_port_nums = (u_short *) NULL;
static int n_udp_ports = 0;
static int n_sockets = 0;
static int max_udp_ports = 0, max_udp_sockets = 0;
static fd_set select_fds;
static int select_nfds;

#define safe_realloc(p,n) ((p)?(realloc(p,n)):(malloc(n)))

static krb5_error_code add_port(port)
     u_short port;
{
    int	i;
    u_short *new_ports;
    int new_max;

    for (i=0; i < n_udp_ports; i++) {
	if (udp_port_nums[i] == port)
	    return 0;
    }
    
    if (n_udp_ports >= max_udp_ports) {
	new_max = max_udp_ports + 10;
	new_ports = safe_realloc(udp_port_nums, new_max * sizeof(u_short));
	if (new_ports == 0)
	    return ENOMEM;
	udp_port_nums = new_ports;

	max_udp_ports = new_max;
    }
	
    udp_port_nums[n_udp_ports++] = port;
    return 0;
}

#define USE_AF AF_INET
#define USE_TYPE SOCK_DGRAM
#define USE_PROTO 0
#define SOCKET_ERRNO errno
#include "foreachaddr.c"

struct socksetup {
    const char *prog;
    krb5_error_code retval;
};

static int
add_fd (struct socksetup *data, int sock)
{
    if (n_sockets == max_udp_sockets) {
	int *new_fds;
	int new_max = max_udp_sockets + n_udp_ports;
	new_fds = safe_realloc(udp_port_fds, new_max * sizeof(int));
	if (new_fds == 0) {
	    data->retval = errno;
	    com_err(data->prog, data->retval, "cannot save socket info");
	    return 1;
	}
	udp_port_fds = new_fds;
	max_udp_sockets = new_max;
    }
    udp_port_fds[n_sockets++] = sock;
    return 0;
}

static void
set_sa_port(struct sockaddr *addr, int port)
{
    switch (addr->sa_family) {
    case AF_INET:
	sa2sin(addr)->sin_port = port;
	break;
#ifdef KRB5_USE_INET6
    case AF_INET6:
	sa2sin6(addr)->sin6_port = port;
	break;
#endif
    default:
	break;
    }
}

static int
setup_port(void *P_data, struct sockaddr *addr)
{
    struct socksetup *data = P_data;
    int sock = -1, i;
    char haddrbuf[NI_MAXHOST];
    int err;

    err = getnameinfo(addr, socklen(addr), haddrbuf, sizeof(haddrbuf),
		      0, 0, NI_NUMERICHOST);
    if (err)
	strcpy(haddrbuf, "<unprintable>");

    switch (addr->sa_family) {
    case AF_INET:
	break;
#ifdef AF_INET6
    case AF_INET6:
#ifndef KRB5_USE_INET6
    {
	static int first = 1;
	if (first) {
	    krb5_klog_syslog (LOG_INFO, "skipping local ipv6 addresses");
	    first = 0;
	}
	return 0;
    }
#else
    break;
#endif
#endif
#ifdef AF_LINK /* some BSD systems, AIX */
    case AF_LINK:
	return 0;
#endif
    default:
	krb5_klog_syslog (LOG_INFO,
			  "skipping unrecognized local address family %d",
			  addr->sa_family);
	return 0;
    }

    for (i = 0; i < n_udp_ports; i++) {
	sock = socket (addr->sa_family, SOCK_DGRAM, 0);
	if (sock == -1) {
	    data->retval = errno;
	    com_err(data->prog, data->retval,
		    "Cannot create server socket for port %d address %s",
		    udp_port_nums[i], haddrbuf);
	    return 1;
	}
	set_sa_port(addr, htons(udp_port_nums[i]));
	if (bind (sock, (struct sockaddr *)addr, socklen (addr)) == -1) {
	    data->retval = errno;
	    com_err(data->prog, data->retval,
		    "Cannot bind server socket to port %d address %s",
		    udp_port_nums[i], haddrbuf);
	    return 1;
	}
	FD_SET (sock, &select_fds);
	if (sock > select_nfds)
	    select_nfds = sock;
	krb5_klog_syslog (LOG_INFO, "listening on fd %d: %s port %d", sock,
			  haddrbuf, udp_port_nums[i]);
	if (add_fd (data, sock))
	    return 1;
    }
    return 0;
}

krb5_error_code
setup_network(prog)
    const char *prog;
{
    struct socksetup setup_data;
    krb5_error_code retval;
    char *cp;
    int i, port;

    FD_ZERO(&select_fds);
    select_nfds = 0;

    /* Handle each realm's ports */
    for (i=0; i<kdc_numrealms; i++) {
	cp = kdc_realmlist[i]->realm_ports;
	while (cp && *cp) {
	    if (*cp == ',' || isspace((int) *cp)) {
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

    setup_data.prog = prog;
    setup_data.retval = 0;
    krb5_klog_syslog (LOG_INFO, "setting up network...");
    if (foreach_localaddr (&setup_data, setup_port, 0, 0)) {
	return setup_data.retval;
    }
    krb5_klog_syslog (LOG_INFO, "set up %d sockets", n_sockets);
    if (n_sockets == 0) {
	com_err(prog, 0, "no sockets set up?");
	exit (1);
    }

    return 0;
}

static void process_packet(port_fd, prog)
    int	port_fd;
    const char	*prog;
{
    int cc, saddr_len;
    krb5_fulladdr faddr;
    krb5_error_code retval;
    struct sockaddr_storage saddr;
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
	if (errno != EINTR
	    /* This is how Linux indicates that a previous
	       transmission was refused, e.g., if the client timed out
	       before getting the response packet.  */
	    && errno != ECONNREFUSED
	    )
	    com_err(prog, errno, "while receiving from network");
	return;
    }
    if (!cc)
	return;		/* zero-length packet? */

    request.length = cc;
    request.data = pktbuf;
    faddr.address = &addr;
    switch (ss2sa(&saddr)->sa_family) {
    case AF_INET:
	addr.addrtype = ADDRTYPE_INET;
	addr.length = 4;
	addr.contents = (krb5_octet *) &ss2sin(&saddr)->sin_addr;
	faddr.port = ntohs(ss2sin(&saddr)->sin_port);
	break;
#ifdef KRB5_USE_INET6
    case AF_INET6:
	addr.addrtype = ADDRTYPE_INET6;
	addr.length = 16;
	addr.contents = (krb5_octet *) &ss2sin6(&saddr)->sin6_addr;
	faddr.port = ntohs(ss2sin6(&saddr)->sin6_port);
	break;
#endif
    default:
	addr.addrtype = -1;
	addr.length = 0;
	addr.contents = 0;
	break;
    }
    /* this address is in net order */
    if ((retval = dispatch(&request, &faddr, &response))) {
	com_err(prog, retval, "while dispatching");
	return;
    }
    cc = sendto(port_fd, response->data, (int) response->length, 0,
		(struct sockaddr *)&saddr, saddr_len);
    if (cc == -1) {
	char addrbuf[46];
	int portno;
        krb5_free_data(kdc_context, response);
	sockaddr2p ((struct sockaddr *) &saddr, addrbuf, sizeof (addrbuf),
		    &portno);
	com_err(prog, errno, "while sending reply to %s/%d",
		addrbuf, ntohs(portno));
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
	if (signal_requests_hup) {
	    krb5_klog_reopen(kdc_context);
	    signal_requests_hup = 0;
	}
	readfds = select_fds;
	nfound = select(select_nfds + 1, &readfds, 0, 0, 0);
	if (nfound == -1) {
	    if (errno == EINTR)
		continue;
	    com_err(prog, errno, "while selecting for network input");
	    continue;
	}
	for (i=0; i<n_sockets; i++) {
	    if (FD_ISSET(udp_port_fds[i], &readfds)) {
		process_packet(udp_port_fds[i], prog);
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

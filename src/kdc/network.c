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
#include <sys/ioctl.h>
#include <syslog.h>

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

#include <net/if.h>

extern int errno;

static int *udp_port_fds = (int *) NULL;
static u_short *udp_port_nums = (u_short *) NULL;
static int n_udp_ports = 0;
static int n_sockets = 0;
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

/* Keep in sync with lib/krb5/os/localaddr.c version.  */

/*
 * BSD 4.4 defines the size of an ifreq to be
 * max(sizeof(ifreq), sizeof(ifreq.ifr_name)+ifreq.ifr_addr.sa_len
 * However, under earlier systems, sa_len isn't present, so the size is 
 * just sizeof(struct ifreq)
 */
#define USE_AF AF_INET
#define USE_TYPE SOCK_DGRAM
#define USE_PROTO 0
#define SOCKET_ERRNO errno

#ifdef HAVE_SA_LEN
#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif
#define ifreq_size(i) max(sizeof(struct ifreq),\
     sizeof((i).ifr_name)+(i).ifr_addr.sa_len)
#else
#define ifreq_size(i) sizeof(struct ifreq)
#endif /* HAVE_SA_LEN*/

static int
foreach_localaddr (data, pass1fn, betweenfn, pass2fn)
    void *data;
    int (*pass1fn) (void *, struct sockaddr *);
    int (*betweenfn) (void *);
    int (*pass2fn) (void *, struct sockaddr *);
{
    struct ifreq *ifr, ifreq;
    struct ifconf ifc;
    int s, code, n, i;
    int est_if_count = 8, est_ifreq_size;
    char *buf = 0;
    size_t current_buf_size = 0;
    
    s = socket (USE_AF, USE_TYPE, USE_PROTO);
    if (s < 0)
	return SOCKET_ERRNO;

    /* At least on NetBSD, an ifreq can hold an IPv4 address, but
       isn't big enough for an IPv6 or ethernet address.  So add a
       little more space.  */
    est_ifreq_size = sizeof (struct ifreq) + 8;
    current_buf_size = est_ifreq_size * est_if_count;
    buf = malloc (current_buf_size);

 ask_again:
    memset(buf, 0, current_buf_size);
    ifc.ifc_len = current_buf_size;
    ifc.ifc_buf = buf;

    code = ioctl (s, SIOCGIFCONF, (char *)&ifc);
    if (code < 0) {
	int retval = errno;
	closesocket (s);
	return retval;
    }
    /* Test that the buffer was big enough that another ifreq could've
       fit easily, if the OS wanted to provide one.  That seems to be
       the only indication we get, complicated by the fact that the
       associated address may make the required storage a little
       bigger than the size of an ifreq.  */
    if (current_buf_size - ifc.ifc_len < sizeof (struct ifreq) + 40) {
	int new_size;
	char *newbuf;

	est_if_count *= 2;
	new_size = est_ifreq_size * est_if_count;
	newbuf = realloc (buf, new_size);
	if (newbuf == 0) {
	    krb5_error_code e = errno;
	    free (buf);
	    return e;
	}
	current_buf_size = new_size;
	buf = newbuf;
	goto ask_again;
    }

    n = ifc.ifc_len;

    for (i = 0; i < n; i+= ifreq_size(*ifr) ) {
	ifr = (struct ifreq *)((caddr_t) ifc.ifc_buf+i);

	strncpy(ifreq.ifr_name, ifr->ifr_name, sizeof (ifreq.ifr_name));
	if (ioctl (s, SIOCGIFFLAGS, (char *)&ifreq) < 0) {
	skip:
	    /* mark for next pass */
	    ifr->ifr_name[0] = 0;

	    continue;
	}
#ifdef IFF_LOOPBACK
	    /* None of the current callers want loopback addresses.  */
	if (ifreq.ifr_flags & IFF_LOOPBACK)
	    goto skip;
#endif
	/* Ignore interfaces that are down.  */
	if (!(ifreq.ifr_flags & IFF_UP))
	    goto skip;

	if ((*pass1fn) (data, &ifr->ifr_addr)) {
	    abort ();
	}
    }

    if (betweenfn && (*betweenfn)(data)) {
	abort ();
    }

    if (pass2fn)
	for (i = 0; i < n; i+= ifreq_size(*ifr) ) {
	    ifr = (struct ifreq *)((caddr_t) ifc.ifc_buf+i);

	    if (ifr->ifr_name[0] == 0)
		/* Marked in first pass to be ignored.  */
		continue;

	    if ((*pass2fn) (data, &ifr->ifr_addr)) {
		abort ();
	    }
	}
    closesocket(s);
    free (buf);

    return 0;
}

struct socksetup {
    const char *prog;
    krb5_error_code retval;
};

static int
setup_port(void *P_data, struct sockaddr *addr)
{
    struct socksetup *data = P_data;
    int sock, i;

    switch (addr->sa_family) {
    case AF_INET:
    {
	struct sockaddr_in *sin = (struct sockaddr_in *) addr, psin;
	for (i = 0; i < n_udp_ports; i++) {
	    sock = socket (PF_INET, SOCK_DGRAM, 0);
	    if (sock == -1) {
		data->retval = errno;
		com_err(data->prog, data->retval,
			"Cannot create server socket for port %d address %s",
			udp_port_nums[i], inet_ntoa (sin->sin_addr));
		return 1;
	    }
	    psin = *sin;
	    psin.sin_port = htons (udp_port_nums[i]);
	    if (bind (sock, (struct sockaddr *)&psin, sizeof (psin)) == -1) {
		data->retval = errno;
		com_err(data->prog, data->retval,
			"Cannot bind server socket to port %d address %s",
			udp_port_nums[i], inet_ntoa (sin->sin_addr));
		return 1;
	    }
	    FD_SET (sock, &select_fds);
	    if (sock > select_nfds)
		select_nfds = sock;
	    udp_port_fds[n_sockets++] = sock;
	    krb5_klog_syslog (LOG_INFO, "listening on fd %d: %s port %d", sock,
			     inet_ntoa (sin->sin_addr), udp_port_nums[i]);
	}
    }
    default:
	break;
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

    setup_data.prog = prog;
    setup_data.retval = 0;
    krb5_klog_syslog (LOG_INFO, "setting up network...");
    if (foreach_localaddr (&setup_data, setup_port, 0, 0)) {
	return setup_data.retval;
    }
    krb5_klog_syslog (LOG_INFO, "set up %d sockets", n_sockets);
    if (n_sockets == 0) {
	com_err(prog, 0, "no sockets set up?");
	return -1;
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
	if (signal_requests_hup) {
	    krb5_klog_reopen();
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

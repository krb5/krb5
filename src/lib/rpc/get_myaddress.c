/* @(#)get_myaddress.c	2.1 88/07/29 4.0 RPCSRC */
/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 * 
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 * 
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 * 
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 * 
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 * 
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */
#if !defined(lint) && defined(SCCSIDS)
static char sccsid[] = "@(#)get_myaddress.c 1.4 87/08/11 Copyr 1984 Sun Micro";
#endif

/*
 * get_myaddress.c
 *
 * Get client's IP address via ioctl.  This avoids using the yellowpages.
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */

#ifdef GSSAPI_KRB5
#include <string.h>
#include <gssrpc/types.h>
#include <gssrpc/pmap_prot.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <krb5.h>
/* 
 * don't use gethostbyname, which would invoke yellow pages
 */
gssrpc_get_myaddress(addr)
	struct sockaddr_in *addr;
{
     krb5_address **addrs, **a;
     int ret;

     /* Hack!  krb5_os_localaddr does not use the context arg! */
     if (ret = krb5_os_localaddr(NULL, &addrs)) {
	  com_err("get_myaddress", ret, "calling krb5_os_localaddr");
	  exit(1);
     }
     a = addrs;
     while (*a) {
	  if ((*a)->addrtype == ADDRTYPE_INET) {
	       memset(addr, 0, sizeof(*addr));
	       addr->sin_family = AF_INET;
	       addr->sin_port = htons(PMAPPORT);
	       memcpy(&addr->sin_addr, (*a)->contents, sizeof(addr->sin_addr));
	       break;
	  }
	  a++;
     }
     if (*a == NULL) {
	  com_err("get_myaddress", 0, "no local AF_INET address");
	  exit(1);
     }
     /* Hack!  krb5_free_addresses does not use the context arg! */
     krb5_free_addresses(NULL, addrs);
}

#else /* !GSSAPI_KRB5 */
#include <gssrpc/types.h>
#include <gssrpc/pmap_prot.h>
#include <sys/socket.h>
#if defined(sun)
#include <sys/sockio.h>
#endif
#include <stdio.h>
#ifdef OSF1
#include <net/route.h>
#include <sys/mbuf.h>
#endif
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* 
 * don't use gethostbyname, which would invoke yellow pages
 */
get_myaddress(addr)
	struct sockaddr_in *addr;
{
	int s;
	char buf[BUFSIZ];
	struct ifconf ifc;
	struct ifreq ifreq, *ifr;
	int len;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	    perror("get_myaddress: socket");
	    exit(1);
	}
	ifc.ifc_len = sizeof (buf);
	ifc.ifc_buf = buf;
	if (ioctl(s, SIOCGIFCONF, (char *)&ifc) < 0) {
		perror("get_myaddress: ioctl (get interface configuration)");
		exit(1);
	}
	ifr = ifc.ifc_req;
	for (len = ifc.ifc_len; len; len -= sizeof ifreq) {
		ifreq = *ifr;
		if (ioctl(s, SIOCGIFFLAGS, (char *)&ifreq) < 0) {
			perror("get_myaddress: ioctl");
			exit(1);
		}
		if ((ifreq.ifr_flags & IFF_UP) &&
		    ifr->ifr_addr.sa_family == AF_INET) {
			*addr = *((struct sockaddr_in *)&ifr->ifr_addr);
			addr->sin_port = htons(PMAPPORT);
			break;
		}
		ifr++;
	}
	(void) close(s);
}
#endif /* !GSSAPI_KRB5 */

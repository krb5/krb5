/*
 * lib/crypto/os/localaddr.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * Return the protocol addresses supported by this host.
 *
 * XNS support is untested, but "Should just work".
 */


#define NEED_SOCKETS
#include "k5-int.h"

#if !defined(HAVE_MACSOCK_H) && !defined(_MSDOS)

/* needed for solaris, harmless elsewhere... */
#define BSD_COMP
#include <sys/ioctl.h>
#include <sys/time.h>
#include <errno.h>

/*
 * The SIOCGIF* ioctls require a socket.
 * It doesn't matter *what* kind of socket they use, but it has to be
 * a socket.
 *
 * Of course, you can't just ask the kernel for a socket of arbitrary
 * type; you have to ask for one with a valid type.
 *
 */
#ifdef KRB5_USE_INET

#include <netinet/in.h>

#ifndef USE_AF
#define USE_AF AF_INET
#define USE_TYPE SOCK_DGRAM
#define USE_PROTO 0
#endif

#endif

#ifdef KRB5_USE_NS

#include <netns/ns.h>

#ifndef USE_AF
#define USE_AF AF_NS
#define USE_TYPE SOCK_DGRAM
#define USE_PROTO 0		/* guess */
#endif

#endif
/*
 * Add more address families here.
 */

/*
 * BSD 4.4 defines the size of an ifreq to be
 * max(sizeof(ifreq), sizeof(ifreq.ifr_name)+ifreq.ifr_addr.sa_len
 * However, under earlier systems, sa_len isn't present, so the size is 
 * just sizeof(struct ifreq)
 */
#ifdef HAVE_SA_LEN
#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif
#define ifreq_size(i) max(sizeof(struct ifreq),\
     sizeof((i).ifr_name)+(i).ifr_addr.sa_len)
#else
#define ifreq_size(i) sizeof(struct ifreq)
#endif /* HAVE_SA_LEN*/



extern int errno;

/*
 * Return all the protocol addresses of this host.
 *
 * We could kludge up something to return all addresses, assuming that
 * they're valid kerberos protocol addresses, but we wouldn't know the
 * real size of the sockaddr or know which part of it was actually the
 * host part.
 *
 * This uses the SIOCGIFCONF, SIOCGIFFLAGS, and SIOCGIFADDR ioctl's.
 */

krb5_error_code INTERFACE
krb5_crypto_os_localaddr(addr)
    krb5_address ***addr;
{
    struct ifreq *ifr, ifreq;
    struct ifconf ifc;
    int s, code, n, i;
    char buf[1024];
    krb5_address *addr_temp [ 1024/sizeof(struct ifreq) ];
    int n_found;
    int mem_err = 0;
    
    memset(buf, 0, sizeof(buf));
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    
    s = socket (USE_AF, USE_TYPE, USE_PROTO);
    if (s < 0)
	return errno;

    code = ioctl (s, SIOCGIFCONF, (char *)&ifc);
    if (code < 0) {
	int retval = errno;
	closesocket (s);
	return retval;
    }
    n = ifc.ifc_len;
    
n_found = 0;
    for (i = 0; i < n; i+= ifreq_size(*ifr) ) {
	krb5_address *address;
	ifr = (struct ifreq *)((caddr_t) ifc.ifc_buf+i);

	strncpy(ifreq.ifr_name, ifr->ifr_name, sizeof (ifreq.ifr_name));
	if (ioctl (s, SIOCGIFFLAGS, (char *)&ifreq) < 0)
	    continue;

#ifdef IFF_LOOPBACK
	if (ifreq.ifr_flags & IFF_LOOPBACK) 
	    continue;
#endif

	if (!(ifreq.ifr_flags & IFF_UP)) 
	    /* interface is down; skip */
	    continue;

	/* ifr->ifr_addr has what we want! */
	switch (ifr->ifr_addr.sa_family) {
#ifdef KRB5_USE_INET
	case AF_INET:
	    {
		struct sockaddr_in *in =
		    (struct sockaddr_in *)&ifr->ifr_addr;
		
		address = (krb5_address *)
		    malloc (sizeof(krb5_address));
		if (address) {
		    address->addrtype = ADDRTYPE_INET;
		    address->length = sizeof(struct in_addr);
		    address->contents = (unsigned char *)malloc(address->length);
		    if (!address->contents) {
			krb5_xfree(address);
			address = 0;
			mem_err++;
		    } else {
			memcpy ((char *)address->contents,
				(char *)&in->sin_addr, 
				address->length);
			break;
		    }
		} else mem_err++;
	    }
#endif
#ifdef KRB5_USE_NS
	    case AF_XNS:
	    {  
		struct sockaddr_ns *ns =
		    (struct sockaddr_ns *)&ifr->ifr_addr;
		address = (krb5_address *)
		    malloc (sizeof (krb5_address) + sizeof (struct ns_addr));
		if (address) {
		    address->addrtype = ADDRTYPE_XNS; 

		    /* XXX should we perhaps use ns_host instead? */

		    address->length = sizeof(struct ns_addr);
		    address->contents = (unsigned char *)malloc(address->length);
		    if (!address->contents) {
			krb5_xfree(address);
			address = 0;
			mem_err++;
		    } else {
			memcpy ((char *)address->contents,
				(char *)&ns->sns_addr,
				address->length);
			break;
		    }
		} else mem_err++;
		break;
	    }
#endif
	/*
	 * Add more address families here..
	 */
	default:
	    continue;
	}
	if (address)
	    addr_temp[n_found++] = address;
	address = 0;
    }
    close(s);

    *addr = (krb5_address **)malloc (sizeof (krb5_address *) * (n_found+1));
    if (*addr == 0)
	mem_err++;
    
    if (mem_err) {
	for (i=0; i<n_found; i++) {
	    krb5_xfree(addr_temp[i]);
	    addr_temp[i] = 0;
	}
	return ENOMEM;
    }
    
    for (i=0; i<n_found; i++) {
	(*addr)[i] = addr_temp[i];
    }
    (*addr)[n_found] = 0;
    return 0;
}

#else /* Windows/Mac version */

/* No ioctls in winsock so we just assume there is only one networking 
 * card per machine, so gethostent is good enough. 
 */

krb5_error_code INTERFACE
krb5_crypto_os_localaddr (krb5_address ***addr) {
    char host[64];                              /* Name of local machine */
    struct hostent *hostrec;
    int err;

    *addr = calloc (2, sizeof (krb5_address *));
    if (*addr == NULL)
        return ENOMEM;

#ifdef HAVE_MACSOCK_H
    hostrec = getmyipaddr();
#else /* HAVE_MACSOCK_H */
    if (gethostname (host, sizeof(host))) {
        err = WSAGetLastError();
        return err;
    }

    hostrec = gethostbyname (host);
    if (hostrec == NULL) {
        err = WSAGetLastError();
        return err;
    }
#endif /* HAVE_MACSOCK_H */

    (*addr)[0] = calloc (1, sizeof(krb5_address));
    if ((*addr)[0] == NULL) {
        free (*addr);
        return ENOMEM;
    }
    (*addr)[0]->addrtype = hostrec->h_addrtype;
    (*addr)[0]->length = hostrec->h_length;
    (*addr)[0]->contents = (unsigned char *)malloc((*addr)[0]->length);
    if (!(*addr)[0]->contents) {
        free((*addr)[0]);
        free(*addr);
        return ENOMEM;
    } else {
        memcpy ((*addr)[0]->contents,
                hostrec->h_addr,
                (*addr)[0]->length);
    }
	/* FIXME, deal with the case where gethostent returns multiple addrs */

    return(0);
}
#endif

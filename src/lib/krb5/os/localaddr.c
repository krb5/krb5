/*
 * lib/krb5/os/localaddr.c
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

#if !defined(HAVE_MACSOCK_H) && !defined(_MSDOS) && !defined(_WIN32)

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
#ifdef HAVE_NETINET_IN_H

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

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_os_localaddr(context, addr)
    krb5_context context;
    krb5_address FAR * FAR * FAR *addr;
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
	return SOCKET_ERRNO;

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
#ifdef HAVE_NETINET_IN_H
	case AF_INET:
	    {
		struct sockaddr_in *in =
		    (struct sockaddr_in *)&ifr->ifr_addr;
		
		address = (krb5_address *)
		    malloc (sizeof(krb5_address));
		if (address) {
		    address->magic = KV5M_ADDRESS;
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
		    address->magic = KV5M_ADDRESS;
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
    closesocket(s);

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

/*
 * Hold on to your lunch!  Backup kludge method of obtaining your
 * local IP address, courtesy of Windows Socket Network Programming,
 * by Robert Quinn
 */
#if defined(_MSDOS) || defined(_WIN32)
static struct hostent *local_addr_fallback_kludge()
{
	static struct hostent	host;
	static SOCKADDR_IN	addr;
	static char *		ip_ptrs[2];
	SOCKET			sock;
	int			size = sizeof(SOCKADDR);
	int			err;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == INVALID_SOCKET)
		return NULL;

	/* connect to arbitrary port and address (NOT loopback) */
	addr.sin_family = AF_INET;
	addr.sin_port = htons(IPPORT_ECHO);
	addr.sin_addr.s_addr = inet_addr("204.137.220.51");

	err = connect(sock, (LPSOCKADDR) &addr, sizeof(SOCKADDR));
	if (err == SOCKET_ERROR)
		return NULL;

	err = getsockname(sock, (LPSOCKADDR) &addr, (int FAR *) size);
	if (err == SOCKET_ERROR)
		return NULL;

	closesocket(sock);

	host.h_name = 0;
	host.h_aliases = 0;
	host.h_addrtype = AF_INET;
	host.h_length = 4;
	host.h_addr_list = ip_ptrs;
	ip_ptrs[0] = (char *) &addr.sin_addr.s_addr;
	ip_ptrs[1] = NULL;

	return &host;
}
#endif

/* No ioctls in winsock so we just assume there is only one networking 
 * card per machine, so gethostent is good enough. 
 */
KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_os_localaddr (krb5_context context, krb5_address ***addr) {
    char host[64];                              /* Name of local machine */
    struct hostent *hostrec;
    int err, count, i;
    krb5_address ** paddr;

    *addr = 0;
    paddr = 0;
    err = 0;
    
    if (gethostname (host, sizeof(host))) {
        err = SOCKET_ERRNO;
    }

    if (!err) {
	    hostrec = gethostbyname (host);
	    if (hostrec == NULL) {
		    err = SOCKET_ERRNO;
	    }
    }

    if (err) {
	    hostrec = local_addr_fallback_kludge();
	    if (!hostrec)
		    return err;
    }

    for (count = 0; hostrec->h_addr_list[count]; count++);


    paddr = (krb5_address **)malloc(sizeof(krb5_address *) * (count+1));
    if (!paddr) {
        err = ENOMEM;
        goto cleanup;
    }

    memset(paddr, 0, sizeof(krb5_address *) * (count+1));

    for (i = 0; i < count; i++)
    {
        paddr[i] = (krb5_address *)malloc(sizeof(krb5_address));
        if (paddr[i] == NULL) {
            err = ENOMEM;
            goto cleanup;
        }

        paddr[i]->magic = KV5M_ADDRESS;
        paddr[i]->addrtype = hostrec->h_addrtype;
        paddr[i]->length = hostrec->h_length;
        paddr[i]->contents = (unsigned char *)malloc(paddr[i]->length);
        if (!paddr[i]->contents) {
            err = ENOMEM;
            goto cleanup;
        }
        memcpy(paddr[i]->contents,
               hostrec->h_addr_list[i],
               paddr[i]->length);
    }

 cleanup:
    if (err) {
        if (paddr) {
            for (i = 0; i < count; i++)
            {
                if (paddr[i]) {
                    if (paddr[i]->contents)
                        free(paddr[i]->contents);
                    free(paddr[i]);
                }
            }
            free(paddr);
        }
    }
    else
        *addr = paddr;

    return(err);
}
#endif

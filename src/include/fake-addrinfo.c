/*
 * Copyright (C) 2001 by the Massachusetts Institute of Technology,
 * Cambridge, MA, USA.  All Rights Reserved.
 * 
 * This software is being provided to you, the LICENSEE, by the 
 * Massachusetts Institute of Technology (M.I.T.) under the following 
 * license.  By obtaining, using and/or copying this software, you agree 
 * that you have read, understood, and will comply with these terms and 
 * conditions:  
 * 
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify and distribute 
 * this software and its documentation for any purpose and without fee or 
 * royalty is hereby granted, provided that you agree to comply with the 
 * following copyright notice and statements, including the disclaimer, and 
 * that the same appear on ALL copies of the software and documentation, 
 * including modifications that you make for internal use or for 
 * distribution:
 * 
 * THIS SOFTWARE IS PROVIDED "AS IS", AND M.I.T. MAKES NO REPRESENTATIONS 
 * OR WARRANTIES, EXPRESS OR IMPLIED.  By way of example, but not 
 * limitation, M.I.T. MAKES NO REPRESENTATIONS OR WARRANTIES OF 
 * MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF 
 * THE LICENSED SOFTWARE OR DOCUMENTATION WILL NOT INFRINGE ANY THIRD PARTY 
 * PATENTS, COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS.   
 * 
 * The name of the Massachusetts Institute of Technology or M.I.T. may NOT 
 * be used in advertising or publicity pertaining to distribution of the 
 * software.  Title to copyright in this software and any associated 
 * documentation shall at all times remain with M.I.T., and USER agrees to 
 * preserve same.
 *
 * Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.  
 */

/* To do, maybe:

   IPv6 support for systems with working inet6 socket code but broken
   getaddrinfo implementations?  (RH Linux 6.1 libc getaddrinfo
   ignores AI_NUMERICHOST.  Solaris 8 doesn't appear to support
   IPv6.)  Could use gethostbyname2 if available.  */

#include "fake-addrinfo.h"

void fixup_addrinfo (struct addrinfo *ai)
{
    struct addrinfo *ai2;

    if (ai == 0)
	return;

    /* Linux libc version 6 (libc-2.2.4.so on Debian) is broken.

       RFC 2553 says that when AI_CANONNAME is set, the ai_canonname
       flag of the first returned structure has the canonical name of
       the host.  Instead, GNU libc sets ai_canonname in all the
       returned structures, sometimes it's the canonical name and
       sometimes it's the numeric form of an address.  So if we
       actually want the canonical name, we may have to look through
       the list and discard numeric addresses.

       Since it's dependent on the target hostname, it's hard to check
       for at configure time.  */
    if (ai->ai_canonname && strchr(ai->ai_canonname, ':')) {
	for (ai2 = ai->ai_next; ai2; ai2 = ai2->ai_next) {
	    if (ai2->ai_canonname == 0)
		continue;
	    if (!strchr(ai2->ai_canonname, ':')) {
		char *p = ai->ai_canonname;
		ai->ai_canonname = ai2->ai_canonname;
		ai2->ai_canonname = p;
		break;
	    }
	}
	if (ai2 == 0)
	    /* Ran off end, with no non-numeric name.  What to do?  */
	    ;
    }

    for (; ai; ai = ai->ai_next) {
	/* AIX 4.3.3 libc is broken.  It doesn't set the family or len
	   fields of the sockaddr structures.  */
	if (ai->ai_addr->sa_family == 0)
	    ai->ai_addr->sa_family = ai->ai_family;
#ifdef HAVE_SA_LEN
	if (ai->ai_addr->sa_len == 0)
	    ai->ai_addr->sa_len = ai->ai_addrlen;
#endif
    }
}

#ifdef HAVE_FAKE_GETADDRINFO

static int translate_h_errno (int h);

static int fai_add_entry (struct addrinfo **result, void *addr, int port,
			  const struct addrinfo *template)
{
    struct addrinfo *n = malloc (sizeof (struct addrinfo));
    struct sockaddr_in *sin4;
    if (n == 0)
	return EAI_MEMORY;
    if (template->ai_family != AF_INET)
	return EAI_FAMILY;
    *n = *template;
    sin4 = malloc (sizeof (struct sockaddr_in));
    if (sin4 == 0)
	return EAI_MEMORY;
    n->ai_addr = (struct sockaddr *) sin4;
    sin4->sin_family = AF_INET;
    sin4->sin_addr = *(struct in_addr *)addr;
    sin4->sin_port = port;
#ifdef HAVE_SA_LEN
    sin4->sin_len = sizeof (struct sockaddr_in);
#endif
    n->ai_next = *result;
    *result = n;
    return 0;
}

static int fai_add_hosts_by_name (const char *name, int af,
				  struct addrinfo *template,
				  int portnum, int flags,
				  struct addrinfo **result)
{
    struct hostent *hp;
    int i, r;

    if (af != AF_INET)
	/* For now, real ipv6 support needs real getaddrinfo.  */
	return EAI_FAMILY;
    hp = gethostbyname (name);
    if (hp == 0)
	return translate_h_errno (h_errno);
    for (i = 0; hp->h_addr_list[i]; i++) {
	r = fai_add_entry (result, hp->h_addr_list[i], portnum, template);
	if (r)
	    return r;
    }
    if (*result && (flags & AI_CANONNAME))
	(*result)->ai_canonname = strdup (hp->h_name);
    return 0;
}

int getaddrinfo (const char *name, const char *serv,
		 const struct addrinfo *hint, struct addrinfo **result)
{
    struct addrinfo *res = 0;
    int ret;
    int port = 0, socktype;
    int flags;
    struct addrinfo template;

    if (hint != 0) {
	if (hint->ai_family != 0 && hint->ai_family != AF_INET)
	    return EAI_NODATA;
	socktype = hint->ai_socktype;
	flags = hint->ai_flags;
    } else {
	socktype = 0;
	flags = 0;
    }

    if (serv) {
	size_t numlen = strspn (serv, "0123456789");
	if (serv[numlen] == '\0') {
	    /* pure numeric */
	    unsigned long p = strtoul (serv, 0, 10);
	    if (p == 0 || p > 65535)
		return EAI_NONAME;
	    port = htons (p);
	} else {
	    struct servent *sp;
	    int try_dgram_too = 0;
	    if (socktype == 0) {
		try_dgram_too = 1;
		socktype = SOCK_STREAM;
	    }
	try_service_lookup:
	    sp = getservbyname (serv, socktype == SOCK_STREAM ? "tcp" : "udp");
	    if (sp == 0) {
		if (try_dgram_too) {
		    socktype = SOCK_DGRAM;
		    goto try_service_lookup;
		}
		return EAI_SERVICE;
	    }
	    port = sp->s_port;
	}
    }

    if (name == 0) {
	name = (flags & AI_PASSIVE) ? "0.0.0.0" : "127.0.0.1";
	flags |= AI_NUMERICHOST;
    }

    template.ai_family = AF_INET;
    template.ai_addrlen = sizeof (struct sockaddr_in);
    template.ai_socktype = socktype;
    template.ai_protocol = 0;
    template.ai_flags = 0;
    template.ai_canonname = 0;
    template.ai_next = 0;
    template.ai_addr = 0;

    /* If NUMERICHOST is set, parse a numeric address.
       If it's not set, don't accept such names.  */
    if (flags & AI_NUMERICHOST) {
	struct in_addr addr4;
#if 0
	ret = inet_aton (name, &addr4);
	if (ret)
	    return EAI_NONAME;
#else
	addr4.s_addr = inet_addr (name);
	if (addr4.s_addr == 0xffffffff || addr4.s_addr == -1)
	    /* 255.255.255.255 or parse error, both bad */
	    return EAI_NONAME;
#endif
	ret = fai_add_entry (&res, &addr4, port, &template);
    } else {
	ret = fai_add_hosts_by_name (name, AF_INET, &template, port, flags,
				     &res);
    }

    if (ret && ret != NO_ADDRESS) {
	freeaddrinfo (res);
	return ret;
    }
    if (res == 0)
	return NO_ADDRESS;
    *result = res;
    return 0;
}

int getnameinfo (const struct sockaddr *sa, socklen_t len,
		 char *host, size_t hostlen,
		 char *service, size_t servicelen,
		 int flags)
{
    struct hostent *hp;
    const struct sockaddr_in *sinp;
    struct servent *sp;

    if (sa->sa_family != AF_INET) {
	return EAI_FAMILY;
    }
    sinp = (const struct sockaddr_in *) sa;

    if (host) {
	if (flags & NI_NUMERICHOST) {
	    char *p;
	numeric_host:
	    p = inet_ntoa (sinp->sin_addr);
	    if (strlen (p) < hostlen)
		strcpy (host, p);
	    else
		return EAI_FAIL; /* ?? */
	} else {
	    hp = gethostbyaddr ((struct sockaddr *) &sinp->sin_addr, sizeof (struct in_addr),
				sa->sa_family);
	    if (hp == 0) {
		if (h_errno == NO_ADDRESS && !(flags & NI_NAMEREQD)) /* ??? */
		    goto numeric_host;
		return translate_h_errno (h_errno);
	    }
	    if (strlen (hp->h_name) < hostlen)
		strcpy (host, hp->h_name);
	    else
		return EAI_FAIL; /* ?? */
	}
    }

    if (service) {
	if (flags & NI_NUMERICSERV) {
	    char numbuf[10];
	    int port;
	numeric_service:
	    port = ntohs (sinp->sin_port);
	    if (port < 0 || port > 65535)
		return EAI_FAIL;
	    sprintf (numbuf, "%d", port);
	    if (strlen (numbuf) < servicelen)
		strcpy (service, numbuf);
	    else
		return EAI_FAIL;
	} else {
	    sp = getservbyport (sinp->sin_port,
				(flags & NI_DGRAM) ? "udp" : "tcp");
	    if (sp == 0)
		goto numeric_service;
	    if (strlen (sp->s_name) < servicelen)
		strcpy (service, sp->s_name);
	    else
		return EAI_FAIL;
	}
    }

    return 0;
}

void freeaddrinfo (struct addrinfo *ai)
{
    struct addrinfo *next;
    while (ai) {
	next = ai->ai_next;
	if (ai->ai_canonname)
	  free (ai->ai_canonname);
	if (ai->ai_addr)
	  free (ai->ai_addr);
	free (ai);
	ai = next;
    }
}

char *gai_strerror (int code)
{
    switch (code) {
    case EAI_ADDRFAMILY: return "address family for nodename not supported";
    case EAI_AGAIN:	return "temporary failure in name resolution";
    case EAI_BADFLAGS:	return "bad flags to getaddrinfo/getnameinfo";
    case EAI_FAIL:	return "non-recoverable failure in name resolution";
    case EAI_FAMILY:	return "ai_family not supported";
    case EAI_MEMORY:	return "out of memory";
    case EAI_NODATA:	return "no address associated with hostname";
    case EAI_NONAME:	return "name does not exist";
    case EAI_SERVICE:	return "service name not supported for specified socket type";
    case EAI_SOCKTYPE:	return "ai_socktype not supported";
    case EAI_SYSTEM:	return strerror (errno);
    default:		return "bogus getaddrinfo error?";
    }
}

static int translate_h_errno (int h)
{
    switch (h) {
    case 0:
	return 0;
#ifdef NETDB_INTERNAL
    case NETDB_INTERNAL:
	if (errno == ENOMEM)
	    return EAI_MEMORY;
	return EAI_SYSTEM;
#endif
    case HOST_NOT_FOUND:
	return EAI_NONAME;
    case TRY_AGAIN:
	return EAI_AGAIN;
    case NO_RECOVERY:
	return EAI_FAIL;
    case NO_DATA:
#if NO_DATA != NO_ADDRESS
    case NO_ADDRESS:
#endif
	return EAI_NODATA;
    default:
	return EAI_SYSTEM;
    }
}

#endif

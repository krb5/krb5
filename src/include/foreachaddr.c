/*
 * include/foreachaddr.c
 *
 * Copyright 1990,1991,2000,2001,2002 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Iterate over the protocol addresses supported by this host, invoking
 * a callback function or three supplied by the caller.
 *
 * XNS support is untested, but "should just work".  (Hah!)
 */

/* This is the primary "export" of this file.  It's a static function,
   so this file must be #included in the .c file containing the
   caller.

   This function iterates over all the addresses it can find for the
   local system, in one or two passes.  In each pass, and between the
   two, it can invoke callback functions supplied by the caller.  The
   two passes should operate on the same information, though not
   necessarily in the same order each time.  Duplicate and local
   addresses should be eliminated.  Storage passed to callback
   functions should not be assumed to be valid after foreach_localaddr
   returns.

   The int return value is an errno value (XXX or krb5_error_code
   returned for a socket error) if something internal to
   foreach_localaddr fails.  If one of the callback functions wants to
   indicate an error, it should store something via the 'data' handle.
   If any callback function returns a non-zero value,
   foreach_localaddr will clean up and return immediately.

   Multiple definitions are provided below, dependent on various
   system facilities for extracting the necessary information.  */
static int
foreach_localaddr (/*@null@*/ void *data,
		   int (*pass1fn) (/*@null@*/ void *, struct sockaddr *) /*@*/,
		   /*@null@*/ int (*betweenfn) (/*@null@*/ void *) /*@*/,
		   /*@null@*/ int (*pass2fn) (/*@null@*/ void *,
					      struct sockaddr *) /*@*/)
#if defined(DEBUG) || defined(TEST)
     /*@modifies fileSystem@*/
#endif
    ;

/* Now, on to the implementations, and heaps of debugging code.  */

#ifdef TEST
# define Tprintf(X) printf X
# define Tperror(X) perror(X)
#else
# define Tprintf(X) (void) X
# define Tperror(X) (void)(X)
#endif

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


#if defined(__linux__) && defined(KRB5_USE_INET6)
#define LINUX_IPV6_HACK
#endif

#include <errno.h>

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

/*
 * BSD 4.4 defines the size of an ifreq to be
 * max(sizeof(ifreq), sizeof(ifreq.ifr_name)+ifreq.ifr_addr.sa_len
 * However, under earlier systems, sa_len isn't present, so the size is 
 * just sizeof(struct ifreq).
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

#if defined(DEBUG) || defined(TEST)
#include <netinet/in.h>
#include <net/if.h>

#include "socket-utils.h"
#include "fake-addrinfo.h"

void printaddr (struct sockaddr *);

void printaddr (struct sockaddr *sa)
    /*@modifies fileSystem@*/
{
    char buf[NI_MAXHOST];
    int err;

    printf ("%p ", (void *) sa);
    err = getnameinfo (sa, socklen (sa), buf, sizeof (buf), 0, 0,
		       NI_NUMERICHOST);
    if (err)
	printf ("<getnameinfo error %d: %s> family=%d",
		err, gai_strerror (err),
		sa->sa_family);
    else
	printf ("%s", buf);
}
#endif

#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>

#ifdef DEBUG
void printifaddr (struct ifaddrs *ifp)
{
    printf ("%p={\n", ifp);
/*  printf ("\tnext=%p\n", ifp->ifa_next); */
    printf ("\tname=%s\n", ifp->ifa_name);
    printf ("\tflags=");
    {
	int ch, flags = ifp->ifa_flags;
	printf ("%x", flags);
	ch = '<';
#define X(F) if (flags & IFF_##F) { printf ("%c%s", ch, #F); flags &= ~IFF_##F; ch = ','; }
	X (UP); X (BROADCAST); X (DEBUG); X (LOOPBACK); X (POINTOPOINT);
	X (NOTRAILERS); X (RUNNING); X (NOARP); X (PROMISC); X (ALLMULTI);
	X (OACTIVE); X (SIMPLEX); X (MULTICAST);
	printf (">");
#undef X
    }
    if (ifp->ifa_addr)
	printf ("\n\taddr="), printaddr (ifp->ifa_addr);
    if (ifp->ifa_netmask)
	printf ("\n\tnetmask="), printaddr (ifp->ifa_netmask);
    if (ifp->ifa_broadaddr)
	printf ("\n\tbroadaddr="), printaddr (ifp->ifa_broadaddr);
    if (ifp->ifa_dstaddr)
	printf ("\n\tdstaddr="), printaddr (ifp->ifa_dstaddr);
    if (ifp->ifa_data)
	printf ("\n\tdata=%p", ifp->ifa_data);
    printf ("\n}\n");
}
#endif /* DEBUG */

static int
addr_eq (const struct sockaddr *s1, const struct sockaddr *s2)
{
    if (s1->sa_family != s2->sa_family)
	return 0;
#ifdef HAVE_SA_LEN
    if (s1->sa_len != s2->sa_len)
	return 0;
    return !memcmp (s1, s2, s1->sa_len);
#else
#define CMPTYPE(T,F) (!memcmp(&((T*)s1)->F,&((T*)s2)->F,sizeof(((T*)s1)->F)))
    switch (s1->sa_family) {
    case AF_INET:
	return CMPTYPE (struct sockaddr_in, sin_addr);
    case AF_INET6:
	return CMPTYPE (struct sockaddr_in6, sin6_addr);
    default:
	/* Err on side of duplicate listings.  */
	return 0;
    }
#endif
}
#endif

/*@-usereleased@*/ /* lclint doesn't understand realloc */
static /*@null@*/ void *
grow_or_free (/*@only@*/ void *ptr, size_t newsize)
     /*@*/
{
    void *newptr;
    newptr = realloc (ptr, newsize);
    if (newptr == NULL && newsize != 0) {
	free (ptr);		/* lclint complains but this is right */
	return NULL;
    }
    return newptr;
}
/*@=usereleased@*/

static int
get_ifconf (int s, size_t *lenp, /*@out@*/ char *buf)
    /*@modifies *buf,*lenp@*/
{
    int ret;
    struct ifconf ifc;

    /*@+matchanyintegral@*/
    ifc.ifc_len = *lenp;
    /*@=matchanyintegral@*/
    ifc.ifc_buf = buf;
    memset(buf, 0, *lenp);
    /*@-moduncon@*/
    ret = ioctl (s, SIOCGIFCONF, (char *)&ifc);
    /*@=moduncon@*/
    /*@+matchanyintegral@*/
    *lenp = ifc.ifc_len;
    /*@=matchanyintegral@*/
    return ret;
}

#ifdef SIOCGLIFCONF /* Solaris */
static int
get_lifconf (int af, int s, size_t *lenp, /*@out@*/ char *buf)
    /*@modifies *buf,*lenp@*/
{
    int ret;
    struct lifconf lifc;

    lifc.lifc_family = af;
    lifc.lifc_flags = 0;
    /*@+matchanyintegral@*/
    lifc.lifc_len = *lenp;
    /*@=matchanyintegral@*/
    lifc.lifc_buf = buf;
    memset(buf, 0, *lenp);
    /*@-moduncon@*/
    ret = ioctl (s, SIOCGLIFCONF, (char *)&lifc);
    if (ret)
	Tperror ("SIOCGLIFCONF");
    /*@=moduncon@*/
    /*@+matchanyintegral@*/
    *lenp = lifc.lifc_len;
    /*@=matchanyintegral@*/
    return ret;
}
#endif

#ifdef LINUX_IPV6_HACK
/* Read IPv6 addresses out of /proc/net/if_inet6, since there isn't
   (currently) any ioctl to return them.  */
struct linux_ipv6_addr_list {
    struct sockaddr_in6 addr;
    struct linux_ipv6_addr_list *next;
};
static struct linux_ipv6_addr_list *
get_linux_ipv6_addrs ()
{
    struct linux_ipv6_addr_list *lst = 0;
    FILE *f;

    /* _PATH_PROCNET_IFINET6 */
    f = fopen("/proc/net/if_inet6", "r");
    if (f) {
	char ifname[21];
	unsigned int idx, pfxlen, scope, dadstat;
	struct in6_addr a6;
	struct linux_ipv6_addr_list *nw;
	int i;
	unsigned int addrbyte[16];

	while (fscanf(f,
		      "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x"
		      " %2x %2x %2x %2x %20s\n",
		      &addrbyte[0], &addrbyte[1], &addrbyte[2], &addrbyte[3],
		      &addrbyte[4], &addrbyte[5], &addrbyte[6], &addrbyte[7],
		      &addrbyte[8], &addrbyte[9], &addrbyte[10], &addrbyte[11],
		      &addrbyte[12], &addrbyte[13], &addrbyte[14],
		      &addrbyte[15],
		      &idx, &pfxlen, &scope, &dadstat, ifname) != EOF) {
	    for (i = 0; i < 16; i++)
		a6.s6_addr[i] = addrbyte[i];
	    if (scope != 0)
		continue;
#if 0 /* These symbol names are as used by ifconfig, but none of the
	 system header files export them.  Dig up the kernel versions
	 someday and see if they're exported.  */
	    switch (scope) {
	    case 0:
	    default:
		break;
	    case IPV6_ADDR_LINKLOCAL:
	    case IPV6_ADDR_SITELOCAL:
	    case IPV6_ADDR_COMPATv4:
	    case IPV6_ADDR_LOOPBACK:
		continue;
	    }
#endif
	    nw = malloc (sizeof (struct linux_ipv6_addr_list));
	    if (nw == 0)
		continue;
	    memset (nw, 0, sizeof (*nw));
	    nw->addr.sin6_addr = a6;
	    nw->addr.sin6_family = AF_INET6;
	    /* Ignore other fields, we don't actually use them here.  */
	    nw->next = lst;
	    lst = nw;
	}
	fclose (f);
    }
    return lst;
}
#endif

/* Return value is errno if internal stuff failed, otherwise zero,
   even in the case where a called function terminated the iteration.

   If one of the callback functions wants to pass back an error
   indication, it should do it via some field pointed to by the DATA
   argument.  */

#ifdef HAVE_IFADDRS_H

static int
foreach_localaddr (/*@null@*/ void *data,
		   int (*pass1fn) (/*@null@*/ void *, struct sockaddr *) /*@*/,
		   /*@null@*/ int (*betweenfn) (/*@null@*/ void *) /*@*/,
		   /*@null@*/ int (*pass2fn) (/*@null@*/ void *,
					      struct sockaddr *) /*@*/)
#if defined(DEBUG) || defined(TEST)
     /*@modifies fileSystem@*/
#endif
{
    struct ifaddrs *ifp_head, *ifp, *ifp2;
    int match;

    if (getifaddrs (&ifp_head) < 0)
	return errno;
    for (ifp = ifp_head; ifp; ifp = ifp->ifa_next) {
#ifdef DEBUG
	printifaddr (ifp);
#endif
	if ((ifp->ifa_flags & IFF_UP) == 0)
	    continue;
	if (ifp->ifa_flags & IFF_LOOPBACK) {
	    ifp->ifa_flags &= ~IFF_UP;
	    continue;
	}
	/* If this address is a duplicate, punt.  */
	match = 0;
	for (ifp2 = ifp_head; ifp2 && ifp2 != ifp; ifp2 = ifp2->ifa_next) {
	    if ((ifp2->ifa_flags & IFF_UP) == 0)
		continue;
	    if (ifp2->ifa_flags & IFF_LOOPBACK)
		continue;
	    if (addr_eq (ifp->ifa_addr, ifp2->ifa_addr)) {
		match = 1;
		ifp->ifa_flags &= ~IFF_UP;
		break;
	    }
	}
	if (match)
	    continue;
	if ((*pass1fn) (data, ifp->ifa_addr))
	    goto punt;
    }
    if (betweenfn && (*betweenfn)(data))
	goto punt;
    if (pass2fn)
	for (ifp = ifp_head; ifp; ifp = ifp->ifa_next) {
	    if (ifp->ifa_flags & IFF_UP)
		if ((*pass2fn) (data, ifp->ifa_addr))
		    goto punt;
	}
 punt:
    freeifaddrs (ifp_head);
    return 0;
}

#elif defined (SIOCGLIFNUM) /* Solaris 8 and later; Sol 7? */

static int
foreach_localaddr (/*@null@*/ void *data,
		   int (*pass1fn) (/*@null@*/ void *, struct sockaddr *) /*@*/,
		   /*@null@*/ int (*betweenfn) (/*@null@*/ void *) /*@*/,
		   /*@null@*/ int (*pass2fn) (/*@null@*/ void *,
					      struct sockaddr *) /*@*/)
#if defined(DEBUG) || defined(TEST)
     /*@modifies fileSystem@*/
#endif
{
    /* Okay, this is kind of odd.  We have to use each of the address
       families we care about, because with an AF_INET socket, extra
       interfaces like hme0:1 that have only AF_INET6 addresses will
       cause errors.  Similarly, if hme0 has more AF_INET addresses
       than AF_INET6 addresses, we won't be able to retrieve all of
       the AF_INET addresses if we use an AF_INET6 socket.  Since
       neither family is guaranteed to have the greater number of
       addresses, we should use both.

       If it weren't for this little quirk, we could use one socket of
       any type, and ask for addresses of all types.  At least, it
       seems to work that way.  */

    static const int afs[] = { AF_INET, AF_NS, AF_INET6 };
#define N_AFS (sizeof (afs) / sizeof (afs[0]))
    struct {
	int af;
	int sock;
	void *buf;
	size_t buf_size;
	struct lifnum lifnum;
    } afp[N_AFS];
    int code, i, j;
    int retval = 0, afidx;
    krb5_error_code sock_err = 0;
    struct lifreq *lifr, lifreq, *lifr2;

#define FOREACH_AF() for (afidx = 0; afidx < N_AFS; afidx++)
#define P (afp[afidx])

    /* init */
    FOREACH_AF () {
	P.af = afs[afidx];
	P.sock = -1;
	P.buf = 0;
    }

    /* first pass: get raw data, discard uninteresting addresses, callback */
    FOREACH_AF () {
	Tprintf (("trying af %d...\n", P.af));
	P.sock = socket (P.af, USE_TYPE, USE_PROTO);
	if (P.sock < 0) {
	    sock_err = SOCKET_ERROR;
	    Tperror ("socket");
	    continue;
	}

	P.lifnum.lifn_family = P.af;
	P.lifnum.lifn_flags = 0;
	P.lifnum.lifn_count = 0;
	code = ioctl (P.sock, SIOCGLIFNUM, &P.lifnum);
	if (code) {
	    Tperror ("ioctl(SIOCGLIFNUM)");
	    retval = errno;
	    goto punt;
	}

	P.buf_size = P.lifnum.lifn_count * sizeof (struct lifreq) * 2;
	P.buf = malloc (P.buf_size);
	if (P.buf == NULL) {
	    retval = errno;
	    goto punt;
	}

	code = get_lifconf (P.af, P.sock, &P.buf_size, P.buf);
	if (code < 0) {
	    retval = errno;
	    goto punt;
	}

	for (i = 0; i < P.buf_size; i+= sizeof (*lifr)) {
	    lifr = (struct lifreq *)((caddr_t) P.buf+i);

	    strncpy(lifreq.lifr_name, lifr->lifr_name,
		    sizeof (lifreq.lifr_name));
	    Tprintf (("interface %s\n", lifreq.lifr_name));
	    /*@-moduncon@*/ /* ioctl unknown to lclint */
	    if (ioctl (P.sock, SIOCGLIFFLAGS, (char *)&lifreq) < 0) {
		Tperror ("ioctl(SIOCGLIFFLAGS)");
	    skip:
		/* mark for next pass */
		lifr->lifr_name[0] = '\0';
		continue;
	    }
	    /*@=moduncon@*/

#ifdef IFF_LOOPBACK
	    /* None of the current callers want loopback addresses.  */
	    if (lifreq.lifr_flags & IFF_LOOPBACK) {
		Tprintf (("  loopback\n"));
		goto skip;
	    }
#endif
	    /* Ignore interfaces that are down.  */
	    if ((lifreq.lifr_flags & IFF_UP) == 0) {
		Tprintf (("  down\n"));
		goto skip;
	    }

	    /* Make sure we didn't process this address already.  */
	    for (j = 0; j < i; j += sizeof (*lifr2)) {
		lifr2 = (struct lifreq *)((caddr_t) P.buf+j);
		if (lifr2->lifr_name[0] == '\0')
		    continue;
		if (lifr2->lifr_addr.ss_family == lifr->lifr_addr.ss_family
		    /* Compare address info.  If this isn't good enough --
		       i.e., if random padding bytes turn out to differ
		       when the addresses are the same -- then we'll have
		       to do it on a per address family basis.  */
		    && !memcmp (&lifr2->lifr_addr, &lifr->lifr_addr,
				sizeof (*lifr))) {
		    Tprintf (("  duplicate addr\n"));
		    goto skip;
		}
	    }

	    /*@-moduncon@*/
	    if ((*pass1fn) (data, ss2sa (&lifr->lifr_addr)))
		goto punt;
	    /*@=moduncon@*/
	}
    }

    /* Did we actually get any working sockets?  */
    FOREACH_AF ()
	if (P.sock != -1)
	    goto have_working_socket;
    retval = sock_err;
    goto punt;
have_working_socket:

    /*@-moduncon@*/
    if (betweenfn != NULL && (*betweenfn)(data))
	goto punt;
    /*@=moduncon@*/

    if (pass2fn)
	FOREACH_AF ()
	    if (P.sock >= 0) {
		for (i = 0; i < P.buf_size; i+= sizeof (*lifr)) {
		    lifr = (struct lifreq *)((caddr_t) P.buf+i);

		    if (lifr->lifr_name[0] == '\0')
			/* Marked in first pass to be ignored.  */
			continue;

		    /*@-moduncon@*/
		    if ((*pass2fn) (data, ss2sa (&lifr->lifr_addr)))
			goto punt;
		    /*@=moduncon@*/
		}
	    }
punt:
    FOREACH_AF () {
	/*@-moduncon@*/
	closesocket(P.sock);
	/*@=moduncon@*/
	free (P.buf);
    }

    return retval;
}

#else /* not defined (SIOCGLIFNUM) */

#define SLOP (sizeof (struct ifreq) + 128)

static int
foreach_localaddr (/*@null@*/ void *data,
		   int (*pass1fn) (/*@null@*/ void *, struct sockaddr *) /*@*/,
		   /*@null@*/ int (*betweenfn) (/*@null@*/ void *) /*@*/,
		   /*@null@*/ int (*pass2fn) (/*@null@*/ void *,
					      struct sockaddr *) /*@*/)
#if defined(DEBUG) || defined(TEST)
     /*@modifies fileSystem@*/
#endif
{
    struct ifreq *ifr, ifreq, *ifr2;
    int s, code;
    int est_if_count = 8;
    size_t est_ifreq_size;
    char *buf = 0;
    size_t current_buf_size = 0, size, n, i, j;
#ifdef SIOCGSIZIFCONF
    int ifconfsize = -1;
#endif
    int retval = 0;
#ifdef SIOCGIFNUM
    int numifs = -1;
#endif
#ifdef LINUX_IPV6_HACK
    struct linux_ipv6_addr_list *linux_ipv6_addrs = get_linux_ipv6_addrs ();
    struct linux_ipv6_addr_list *lx_v6;
#endif

    s = socket (USE_AF, USE_TYPE, USE_PROTO);
    if (s < 0)
	return SOCKET_ERRNO;

    /* At least on NetBSD, an ifreq can hold an IPv4 address, but
       isn't big enough for an IPv6 or ethernet address.  So add a
       little more space.  */
    est_ifreq_size = sizeof (struct ifreq) + 8;
#ifdef SIOCGSIZIFCONF
    code = ioctl (s, SIOCGSIZIFCONF, &ifconfsize);
    if (!code) {
	current_buf_size = ifconfsize;
	est_if_count = ifconfsize / est_ifreq_size;
    }
#elif defined (SIOCGIFNUM)
    code = ioctl (s, SIOCGIFNUM, &numifs);
    if (!code && numifs > 0)
	est_if_count = numifs;
#endif
    if (current_buf_size == 0)
	current_buf_size = est_ifreq_size * est_if_count + SLOP;
    buf = malloc (current_buf_size);
    if (buf == NULL)
	return errno;

 ask_again:
    size = current_buf_size;
    code = get_ifconf (s, &size, buf);
    if (code < 0) {
	retval = errno;
	/*@-moduncon@*/ /* close() unknown to lclint */
	closesocket (s);
	/*@=moduncon@*/
	free (buf);
	return retval;
    }
    /* Test that the buffer was big enough that another ifreq could've
       fit easily, if the OS wanted to provide one.  That seems to be
       the only indication we get, complicated by the fact that the
       associated address may make the required storage a little
       bigger than the size of an ifreq.  */
    if (current_buf_size - size < SLOP
#ifdef SIOCGSIZIFCONF
	/* Unless we hear SIOCGSIZIFCONF is broken somewhere, let's
	   trust the value it returns.  */
	&& ifconfsize <= 0
#elif defined (SIOCGIFNUM)
	&& numifs <= 0
#endif
	/* And we need *some* sort of bounds.  */
	&& current_buf_size <= 100000
	) {
	size_t new_size;

	est_if_count *= 2;
	new_size = est_ifreq_size * est_if_count + SLOP;
	buf = grow_or_free (buf, new_size);
	if (buf == 0)
	    return errno;
	current_buf_size = new_size;
	goto ask_again;
    }

    n = size;
    if (n > current_buf_size)
	n = current_buf_size;

    /* Note: Apparently some systems put the size (used or wanted?)
       into the start of the buffer, just none that I'm actually
       using.  Fix this when there's such a test system available.
       The Samba mailing list archives mention that NTP looks for the
       size on these systems: *-fujitsu-uxp* *-ncr-sysv4*
       *-univel-sysv*.  */
    for (i = 0; i < n; i+= ifreq_size(*ifr) ) {
	ifr = (struct ifreq *)((caddr_t) buf+i);

	strncpy(ifreq.ifr_name, ifr->ifr_name, sizeof (ifreq.ifr_name));
	Tprintf (("interface %s\n", ifreq.ifr_name));
	/*@-moduncon@*/ /* ioctl unknown to lclint */
	if (ioctl (s, SIOCGIFFLAGS, (char *)&ifreq) < 0) {
	skip:
	    /* mark for next pass */
	    ifr->ifr_name[0] = '\0';
	    continue;
	}
	/*@=moduncon@*/

#ifdef IFF_LOOPBACK
	/* None of the current callers want loopback addresses.  */
	if (ifreq.ifr_flags & IFF_LOOPBACK) {
	    Tprintf (("  loopback\n"));
	    goto skip;
	}
#endif
	/* Ignore interfaces that are down.  */
	if ((ifreq.ifr_flags & IFF_UP) == 0) {
	    Tprintf (("  down\n"));
	    goto skip;
	}

	/* Make sure we didn't process this address already.  */
	for (j = 0; j < i; j += ifreq_size(*ifr2)) {
	    ifr2 = (struct ifreq *)((caddr_t) buf+j);
	    if (ifr2->ifr_name[0] == '\0')
		continue;
	    if (ifr2->ifr_addr.sa_family == ifr->ifr_addr.sa_family
		&& ifreq_size (*ifr) == ifreq_size (*ifr2)
		/* Compare address info.  If this isn't good enough --
		   i.e., if random padding bytes turn out to differ
		   when the addresses are the same -- then we'll have
		   to do it on a per address family basis.  */
		&& !memcmp (&ifr2->ifr_addr.sa_data, &ifr->ifr_addr.sa_data,
			    (ifreq_size (*ifr)
			     - offsetof (struct ifreq, ifr_addr.sa_data)))) {
		Tprintf (("  duplicate addr\n"));
		goto skip;
	    }
	}

	/*@-moduncon@*/
	if ((*pass1fn) (data, &ifr->ifr_addr))
	    goto punt;
	/*@=moduncon@*/
    }

#ifdef LINUX_IPV6_HACK
    for (lx_v6 = linux_ipv6_addrs; lx_v6; lx_v6 = lx_v6->next)
	if ((*pass1fn) (data, (struct sockaddr *) &lx_v6->addr))
	    goto punt;
#endif

    /*@-moduncon@*/
    if (betweenfn != NULL && (*betweenfn)(data))
	goto punt;
    /*@=moduncon@*/

    if (pass2fn) {
	for (i = 0; i < n; i+= ifreq_size(*ifr) ) {
	    ifr = (struct ifreq *)((caddr_t) buf+i);

	    if (ifr->ifr_name[0] == '\0')
		/* Marked in first pass to be ignored.  */
		continue;

	    /*@-moduncon@*/
	    if ((*pass2fn) (data, &ifr->ifr_addr))
		goto punt;
	    /*@=moduncon@*/
	}
#ifdef LINUX_IPV6_HACK
	for (lx_v6 = linux_ipv6_addrs; lx_v6; lx_v6 = lx_v6->next)
	    if ((*pass2fn) (data, (struct sockaddr *) &lx_v6->addr))
		goto punt;
#endif
    }
 punt:
    /*@-moduncon@*/
    closesocket(s);
    /*@=moduncon@*/
    free (buf);
#ifdef LINUX_IPV6_HACK
    while (linux_ipv6_addrs) {
	lx_v6 = linux_ipv6_addrs->next;
	free (linux_ipv6_addrs);
	linux_ipv6_addrs = lx_v6;
    }
#endif

    return retval;
}

#endif /* not HAVE_IFADDRS_H and not SIOCGLIFNUM */

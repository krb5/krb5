/*
 * pty_make_sane_hostname: Make a sane hostname from an IP address.
 * This returns allocated memory!
 * 
 * Copyright 1999, 2000, 2001 by the Massachusetts Institute of
 * Technology.
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appear in all
 * copies and that both that copyright notice and this permission
 * notice appear in supporting documentation, and that the name of
 * M.I.T. not be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability
 * of this software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 * 
 */
#include <com_err.h>
#include "pty-int.h"
#include <sys/socket.h>
#include "libpty.h"
#include <arpa/inet.h>

static size_t
sockaddrlen (const struct sockaddr *addr)
{
#ifdef HAVE_SA_LEN
    return addr->sa_len;
#else
    if (addr->sa_family == AF_INET)
	return sizeof (struct sockaddr_in);
#ifdef KRB5_USE_INET6
    if (addr->sa_family == AF_INET6)
	return sizeof (struct sockaddr_in6);
#endif
    /* unknown address family */
    return 0;
#endif
}

static void
downcase (char *s)
{
    for (; *s != '\0'; s++)
	*s = tolower (*s);
}

static long
do_ntoa(const struct sockaddr *addr, size_t hostlen, char **out)
{
#ifdef HAVE_GETNAMEINFO
    char addrbuf[NI_MAXHOST];
    if (getnameinfo (addr, sockaddrlen (addr), addrbuf, sizeof (addrbuf),
		     (char *)0, 0, NI_NUMERICHOST) == 0)
	strncpy(*out, addrbuf, hostlen);
    else
	strncpy(*out, "??", hostlen);
#else
    if (addr->sa_family == AF_INET)
	strncpy(*out, inet_ntoa(((const struct sockaddr_in *)addr)->sin_addr),
		hostlen);
    else
	strncpy(*out, "??", hostlen);
#endif
    (*out)[hostlen - 1] = '\0';
    return 0;
}

long
pty_make_sane_hostname(const struct sockaddr *addr, int maxlen,
		       int strip_ldomain, int always_ipaddr, char **out)
{
#ifdef HAVE_GETNAMEINFO
    struct addrinfo *ai;
    char addrbuf[NI_MAXHOST];
#else
    struct hostent *hp;
#endif
#ifndef NO_UT_HOST
    struct utmp ut;
#else
    struct utmpx utx;
#endif
    char *cp, *domain;
    char lhost[MAXHOSTNAMELEN];
    size_t ut_host_len;

    *out = NULL;
    if (maxlen && maxlen < 16)
	/* assume they meant 16, otherwise IP addr won't fit */
	maxlen = 16;
#ifndef NO_UT_HOST
    ut_host_len = sizeof (ut.ut_host);
#else
    ut_host_len = sizeof (utx.ut_host);
#endif
    if (maxlen == 0)
	maxlen = ut_host_len;
    *out = malloc(ut_host_len);
    if (*out == NULL)
	return ENOMEM;

    if (always_ipaddr)
    use_ipaddr:
	return do_ntoa(addr, ut_host_len, out);

#ifdef HAVE_GETNAMEINFO
    /* If we didn't want to chop off the local domain, this would be
       much simpler -- just a single getnameinfo call and a strncpy.  */
    if (getnameinfo(addr, sockaddrlen (addr), addrbuf, sizeof (addrbuf),
		    (char *) NULL, 0, NI_NAMEREQD) != 0)
	goto use_ipaddr;
    downcase (addrbuf);
    if (strip_ldomain) {
	struct addrinfo hints;
	(void) gethostname(lhost, sizeof (lhost));
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = AI_CANONNAME;
	if (getaddrinfo(lhost, (char *)NULL, &hints, &ai) == 0
	    && ai != NULL) {
		if (ai->ai_canonname != NULL) {
			downcase (ai->ai_canonname);
			domain = strchr (ai->ai_canonname, '.');
			if (domain != NULL) {
				cp = strstr (addrbuf, domain);
				if (cp != NULL)
					*cp = '\0';
			}
		}
		freeaddrinfo (ai);
	}
    }
    strncpy(*out, addrbuf, ut_host_len);
    (*out)[ut_host_len - 1] = '\0';
#else /* old gethostbyaddr interface; how quaint :-) */
    if (addr->sa_family == AF_INET)
	hp = gethostbyaddr((char *)&((struct sockaddr_in *)addr)->sin_addr,
			   sizeof (struct in_addr), addr->sa_family);
    else
	hp = NULL;
    if (hp == NULL) {
	return do_ntoa(addr, ut_host_len, out);
    }
    strncpy(*out, hp->h_name, ut_host_len);
    (*out)[ut_host_len - 1] = '\0';
    downcase (*out);

    if (strip_ldomain) {
	(void) gethostname(lhost, sizeof (lhost));
	hp = gethostbyname(lhost);
	if (hp != NULL) {
	    strncpy(lhost, hp->h_name, sizeof (lhost));
	    domain = strchr(lhost, '.');
	    if (domain != NULL) {
		downcase (domain);
		cp = strstr(*out, domain);
		if (cp != NULL)
		    *cp = '\0';
	    }
	}
    }
#endif

    if (strlen(*out) >= maxlen) {
	return do_ntoa(addr, ut_host_len, out);
    }
    return 0;
}

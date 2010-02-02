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
#include "com_err.h"
#include "pty-int.h"
#include <sys/socket.h>
#include "libpty.h"
#include <arpa/inet.h>

#include "socket-utils.h"
#include "fake-addrinfo.h"

static void
downcase (char *s)
{
    for (; *s != '\0'; s++)
	*s = tolower ((int) *s);
}

long
pty_make_sane_hostname(const struct sockaddr *addr, int maxlen,
		       int strip_ldomain, int always_ipaddr, char **out)
{
    struct addrinfo *ai = 0;
    char addrbuf[NI_MAXHOST];
#ifdef HAVE_STRUCT_UTMP_UT_HOST
    struct utmp ut;
#else
    struct utmpx utx;
#endif
    char *cp, *domain;
    char lhost[MAXHOSTNAMELEN];
    size_t ut_host_len;

    /* Note that on some systems (e.g., AIX 4.3.3), we may get an IPv6
       address such as ::FFFF:18.18.1.71 when an IPv4 connection comes
       in.  That's okay; at least on AIX, getnameinfo will deal with
       that properly.  */

    *out = NULL;
    if (maxlen && maxlen < 16)
	/* assume they meant 16, otherwise IPv4 addr won't fit */
	maxlen = 16;
#ifdef HAVE_STRUCT_UTMP_UT_HOST
    ut_host_len = sizeof (ut.ut_host);
#else
    ut_host_len = sizeof (utx.ut_host);
#endif
    if (maxlen == 0)
	maxlen = ut_host_len;
    *out = malloc(ut_host_len);
    if (*out == NULL)
	return ENOMEM;

    if (always_ipaddr) {
    use_ipaddr:
	if (getnameinfo (addr, socklen (addr), addrbuf, sizeof (addrbuf),
			 (char *)0, 0, NI_NUMERICHOST) == 0)
	    strncpy(*out, addrbuf, ut_host_len);
	else
	    strncpy(*out, "??", ut_host_len);
	(*out)[ut_host_len - 1] = '\0';
	return 0;
    }

    /* If we didn't want to chop off the local domain, this would be
       much simpler -- just a single getnameinfo call and a strncpy.  */
    if (getnameinfo(addr, socklen (addr), addrbuf, sizeof (addrbuf),
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
    if (strlen(*out) >= maxlen)
	goto use_ipaddr;
    return 0;
}

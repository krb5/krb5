/*
 * pty_make_sane_hostname: Make a sane hostname from an IP address.
 * This returns allocated memory!
 * 
 * Copyright 1999 by the Massachusetts Institute of Technology.
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appear in all
 * copies and that both that copyright notice and this permission
 * notice appear in supporting documentation, and that the name of
 * M.I.T. not be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability
 * of this software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 * 
 */
#include <com_err.h>
#include <arpa/inet.h>
#include "libpty.h"
#include "pty-int.h"

static long
do_ntoa(struct sockaddr_in *addr,
		     size_t hostlen,
		     char **out)
{
    strncpy(*out, inet_ntoa(addr->sin_addr), hostlen);
    (*out)[hostlen - 1] = '\0';
    return 0;
}

long
pty_make_sane_hostname(struct sockaddr_in *addr,
		       int maxlen,
		       int strip_ldomain,
		       int always_ipaddr,
		       char **out)
{
    struct hostent *hp;
#ifndef NO_UT_HOST
    struct utmp ut;
#else
    struct utmpx utx;
#endif
    char *scratch;
    char *cp, *domain;
    char lhost[MAXHOSTNAMELEN];
    size_t ut_host_len;

    *out = NULL;
    if (maxlen && maxlen < 16)
	return -1;		/* XXX */
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

    if (always_ipaddr) {
	return do_ntoa(addr, ut_host_len, out);
    }
    hp = gethostbyaddr((char *)&addr->sin_addr, sizeof (struct in_addr),
		       addr->sin_family);
    if (hp == NULL) {
	return do_ntoa(addr, ut_host_len, out);
    }
    strncpy(*out, hp->h_name, ut_host_len);
    (*out)[ut_host_len - 1] = '\0';
    for (cp = *out; *cp != '\0'; cp++)
	*cp = tolower(*cp);

    if (strip_ldomain) {
	(void) gethostname(lhost, sizeof (lhost));
	hp = gethostbyname(lhost);
	if (hp != NULL) {
	    strncpy(lhost, hp->h_name, sizeof (lhost));
	    domain = strchr(lhost, '.');
	    if (domain != NULL) {
		for (cp = domain; *cp != '\0'; cp++)
		    *cp = tolower(*cp);
		cp = strstr(*out, domain);
		if (cp != NULL)
		    *cp = '\0';
	    }
	}
    }

    if (strlen(*out) >= maxlen) {
	return do_ntoa(addr, ut_host_len, out);
    }
    return 0;
}

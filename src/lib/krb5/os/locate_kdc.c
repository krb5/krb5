/*
 * lib/krb5/os/locate_kdc.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * get socket addresses for KDC.
 */

#define NEED_SOCKETS
#include "k5-int.h"
#include <stdio.h>

/*
 * returns count of number of addresses found
 * if master is non-NULL, it is filled in with the index of
 * the master kdc
 */

krb5_error_code
krb5_locate_kdc(context, realm, addr_pp, naddrs, master_index, nmasters)
    krb5_context context;
    const krb5_data *realm;
    struct sockaddr **addr_pp;
    int *naddrs;
    int *master_index;
    int *nmasters;
{
    const char	*realm_kdc_names[4];
    char **masterlist, **hostlist, *host, *port, *cp;
    krb5_error_code code;
    int i, j, out, count, ismaster;
    struct sockaddr *addr_p;
    struct sockaddr_in *sin_p;
    struct hostent *hp;
    struct servent *sp;
#ifdef HAVE_NETINET_IN_H
    u_short udpport = htons(KRB5_DEFAULT_PORT);
    u_short sec_udpport = htons(KRB5_DEFAULT_SEC_PORT);
#endif

    if ((host = malloc(realm->length + 1)) == NULL) 
	return ENOMEM;

    strncpy(host, realm->data, realm->length);
    host[realm->length] = '\0';
    hostlist = 0;

    masterlist = NULL;

    realm_kdc_names[0] = "realms";
    realm_kdc_names[1] = host;
    realm_kdc_names[2] = "kdc";
    realm_kdc_names[3] = 0;

    code = profile_get_values(context->profile, realm_kdc_names, &hostlist);

    if (code) {
	if (code == PROF_NO_SECTION || code == PROF_NO_RELATION)
	    code = KRB5_REALM_UNKNOWN;
	krb5_xfree(host);
	return code;
    }

#ifdef HAVE_NETINET_IN_H
    if ((sp = getservbyname(KDC_PORTNAME, "udp")))
	udpport = sp->s_port;
    if ((sp = getservbyname(KDC_SECONDARY_PORTNAME, "udp")))
	sec_udpport = sp->s_port;
#endif
    if (sec_udpport == udpport)
	sec_udpport = 0;

    count = 0;
    while (hostlist && hostlist[count])
	    count++;
    
    if (count == 0) {
	krb5_xfree(host);
	*naddrs = 0;
	return 0;
    }
    
    if (master_index) {
        *master_index = 0;
	*nmasters = 0;

	realm_kdc_names[0] = "realms";
	realm_kdc_names[1] = host;
	realm_kdc_names[2] = "admin_server";
	realm_kdc_names[3] = 0;

	code = profile_get_values(context->profile, realm_kdc_names,
				  &masterlist);

	krb5_xfree(host);

	if (code == 0) {
	    for (i=0; masterlist[i]; i++) {
		host = masterlist[i];

		/*
		 * Strip off excess whitespace
		 */
		cp = strchr(host, ' ');
		if (cp)
		    *cp = 0;
		cp = strchr(host, '\t');
		if (cp)
		    *cp = 0;
		cp = strchr(host, ':');
		if (cp)
		    *cp = 0;
	    }
	}
    } else {
	krb5_xfree(host);
    }

    /* at this point, if master is non-NULL, then either the master kdc
       is required, and there is one, or the master kdc is not required,
       and there may or may not be one. */

#ifdef HAVE_NETINET_IN_H
    if (sec_udpport)
	    count = count * 2;
#endif

    addr_p = (struct sockaddr *)malloc (sizeof (struct sockaddr) * count);
    if (addr_p == NULL)
	return ENOMEM;

    for (i=0, out=0; hostlist[i]; i++) {
	host = hostlist[i];
	/*
	 * Strip off excess whitespace
	 */
	cp = strchr(host, ' ');
	if (cp)
	    *cp = 0;
	cp = strchr(host, '\t');
	if (cp)
	    *cp = 0;
	port = strchr(host, ':');
	if (port) {
	    *port = 0;
	    port++;
	}

	if ((hp = gethostbyname(hostlist[i])) == 0) {
	    free(hostlist[i]);
	    hostlist[i] = 0;
	    continue;
	}

	ismaster = 0;
	if (masterlist) {
	    for (j=0; masterlist[j]; j++) {
		if (strcasecmp(hostlist[i], masterlist[j]) == 0) {
		    *master_index = out;
		    ismaster = 1;
		}
	    }
	}

	switch (hp->h_addrtype) {

#ifdef HAVE_NETINET_IN_H
	case AF_INET:
	    for (j=0; hp->h_addr_list[j]; j++) {
		sin_p = (struct sockaddr_in *) &addr_p[out++];
		memset ((char *)sin_p, 0, sizeof(struct sockaddr));
		sin_p->sin_family = hp->h_addrtype;
		sin_p->sin_port = port ? htons(atoi(port)) : udpport;
		memcpy((char *)&sin_p->sin_addr,
		       (char *)hp->h_addr_list[j],
		       sizeof(struct in_addr));
		if (out+1 >= count) {
		    count += 5;
		    addr_p = (struct sockaddr *)
			realloc ((char *)addr_p,
				 sizeof(struct sockaddr) * count);
		    if (addr_p == NULL)
			return ENOMEM;
		}
		if (sec_udpport && !port) {
		    addr_p[out] = addr_p[out-1];
  		    sin_p = (struct sockaddr_in *) &addr_p[out++];
		    sin_p->sin_port = sec_udpport;
		}
	    }
	    break;
#endif
	default:
	    break;
	}
	if (ismaster)
	    *nmasters = out - *master_index;

	/* Free the hostlist entry we are looping over. */
	free(hostlist[i]);
	hostlist[i] = 0;
    }

    if (masterlist) {
       for (i=0; masterlist[i]; i++)
	  free(masterlist[i]);
       free(masterlist);
    }

    free ((char *)hostlist);

    if (out == 0) {     /* Couldn't resolve any KDC names */
        free (addr_p);
        return KRB5_REALM_CANT_RESOLVE;
    }

    *addr_pp = addr_p;
    *naddrs = out;
    return 0;
}

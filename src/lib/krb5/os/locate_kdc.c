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
 */

krb5_error_code
krb5_locate_kdc(context, realm, addr_pp, naddrs)
    krb5_context context;
    const krb5_data *realm;
    struct sockaddr **addr_pp;
    int *naddrs;
{
    const char	*realm_kdc_names[4];
    char **hostlist, *host, *port, *cp;
    krb5_error_code code;
    int i, j, out, count;
    struct sockaddr *addr_p;
    struct sockaddr_in *sin_p;
    struct hostent *hp;
    struct servent *sp;
#ifdef KRB5_USE_INET
    u_short udpport = htons(KRB5_DEFAULT_PORT);
    u_short sec_udpport = htons(KRB5_DEFAULT_SEC_PORT);
#endif

    if ((host = malloc(realm->length + 1)) == NULL) 
	return ENOMEM;

    strncpy(host, realm->data, realm->length);
    host[realm->length] = '\0';
    hostlist = 0;
    
    realm_kdc_names[0] = "realms";
    realm_kdc_names[1] = host;
    realm_kdc_names[2] = "kdc";
    realm_kdc_names[3] = 0;

    code = profile_get_values(context->profile, realm_kdc_names, &hostlist);
    krb5_xfree(host);

    if (code == PROF_NO_SECTION)
	return KRB5_REALM_UNKNOWN;
    if (code == PROF_NO_RELATION)
	return KRB5_CONFIG_BADFORMAT;
    if (code)
	return code;

#ifdef KRB5_USE_INET
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
	*naddrs = 0;
	return 0;
    }
    
#ifdef KRB5_USE_INET
    if (sec_udpport)
	    count = count * 2;
#endif

    addr_p = (struct sockaddr *)malloc (sizeof (struct sockaddr) * count);

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
	hp = gethostbyname(hostlist[i]);
	if (hp != 0) {
	    switch (hp->h_addrtype) {
#ifdef KRB5_USE_INET
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
	}
	free(hostlist[i]);
	hostlist[i] = 0;
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

/*
 * lib/krb4/send_to_kdc.c
 *
 * Copyright 1987-2002 by the Massachusetts Institute of Technology.
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
 */

#include "krb.h"
#include "krbports.h"
#include "prot.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "krb5/autoconf.h"
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "port-sockets.h"
#include "fake-addrinfo.h"
#include "k5-int.h"
#include "krb4int.h"

#define S_AD_SZ sizeof(struct sockaddr_in)

/* These are really defaults from getservbyname() or hardcoded. */
static int cached_krb_udp_port = 0;
static int cached_krbsec_udp_port = 0;

int krb4int_send_to_kdc_addr(KTEXT, KTEXT, char *,
			     struct sockaddr *, socklen_t *);

#ifdef DEBUG
static char *prog = "send_to_kdc";
#endif

/*
 * send_to_kdc() sends a message to the Kerberos authentication
 * server(s) in the given realm and returns the reply message.
 * The "pkt" argument points to the message to be sent to Kerberos;
 * the "rpkt" argument will be filled in with Kerberos' reply.
 * The "realm" argument indicates the realm of the Kerberos server(s)
 * to transact with.  If the realm is null, the local realm is used.
 *
 * If more than one Kerberos server is known for a given realm,
 * different servers will be queried until one of them replies.
 * Several attempts (retries) are made for each server before
 * giving up entirely.
 *
 * The following results can be returned:
 *
 * KSUCCESS	- an answer was received from a Kerberos host
 *
 * SKDC_CANT    - can't get local realm
 *              - can't find "kerberos" in /etc/services database
 *              - can't open socket
 *              - can't bind socket
 *              - all ports in use
 *              - couldn't find any Kerberos host
 *
 * SKDC_RETRY   - couldn't get an answer from any Kerberos server,
 *		  after several retries
 */

int
krb4int_send_to_kdc_addr(
    KTEXT pkt, KTEXT rpkt, char *realm,
    struct sockaddr *addr, socklen_t *addrlen)
{
    struct addrlist	al = ADDRLIST_INIT;
    char		lrealm[REALM_SZ];
    krb5int_access	internals;
    krb5_error_code	retval;
    struct servent	*sp;
    int			krb_udp_port = 0;
    int			krbsec_udp_port = 0;
    char		krbhst[MAXHOSTNAMELEN];
    char		*scol;
    int			i;
    int			err;
    krb5_data		message, reply;

    /*
     * If "realm" is non-null, use that, otherwise get the
     * local realm.
     */
    if (realm)
	strncpy(lrealm, realm, sizeof(lrealm) - 1);
    else {
	if (krb_get_lrealm(lrealm, 1)) {
	    DEB (("%s: can't get local realm\n", prog));
	    return SKDC_CANT;
	}
    }
    lrealm[sizeof(lrealm) - 1] = '\0';
    DEB (("lrealm is %s\n", lrealm));

    retval = krb5int_accessor(&internals, KRB5INT_ACCESS_VERSION);
    if (retval)
	return KFAILURE;

    /* The first time, decide what port to use for the KDC.  */
    if (cached_krb_udp_port == 0) {
	sp = getservbyname("kerberos","udp");
        if (sp)
	    cached_krb_udp_port = sp->s_port;
	else
	    cached_krb_udp_port = htons(KERBEROS_PORT); /* kerberos/udp */
        DEB (("cached_krb_udp_port is %d\n", cached_krb_udp_port));
    }
    /* If kerberos/udp isn't 750, try using kerberos-sec/udp (or 750) 
       as a fallback. */
    if (cached_krbsec_udp_port == 0 && 
	cached_krb_udp_port != htons(KERBEROS_PORT)) {
	sp = getservbyname("kerberos-sec","udp");
        if (sp)
	    cached_krbsec_udp_port = sp->s_port;
	else
	    cached_krbsec_udp_port = htons(KERBEROS_PORT); /* kerberos/udp */
        DEB (("cached_krbsec_udp_port is %d\n", cached_krbsec_udp_port));
    }

    for (i = 1; krb_get_krbhst(krbhst, lrealm, i) == KSUCCESS; ++i) {
#ifdef DEBUG
        if (krb_debug) {
            DEB (("Getting host entry for %s...",krbhst));
            (void) fflush(stdout);
        }
#endif
	if (0 != (scol = strchr(krbhst,':'))) {
	    krb_udp_port = htons(atoi(scol+1));
	    *scol = 0;
	    if (krb_udp_port == 0) {
#ifdef DEBUG
		if (krb_debug) {
		    DEB (("bad port number %s\n",scol+1));
		    (void) fflush(stdout);
		}
#endif
		continue;
	    }
	    krbsec_udp_port = 0;
	} else {
	    krb_udp_port = cached_krb_udp_port;
	    krbsec_udp_port = cached_krbsec_udp_port;
	}
        err = internals.add_host_to_list(&al, krbhst,
					 krb_udp_port, krbsec_udp_port,
					 SOCK_DGRAM, PF_INET);
	if (err) {
	    retval = SKDC_CANT;
	    goto free_al;
	}
    }
    if (al.naddrs == 0) {
	DEB (("%s: can't find any Kerberos host.\n", prog));
        retval = SKDC_CANT;
    }

    message.length = pkt->length;
    message.data = (char *)pkt->dat; /* XXX yuck */
    retval = internals.sendto_udp(NULL, &message, &al, &reply, addr,
				  addrlen);
    DEB(("sendto_udp returns %d\n", retval));
free_al:
    internals.free_addrlist(&al);
    if (retval)
	return SKDC_CANT;
    DEB(("reply.length=%d\n", reply.length));
    if (reply.length > sizeof(rpkt->dat))
	retval = SKDC_CANT;
    rpkt->length = 0;
    if (!retval) {
	memcpy(rpkt->dat, reply.data, reply.length);
	rpkt->length = reply.length;
    }
    krb5_free_data_contents(NULL, &reply);
    return retval;
}

int
send_to_kdc(KTEXT pkt, KTEXT rpkt, char *realm)
{
    return krb4int_send_to_kdc_addr(pkt, rpkt, realm, NULL, NULL);
}

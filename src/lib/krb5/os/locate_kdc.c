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
#ifdef KRB5_DNS_LOOKUP
#ifdef WSHELPER
#include <wshelper.h>
#else /* WSHELPER */
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#endif /* WSHELPER */
#ifndef T_SRV
#define T_SRV 33
#endif /* T_SRV */

/* for old Unixes and friends ... */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#define MAX_DNS_NAMELEN (15*(MAXHOSTNAMELEN + 1)+1)
#endif /* KRB5_DNS_LOOKUP */

/*
 * returns count of number of addresses found
 * if master is non-NULL, it is filled in with the index of
 * the master kdc
 */

static krb5_error_code
krb5_locate_srv_conf(context, realm, name, addr_pp, naddrs, master_index, nmasters)
    krb5_context context;
    const krb5_data *realm;
    const char * name;
    struct sockaddr **addr_pp;
    int *naddrs;
    int *master_index;
    int *nmasters;
{
    const char	*realm_srv_names[4];
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

    realm_srv_names[0] = "realms";
    realm_srv_names[1] = host;
    realm_srv_names[2] = name;
    realm_srv_names[3] = 0;

    code = profile_get_values(context->profile, realm_srv_names, &hostlist);

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

	realm_srv_names[0] = "realms";
	realm_srv_names[1] = host;
	realm_srv_names[2] = "admin_server";
	realm_srv_names[3] = 0;

	code = profile_get_values(context->profile, realm_srv_names,
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

#ifdef KRB5_DNS_LOOKUP

/*
 * Lookup a KDC via DNS SRV records
 */

static krb5_error_code
krb5_locate_srv_dns(realm, service, protocol, addr_pp, naddrs)
    const krb5_data *realm;
    const char *service;
    const char *protocol;
    struct sockaddr **addr_pp;
    int *naddrs;
{
    krb5_error_code code;
    int out, j, count;
    union {
        unsigned char bytes[2048];
        HEADER hdr;
    } answer;
    unsigned char *p=NULL;
    char host[MAX_DNS_NAMELEN];
    struct sockaddr *addr = NULL;
    struct sockaddr_in *sin = NULL;
    struct hostent *hp = NULL;
    int type, class;
    int status, priority, weight, size, len, numanswers, numqueries, rdlen;
    unsigned short port;
    const int hdrsize = sizeof(HEADER);
    struct srv_dns_entry {
	struct srv_dns_entry *next;
	int priority;
	int weight;
	unsigned short port;
	char *host;
    };

    struct srv_dns_entry *head = NULL;
    struct srv_dns_entry *srv = NULL, *entry = NULL;

    out = 0;
    addr = (struct sockaddr *) malloc(sizeof(struct sockaddr));
    if (addr == NULL)
	return ENOMEM;

    count = 1;

    /*
     * First off, build a query of the form:
     *
     * service.protocol.realm
     *
     * which will most likely be something like:
     *
     * _kerberos._udp.REALM
     *
     */

    if ( strlen(service) + strlen(protocol) + realm->length + 5 
         > MAX_DNS_NAMELEN )
        goto out;
    sprintf(host, "%s.%s.%.*s", service, protocol, realm->length,
	    realm->data);

    size = res_search(host, C_IN, T_SRV, answer.bytes, sizeof(answer.bytes));

    if (size < hdrsize)
	goto out;

    /*
     * We got an answer!  First off, parse the header and figure out how
     * many answers we got back.
     */

    p = answer.bytes;

    numqueries = ntohs(answer.hdr.qdcount);
    numanswers = ntohs(answer.hdr.ancount);

    p += sizeof(HEADER);

    /*
     * We need to skip over all of the questions, so we have to iterate
     * over every query record.  dn_expand() is able to tell us the size
     * of compress DNS names, so we use it.
     */

#define INCR_CHECK(x,y) x += y; if (x > size + answer.bytes) goto out
#define CHECK(x,y) if (x + y > size + answer.bytes) goto out
#define NTOHSP(x,y) x[0] << 8 | x[1]; x += y

    while (numqueries--) {
	len = dn_expand(answer.bytes, answer.bytes + size, p, host, sizeof(host));
	if (len < 0)
	    goto out;
	INCR_CHECK(p, len + 4);
    }

    /*
     * We're now pointing at the answer records.  Only process them if
     * they're actually T_SRV records (they might be CNAME records,
     * for instance).
     *
     * But in a DNS reply, if you get a CNAME you always get the associated
     * "real" RR for that CNAME.  RFC 1034, 3.6.2:
     *
     * CNAME RRs cause special action in DNS software.  When a name server
     * fails to find a desired RR in the resource set associated with the
     * domain name, it checks to see if the resource set consists of a CNAME
     * record with a matching class.  If so, the name server includes the CNAME
     * record in the response and restarts the query at the domain name
     * specified in the data field of the CNAME record.  The one exception to
     * this rule is that queries which match the CNAME type are not restarted.
     *
     * In other words, CNAMEs do not need to be expanded by the client.
     */

    while (numanswers--) {

	/* First is the name; use dn_expand to get the compressed size */
	len = dn_expand(answer.bytes, answer.bytes + size, p, host, sizeof(host));
	if (len < 0)
	    goto out;
	INCR_CHECK(p, len);

	/* Next is the query type */
        CHECK(p, 2);
	type = NTOHSP(p,2);

	/* Next is the query class; also skip over 4 byte TTL */
        CHECK(p, 6);
	class = NTOHSP(p,6);

	/* Record data length */

        CHECK(p,2);
	rdlen = NTOHSP(p,2);

	/*
	 * If this is an SRV record, process it.  Record format is:
	 *
	 * Priority
	 * Weight
	 * Port
	 * Server name
	 */

	if (class == C_IN && type == T_SRV) {
            CHECK(p,2);
	    priority = NTOHSP(p,2);
	    CHECK(p, 2);
	    weight = NTOHSP(p,2);
	    CHECK(p, 2);
	    port = NTOHSP(p,2);
	    len = dn_expand(answer.bytes, answer.bytes + size, p, host, sizeof(host));
	    if (len < 0)
		goto out;
	    INCR_CHECK(p, len);

	    /*
	     * We got everything!  Insert it into our list, but make sure
	     * it's in the right order.  Right now we don't do anything
	     * with the weight field
	     */

	    srv = (struct srv_dns_entry *) malloc(sizeof(struct srv_dns_entry));
	    if (srv == NULL)
		goto out;
	
	    srv->priority = priority;
	    srv->weight = weight;
	    srv->port = port;
	    srv->host = strdup(host);

	    if (head == NULL || head->priority > srv->priority) {
		srv->next = head;
		head = srv;
	    } else
		/*
		 * This is confusing.  Only insert an entry into this
		 * spot if:
		 * The next person has a higher priority (lower priorities
		 * are preferred).
		 * Or
		 * There is no next entry (we're at the end)
		 */
		for (entry = head; entry != NULL; entry = entry->next)
		    if ((entry->next &&
			 entry->next->priority > srv->priority) ||
			entry->next == NULL) {
			srv->next = entry->next;
			entry->next = srv;
			break;
		    }
	} else
	    INCR_CHECK(p, rdlen);
    }
	
    /*
     * Okay!  Now we've got a linked list of entries sorted by
     * priority.  Start looking up A records and returning
     * addresses.
     */

    if (head == NULL)
	goto out;

    for (entry = head; entry != NULL; entry = entry->next) {
	hp = gethostbyname(entry->host);
	if (hp != 0) {
	    switch (hp->h_addrtype) {
#ifdef HAVE_NETINET_IN_H
            case AF_INET:
		for (j=0; hp->h_addr_list[j]; j++) {
		    sin = (struct sockaddr_in *) &addr[out++];
		    memset ((char *) sin, 0, sizeof (struct sockaddr));
		    sin->sin_family = hp->h_addrtype;
		    sin->sin_port = htons(entry->port);
		    memcpy((char *) &sin->sin_addr,
			   (char *) hp->h_addr_list[j],
			   sizeof(struct in_addr));
		    if (out + 1 >= count) {
			count += 5;
			addr = (struct sockaddr *)
				realloc((char *) addr,
					sizeof(struct sockaddr) * count);
			if (!addr)
			    goto out;
		    }
		}
		break;
#endif /* HAVE_NETINET_IN_H */
	    default:
		break;
	    }
	}
    }

    for (entry = head; entry != NULL; ) {
	free(entry->host);
        entry->host = NULL;
	srv = entry;
	entry = entry->next;
	free(srv);
        srv = NULL;
    }

  out:
    if (srv)
        free(srv);

    if (out == 0) {	/* No good servers */
        if (addr)
            free(addr);
	return KRB5_REALM_CANT_RESOLVE;
    }

    *addr_pp = addr;
    *naddrs = out;
    return 0;
}
#endif /* KRB5_DNS_LOOKUP */

/*
 * Wrapper function for the two backends
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
    krb5_error_code code;
#ifdef KRB5_DNS_LOOKUP
    struct sockaddr *admin_addr_p, *kdc_addr_p;
    int nadmin_addrs, nkdc_addrs;
    int i,j;
#endif /* KRB5_DNS_LOOKUP */

    /*
     * We always try the local file first
     */

    code = krb5_locate_srv_conf(context, realm, "kdc", addr_pp, naddrs, 
                                 master_index, nmasters);

#ifdef KRB5_DNS_LOOKUP
    if (code) {
	code = krb5_locate_srv_dns(realm, "_kerberos", "_udp",
				   addr_pp, naddrs);
        if ( master_index && nmasters ) {

            code = krb5_locate_srv_dns(realm, "_kerberos-adm", "_tcp",
                                        &admin_addr_p, &nadmin_addrs);
            if ( code ) {
                free(*addr_pp);
                *addr_pp = NULL;
                *naddrs = 0;
                return(code);
            } 

            kdc_addr_p = *addr_pp;
            nkdc_addrs = *naddrs;

            *naddrs = 0;
            *addr_pp = (struct sockaddr *) malloc(sizeof(*kdc_addr_p));
            if ( *addr_pp == NULL ) {
                free(kdc_addr_p);
                free(admin_addr_p);
                return ENOMEM;
            }

            for ( i=0; i<nkdc_addrs; i++ ) {
                for ( j=0 ; j<nadmin_addrs; j++) {
                    if ( !memcmp(&kdc_addr_p[i].sa_data[2],&admin_addr_p[j].sa_data[2],4) ) {
                        memcpy(&(*addr_pp)[(*naddrs)],&kdc_addr_p[i],
                                sizeof(struct sockaddr));
                        (*naddrs)++;
                        break;
                    }
                }
            }
 
            free(kdc_addr_p);
            free(admin_addr_p);

            if ( *naddrs == 0 ) {
                free(*addr_pp);
                *addr_pp = NULL;
                return KRB5_REALM_CANT_RESOLVE;
            }
            *master_index = 1;
            *nmasters = *naddrs;
        }
    }
#endif /* KRB5_DNS_LOOKUP */
    return (code);
}

#if 0 /* Why is this useful?  It's not used now, and it's certainly
	 not useful if you don't have the DNS code enabled.  -KR  */

/*
 * It turns out that it is really useful to be able to use these functions
 * for other things (like admin servers), so create an abstract function
 * for this
 */

krb5_error_code
krb5_locate_server(realm, name, proto, addr_pp, naddrs)
    const krb5_data *realm;
    const char *name, *proto;
    struct sockaddr **addr_pp;
    int *naddrs;
{
    krb5_error_code code = KRB5_REALM_UNKNOWN;
#ifdef KRB5_DNS_LOOKUP
    code = krb5_locate_srv_dns(realm, name, proto,
                                (struct sockaddr **) addr_pp, naddrs);
#endif /* KRB5_DNS_LOOKUP */
    return (code);
}
#endif

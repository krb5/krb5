/*
 * lib/krb5/os/dnssrv.c
 *
 * Copyright 1990,2000,2001,2002,2003 by the Massachusetts Institute of Technology.
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
 * do DNS SRV RR queries
 */

#ifdef KRB5_DNS_LOOKUP
#define NEED_SOCKETS
#include "k5-int.h"
#include "os-proto.h"
#include <stdio.h>
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

/*
 * Lookup a KDC via DNS SRV records
 */

void krb5int_free_srv_dns_data (struct srv_dns_entry *p)
{
    struct srv_dns_entry *next;
    while (p) {
	next = p->next;
	free(p->host);
	free(p);
	p = next;
    }
}

/* Do DNS SRV query, return results in *answers.

   Make best effort to return all the data we can.  On memory or
   decoding errors, just return what we've got.  Always return 0,
   currently.  */

krb5_error_code
krb5int_make_srv_query_realm(const krb5_data *realm,
			     const char *service,
			     const char *protocol,
			     struct srv_dns_entry **answers)
{
    union {
        unsigned char bytes[2048];
        HEADER hdr;
    } answer;
    unsigned char *p=NULL;
    char host[MAX_DNS_NAMELEN], *h;
    int type, rrclass;
    int priority, weight, size, len, numanswers, numqueries, rdlen;
    unsigned short port;
    const int hdrsize = sizeof(HEADER);

    struct srv_dns_entry *head = NULL;
    struct srv_dns_entry *srv = NULL, *entry = NULL;

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

    if (memchr(realm->data, 0, realm->length))
	return 0;
    if ( strlen(service) + strlen(protocol) + realm->length + 6 
         > MAX_DNS_NAMELEN )
	return 0;
    sprintf(host, "%s.%s.%.*s", service, protocol, (int) realm->length,
	    realm->data);

    /* Realm names don't (normally) end with ".", but if the query
       doesn't end with "." and doesn't get an answer as is, the
       resolv code will try appending the local domain.  Since the
       realm names are absolutes, let's stop that.  

       But only if a name has been specified.  If we are performing
       a search on the prefix alone then the intention is to allow
       the local domain or domain search lists to be expanded.  */

    h = host + strlen (host);
    if ((h[-1] != '.') && ((h - host + 1) < sizeof(host)))
        strcpy (h, ".");

#ifdef TEST
    fprintf (stderr, "sending DNS SRV query for %s\n", host);
#endif

    size = res_search(host, C_IN, T_SRV, answer.bytes, sizeof(answer.bytes));

    if ((size < hdrsize) || (size > sizeof(answer.bytes)))
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
	rrclass = NTOHSP(p,6);

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

	if (rrclass == C_IN && type == T_SRV) {
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
	    if (srv->host == NULL) {
		free(srv);
		goto out;
	    }

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
	
  out:
    *answers = head;
    return 0;
}
#endif

/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_walk_realm_tree()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_walk_rtree_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include "int-proto.h"

/* internal function, used by krb5_get_cred_from_kdc() */

#define REALM_BRANCH_CHAR '.'

#ifndef min
#define min(x,y) ((x) < (y) ? (x) : (y))
#define max(x,y) ((x) > (y) ? (x) : (y))
#endif

krb5_error_code
krb5_walk_realm_tree(client, server, tree)
const krb5_principal client, server;
krb5_principal **tree;
{
    krb5_error_code retval;
    krb5_principal *rettree;
    register char *ccp, *scp;
    register char *prevccp, *prevscp;
    char *com_sdot = 0, *com_cdot = 0;
    register int i, links = 0;
    int clen, slen;
    krb5_data tmpcrealm, tmpsrealm;
    int nocommon = 1;

    clen = krb5_princ_realm(client)->length;
    slen = krb5_princ_realm(server)->length;

    for (com_cdot = ccp = krb5_princ_realm(client)->data + clen - 1,
	 com_sdot = scp = krb5_princ_realm(server)->data + slen - 1;
	 clen && slen && *ccp == *scp ;
	 ccp--, scp--, 	clen--, slen--) {
	if (*ccp == REALM_BRANCH_CHAR) {
	    com_cdot = ccp;
	    com_sdot = scp;
	    nocommon = 0;
	}
    }

    /* ccp, scp point to common root.
       com_cdot, com_sdot point to common components. */
    /* handle case of one ran out */
    if (!clen) {
	/* construct path from client to server, down the tree */
	if (!slen)
	    /* in the same realm--this means there is no ticket
	       in this realm. */
	    return KRB5_NO_TKT_IN_RLM;
	if (*scp == REALM_BRANCH_CHAR) {
	    /* one is a subdomain of the other */
	    com_cdot = krb5_princ_realm(client)->data;
	    com_sdot = scp;
	} /* else normal case of two sharing parents */
    }
    if (!slen) {
	/* construct path from client to server, up the tree */
	if (*ccp == REALM_BRANCH_CHAR) {
	    /* one is a subdomain of the other */
	    com_sdot = krb5_princ_realm(server)->data;
	    com_cdot = ccp;
	} /* else normal case of two sharing parents */
    }
    /* determine #links to/from common ancestor */
    if (nocommon)
	links = 1;
    else
	links = 2;
    /* if no common ancestor, artificially set up common root at the last
       component, then join with special code */
    for (ccp = krb5_princ_realm(client)->data; ccp < com_cdot; ccp++) {
	if (*ccp == REALM_BRANCH_CHAR) {
	    links++;
	    if (nocommon)
		com_cdot = prevccp = ccp;
	}
    }

    for (scp = krb5_princ_realm(server)->data; scp < com_sdot; scp++) {
	if (*scp == REALM_BRANCH_CHAR) {
	    links++;
	    if (nocommon)
		com_sdot = prevscp = scp;
	}
    }
    if (nocommon && links == 3) {
	/* no components, and not the same */
	com_cdot = krb5_princ_realm(client)->data;
	com_sdot = krb5_princ_realm(server)->data;
    }

    if (!(rettree = (krb5_principal *)calloc(links+2,
					     sizeof(krb5_principal)))) {
	return ENOMEM;
    }
    i = 1;
    if (retval = krb5_tgtname(krb5_princ_realm(client),
			      krb5_princ_realm(client), &rettree[0])) {
	xfree(rettree);
	return retval;
    }
    for (prevccp = ccp = krb5_princ_realm(client)->data;
	 ccp <= com_cdot;
	 ccp++) {
	if (*ccp != REALM_BRANCH_CHAR)
	    continue;
	++ccp;				/* advance past dot */
	tmpcrealm.data = prevccp;
	tmpcrealm.length = krb5_princ_realm(client)->length -
	    (prevccp - krb5_princ_realm(client)->data);
	tmpsrealm.data = ccp;
	tmpsrealm.length = krb5_princ_realm(client)->length -
	    (ccp - krb5_princ_realm(client)->data);
	if (retval = krb5_tgtname(&tmpsrealm, &tmpcrealm, &rettree[i])) {
	    while (i) {
		krb5_free_principal(rettree[i-1]);
		i--;
	    }
	    xfree(rettree);
	    return retval;
	}
	prevccp = ccp;
	i++;
    }
    if (nocommon) {
	tmpcrealm.data = com_cdot + 1;
	tmpcrealm.length = krb5_princ_realm(client)->length -
	    (com_cdot + 1 - krb5_princ_realm(client)->data);
	tmpsrealm.data = com_sdot + 1;
	tmpsrealm.length = krb5_princ_realm(server)->length -
	    (com_sdot + 1 - krb5_princ_realm(server)->data);
	if (retval = krb5_tgtname(&tmpsrealm, &tmpcrealm, &rettree[i])) {
	    while (i) {
		krb5_free_principal(rettree[i-1]);
		i--;
	    }
	    xfree(rettree);
	    return retval;
	}
	i++;
    }

    for (prevscp = com_sdot + 1, scp = com_sdot - 1;
	 scp > krb5_princ_realm(server)->data;
	 scp--) {
	if (*scp != REALM_BRANCH_CHAR)
	    continue;
	if (scp - 1 < krb5_princ_realm(server)->data)
	    break;			/* XXX only if . starts realm? */
	tmpcrealm.data = prevscp;
	tmpcrealm.length = krb5_princ_realm(server)->length -
	    (prevscp - krb5_princ_realm(server)->data);
	tmpsrealm.data = scp + 1;
	tmpsrealm.length = krb5_princ_realm(server)->length -
	    (scp + 1 - krb5_princ_realm(server)->data);
	if (retval = krb5_tgtname(&tmpsrealm, &tmpcrealm, &rettree[i])) {
	    while (i) {
		krb5_free_principal(rettree[i-1]);
		i--;
	    }
	    xfree(rettree);
	    return retval;
	}
	prevscp = scp + 1;
	i++;
    }
    if (slen) {
	/* only necessary if building down tree from ancestor or client */
	tmpcrealm.data = prevscp;
	tmpcrealm.length = krb5_princ_realm(server)->length -
	    (prevscp - krb5_princ_realm(server)->data);
	if (retval = krb5_tgtname(krb5_princ_realm(server), &tmpcrealm,
				  &rettree[i])) {
	    while (i) {
		krb5_free_principal(rettree[i-1]);
		i--;
	    }
	    xfree(rettree);
	    return retval;
	}
    }
    *tree = rettree;
    return 0;
}

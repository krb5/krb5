/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 * Utility functions for the KDC implementation.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_kdc_util_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/asn1.h>

#include "kdc_util.h"
#include "extern.h"

#include <krb5/ext-proto.h>
#include <stdio.h>

#include <syslog.h>

/*
 * concatenate first two authdata arrays, returning an allocated replacement.
 * The replacement should be freed with krb5_free_authdata().
 */
krb5_error_code
concat_authorization_data(first, second, output)
krb5_authdata **first;
krb5_authdata **second;
krb5_authdata ***output;
{
    register int i, j;
    register krb5_authdata **ptr, **retdata;

    /* count up the entries */
    i = 0;
    if (first)
	for (ptr = first; *ptr; ptr++)
	    i++;
    if (second)
	for (ptr = second; *ptr; ptr++)
	    i++;
    
    retdata = (krb5_authdata **)malloc((i+1)*sizeof(*retdata));
    if (!retdata)
	return ENOMEM;
    retdata[i] = 0;			/* null-terminated array */
    for (i = 0, j = 0, ptr = first; j < 2 ; ptr = second, j++)
	while (ptr && *ptr) {
	    /* now walk & copy */
	    retdata[i] = (krb5_authdata *)malloc(sizeof(*retdata[i]));
	    if (!retdata[i]) {
		krb5_free_authdata(retdata);
		return ENOMEM;
	    }
	    *retdata[i] = **ptr;
	    if (!(retdata[i]->contents =
		  (krb5_octet *)malloc(retdata[i]->length))) {
		xfree(retdata[i]);
		retdata[i] = 0;
		krb5_free_authdata(retdata);
		return ENOMEM;
	    }
	    memcpy((char *) retdata[i]->contents,
		   (char *)(*ptr)->contents,
		   retdata[i]->length);

	    ptr++;
	    i++;
	}
    *output = retdata;
    return 0;
}

krb5_boolean
realm_compare(realmname, princ)
krb5_data *realmname;
krb5_principal princ;
{
    if (realmname->length != krb5_princ_realm(princ)->length)
	return FALSE;
    return(memcmp((char *)realmname->data,
		  (char *)krb5_princ_realm(princ)->data,
		  realmname->length) ? FALSE : TRUE);
}

struct kparg {
    krb5_keyblock *key;
    krb5_kvno kvno;
};

/*
 * Since we do the checking of the server name before passing into
 * krb5_rd_req_decoded, there's no reason to do it here, so we ignore the
 * "principal" argument.
 */

static krb5_error_code
kdc_rdreq_keyproc(DECLARG(krb5_pointer, keyprocarg),
		  DECLARG(krb5_principal, principal),
		  DECLARG(krb5_kvno, vno),
		  DECLARG(krb5_keyblock **, key))
OLDDECLARG(krb5_pointer, keyprocarg)
OLDDECLARG(krb5_principal, principal)
OLDDECLARG(krb5_kvno, vno)
OLDDECLARG(krb5_keyblock **, key)
{
    register struct kparg *whoisit = (struct kparg *)keyprocarg;

    if (vno != whoisit->kvno)
	return KRB5KRB_AP_ERR_BADKEYVER;
    return(krb5_copy_keyblock(whoisit->key, key));
}


/*
 * given authentication data (provides seed for checksum), calculate checksum
 * for source data and compare to authdata checksum.  Storage for checksum
 * is provided.
 */
static krb5_error_code
comp_cksum(type, source, authdat, dest)
krb5_cksumtype type;
krb5_data *source;
krb5_tkt_authent *authdat;
krb5_checksum *dest;
{
	krb5_error_code retval;

	/* first compute checksum */
	if (retval = krb5_calculate_checksum(type, 
 					     source->data, 
 					     source->length,
					     authdat->ticket->enc_part2->session->contents, /* seed */
					     authdat->ticket->enc_part2->session->length,   /* seed length */
					     dest)) {
		return retval;
	}
        if (dest->length != authdat->authenticator->checksum->length ||
	    memcmp((char *)dest->contents,
	           (char *)authdat->authenticator->checksum->contents,
	           dest->length)) {
	    return KRB5KRB_AP_ERR_BAD_INTEGRITY;
    }
    return 0;	
}

krb5_error_code 
kdc_process_tgs_req(request, from, pkt, ret_authdat)
krb5_kdc_req *request;
const krb5_fulladdr *from;
krb5_data *pkt;
krb5_tkt_authent **ret_authdat;
{
    krb5_ap_req *apreq = 0;
    krb5_tkt_authent *authdat, *nauthdat;
    struct kparg who;
    krb5_error_code retval = 0;
    krb5_checksum our_cksum;
    krb5_data *scratch = 0, scratch1, scratch2;
    krb5_pa_data **tmppa;
    krb5_boolean local_client = TRUE;
    krb5_enc_tkt_part *ticket_enc;

    our_cksum.contents = 0;

    if (!request->padata)
	return KRB5KDC_ERR_PADATA_TYPE_NOSUPP;
    for (tmppa = request->padata; *tmppa; tmppa++) {
	if ((*tmppa)->pa_type == KRB5_PADATA_AP_REQ)
	    break;
    }
    if (!*tmppa)			/* cannot find any AP_REQ */
	return KRB5KDC_ERR_PADATA_TYPE_NOSUPP;

    scratch2.length = (*tmppa)->length;
    scratch2.data = (char *)(*tmppa)->contents;

    if (retval = decode_krb5_ap_req(&scratch2, &apreq))
	return retval;

    if (!(authdat = (krb5_tkt_authent *)malloc(sizeof(*authdat)))) {
	retval = ENOMEM;
	goto cleanup;
    }
    memset((char *)authdat, 0, sizeof(*authdat));
    authdat->ticket = apreq->ticket;
    *ret_authdat = authdat;

    if (isflagset(apreq->ap_options, AP_OPTS_USE_SESSION_KEY) ||
	isflagset(apreq->ap_options, AP_OPTS_MUTUAL_REQUIRED)) {
	retval = KRB5KDC_ERR_POLICY;
	apreq->ticket = 0;		/* Caller will free the ticket */
	goto cleanup;
    }

    if (retval = kdc_get_server_key(authdat->ticket, &who.key,
				    &who.kvno)) {
	apreq->ticket = 0;		/* Caller will free the ticket */
	goto cleanup;
    }

    /* If the "server" principal in the ticket is not something
       in the local realm, then we must refuse to service the request
       if the client claims to be from the local realm.
       
       If we don't do this, then some other realm's nasty KDC can
       claim to be authenticating a client from our realm, and we'll
       give out tickets concurring with it!
       
       we set a flag here for checking below.
       */
    if ((krb5_princ_realm(apreq->ticket->server)->length !=
	 krb5_princ_realm(tgs_server)->length) ||
	memcmp(krb5_princ_realm(apreq->ticket->server)->data,
	       krb5_princ_realm(tgs_server)->data,
	       krb5_princ_realm(tgs_server)->length))
	local_client = FALSE;

    retval = krb5_rd_req_decoded(apreq, apreq->ticket->server,
				 from->address,
				 0,	/* no fetchfrom */
				 kdc_rdreq_keyproc,
				 (krb5_pointer)&who,
				 kdc_rcache,
				 &nauthdat);
    krb5_free_keyblock(who.key);

    if (retval) {
	apreq->ticket = 0;		/* Caller will free the ticket */
	goto cleanup;
    }

    /*
     * no longer need to protect the ticket in apreq, since
     * authdat is about to get nuked --- it's going to get reassigned.
     */
    xfree(authdat);

    authdat = nauthdat;
    *ret_authdat = authdat;
    ticket_enc = authdat->ticket->enc_part2;

    /* now rearrange output from rd_req_decoded */

    /* make sure the client is of proper lineage (see above) */
    if (!local_client) {
	krb5_data *tkt_realm = krb5_princ_realm(ticket_enc->client);
	krb5_data *tgs_realm = krb5_princ_realm(tgs_server);
	if (tkt_realm->length != tgs_realm->length ||
	    memcmp(tkt_realm->data, tgs_realm->data, tgs_realm->length)) {
	    /* someone in a foreign realm claiming to be local */
	    retval = KRB5KDC_ERR_POLICY;
	    goto cleanup;
	}
    }
    our_cksum.checksum_type = authdat->authenticator->checksum->checksum_type;
    if (!valid_cksumtype(our_cksum.checksum_type)) {
	retval = KRB5KDC_ERR_SUMTYPE_NOSUPP;
	goto cleanup;
    }	
    /* must be collision proof */
    if (!is_coll_proof_cksum(our_cksum.checksum_type)) {
	retval = KRB5KRB_AP_ERR_INAPP_CKSUM;
	goto cleanup;
    }

    if (!(our_cksum.contents = (krb5_octet *)
	  malloc(krb5_checksum_size(our_cksum.checksum_type)))) {
	retval = ENOMEM;
	goto cleanup;
    }

    /*
     * Check application checksum vs. tgs request
     * 	 
     * We try checksumming the req-body two different ways: first we
     * try reaching into the raw asn.1 stream (if available), and
     * checksum that directly; if that failes, then we try encoding
     * using our local asn.1 library.
     */
    retval = KRB5KRB_AP_ERR_BAD_INTEGRITY;
    if (pkt && (fetch_asn1_field(pkt->data, 1, 4, &scratch1) >= 0)) {
	retval = comp_cksum(our_cksum.checksum_type, &scratch1, authdat,
			    &our_cksum);
    }
    if (retval) {
	if (retval = encode_krb5_kdc_req_body(request, &scratch)) 
	    goto cleanup;	 /* XXX retval should be in kdc range */
	retval = comp_cksum(our_cksum.checksum_type, scratch, authdat,
			    &our_cksum);
    }
    
    xfree(our_cksum.contents);
    
cleanup:
    if (apreq)
	krb5_free_ap_req(apreq);
    if (scratch)
	krb5_free_data(scratch);
    return retval;
}

krb5_error_code
kdc_get_server_key(ticket, key, kvno)
krb5_ticket *ticket;
krb5_keyblock **key;
krb5_kvno *kvno;
{
    krb5_error_code retval;
    int nprincs;
    krb5_db_entry server;
    krb5_boolean more;

    if (krb5_principal_compare(tgs_server, ticket->server)) {
	*kvno = tgs_kvno;
	return krb5_copy_keyblock(&tgs_key, key);
    } else {
	nprincs = 1;

	if (retval = krb5_db_get_principal(ticket->server,
					   &server, &nprincs,
					   &more)) {
	    return(retval);
	}
	if (more) {
	    krb5_db_free_principal(&server, nprincs);
	    return(KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE);
	} else if (nprincs != 1) {
	    char *sname;

	    krb5_db_free_principal(&server, nprincs);
	    if (!krb5_unparse_name(ticket->server, &sname)) {
		syslog(LOG_ERR, "TGS_REQ: can't find key for '%s'",
		       sname);
		free(sname);
	    }
	    return(KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN);
	}
	/* convert server.key into a real key (it may be encrypted
	   in the database) */
	if (*key = (krb5_keyblock *)malloc(sizeof **key)) {
	    retval = KDB_CONVERT_KEY_OUTOF_DB(&server.key, *key);
	} else
	    retval = ENOMEM;
	*kvno = server.kvno;
	krb5_db_free_principal(&server, nprincs);
	return retval;
    }
}

/* This probably wants to be updated if you support last_req stuff */

static krb5_last_req_entry nolrentry = { KRB5_LRQ_NONE, 0 };
static krb5_last_req_entry *nolrarray[] = { &nolrentry, 0 };

krb5_error_code
fetch_last_req_info(dbentry, lrentry)
krb5_db_entry *dbentry;
krb5_last_req_entry ***lrentry;
{
    *lrentry = nolrarray;
    return 0;
}


/* XXX!  This is a temporary place-holder */

krb5_error_code
check_hot_list(ticket)
krb5_ticket *ticket;
{
    return 0;
}


#define MAX_REALM_LN 500


/* 
 * subrealm - determine if r2 is a subrealm of r1
 *
 *            SUBREALM takes two realms, r1 and r2, and 
 *            determines if r2 is a subrealm of r1.   
 *            r2 is a subrealm of r1 if (r1 is a prefix
 *            of r2 AND r1 and r2 begin with a /) or if 
 *            (r1 is a suffix of r2 and neither r1 nor r2
 *            begin with a /).
 *
 * RETURNS:   If r2 is a subrealm, and r1 is a prefix, the number
 *            of characters in the suffix of r2 is returned as a
 *            negative number.
 *
 *            If r2 is a subrealm, and r1 is a suffix, the number
 *            of characters in the prefix of r2 is returned as a
 *            positive number.
 *
 *            If r2 is not a subrealm, SUBREALM returns 0.
 */
static  int
subrealm(r1,r2)
char	*r1;
char	*r2;
{
    int	l1,l2;
    l1 = strlen(r1);
    l2 = strlen(r2);
    if(l2 <= l1) return(0);
    if((*r1 == '/') && (*r2 == '/') && (strncmp(r1,r2,l1) == 0)) return(l1-l2);
    if((*r1 != '/') && (*r2 != '/') && (strncmp(r1,r2+l2-l1,l1) == 0))
	return(l2-l1);
    return(0);
}

/*
 * add_to_transited  Adds the name of the realm which issued the
 *                   ticket granting ticket on which the new ticket to
 *                   be issued is based (note that this is the same as
 *                   the realm of the server listed in the ticket
 *                   granting ticket. 
 *
 * ASSUMPTIONS:  This procedure assumes that the transited field from
 *               the existing ticket granting ticket already appears
 *               in compressed form.  It will add the new realm while
 *               maintaining that form.   As long as each successive
 *               realm is added using this (or a similar) routine, the
 *               transited field will be in compressed form.  The
 *               basis step is an empty transited field which is, by
 *               its nature, in its most compressed form.
 *
 * ARGUMENTS: krb5_data *tgt_trans  Transited field from TGT
 *            krb5_data *new_trans  The transited field for the new ticket
 *            krb5_principal tgs    Name of ticket granting server
 *                                  This includes the realm of the KDC
 *                                  that issued the ticket granting
 *                                  ticket.  This is the realm that is
 *                                  to be added to the transited field.
 *            krb5_principal client Name of the client
 *            krb5_principal server The name of the requested server.
 *                                  This may be the an intermediate
 *                                  ticket granting server.
 *
 *            The last two argument are needed since they are
 *            implicitly part of the transited field of the new ticket
 *            even though they are not explicitly listed.
 *
 * RETURNS:   krb5_error_code - Success, or out of memory
 *
 * MODIFIES:  new_trans:  ->length will contain the length of the new
 *                        transited field.
 * 
 *                        If ->data was not null when this procedure
 *                        is called, the memory referenced by ->data
 *                        will be deallocated. 
 *
 *                        Memory will be allocated for the new transited field
 *                        ->data will be updated to point to the newly
 *                        allocated memory.  
 *
 * BUGS:  The space allocated for the new transited field is the
 *        maximum that might be needed given the old transited field,
 *        and the realm to be added.  This length is calculated
 *        assuming that no compression of the new realm is possible.
 *        This has no adverse consequences other than the allocation
 *        of more space than required.  
 *
 *        This procedure will not yet use the null subfield notation,
 *        and it will get confused if it sees it.
 *
 *        This procedure does not check for quoted commas in realm
 *        names.
 */

krb5_error_code 
add_to_transited(tgt_trans,new_trans,tgs,client,server)
krb5_data *tgt_trans;
krb5_data *new_trans;
krb5_principal tgs;
krb5_principal client;
krb5_principal server;
{
    char	*realm = (char *)krb5_princ_realm(tgs)->data;
    char	*trans = (char *)malloc(strlen(realm) + tgt_trans->length + 1);
    char	*otrans = tgt_trans->data;

    /* The following are for stepping through the transited field     */
    char	prev[MAX_REALM_LN];
    char	next[MAX_REALM_LN];
    char	current[MAX_REALM_LN];
    char	exp[MAX_REALM_LN];	/* Expanded current realm name     */

    int	retval;
    int	clst,nlst;			/* count of last character in current and next */
    int	pl,pl1;				/* prefix length                               */
    int	added = 0;			/* 1 = new realm has been added                */

    if(!trans) return(ENOMEM);

    if(new_trans->data) xfree(new_trans->data);

    new_trans->data = trans;

    /* For the purpose of appending, the realm preceding the first */
    /* relam in the transited field is considered the null realm   */
    strcpy(prev,"");

    /***** In next statement, need to keep reading if the , was quoted *****/
    /* read field into current */
    retval = sscanf(otrans,"%[^,]",current);

    if(retval == 1) otrans = otrans + strlen(current);
    else *current = '\0';

    if(*otrans == ',') otrans++;
	       
    if(strcmp(krb5_princ_realm(client)->data,realm) == 0)
	added = 1;

    if(strcmp(krb5_princ_realm(server)->data,realm) == 0)
	added = 1;

    while(*current) {

	/* figure out expanded form of current name */
	clst = strlen(current) - 1;
	if(current[0] == ' ') {
	    strcpy(exp,current+1);
	}
	else if((current[0] == '/') && (prev[0] == '/')) {
	    strcpy(exp,prev);
	    strcat(exp,current);
	}
	else if(current[clst] == '.') {
	    strcpy(exp,current);
	    strcat(exp,prev);
	}
	else strcpy(exp,current);

	/***** next statement, need to keep reading if the , was quoted *****/
	/* read field into next */
	retval = sscanf(otrans,"%[^,]",next);

	if(retval == 1) {
	    otrans = otrans + strlen(next);
	    nlst = strlen(next) - 1;
	}
	else {
	    *next = '\0';
	    nlst = 0;
	}

	if(*otrans == ',') otrans++;

	if(strcmp(exp,realm) == 0) added = 1;

	/* If we still have to insert the new realm */
	if(added == 0) {
	    /* Is the next field compressed?  If not, and if the new */
	    /* realm is a subrealm of the current realm, compress    */
	    /* the new realm, and insert immediately following the   */
	    /* current one.  Note that we can not do this if the next*/
	    /* field is already compressed since it would mess up    */
	    /* what has already been done.  In most cases, this is   */
	    /* not a problem becase the realm to be added will be a  */
	    /* subrealm of the next field too, and we will catch     */
	    /* it in a future iteration.                             */
	    if((next[nlst] != '.') && (next[0] != '/') && 
	       (pl = subrealm(exp,realm))) {
		added = 1;
		strcat(current,",");
		if(pl > 0) strncat(current,realm,pl);
		else strncat(current,realm+strlen(realm)+pl,-pl);
	    }
	    /* Whether or not the next field is compressed, if the    */
	    /* realm to be added is a superrealm of the current realm,*/
	    /* then the current realm can be compressed.  First the   */
	    /* realm to be added must be compressed relative to the   */
	    /* previous realm (if possible), and then the current     */
	    /* realm compressed relative to the new realm.  Note that */
	    /* if the realm to be added is also a superrealm of the   */
	    /* previous realm, it would have been added earlier, and  */
	    /* we would not reach this step this time around.         */
	    else if(pl = subrealm(realm,exp)) {
		added = 1;
		*current = '\0';
		pl1 = subrealm(prev,realm);
		if(pl1) {
		    if(pl1 > 0) strncat(current,realm,pl1);
		    else strncat(current,realm+strlen(realm)+pl1,-pl1);
		}
		else { /* If not a subrealm */
		    if((realm[0] == '/') && prev[0]) strcat(current," ");
		    strcat(current,realm);
		}
		strcat(current,",");
		if(pl > 0) strncat(current,exp,pl);
		else strncat(current,exp+strlen(exp)+pl,-pl);
	    }
	}

	if(new_trans->length != 0) strcat(trans,",");
	strcat(trans,current);
	new_trans->length = strlen(trans) + 1;

	strcpy(prev,exp);
	strcpy(current,next);
    }

    if(added == 0) {
	if(new_trans->length != 0) strcat(trans,",");
	if((realm[0] == '/') && trans[0]) strcat(trans," ");
	strcat(trans,realm);
	new_trans->length = strlen(trans) + 1;
    }
    return 0;
}

/*
 * Routines that validate a AS request; checks a lot of things.  :-)
 *
 * Returns a Kerberos protocol error number, which is _not_ the same
 * as a com_err error number!
 */
#define AS_OPTIONS_HANDLED (KDC_OPT_FORWARDABLE | KDC_OPT_PROXIABLE | \
			     KDC_OPT_ALLOW_POSTDATE | KDC_OPT_POSTDATED | \
			     KDC_OPT_RENEWABLE | KDC_OPT_RENEWABLE_OK)
int
validate_as_request(request, client, server, kdc_time, status)
register krb5_kdc_req *request;
krb5_db_entry client;
krb5_db_entry server;
krb5_timestamp kdc_time;
char	**status;
{
    int		errcode;
    
    /*
     * If an illegal option is set, complain.
     */
    if (request->kdc_options & ~(AS_OPTIONS_HANDLED)) {
	*status = "INVALID AS OPTIONS";
	return KDC_ERR_BADOPTION;
    }

     /* An AS request must include the addresses field */
    if (request->addresses == 0) {
	*status = "NO ADDRESS";
	return KRB_AP_ERR_BADADDR;
    }
    
    /* The client's password must not be expired */
    if (client.pw_expiration && client.pw_expiration < kdc_time) {
	*status = "CLIENT KEY EXPIRED";
#ifdef KRBCONF_VAGUE_ERRORS
	return(KRB_ERR_GENERIC);
#else
	return(KDC_ERR_KEY_EXP);
#endif
    }

    /* The client must not be expired */
    if (client.expiration && client.expiration < kdc_time) {
	*status = "CLIENT EXPIRED";
#ifdef KRBCONF_VAGUE_ERRORS
	return(KRB_ERR_GENERIC);
#else
	return(KDC_ERR_NAME_EXP);
#endif
    }

    /* The server must not be expired */
    if (server.expiration && server.expiration < kdc_time) {
	*status = "SERVICE EXPIRED";
	    return(KDC_ERR_SERVICE_EXP);
    }

    /*
     * If the client requires password changing, then only allow the 
     * pwchange service.
     */
    if (isflagset(client.attributes, KRB5_KDB_REQUIRES_PWCHANGE) &&
	!isflagset(server.attributes, KRB5_KDB_PWCHANGE_SERVICE)) {
	*status = "REQUIRED PWCHANGE";
	return(KDC_ERR_KEY_EXP);
    }

    /* Client and server must allow postdating tickets */
    if ((isflagset(request->kdc_options, KDC_OPT_ALLOW_POSTDATE) ||
	 isflagset(request->kdc_options, KDC_OPT_POSTDATED)) && 
	(isflagset(client.attributes, KRB5_KDB_DISALLOW_POSTDATED) ||
	 isflagset(server.attributes, KRB5_KDB_DISALLOW_POSTDATED))) {
	*status = "POSTDATE NOT ALLOWED";
	return(KDC_ERR_CANNOT_POSTDATE);
    }
    
    /* Client and server must allow forwardable tickets */
    if (isflagset(request->kdc_options, KDC_OPT_FORWARDABLE) &&
	(isflagset(client.attributes, KRB5_KDB_DISALLOW_FORWARDABLE) ||
	 isflagset(server.attributes, KRB5_KDB_DISALLOW_FORWARDABLE))) {
	*status = "FORWARDABLE NOT ALLOWED";
	return(KDC_ERR_POLICY);
    }
    
    /* Client and server must allow renewable tickets */
    if (isflagset(request->kdc_options, KDC_OPT_RENEWABLE) &&
	(isflagset(client.attributes, KRB5_KDB_DISALLOW_RENEWABLE) ||
	 isflagset(server.attributes, KRB5_KDB_DISALLOW_RENEWABLE))) {
	*status = "RENEWABLE NOT ALLOWED";
	return(KDC_ERR_POLICY);
    }
    
    /* Client and server must allow proxiable tickets */
    if (isflagset(request->kdc_options, KDC_OPT_PROXIABLE) &&
	(isflagset(client.attributes, KRB5_KDB_DISALLOW_PROXIABLE) ||
	 isflagset(server.attributes, KRB5_KDB_DISALLOW_PROXIABLE))) {
	*status = "PROXIABLE NOT ALLOWED";
	return(KDC_ERR_POLICY);
    }
    
    /* Check to see if client is locked out */
    if (isflagset(client.attributes, KRB5_KDB_DISALLOW_ALL_TIX)) {
	*status = "CLIENT LOCKED OUT";
	return(KDC_ERR_C_PRINCIPAL_UNKNOWN);
    }

    /* Check to see if server is locked out */
    if (isflagset(server.attributes, KRB5_KDB_DISALLOW_ALL_TIX)) {
	*status = "SERVICE LOCKED OUT";
	return(KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }
	
    /* Check to see if server is allowed to be a service */
    if (isflagset(server.attributes, KRB5_KDB_DISALLOW_SVR)) {
	*status = "SERVICE NOT ALLOWED";
	return(KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }

    /* Check to see if preauthentication is required */
    if (isflagset(client.attributes, KRB5_KDB_REQUIRES_PRE_AUTH) &&
        !request->padata) {
	*status = "MISSING PRE_AUTH";
#ifdef KRBCONF_VAGUE_ERRORS
	return KRB_ERR_GENERIC;
#else
	return KDC_PREAUTH_FAILED;
#endif
    }

    /*
     * Check against local policy
     */
    errcode = against_local_policy_as(request, server, client,
				      kdc_time, status); 
    if (errcode)
	return errcode;

    return 0;
}

#define ASN1_ID_CLASS	(0xc0)
#define ASN1_ID_TYPE    (0x20)
#define ASN1_ID_TAG	(0x1f)	
#define ASN1_CLASS_UNIV	(0)
#define ASN1_CLASS_APP	(1)
#define ASN1_CLASS_CTX	(2)
#define ASN1_CLASS_PRIV	(3)
#define asn1_id_constructed(x) 	(x & ASN1_ID_TYPE)
#define asn1_id_primitive(x) 	(!asn1_id_constructed(x))
#define asn1_id_class(x)	((x & ASN1_ID_CLASS) >> 6)
#define asn1_id_tag(x)		(x & ASN1_ID_TAG)

/*
 * asn1length - return encoded length of value.
 *
 * passed a pointer into the asn.1 stream, which is updated
 * to point right after the length bits.
 *
 * returns -1 on failure.
 */
static int
asn1length(astream)
unsigned char **astream;
{
    int length;		/* resulting length */
    int sublen;		/* sublengths */
    int blen;		/* bytes of length */ 
    unsigned char *p;	/* substring searching */	

    if (**astream & 0x80) {
        blen = **astream & 0x7f;
	if (blen > 3) {
	   return(-1);
	}
	for (++*astream, length = 0; blen; ++*astream, blen--) {
	    length = (length << 8) | **astream;
	}
	if (length == 0) {
		/* indefinite length, figure out by hand */
	    p = *astream;
	    p++;
	    while (1) {
		/* compute value length. */
		if ((sublen = asn1length(&p)) < 0) {
		    return(-1);
		}
		p += sublen;
                /* check for termination */
		if ((!*p++) && (!*p)) {
		    p++;
		    break;
		}
	    }
	    length = p - *astream;	 
	}
    } else {
	length = **astream;
	++*astream;
    } 
   return(length);
}

/*
 * fetch_asn1_field - return raw asn.1 stream of subfield.
 *
 * this routine is passed a context-dependent tag number and "level" and returns
 * the size and length of the corresponding level subfield.
 *
 * levels and are numbered starting from 1.  
 *
 * returns 0 on success, -1 otherwise.
 */
int
fetch_asn1_field(astream, level, field, data)
unsigned char *astream;
unsigned int level;
unsigned int field;
krb5_data *data;
{
    unsigned char *estream;	/* end of stream */
    int classes;		/* # classes seen so far this level */
    int levels = 0;		/* levels seen so far */
    int lastlevel = 1000;       /* last level seen */
    int length;			/* various lengths */
    int tag;			/* tag number */

    /* we assume that the first identifier/length will tell us 
       how long the entire stream is. */
    astream++;
    estream = astream;
    if ((length = asn1length(&astream)) < 0) {
	return(-1);
    }
    estream += length;
    /* search down the stream, checking identifiers.  we process identifiers
       until we hit the "level" we want, and then process that level for our
       subfield, always making sure we don't go off the end of the stream.  */
    while (astream < estream) {
	if (!asn1_id_constructed(*astream)) {
	    return(-1);
	}
        if (asn1_id_class(*astream) == ASN1_CLASS_CTX) {
            if ((tag = (int)asn1_id_tag(*astream)) <= lastlevel) {
                levels++;
                classes = -1;
            }
            lastlevel = tag; 
            if (levels == level) {
	        /* in our context-dependent class, is this the one we're looking for ? */
	        if (tag == field) {
		    /* return length and data */ 
		    astream++;
		    if ((data->length = asn1length(&astream)) < 0) {
		        return(-1);
	 	    }
		    data->data = (char *)astream;
		    return(0);
	        } else if (tag <= classes) {
		    /* we've seen this class before, something must be wrong */
		    return(-1);
	        } else {
		    classes = tag;
	        }
	    }
        }
        /* if we're not on our level yet, process this value.  otherwise skip over it */
	astream++;
	if ((length = asn1length(&astream)) < 0) {
	    return(-1);
	}
	if (levels == level) {
	    astream += length;
	}
    }
    return(-1);
}

/*
 * Routines that validate a TGS request; checks a lot of things.  :-)
 *
 * Returns a Kerberos protocol error number, which is _not_ the same
 * as a com_err error number!
 */
#define TGS_OPTIONS_HANDLED (KDC_OPT_FORWARDABLE | KDC_OPT_FORWARDED | \
			     KDC_OPT_PROXIABLE | KDC_OPT_PROXY | \
			     KDC_OPT_ALLOW_POSTDATE | KDC_OPT_POSTDATED | \
			     KDC_OPT_RENEWABLE | KDC_OPT_RENEWABLE_OK | \
			     KDC_OPT_ENC_TKT_IN_SKEY | KDC_OPT_RENEW | \
			     KDC_OPT_VALIDATE)

int
validate_tgs_request(request, server, ticket, kdc_time, status)
register krb5_kdc_req *request;
krb5_db_entry server;
krb5_ticket *ticket;
krb5_timestamp kdc_time;
char **status;
{
    int		errcode;
    int		st_idx = 0;

    /*
     * If an illegal option is set, complain.
     */
    if (request->kdc_options & ~(TGS_OPTIONS_HANDLED)) {
	*status = "INVALID TGS OPTIONS";
	return KDC_ERR_BADOPTION;
    }
    
    /* Check to see if server has expired */
    if (server.expiration && server.expiration < kdc_time) {
	*status = "SERVICE EXPIRED";
	return(KDC_ERR_SERVICE_EXP);
    }

    /*
     * Verify that the server principal in authdat->ticket is correct
     * (either the ticket granting service or the service we're
     * looking for)
     */
    if (krb5_principal_compare(ticket->server, tgs_server)) {
	/* Server must allow TGS based issuances */
	if (isflagset(server.attributes, KRB5_KDB_DISALLOW_TGT_BASED)) {
	    *status = "TGT BASED NOT ALLOWED";
	    return(KDC_ERR_POLICY);
	}
    } else {
	if (!krb5_principal_compare(ticket->server,
				    request->server)) {
	    *status = "BAD SERVER IN TKT";
	    return KRB5KRB_AP_ERR_NOT_US;
	}
    }
    
    /* TGS must be forwardable to get forwarded or forwardable ticket */
    if ((isflagset(request->kdc_options, KDC_OPT_FORWARDED) ||
	 isflagset(request->kdc_options, KDC_OPT_FORWARDABLE)) &&
	!isflagset(ticket->enc_part2->flags, TKT_FLG_FORWARDABLE)) {
	*status = "TGT NOT FORWARDABLE";

	return KDC_ERR_BADOPTION;
    }

    /* TGS must be proxiable to get proxiable ticket */    
    if ((isflagset(request->kdc_options, KDC_OPT_PROXY) ||
	 isflagset(request->kdc_options, KDC_OPT_PROXIABLE)) &&
	!isflagset(ticket->enc_part2->flags, TKT_FLG_PROXIABLE)) {
	*status = "TGT NOT PROXIABLE";
	return KDC_ERR_BADOPTION;
    }

    /* TGS must allow postdating to get postdated ticket */
    if ((isflagset(request->kdc_options, KDC_OPT_ALLOW_POSTDATE) ||
	  isflagset(request->kdc_options, KDC_OPT_POSTDATED)) &&
	!isflagset(ticket->enc_part2->flags, TKT_FLG_MAY_POSTDATE)) {
	*status = "TGT NOT POSTDATABLE";
	return KDC_ERR_BADOPTION;
    }

    /* can only validate invalid tix */
    if (isflagset(request->kdc_options, KDC_OPT_VALIDATE) &&
	!isflagset(ticket->enc_part2->flags, TKT_FLG_INVALID)) {
	*status = "VALIDATE VALID TICKET";
	return KDC_ERR_BADOPTION;
    }

    /* can only renew renewable tix */
    if ((isflagset(request->kdc_options, KDC_OPT_RENEW) ||
	  isflagset(request->kdc_options, KDC_OPT_RENEWABLE)) &&
	!isflagset(ticket->enc_part2->flags, TKT_FLG_RENEWABLE)) {
	*status = "TICKET NOT RENEWABLE";
	return KDC_ERR_BADOPTION;
    }

    /* can not proxy ticket granting tickets */
    if (isflagset(request->kdc_options, KDC_OPT_PROXY) &&
	(!request->server->data ||
	 request->server->data[0].length != 6 ||
	 memcmp(request->server->data[0].data, "krbtgt", 6))) {
	*status = "CAN'T PROXY TGT";
	return KDC_ERR_BADOPTION;
    }
    
    /* Server must allow forwardable tickets */
    if (isflagset(request->kdc_options, KDC_OPT_FORWARDABLE) &&
	isflagset(server.attributes, KRB5_KDB_DISALLOW_FORWARDABLE)) {
	*status = "NON-FORWARDABLE TICKET";
	return(KDC_ERR_POLICY);
    }
    
    /* Server must allow renewable tickets */
    if (isflagset(request->kdc_options, KDC_OPT_RENEWABLE) &&
	isflagset(server.attributes, KRB5_KDB_DISALLOW_RENEWABLE)) {
	*status = "NON-RENEWABLE TICKET";
	return(KDC_ERR_POLICY);
    }
    
    /* Server must allow proxiable tickets */
    if (isflagset(request->kdc_options, KDC_OPT_PROXIABLE) &&
	isflagset(server.attributes, KRB5_KDB_DISALLOW_PROXIABLE)) {
	*status = "NON-PROXIABLE TICKET";
	return(KDC_ERR_POLICY);
    }
    
    /* Server must allow postdated tickets */
    if (isflagset(request->kdc_options, KDC_OPT_ALLOW_POSTDATE) &&
	isflagset(server.attributes, KRB5_KDB_DISALLOW_POSTDATED)) {
	*status = "NON-POSTDATABLE TICKET";
	return(KDC_ERR_CANNOT_POSTDATE);
    }
    
    /* Server must allow DUP SKEY requests */
    if (isflagset(request->kdc_options, KDC_OPT_ENC_TKT_IN_SKEY) &&
	isflagset(server.attributes, KRB5_KDB_DISALLOW_DUP_SKEY)) {
	*status = "DUP_SKEY DISALLOWED";
	return(KDC_ERR_POLICY);
    }

    /* Server must not be locked out */
    if (isflagset(server.attributes, KRB5_KDB_DISALLOW_ALL_TIX)) {
	*status = "SERVER LOCKED OUT";
	return(KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }
	
    /* Server must be allowed to be a service */
    if (isflagset(server.attributes, KRB5_KDB_DISALLOW_SVR)) {
	*status = "SERVER NOT ALLOWED";
	return(KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }

    /* Check the hot list */
    if (check_hot_list(ticket)) {
	*status = "HOT_LIST";
	return(KRB_AP_ERR_REPEAT);
    }
    
    /* Check the start time vs. the KDC time */
    if (isflagset(request->kdc_options, KDC_OPT_VALIDATE)) {
	if (ticket->enc_part2->times.starttime > kdc_time) {
	    *status = "NOT_YET_VALID";
	    return(KRB_AP_ERR_TKT_NYV);
	}
    }
    
    /*
     * Check the renew_till time.  The endtime was already
     * been checked in the initial authentication check.
     */
    if (isflagset(request->kdc_options, KDC_OPT_RENEW) &&
	(ticket->enc_part2->times.renew_till < kdc_time)) {
	*status = "TKT_EXPIRED";
	return(KRB_AP_ERR_TKT_EXPIRED);
    }
    
    /*
     * Checks for ENC_TKT_IN_SKEY:
     *
     * (1) Make sure the second ticket exists
     * (2) Make sure it is a ticket granting ticket
     */
    if (isflagset(request->kdc_options, KDC_OPT_ENC_TKT_IN_SKEY)) {
	if (!request->second_ticket ||
	    !request->second_ticket[st_idx]) {
	    *status = "NO_2ND_TKT";
	    return(KDC_ERR_BADOPTION);
	}
	if (!krb5_principal_compare(request->second_ticket[st_idx]->server,
				    tgs_server)) {
		*status = "2ND_TKT_NOT_TGS";
		return(KDC_ERR_POLICY);
	}
	st_idx++;
    }

    /* Check for hardware preauthentication */
    if (isflagset(server.attributes, KRB5_KDB_REQUIRES_HW_AUTH) &&
	!isflagset(ticket->enc_part2->flags,TKT_FLG_HW_AUTH)) {
	*status = "NO HW PREAUTH";
	return KRB_ERR_GENERIC;
    }

    /* Check for any kind of preauthentication */
    if (isflagset(server.attributes, KRB5_KDB_REQUIRES_PRE_AUTH) &&
	!isflagset(ticket->enc_part2->flags, TKT_FLG_PRE_AUTH)) {
	*status = "NO PREAUTH";
	return KRB_ERR_GENERIC;
    }
    
    /*
     * Check local policy
     */
    errcode = against_local_policy_tgs(request, server, ticket, status);
    if (errcode)
	return errcode;
    
    
    return 0;
}

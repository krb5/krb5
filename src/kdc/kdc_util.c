/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Utility functions for the KDC implementation.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_kdc_util_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/asn1.h>

#include "kdc_util.h"
#include "extern.h"

#include <krb5/ext-proto.h>
#include <stdio.h>

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
	for (ptr = first; *ptr; ptr++,i++);
    if (second)
	for (ptr = second; *ptr; ptr++,i++);
    
    retdata = (krb5_authdata **)malloc((i+1)*sizeof(*retdata));
    if (!retdata)
	return ENOMEM;
    retdata[i] = 0;			/* null-terminated array */
    for (i = 0, j = 0, ptr = first; j < 2 ; ptr = second, j++)
	while (ptr && *ptr) {
	    /* now walk & copy */
	    retdata[i] = (krb5_authdata *)malloc(sizeof(*retdata[i]));
	    if (!retdata[i]) {
		/* XXX clean up */
		return ENOMEM;
	    }
	    *retdata[i] = **ptr;
	    if (!(retdata[i]->contents =
		  (krb5_octet *)malloc(retdata[i]->length))) {
		/* XXX clean up */
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
    return(strncmp(realmname->data, krb5_princ_realm(princ)->data,
		   min(realmname->length,
		       krb5_princ_realm(princ)->length)) ? FALSE : TRUE);
}

struct kparg {
    krb5_db_entry *dbentry;
    krb5_keyblock *key;
};

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

    if (vno != whoisit->dbentry->kvno)
	return KRB5KRB_AP_ERR_BADKEYVER;
    if (!krb5_principal_compare(principal, whoisit->dbentry->principal))
	return KRB5KRB_AP_ERR_NOKEY;
    return(krb5_copy_keyblock(whoisit->key, key));
}


krb5_error_code 
kdc_process_tgs_req(request, from, ticket)
krb5_kdc_req *request;
const krb5_fulladdr *from;
krb5_ticket **ticket;
{
    krb5_ap_req *apreq;
    int nprincs;
    krb5_boolean more;
    krb5_db_entry server;
    krb5_keyblock encrypting_key;
    krb5_tkt_authent *authdat;
    struct kparg who;
    krb5_error_code retval;
    krb5_checksum our_cksum;
    krb5_data *scratch, scratch2;
    krb5_pa_data **tmppa;
    krb5_boolean freeprinc = FALSE;

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

    *ticket = apreq->ticket;

    /* the caller will free the ticket when cleaning up */
#define cleanup_apreq() {apreq->ticket = 0; krb5_free_ap_req(apreq);}

#ifdef notdef
    /* XXX why copy here? */
    krb5_free_data(request->server[0]);
    if (retval = krb5_copy_data(apreq->ticket->server[0],
				  &request->server[0])) {
	register krb5_data **foo;
	request->server[0] = 0;
	for (foo = &request->server[1]; *foo; foo++)
	    krb5_free_data(*foo);
	/* XXX mem leak plugged? */
	cleanup_apreq();
	return retval;
    }
#endif

    if (isflagset(apreq->ap_options, AP_OPTS_USE_SESSION_KEY) ||
	isflagset(apreq->ap_options, AP_OPTS_MUTUAL_REQUIRED)) {
	cleanup_apreq();
	return KRB5KDC_ERR_POLICY;
    }

    if (krb5_principal_compare(tgs_server, apreq->ticket->server)) {
	encrypting_key = tgs_key;
	server.kvno = tgs_kvno;
	server.principal = tgs_server;
    } else {
	nprincs = 1;
	if (retval = krb5_db_get_principal(apreq->ticket->server,
					   &server, &nprincs,
					   &more)) {
	    cleanup_apreq();
	    return(retval);
	}
	if (more) {
	    krb5_db_free_principal(&server, nprincs);
	    cleanup_apreq();
	    return(KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE);
	} else if (nprincs != 1) {
	    krb5_db_free_principal(&server, nprincs);
	    cleanup_apreq();
	    return(KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN);
	}
	/* convert server.key into a real key (it may be encrypted
	   in the database) */
	if (retval = KDB_CONVERT_KEY_OUTOF_DB(&server.key, &encrypting_key)) {
	    krb5_db_free_principal(&server, nprincs);
	    cleanup_apreq();
	    return retval;
	}
	freeprinc = TRUE;
    }
    who.dbentry = &server;
    who.key = &encrypting_key;
    retval = krb5_rd_req_decoded(apreq, apreq->ticket->server,
				 from->address,
				 0,	/* no fetchfrom */
				 kdc_rdreq_keyproc,
				 (krb5_pointer)&who,
				 0,	/* no replay cache */
				 &authdat);
    if (freeprinc) {
	krb5_db_free_principal(&server, nprincs);
	memset((char *)encrypting_key.contents, 0, encrypting_key.length);
	free((char *)encrypting_key.contents);
    }
    if (retval) {
	cleanup_apreq();
	return(retval);
    }

    /* now rearrange output from rd_req_decoded */

    our_cksum.checksum_type = authdat->authenticator->checksum->checksum_type;
    if (!valid_cksumtype(our_cksum.checksum_type)) {
	krb5_free_tkt_authent(authdat);
	cleanup_apreq();
	return KRB5KDC_ERR_SUMTYPE_NOSUPP;
    }	
    /* must be collision proof */
    if (!is_coll_proof_cksum(our_cksum.checksum_type)) {
	krb5_free_tkt_authent(authdat);
	cleanup_apreq();
	return KRB5KRB_AP_ERR_INAPP_CKSUM;
    }

    /* check application checksum vs. tgs request */
    if (!(our_cksum.contents = (krb5_octet *)
	  malloc(krb5_cksumarray[our_cksum.checksum_type]->checksum_length))) {
	krb5_free_tkt_authent(authdat);
	cleanup_apreq();
	return ENOMEM; /* XXX cktype nosupp */
    }

    /* encode the body, verify the checksum */
    if (retval = encode_krb5_kdc_req_body(request, &scratch)) {
	krb5_free_tkt_authent(authdat);
	cleanup_apreq();
	return retval; /* XXX should be in kdc range */
    }

    if (retval = (*krb5_cksumarray[our_cksum.checksum_type]->
		  sum_func)(scratch->data,
			    scratch->length,
			    authdat->ticket->enc_part2->session->contents, /* seed */
			    authdat->ticket->enc_part2->session->length,	/* seed length */
			    &our_cksum)) {
	krb5_free_tkt_authent(authdat);
	xfree(our_cksum.contents);
	xfree(scratch->data);
	cleanup_apreq();
	return retval;
    }
    if (our_cksum.length != authdat->authenticator->checksum->length ||
	memcmp((char *)our_cksum.contents,
	       (char *)authdat->authenticator->checksum->contents,
	       our_cksum.length)) {
	krb5_free_tkt_authent(authdat);
	xfree(our_cksum.contents);
	xfree(scratch->data);
	cleanup_apreq();
	return KRB5KRB_AP_ERR_BAD_INTEGRITY; /* XXX wrong code? */
    }
    xfree(scratch->data);
    xfree(our_cksum.contents);

    krb5_free_tkt_authent(authdat);
    cleanup_apreq();
    return 0;
}

/* This probably wants to be updated if you support last_req stuff */

static krb5_last_req_entry *nolrarray[] = { 0 };

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

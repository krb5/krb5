/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
    register krb5_keyblock *newkey;
    krb5_error_code retval;

    if (vno != whoisit->dbentry->kvno)
	return KRB5KRB_AP_ERR_BADKEYVER;
    if (!krb5_principal_compare(principal, whoisit->dbentry->principal))
	return KRB5KRB_AP_ERR_NOKEY;
    if (!(newkey = (krb5_keyblock *)malloc(sizeof(*newkey))))
	return ENOMEM;
    if (retval = krb5_copy_keyblock(whoisit->key, newkey))
	return retval;
    *key = newkey;
    return 0;
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
    krb5_tkt_authent authdat;
    struct kparg who;
    krb5_error_code retval;
    krb5_checksum our_cksum;
    krb5_data *scratch;

    if (request->padata_type != KRB5_PADATA_AP_REQ)
	return KRB5KDC_ERR_PADATA_TYPE_NOSUPP;

    if (retval = decode_krb5_ap_req(&request->padata, &apreq))
	return retval;

#define cleanup_apreq() {krb5_free_ap_req(apreq); *ticket = 0;}

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

    /* XXX perhaps we should optimize the case of the TGS ? */

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
    if (retval = kdc_convert_key(&server.key, &encrypting_key,
				 CONVERT_OUTOF_DB)) {
	krb5_db_free_principal(&server, nprincs);
	cleanup_apreq();
	return retval;
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
    krb5_db_free_principal(&server, nprincs);
    bzero((char *)encrypting_key.contents, encrypting_key.length);
    free((char *)encrypting_key.contents);
    if (retval) {
	cleanup_apreq();
	return(retval);
    }

    /* now rearrange output from rd_req_decoded */

    our_cksum.checksum_type = authdat.authenticator->checksum->checksum_type;
    if (!valid_cksumtype(our_cksum.checksum_type)) {
	krb5_free_authenticator(authdat.authenticator);
	krb5_free_ticket(authdat.ticket);
	cleanup_apreq();
	return KRB5KDC_ERR_SUMTYPE_NOSUPP;
    }	

    /* check application checksum vs. tgs request */
    if (!(our_cksum.contents = (krb5_octet *)
	  malloc(krb5_cksumarray[our_cksum.checksum_type]->checksum_length))) {
	krb5_free_authenticator(authdat.authenticator);
	krb5_free_ticket(authdat.ticket);
	cleanup_apreq();
	return ENOMEM; /* XXX cktype nosupp */
    }

    /* encode the body, verify the checksum */
    if (retval = encode_krb5_kdc_req_body(request, &scratch)) {
	krb5_free_authenticator(authdat.authenticator);
	krb5_free_ticket(authdat.ticket);
	cleanup_apreq();
	return retval; /* XXX should be in kdc range */
    }

    if (retval = (*krb5_cksumarray[our_cksum.checksum_type]->
		  sum_func)(scratch->data,
			    scratch->length,
			    authdat.ticket->enc_part2->session->contents, /* seed */
			    authdat.ticket->enc_part2->session->length,	/* seed length */
			    &our_cksum)) {
	krb5_free_authenticator(authdat.authenticator);
	krb5_free_ticket(authdat.ticket);
	xfree(our_cksum.contents);
	xfree(scratch->data);
	cleanup_apreq();
	return retval;
    }
    if (our_cksum.length != authdat.authenticator->checksum->length ||
	memcmp((char *)our_cksum.contents,
	       (char *)authdat.authenticator->checksum->contents,
	       our_cksum.length)) {
	krb5_free_authenticator(authdat.authenticator);
	krb5_free_ticket(authdat.ticket);
	xfree(our_cksum.contents);
	xfree(scratch->data);
	cleanup_apreq();
	return KRB5KRB_AP_ERR_BAD_INTEGRITY; /* XXX wrong code? */
    }
    xfree(scratch->data);
    xfree(our_cksum.contents);

    /* don't need authenticator anymore */
    krb5_free_authenticator(authdat.authenticator);

    /* ticket already filled in by rd_req_dec, so free the ticket */
    krb5_free_ticket(authdat.ticket);
    *ticket = apreq->ticket;
    apreq->ticket = 0;
    krb5_free_ap_req(apreq);
    return 0;
}

krb5_error_code
kdc_convert_key(in, out, direction)
krb5_keyblock *in, *out;
int direction;
{
    if (direction == CONVERT_INTO_DB) {
	return krb5_kdb_encrypt_key(&master_encblock, in, out);
    } else if (direction == CONVERT_OUTOF_DB) {
	return krb5_kdb_decrypt_key(&master_encblock, in, out);
    } else
	return KRB5_KDB_ILLDIRECTION;
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
 */

/* subrealm takes two realms, r1 and r2,  and determines if r2    */
/* is a subrealm of r1.  Keep in mind that the name of a subrealm */
/* is a superstring of its parent and vice versa.  If a subrealm, */
/* then the number of charcters that form the prefix in r2 is     */
/* returned.  Otherwise subrealm returns 0.                       */
static  int
subrealm(r1,r2)
char	*r1;
char	*r2;
{
    int	l1,l2;
    l1 = strlen(r1);
    l2 = strlen(r2);
    if (l2 <= l1) return(0);
    if (strcmp(r1,r2+l2-l1)  != 0) return(0);
    return(l2-l1);
}

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

    strcpy(prev,krb5_princ_realm(client)->data);

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
	strcpy(exp,current);
	if(current[clst] == '.') {
	    strcat(exp,prev);
	}

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
	    /* realm is a superstring of the current realm, compress */
	    /* the new realm, and insert immediately following the   */
	    /* current one.  Note that we can not do this if the next*/
	    /* field is already compressed since it would mess up    */
	    /* what has already been done.  In most cases, this is   */
	    /* not a problem becase the realm to be added will be a  */
	    /* superstring of the next field too, and we will catch  */
	    /* it in a future iteration.                             */
	    if((next[nlst] != '.') && (pl = subrealm(exp,realm))) {
		added = 1;
		strcat(current,",");
		strncat(current,realm,pl);
	    }

	    /* Whether or not the next field is compressed, if the   */
	    /* realm to be added is a substring of the current field,*/
	    /* then the current field can be compressed.  First the  */
	    /* realm to be added must be compressed relative to the  */
	    /* previous field (of possible), and then the current    */
	    /* field compressed relative to the new realm.  Note that*/
	    /* if the realm to be added is also a substring of the   */
	    /* previous realm, it would have been added earlier, and */
	    /* we would not reach this step this time around.        */
	    else if(pl = subrealm(realm,exp)) {
		added = 1;
		*current = '\0';
		pl1 = subrealm(prev,realm);
		if(pl1) strncat(current,realm,subrealm(prev,realm));
		else strcat(current,realm);
		strcat(current,",");
		strncat(current,exp,pl);
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
	strcat(trans,realm);
	new_trans->length = strlen(trans) + 1;
    }
    return 0;
}


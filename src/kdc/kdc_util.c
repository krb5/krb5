/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
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
#include <krb5/krb5_err.h>
#include <krb5/kdb5_err.h>
#include <krb5/asn1.h>

#include "kdc_util.h"
#include "extern.h"

#include <errno.h>
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
    for (i = 0, ptr = first; *ptr; ptr++,i++);
    for (ptr = second; *ptr; ptr++,i++);
    
    retdata = (krb5_authdata **)malloc((i+1)*sizeof(*retdata));
    if (!retdata)
	return ENOMEM;
    retdata[i] = 0;			/* null-terminated array */
    for (i = 0, j = 0, ptr = first; j < 2 ; ptr = second, j++)
	while (*ptr) {
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
	    bcopy((char *)(*ptr)->contents, (char *) retdata[i]->contents,
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

krb5_error_code
decrypt_tgs_req(tgs_req, from)
krb5_tgs_req *tgs_req;
const krb5_fulladdr *from;
{
    krb5_error_code retval;
    krb5_data scratch;
    krb5_encrypt_block eblock;
    krb5_tgs_req_enc_part *local_encpart;

    if (retval = kdc_process_tgs_req(tgs_req, from))
	return(retval);

    if (tgs_req->tgs_request2->enc_part.length) {
	/* decrypt encrypted part, attach to enc_part2 */

	if (!valid_etype(tgs_req->tgs_request2->etype)) /* XXX wrong etype to use? */
	    return KRB5KDC_ERR_ETYPE_NOSUPP;

	scratch.length = tgs_req->tgs_request2->enc_part.length;
	if (!(scratch.data = malloc(tgs_req->tgs_request2->enc_part.length))) {
	    return(ENOMEM);
	}
	/* put together an eblock for this encryption */

	eblock.crypto_entry = krb5_csarray[tgs_req->tgs_request2->etype]->system; /* XXX */
	/* do any necessary key pre-processing */
	if (retval = (*eblock.crypto_entry->process_key)(&eblock,
							 tgs_req->header2->ticket->enc_part2->session)) {
	    free(scratch.data);
	    return(retval);
	}

	/* call the encryption routine */
	if (retval =
	    (*eblock.crypto_entry->decrypt_func)((krb5_pointer) tgs_req->tgs_request2->enc_part.data,
						 (krb5_pointer) scratch.data,
						 scratch.length, &eblock)) {
	    (void) (*eblock.crypto_entry->finish_key)(&eblock);
	    free(scratch.data);
	    return retval;
	}

#define clean_scratch() {bzero(scratch.data, scratch.length); free(scratch.data);}

	if (retval = (*eblock.crypto_entry->finish_key)(&eblock)) {
	    clean_scratch();
	    return retval;
	}
	if (retval = decode_krb5_tgs_req_enc_part(&scratch, &local_encpart)) {
	    clean_scratch();
	    return retval;
	}
	clean_scratch();
#undef clean_scratch

	tgs_req->tgs_request2->enc_part2 = local_encpart;
    }
    return 0;
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
kdc_process_tgs_req(request, from)
krb5_tgs_req *request;
const krb5_fulladdr *from;
{
    register krb5_ap_req *apreq;
    int nprincs;
    krb5_boolean more;
    krb5_db_entry server;
    krb5_keyblock encrypting_key;
    krb5_tkt_authent authdat;
    struct kparg who;
    krb5_error_code retval;
    krb5_checksum our_cksum;

    if (retval = decode_krb5_ap_req(&request->header, &request->header2))
	return retval;
    if (retval = decode_krb5_real_tgs_req(&request->tgs_request, &request->tgs_request2))
	return retval;
    krb5_free_data(request->tgs_request2->server[0]);
    if (retval = krb5_copy_data(request->header2->ticket->server[0],
				  &request->tgs_request2->server[0])) {
	request->tgs_request2->server[0] = 0;
	/* XXX mem leak of rest of server components... */
	return retval;
    }

    apreq = request->header2;
    if (isflagset(apreq->ap_options, AP_OPTS_USE_SESSION_KEY) ||
	isflagset(apreq->ap_options, AP_OPTS_MUTUAL_REQUIRED))
	return KRB5KDC_ERR_POLICY;

    /* XXX perhaps we should optimize the case of the TGS ? */

    nprincs = 1;
    if (retval = krb5_db_get_principal(apreq->ticket->server,
				       &server, &nprincs,
				       &more))
	return(retval);
    if (more) {
	krb5_db_free_principal(&server, nprincs);
	return(KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE);
    } else if (nprincs != 1) {
	krb5_db_free_principal(&server, nprincs);
	return(KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }
    /* convert server.key into a real key (it may be encrypted
       in the database) */
    if (retval = kdc_convert_key(&server.key, &encrypting_key,
				 CONVERT_OUTOF_DB)) {
	krb5_db_free_principal(&server, nprincs);
	return retval;
    }
    who.dbentry = &server;
    who.key = &encrypting_key;
    if (retval = krb5_rd_req_decoded(apreq, apreq->ticket->server,
				     from->address,
				     0,	/* no fetchfrom */
				     kdc_rdreq_keyproc,
				     (krb5_pointer)&who,
				     kdc_rcache,
				     &authdat)) {
	krb5_db_free_principal(&server, nprincs);
	bzero((char *)encrypting_key.contents, encrypting_key.length);
	free((char *)encrypting_key.contents);

	return(retval);
    }
    krb5_db_free_principal(&server, nprincs);
    bzero((char *)encrypting_key.contents, encrypting_key.length);
    free((char *)encrypting_key.contents);

    /* now rearrange output from rd_req_decoded */


    our_cksum.checksum_type = authdat.authenticator->checksum->checksum_type;
    if (!valid_cksumtype(our_cksum.checksum_type)) {
	krb5_free_authenticator(authdat.authenticator);
	krb5_free_ticket(authdat.ticket);
	return KRB5KDC_ERR_ETYPE_NOSUPP; /* XXX cktype nosupp */
    }	
    /* check application checksum vs. tgs request */
#ifdef notdef
    if (retval = (*krb5_cksumarray[our_cksum.checksum_type]->
		  sum_func)(in,		/* where to? */
			    NULL,	/* don't produce output */
			    authdat.ticket->enc_part2->session->contents, /* seed */
			    in_length,	/* input length */
			    authdat.ticket->enc_part2->session->length,	/* seed length */
			    &our_cksum)) {
	krb5_free_authenticator(authdat.authenticator);
	krb5_free_ticket(authdat.ticket);
	return KRB5KRB_AP_ERR_BAD_INTEGRITY; /* XXX wrong code? */
    }
#endif
    /* don't need authenticator anymore */
    krb5_free_authenticator(authdat.authenticator);

    /* ticket already filled in by rd_req_dec, so free the ticket */
    krb5_free_ticket(authdat.ticket);

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

/* XXX!  This is a temporary place-holder */

krb5_error_code
compress_transited(in_tran, princ, out_tran)
krb5_data *in_tran;
krb5_principal princ;
krb5_data *out_tran;
{
    return EOPNOTSUPP;
}

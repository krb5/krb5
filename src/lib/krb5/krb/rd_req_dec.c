/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_rd_req_decoded()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_rd_req_dec_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/libos-proto.h>
#include <krb5/asn1.h>

/*
 essentially the same as krb_rd_req, but uses a decoded AP_REQ as the input
 rather than an encoded input.
 */
/*
 Parses a KRB_AP_REQ message, returning its contents.

 server specifies the expected server's name for the ticket.

 sender_addr specifies the address(es) expected to be present in the
 ticket.

 rcache specifies a replay detection cache used to store authenticators and
 server names

 keyproc specifies a procedure to generate a decryption key for the
 ticket.  If keyproc is non-NULL, keyprocarg is passed to it, and the result
 used as a decryption key. If keyproc is NULL, then fetchfrom is checked;
 if it is non-NULL, it specifies a parameter name from which to retrieve the
 decryption key.  If fetchfrom is NULL, then the default key store is
 consulted.

 authdat->ticket and authdat->authenticator are set to allocated storage
 structures; the caller should free them when finished.

 returns system errors, encryption errors, replay errors
 */

static krb5_error_code decrypt_authenticator PROTOTYPE((const krb5_ap_req *,
							krb5_authenticator **));
extern krb5_deltat krb5_clockskew;
#define in_clock_skew(date) (abs((date)-currenttime) < krb5_clockskew)

krb5_error_code
krb5_rd_req_decoded(req, server, sender_addr, fetchfrom, keyproc, keyprocarg,
		    rcache, tktauthent)
const krb5_ap_req *req;
krb5_const_principal server;
const krb5_address *sender_addr;
krb5_const_pointer fetchfrom;
krb5_error_code (*keyproc) PROTOTYPE((krb5_pointer,
				      krb5_principal,
				      krb5_kvno,
				      krb5_keyblock **));
krb5_pointer keyprocarg;
krb5_rcache rcache;
krb5_tkt_authent *tktauthent;
{
    krb5_error_code retval;
    krb5_keyblock *tkt_key;
    krb5_keyblock tkt_key_real;
    krb5_timestamp currenttime;


    if (!krb5_principal_compare(server,
				(krb5_const_principal) req->ticket->server))
	return KRB5KRB_AP_WRONG_PRINC;

    /* if (req->ap_options & AP_OPTS_USE_SESSION_KEY)
       do we need special processing here ?	*/
    
    /* fetch a server key */
    if (keyproc) {
	retval = (*keyproc)(keyprocarg, req->ticket->server,
			    req->ticket->enc_part.kvno, &tkt_key);
    } else {
	krb5_keytab keytabid;
	krb5_keytab_entry ktentry;

	if (fetchfrom) {
	    /* use the named keytab */
	    retval = krb5_kt_resolve((char *)fetchfrom, &keytabid);
	} else {
	    /* use default keytab */
	    retval = krb5_kt_default(&keytabid);
	}
	if (!retval) {
	    retval = krb5_kt_get_entry(keytabid, req->ticket->server,
				       req->ticket->enc_part.kvno, &ktentry);
	    (void) krb5_kt_close(keytabid);
	    if (!retval) {
		retval = krb5_copy_keyblock(&ktentry.key, &tkt_key_real);
		tkt_key = &tkt_key_real;
		(void) krb5_kt_free_entry(&ktentry);
	    }
	}
    }
    if (retval)
	return retval;			/* some error in getting the key */

    /* decrypt the ticket */
    if (retval = krb5_decrypt_tkt_part(tkt_key, req->ticket))
	return(retval);

#define clean_ticket() krb5_free_enc_tkt_part(req->ticket->enc_part2)

    if (retval = decrypt_authenticator(req, &tktauthent->authenticator)) {
	clean_ticket();
	return retval;
    }
#define clean_authenticator() {(void) krb5_free_authenticator(tktauthent->authenticator); tktauthent->authenticator = 0;}

    if (!krb5_principal_compare((krb5_const_principal)tktauthent->authenticator->client,
				(krb5_const_principal)req->ticket->enc_part2->client)) {
	clean_authenticator();
	return KRB5KRB_AP_ERR_BADMATCH;
    }
    if (sender_addr && !krb5_address_search(sender_addr, req->ticket->enc_part2->caddrs)) {
	clean_authenticator();
	return KRB5KRB_AP_ERR_BADADDR;
    }

    if (retval = krb5_timeofday(&currenttime)) {
	clean_authenticator();
	return retval;
    }
    if (!in_clock_skew(tktauthent->authenticator->ctime)) {
	clean_authenticator();
	return KRB5KRB_AP_ERR_SKEW;
    }

    tktauthent->ticket = req->ticket;	/* only temporarily...allocated
					   below */

    /* only check rcache if sender has provided one---some services
       may not be able to use replay caches (such as datagram servers) */
    if (rcache && (retval = krb5_rc_store(rcache, tktauthent))) {
	tktauthent->ticket = 0;
	clean_authenticator();
	return retval;
    }
    tktauthent->ticket = 0;
    if (req->ticket->enc_part2->times.starttime - currenttime > krb5_clockskew) {
	clean_authenticator();
	return KRB5KRB_AP_ERR_TKT_NYV;	/* ticket not yet valid */
    }	
    if (currenttime - req->ticket->enc_part2->times.endtime > krb5_clockskew) {
	clean_authenticator();
	return KRB5KRB_AP_ERR_TKT_EXPIRED;	/* ticket expired */
    }	
    if (req->ticket->enc_part2->flags & TKT_FLG_INVALID) {
	clean_authenticator();
	return KRB5KRB_AP_ERR_TKT_INVALID;
    }
    if (retval = krb5_copy_ticket(req->ticket, &tktauthent->ticket)) {
	clean_authenticator();
    } else
	tktauthent->ap_options = req->ap_options;
    return retval;
}

static krb5_error_code
decrypt_authenticator(request, authpp)
const krb5_ap_req *request;
krb5_authenticator **authpp;
{
    krb5_authenticator *local_auth;
    krb5_error_code retval;
    krb5_encrypt_block eblock;
    krb5_data scratch;
    krb5_keyblock *sesskey;

    sesskey = request->ticket->enc_part2->session;

    if (!valid_keytype(sesskey->keytype))
	return KRB5_PROG_KEYTYPE_NOSUPP;

    /* put together an eblock for this encryption */

    if (!valid_etype(request->authenticator.etype))
	return KRB5_PROG_ETYPE_NOSUPP;

    eblock.crypto_entry = krb5_csarray[request->authenticator.etype]->system;

    scratch.length = request->authenticator.ciphertext.length;
    if (!(scratch.data = malloc(scratch.length)))
	return(ENOMEM);

    /* do any necessary key pre-processing */
    if (retval = krb5_process_key(&eblock, sesskey)) {
	free(scratch.data);
	return(retval);
    }

    /* call the encryption routine */
    if (retval = krb5_decrypt((krb5_pointer) request->authenticator.ciphertext.data,
			      (krb5_pointer) scratch.data,
			      scratch.length, &eblock, 0)) {
	(void) krb5_finish_key(&eblock);
	free(scratch.data);
	return retval;
    }
#define clean_scratch() {bzero(scratch.data, scratch.length); free(scratch.data);}
    if (retval = krb5_finish_key(&eblock)) {

	clean_scratch();
	return retval;
    }
    /*  now decode the decrypted stuff */
    if (!(retval = decode_krb5_authenticator(&scratch, &local_auth))) {
	*authpp = local_auth;
    }
    clean_scratch();
    return retval;
}


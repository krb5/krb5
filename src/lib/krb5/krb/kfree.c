/*
 * lib/krb5/free/f_addr.c
 *
 * Copyright 1990-1998 by the Massachusetts Institute of Technology.
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
 * krb5_free_address()
 */

#include "k5-int.h"

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_address(context, val)
    krb5_context context;
    krb5_address FAR *val;
{
    if (val->contents)
	krb5_xfree(val->contents);
    krb5_xfree(val);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_addresses(context, val)
    krb5_context context;
    krb5_address FAR * FAR *val;
{
    register krb5_address **temp;

    for (temp = val; *temp; temp++) {
	if ((*temp)->contents)
	    krb5_xfree((*temp)->contents);
	krb5_xfree(*temp);
    }
    krb5_xfree(val);
    return;
}


KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_ap_rep(context, val)
    krb5_context context;
    register krb5_ap_rep FAR *val;
{
    if (val->enc_part.ciphertext.data)
	krb5_xfree(val->enc_part.ciphertext.data);
    krb5_xfree(val);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_ap_req(context, val)
    krb5_context context;
    register krb5_ap_req FAR *val;
{
    if (val->ticket)
	krb5_free_ticket(context, val->ticket);
    if (val->authenticator.ciphertext.data)
	krb5_xfree(val->authenticator.ciphertext.data);
    krb5_xfree(val);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_ap_rep_enc_part(context, val)
    krb5_context context;
    krb5_ap_rep_enc_part FAR *val;
{
    if (val->subkey)
	krb5_free_keyblock(context, val->subkey);
    krb5_xfree(val);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_authenticator_contents(context, val)
    krb5_context context;
    krb5_authenticator FAR *val;
{
    if (val->checksum)
	krb5_free_checksum(context, val->checksum);
    if (val->client)
	krb5_free_principal(context, val->client);
    if (val->subkey)
	krb5_free_keyblock(context, val->subkey);
    if (val->authorization_data)        
       krb5_free_authdata(context, val->authorization_data);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_authdata(context, val)
    krb5_context context;
    krb5_authdata FAR * FAR *val;
{
    register krb5_authdata **temp;

    for (temp = val; *temp; temp++) {
	if ((*temp)->contents)
	    krb5_xfree((*temp)->contents);
	krb5_xfree(*temp);
    }
    krb5_xfree(val);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_authenticator(context, val)
    krb5_context context;
    krb5_authenticator FAR *val;
{
    if (val->checksum)
	krb5_free_checksum(context, val->checksum);
    if (val->client)
	krb5_free_principal(context, val->client);
    if (val->subkey)
	krb5_free_keyblock(context, val->subkey);
    if (val->authorization_data)        
       krb5_free_authdata(context, val->authorization_data);
    krb5_xfree(val);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_checksum(context, val)
    krb5_context context;
    register krb5_checksum *val;
{
    if (val->contents)
	krb5_xfree(val->contents);
    krb5_xfree(val);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_cred(context, val)
    krb5_context context;
    register krb5_cred FAR *val;
{
    if (val->tickets)
        krb5_free_tickets(context, val->tickets);
    if (val->enc_part.ciphertext.data)
	krb5_xfree(val->enc_part.ciphertext.data);
    krb5_xfree(val);
    return;
}

/*
 * krb5_free_cred_contents zeros out the session key, and then frees
 * the credentials structures 
 */

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_cred_contents(context, val)
    krb5_context context;
    krb5_creds FAR *val;
{
    if (val->client)
	krb5_free_principal(context, val->client);
    if (val->server)
	krb5_free_principal(context, val->server);
    if (val->keyblock.contents) {
	memset((char *)val->keyblock.contents, 0, val->keyblock.length);
	krb5_xfree(val->keyblock.contents);
    }
    if (val->ticket.data)
	krb5_xfree(val->ticket.data);
    if (val->second_ticket.data)
	krb5_xfree(val->second_ticket.data);
    if (val->addresses)
	krb5_free_addresses(context, val->addresses);
    if (val->authdata)
	krb5_free_authdata(context, val->authdata);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV 
krb5_free_cred_enc_part(context, val)
    krb5_context context;
    register krb5_cred_enc_part FAR *val;
{
    register krb5_cred_info **temp;
    
    if (val->r_address)
      krb5_free_address(context, val->r_address);
    if (val->s_address)
      krb5_free_address(context, val->s_address);

    if (val->ticket_info) {
	for (temp = val->ticket_info; *temp; temp++) {
	    if ((*temp)->session)
		krb5_free_keyblock(context, (*temp)->session);
	    if ((*temp)->client)
		krb5_free_principal(context, (*temp)->client);
	    if ((*temp)->server)
		krb5_free_principal(context, (*temp)->server);
	    if ((*temp)->caddrs)
		krb5_free_addresses(context, (*temp)->caddrs);
	    krb5_xfree((*temp));
	}
	krb5_xfree(val->ticket_info);
    }
    return;
}


KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_creds(context, val)
    krb5_context context;
    krb5_creds FAR *val;
{
    krb5_free_cred_contents(context, val);
    krb5_xfree(val);
    return;
}


KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_data(context, val)
    krb5_context context;
    krb5_data FAR * val;
{
    if (val->data)
	krb5_xfree(val->data);
    krb5_xfree(val);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_data_contents(context, val)
    krb5_context context;
    krb5_data FAR * val;
{
    if (val->data)
	krb5_xfree(val->data);
    return;
}

void krb5_free_etype_info(context, info)
    krb5_context context;
    krb5_etype_info info;
{
  int i;

  for(i=0; info[i] != NULL; i++) {
      if (info[i]->salt)
	  free(info[i]->salt);
      free(info[i]);
  }
  free(info);
}
    

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_enc_kdc_rep_part(context, val)
    krb5_context context;
    register krb5_enc_kdc_rep_part *val;
{
    if (val->session)
	krb5_free_keyblock(context, val->session);
    if (val->last_req)
	krb5_free_last_req(context, val->last_req);
    if (val->server)
	krb5_free_principal(context, val->server);
    if (val->caddrs)
	krb5_free_addresses(context, val->caddrs);
    krb5_xfree(val);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_enc_tkt_part(context, val)
    krb5_context context;
    krb5_enc_tkt_part FAR *val;
{
    if (val->session)
	krb5_free_keyblock(context, val->session);
    if (val->client)
	krb5_free_principal(context, val->client);
    if (val->transited.tr_contents.data)
	krb5_xfree(val->transited.tr_contents.data);
    if (val->caddrs)
	krb5_free_addresses(context, val->caddrs);
    if (val->authorization_data)
	krb5_free_authdata(context, val->authorization_data);
    krb5_xfree(val);
    return;
}


KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_error(context, val)
    krb5_context context;
    register krb5_error FAR *val;
{
    if (val->client)
	krb5_free_principal(context, val->client);
    if (val->server)
	krb5_free_principal(context, val->server);
    if (val->text.data)
	krb5_xfree(val->text.data);
    if (val->e_data.data)
	krb5_xfree(val->e_data.data);
    krb5_xfree(val);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_kdc_rep(context, val)
    krb5_context context;
    krb5_kdc_rep FAR *val;
{
    if (val->padata)
	krb5_free_pa_data(context, val->padata);
    if (val->client)
	krb5_free_principal(context, val->client);
    if (val->ticket)
	krb5_free_ticket(context, val->ticket);
    if (val->enc_part.ciphertext.data)
	krb5_xfree(val->enc_part.ciphertext.data);
    if (val->enc_part2)
	krb5_free_enc_kdc_rep_part(context, val->enc_part2);
    krb5_xfree(val);
    return;
}


KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_kdc_req(context, val)
    krb5_context context;
    krb5_kdc_req FAR *val;
{
    if (val->padata)
	krb5_free_pa_data(context, val->padata);
    if (val->client)
	krb5_free_principal(context, val->client);
    if (val->server)
	krb5_free_principal(context, val->server);
    if (val->ktype)
	krb5_xfree(val->ktype);
    if (val->addresses)
	krb5_free_addresses(context, val->addresses);
    if (val->authorization_data.ciphertext.data)
	krb5_xfree(val->authorization_data.ciphertext.data);
    if (val->unenc_authdata)
	krb5_free_authdata(context, val->unenc_authdata);
    if (val->second_ticket)
	krb5_free_tickets(context, val->second_ticket);
    krb5_xfree(val);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_keyblock_contents(context, key)
     krb5_context context;
     register krb5_keyblock FAR *key;
{
     if (key->contents) {
	  memset(key->contents, 0, key->length);
	  krb5_xfree(key->contents);
     }
     return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_keyblock(context, val)
    krb5_context context;
    register krb5_keyblock FAR *val;
{
    krb5_free_keyblock_contents(context, val);
    krb5_xfree(val);
    return;
}



KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_last_req(context, val)
    krb5_context context;
    krb5_last_req_entry FAR * FAR *val;
{
    register krb5_last_req_entry **temp;

    for (temp = val; *temp; temp++)
	krb5_xfree(*temp);
    krb5_xfree(val);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_pa_data(context, val)
    krb5_context context;
    krb5_pa_data FAR * FAR *val;
{
    register krb5_pa_data **temp;

    for (temp = val; *temp; temp++) {
	if ((*temp)->contents)
	    krb5_xfree((*temp)->contents);
	krb5_xfree(*temp);
    }
    krb5_xfree(val);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_principal(context, val)
    krb5_context context;
    krb5_principal val;
{
    register krb5_int32 i;

    if (!val)
	return;
    
    if (val->data) {
	i = krb5_princ_size(context, val);
	while(--i >= 0)
	    free(krb5_princ_component(context, val, i)->data);
	krb5_xfree(val->data);
    }
    if (val->realm.data)
	krb5_xfree(val->realm.data);
    krb5_xfree(val);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_priv(context, val)
    krb5_context context;
    register krb5_priv FAR *val;
{
    if (val->enc_part.ciphertext.data)
	krb5_xfree(val->enc_part.ciphertext.data);
    krb5_xfree(val);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_priv_enc_part(context, val)
    krb5_context context;
    register krb5_priv_enc_part FAR *val;
{
    if (val->user_data.data)
	krb5_xfree(val->user_data.data);
    if (val->r_address)
	krb5_free_address(context, val->r_address);
    if (val->s_address)
	krb5_free_address(context, val->s_address);
    krb5_xfree(val);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_pwd_data(context, val)
    krb5_context context;
    krb5_pwd_data FAR *val;
{
    if (val->element)
	krb5_free_pwd_sequences(context, val->element);
    krb5_xfree(val);
    return;
}


KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_pwd_sequences(context, val)
    krb5_context context;
    passwd_phrase_element FAR * FAR *val;
{
    if ((*val)->passwd)
	krb5_xfree((*val)->passwd);
    if ((*val)->phrase)
	krb5_xfree((*val)->phrase);
    return;
}


KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_safe(context, val)
    krb5_context context;
    register krb5_safe FAR *val;
{
    if (val->user_data.data)
	krb5_xfree(val->user_data.data);
    if (val->r_address)
	krb5_free_address(context, val->r_address);
    if (val->s_address)
	krb5_free_address(context, val->s_address);
    if (val->checksum)
	krb5_free_checksum(context, val->checksum);
    krb5_xfree(val);
    return;
}


KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_ticket(context, val)
    krb5_context context;
    krb5_ticket FAR *val;
{
    if (val->server)
	krb5_free_principal(context, val->server);
    if (val->enc_part.ciphertext.data)
	krb5_xfree(val->enc_part.ciphertext.data);
    if (val->enc_part2)
	krb5_free_enc_tkt_part(context, val->enc_part2);
    krb5_xfree(val);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_tickets(context, val)
    krb5_context context;
    krb5_ticket FAR * FAR *val;
{
    register krb5_ticket **temp;

    for (temp = val; *temp; temp++)
        krb5_free_ticket(context, *temp);
    krb5_xfree(val);
    return;
}


KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_tgt_creds(context, tgts)
    krb5_context context;
    krb5_creds FAR * FAR *tgts;
{
    register krb5_creds **tgtpp;
    for (tgtpp = tgts; *tgtpp; tgtpp++)
	krb5_free_creds(context, *tgtpp);
    krb5_xfree(tgts);
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_tkt_authent(context, val)
    krb5_context context;
    krb5_tkt_authent FAR *val;
{
    if (val->ticket)
	    krb5_free_ticket(context, val->ticket);
    if (val->authenticator)
	    krb5_free_authenticator(context, val->authenticator);
    krb5_xfree(val);
    return;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_unparsed_name(context, val)
    krb5_context context;
    char FAR * val;
{
    if (val)
	krb5_xfree(val);
    return;
}

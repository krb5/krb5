#include <stdlib.h>
#include <stdio.h>
#include "ktest_equal.h"

#define FALSE 0
#define TRUE 1

#define struct_equal(field,comparator)\
comparator(&(ref->field),&(var->field))

#define ptr_equal(field,comparator)\
comparator(ref->field,var->field)

#define scalar_equal(field)\
((ref->field) == (var->field))

#define len_equal(length,field,comparator)\
((ref->length == var->length) && \
 comparator(ref->length,ref->field,var->field))

int ktest_equal_authenticator(DECLARG(krb5_authenticator *, ref),
			      DECLARG(krb5_authenticator *, var))
     OLDDECLARG(krb5_authenticator *, ref)
     OLDDECLARG(krb5_authenticator *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p = p && ptr_equal(client,ktest_equal_principal_data);
  p = p && ptr_equal(checksum,ktest_equal_checksum);
  p = p && scalar_equal(cusec);
  p = p && scalar_equal(ctime);
  p = p && ptr_equal(subkey,ktest_equal_keyblock);
  p = p && scalar_equal(seq_number);
  p = p && ptr_equal(authorization_data,ktest_equal_authorization_data);
  return p;
}

int ktest_equal_principal_data(DECLARG(krb5_principal_data *, ref),
			       DECLARG(krb5_principal_data *, var))
     OLDDECLARG(krb5_principal_data *, ref)
     OLDDECLARG(krb5_principal_data *, var)
{
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  return(struct_equal(realm,ktest_equal_data) &&
	 len_equal(length,data,ktest_equal_array_of_data) &&
	 scalar_equal(type));
}

int ktest_equal_authdata(DECLARG(krb5_authdata *, ref),
			 DECLARG(krb5_authdata *, var))
     OLDDECLARG(krb5_authdata *, ref)
     OLDDECLARG(krb5_authdata *, var)
{
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  return(scalar_equal(ad_type) &&
	 len_equal(length,contents,ktest_equal_array_of_octet));
}

int ktest_equal_checksum(DECLARG(krb5_checksum *, ref),
			 DECLARG(krb5_checksum *, var))
     OLDDECLARG(krb5_checksum *, ref)
     OLDDECLARG(krb5_checksum *, var)
{
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  return(scalar_equal(checksum_type) && len_equal(length,contents,ktest_equal_array_of_octet));
}

int ktest_equal_keyblock(DECLARG(krb5_keyblock *, ref),
			 DECLARG(krb5_keyblock *, var))
     OLDDECLARG(krb5_keyblock *, ref)
     OLDDECLARG(krb5_keyblock *, var)
{
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  return(scalar_equal(keytype) && len_equal(length,contents,ktest_equal_array_of_octet));
}

int ktest_equal_data(DECLARG(krb5_data *, ref),
		     DECLARG(krb5_data *, var))
     OLDDECLARG(krb5_data *, ref)
     OLDDECLARG(krb5_data *, var)
{
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  return(len_equal(length,data,ktest_equal_array_of_char));
}

int ktest_equal_ticket(DECLARG(krb5_ticket *, ref),
		       DECLARG(krb5_ticket *, var))
     OLDDECLARG(krb5_ticket *, ref)
     OLDDECLARG(krb5_ticket *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p = p && ptr_equal(server,ktest_equal_principal_data);
  p = p && struct_equal(enc_part,ktest_equal_enc_data);
  /* enc_part2 is irrelevant, as far as the ASN.1 code is concerned */
  return p;
}

int ktest_equal_enc_data(DECLARG(krb5_enc_data *, ref),
			 DECLARG(krb5_enc_data *, var))
     OLDDECLARG(krb5_enc_data *, ref)
     OLDDECLARG(krb5_enc_data *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&scalar_equal(etype);
  p=p&&scalar_equal(kvno);
  p=p&&struct_equal(ciphertext,ktest_equal_data);
  return p;
}

int ktest_equal_encryption_key(DECLARG(krb5_keyblock *, ref),
			       DECLARG(krb5_keyblock *, var))
     OLDDECLARG(krb5_keyblock *, ref)
     OLDDECLARG(krb5_keyblock *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p = p && scalar_equal(keytype);
  p = p && len_equal(length,contents,ktest_equal_array_of_octet);
  return p;
}

int ktest_equal_enc_tkt_part(DECLARG(krb5_enc_tkt_part *, ref),
			     DECLARG(krb5_enc_tkt_part *, var))
     OLDDECLARG(krb5_enc_tkt_part *, ref)
     OLDDECLARG(krb5_enc_tkt_part *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p = p && scalar_equal(flags);
  p = p && ptr_equal(session,ktest_equal_encryption_key);
  p = p && ptr_equal(client,ktest_equal_principal_data);
  p = p && struct_equal(transited,ktest_equal_transited);
  p = p && struct_equal(times,ktest_equal_ticket_times);
  p = p && ptr_equal(caddrs,ktest_equal_addresses);
  p = p && ptr_equal(authorization_data,ktest_equal_authorization_data);
  return p;
}

int ktest_equal_transited(DECLARG(krb5_transited *, ref),
			  DECLARG(krb5_transited *, var))
     OLDDECLARG(krb5_transited *, ref)
     OLDDECLARG(krb5_transited *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p = p && scalar_equal(tr_type);
  p = p && struct_equal(tr_contents,ktest_equal_data);
  return p;
}

int ktest_equal_ticket_times(DECLARG(krb5_ticket_times *, ref),
			     DECLARG(krb5_ticket_times *, var))
     OLDDECLARG(krb5_ticket_times *, ref)
     OLDDECLARG(krb5_ticket_times *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p = p && scalar_equal(authtime);
  p = p && scalar_equal(starttime);
  p = p && scalar_equal(endtime);
  p = p && scalar_equal(renew_till);
  return p;
}

int ktest_equal_address(DECLARG(krb5_address *, ref),
			DECLARG(krb5_address *, var))
     OLDDECLARG(krb5_address *, ref)
     OLDDECLARG(krb5_address *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&scalar_equal(addrtype);
  p=p&&len_equal(length,contents,ktest_equal_array_of_octet);
  return p;
}

int ktest_equal_enc_kdc_rep_part(DECLARG(krb5_enc_kdc_rep_part *, ref),
				 DECLARG(krb5_enc_kdc_rep_part *, var))
     OLDDECLARG(krb5_enc_kdc_rep_part *, ref)
     OLDDECLARG(krb5_enc_kdc_rep_part *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&ptr_equal(session,ktest_equal_keyblock);
  p=p&&ptr_equal(last_req,ktest_equal_last_req);
  p=p&&scalar_equal(nonce);
  p=p&&scalar_equal(key_exp);
  p=p&&scalar_equal(flags);
  p=p&&struct_equal(times,ktest_equal_ticket_times);
  p=p&&ptr_equal(server,ktest_equal_principal_data);
  p=p&&ptr_equal(caddrs,ktest_equal_addresses);
  return p;
}

int ktest_equal_priv(DECLARG(krb5_priv *, ref),
		     DECLARG(krb5_priv *, var))
     OLDDECLARG(krb5_priv *, ref)
     OLDDECLARG(krb5_priv *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&struct_equal(enc_part,ktest_equal_enc_data);
  return p;
}

int ktest_equal_cred(DECLARG(krb5_cred *, ref),
		     DECLARG(krb5_cred *, var))
     OLDDECLARG(krb5_cred *, ref)
     OLDDECLARG(krb5_cred *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&ptr_equal(tickets,ktest_equal_sequence_of_ticket);
  p=p&&struct_equal(enc_part,ktest_equal_enc_data);
  return p;
}

int ktest_equal_error(DECLARG(krb5_error *, ref),
		      DECLARG(krb5_error *, var))
     OLDDECLARG(krb5_error *, ref)
     OLDDECLARG(krb5_error *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&scalar_equal(ctime);
  p=p&&scalar_equal(cusec);
  p=p&&scalar_equal(susec);
  p=p&&scalar_equal(stime);
  p=p&&scalar_equal(error);
  p=p&&ptr_equal(client,ktest_equal_principal_data);
  p=p&&ptr_equal(server,ktest_equal_principal_data);
  p=p&&struct_equal(text,ktest_equal_data);
  p=p&&struct_equal(e_data,ktest_equal_data);
  return p;
}

int ktest_equal_ap_req(DECLARG(krb5_ap_req *, ref),
		       DECLARG(krb5_ap_req *, var))
     OLDDECLARG(krb5_ap_req *, ref)
     OLDDECLARG(krb5_ap_req *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&scalar_equal(ap_options);
  p=p&&ptr_equal(ticket,ktest_equal_ticket);
  p=p&&struct_equal(authenticator,ktest_equal_enc_data);
  return p;
}

int ktest_equal_ap_rep(DECLARG(krb5_ap_rep *, ref),
		       DECLARG(krb5_ap_rep *, var))
     OLDDECLARG(krb5_ap_rep *, ref)
     OLDDECLARG(krb5_ap_rep *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&struct_equal(enc_part,ktest_equal_enc_data);
  return p;
}

int ktest_equal_ap_rep_enc_part(DECLARG(krb5_ap_rep_enc_part *, ref),
				DECLARG(krb5_ap_rep_enc_part *, var))
     OLDDECLARG(krb5_ap_rep_enc_part *, ref)
     OLDDECLARG(krb5_ap_rep_enc_part *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&scalar_equal(ctime);
  p=p&&scalar_equal(cusec);
  p=p&&ptr_equal(subkey,ktest_equal_encryption_key);
  p=p&&scalar_equal(seq_number);
  return p;
}

int ktest_equal_safe(DECLARG(krb5_safe *, ref),
		     DECLARG(krb5_safe *, var))
     OLDDECLARG(krb5_safe *, ref)
     OLDDECLARG(krb5_safe *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&struct_equal(user_data,ktest_equal_data);
  p=p&&scalar_equal(timestamp);
  p=p&&scalar_equal(usec);
  p=p&&scalar_equal(seq_number);
  p=p&&ptr_equal(s_address,ktest_equal_address);
  p=p&&ptr_equal(r_address,ktest_equal_address);
  p=p&&ptr_equal(checksum,ktest_equal_checksum);
  return p;
}


int ktest_equal_enc_cred_part(DECLARG(krb5_cred_enc_part *, ref),
			      DECLARG(krb5_cred_enc_part *, var))
     OLDDECLARG(krb5_cred_enc_part *, ref)
     OLDDECLARG(krb5_cred_enc_part *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&scalar_equal(nonce);
  p=p&&scalar_equal(timestamp);
  p=p&&scalar_equal(usec);
  p=p&&ptr_equal(s_address,ktest_equal_address);
  p=p&&ptr_equal(r_address,ktest_equal_address);
  p=p&&ptr_equal(ticket_info,ktest_equal_sequence_of_cred_info);
  return p;
}

int ktest_equal_enc_priv_part(DECLARG(krb5_priv_enc_part *, ref),
			      DECLARG(krb5_priv_enc_part *, var))
     OLDDECLARG(krb5_priv_enc_part *, ref)
     OLDDECLARG(krb5_priv_enc_part *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&struct_equal(user_data,ktest_equal_data);
  p=p&&scalar_equal(timestamp);
  p=p&&scalar_equal(usec);
  p=p&&scalar_equal(seq_number);
  p=p&&ptr_equal(s_address,ktest_equal_address);
  p=p&&ptr_equal(r_address,ktest_equal_address);
  return p;
}

int ktest_equal_as_rep(DECLARG(krb5_kdc_rep *, ref),
		       DECLARG(krb5_kdc_rep *, var))
     OLDDECLARG(krb5_kdc_rep *, ref)
     OLDDECLARG(krb5_kdc_rep *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&scalar_equal(msg_type);
  p=p&&ptr_equal(padata,ktest_equal_sequence_of_pa_data);
  p=p&&ptr_equal(client,ktest_equal_principal_data);
  p=p&&ptr_equal(ticket,ktest_equal_ticket);
  p=p&&struct_equal(enc_part,ktest_equal_enc_data);
  p=p&&ptr_equal(enc_part2,ktest_equal_enc_kdc_rep_part);
  return p;
}

int ktest_equal_tgs_rep(DECLARG(krb5_kdc_rep *, ref),
			DECLARG(krb5_kdc_rep *, var))
     OLDDECLARG(krb5_kdc_rep *, ref)
     OLDDECLARG(krb5_kdc_rep *, var)
{
  return ktest_equal_as_rep(ref,var);
}

int ktest_equal_as_req(DECLARG(krb5_kdc_req *, ref),
		       DECLARG(krb5_kdc_req *, var))
     OLDDECLARG(krb5_kdc_req *, ref)
     OLDDECLARG(krb5_kdc_req *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&scalar_equal(msg_type);
  p=p&&ptr_equal(padata,ktest_equal_sequence_of_pa_data);
  p=p&&scalar_equal(kdc_options);
  p=p&&ptr_equal(client,ktest_equal_principal_data);
  p=p&&ptr_equal(server,ktest_equal_principal_data);
  p=p&&scalar_equal(from);
  p=p&&scalar_equal(till);
  p=p&&scalar_equal(rtime);
  p=p&&scalar_equal(nonce);
  p=p&&len_equal(netypes,etype,ktest_equal_array_of_enctype);
  p=p&&ptr_equal(addresses,ktest_equal_addresses);
  p=p&&struct_equal(authorization_data,ktest_equal_enc_data);
/* This field isn't actually in the ASN.1 encoding. */
/* p=p&&ptr_equal(unenc_authdata,ktest_equal_authorization_data); */
  return p;
}

int ktest_equal_tgs_req(DECLARG(krb5_kdc_req *, ref),
			DECLARG(krb5_kdc_req *, var))
     OLDDECLARG(krb5_kdc_req *, ref)
     OLDDECLARG(krb5_kdc_req *, var)
{
  return ktest_equal_as_req(ref,var);
}

int ktest_equal_kdc_req_body(DECLARG(krb5_kdc_req *, ref),
			     DECLARG(krb5_kdc_req *, var))
     OLDDECLARG(krb5_kdc_req *, ref)
     OLDDECLARG(krb5_kdc_req *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&scalar_equal(kdc_options);
  p=p&&ptr_equal(client,ktest_equal_principal_data);
  p=p&&ptr_equal(server,ktest_equal_principal_data);
  p=p&&scalar_equal(from);
  p=p&&scalar_equal(till);
  p=p&&scalar_equal(rtime);
  p=p&&scalar_equal(nonce);
  p=p&&len_equal(netypes,etype,ktest_equal_array_of_enctype);
  p=p&&ptr_equal(addresses,ktest_equal_addresses);
  p=p&&struct_equal(authorization_data,ktest_equal_enc_data);
  /* This isn't part of the ASN.1 encoding. */
  /* p=p&&ptr_equal(unenc_authdata,ktest_equal_authorization_data); */
  return p;
}

int ktest_equal_last_req_entry(DECLARG(krb5_last_req_entry *, ref),
			       DECLARG(krb5_last_req_entry *, var))
     OLDDECLARG(krb5_last_req_entry *, ref)
     OLDDECLARG(krb5_last_req_entry *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&scalar_equal(lr_type);
  p=p&&scalar_equal(value);
  return p;
}

int ktest_equal_pa_data(DECLARG(krb5_pa_data *, ref),
			DECLARG(krb5_pa_data *, var))
     OLDDECLARG(krb5_pa_data *, ref)
     OLDDECLARG(krb5_pa_data *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&scalar_equal(pa_type);
  p=p&&len_equal(length,contents,ktest_equal_array_of_octet);
  return p;
}

int ktest_equal_cred_info(DECLARG(krb5_cred_info *, ref),
			  DECLARG(krb5_cred_info *, var))
     OLDDECLARG(krb5_cred_info *, ref)
     OLDDECLARG(krb5_cred_info *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&ptr_equal(session,ktest_equal_keyblock);
  p=p&&ptr_equal(client,ktest_equal_principal_data);
  p=p&&ptr_equal(server,ktest_equal_principal_data);
  p=p&&scalar_equal(flags);
  p=p&&struct_equal(times,ktest_equal_ticket_times);
  p=p&&ptr_equal(caddrs,ktest_equal_addresses);

  return p;
}

int ktest_equal_passwd_phrase_element(DECLARG(passwd_phrase_element *, ref),
				      DECLARG(passwd_phrase_element *, var))
     OLDDECLARG(passwd_phrase_element *, ref)
     OLDDECLARG(passwd_phrase_element *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&ptr_equal(passwd,ktest_equal_data);
  p=p&&ptr_equal(phrase,ktest_equal_data);
  return p;
}

int ktest_equal_krb5_pwd_data(DECLARG(krb5_pwd_data *, ref),
			      DECLARG(krb5_pwd_data *, var))
     OLDDECLARG(krb5_pwd_data *, ref)
     OLDDECLARG(krb5_pwd_data *, var)
{
  int p=TRUE;
  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  p=p&&scalar_equal(sequence_count);
  p=p&&ptr_equal(element,ktest_equal_array_of_passwd_phrase_element);
  return p;
}

/**** arrays ****************************************************************/

int ktest_equal_array_of_data(DECLARG(const int , length),
			      DECLARG(krb5_data *, ref),
			      DECLARG(krb5_data *, var))
     OLDDECLARG(const int , length)
     OLDDECLARG(krb5_data *, ref)
     OLDDECLARG(krb5_data *, var)
{
  int i,p=TRUE;

  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  for(i=0; i<(length); i++){
    p = p && ktest_equal_data(&(ref[i]),&(var[i]));
  }
  return p;
}

int ktest_equal_array_of_octet(DECLARG(const int , length),
			       DECLARG(krb5_octet *, ref),
			       DECLARG(krb5_octet *, var))
     OLDDECLARG(const int , length)
     OLDDECLARG(krb5_octet *, ref)
     OLDDECLARG(krb5_octet *, var)
{
  int i, p=TRUE;

  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  for(i=0; i<length; i++)
    p = p && (ref[i] == var[i]);
  return p;
}

int ktest_equal_array_of_char(DECLARG(const int , length),
			      DECLARG(char *, ref),
			      DECLARG(char *, var))
     OLDDECLARG(const int , length)
     OLDDECLARG(char *, ref)
     OLDDECLARG(char *, var)
{
  int i, p=TRUE;

  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  for(i=0; i<length; i++)
    p = p && (ref[i] == var[i]);
  return p;
}

int ktest_equal_array_of_enctype(DECLARG(const int , length),
				 DECLARG(krb5_enctype *, ref),
				 DECLARG(krb5_enctype *, var))
     OLDDECLARG(const int , length)
     OLDDECLARG(krb5_enctype *, ref)
     OLDDECLARG(krb5_enctype *, var)
{
  int i, p=TRUE;

  if(ref==var) return TRUE;
  else if(ref == NULL || var == NULL) return FALSE;
  for(i=0; i<length; i++)
    p = p && (ref[i] == var[i]);
  return p;
}

#define array_compare(comparator)\
int i,p=TRUE;\
if(ref==var) return TRUE;\
if(!ref || !ref[0])\
  return (!var || !var[0]);\
if(!var || !var[0]) return FALSE;\
for(i=0; ref[i] != NULL && var[i] != NULL; i++)\
  p = p && comparator(ref[i],var[i]);\
if(ref[i] == NULL && var[i] == NULL) return p;\
else return FALSE

int ktest_equal_authorization_data(DECLARG(krb5_authdata **, ref),
				   DECLARG(krb5_authdata **, var))
     OLDDECLARG(krb5_authdata **, ref)
     OLDDECLARG(krb5_authdata **, var)
{
  array_compare(ktest_equal_authdata);
}

int ktest_equal_addresses(DECLARG(krb5_address **, ref),
			  DECLARG(krb5_address **, var))
     OLDDECLARG(krb5_address **, ref)
     OLDDECLARG(krb5_address **, var)
{
  array_compare(ktest_equal_address);
}

int ktest_equal_last_req(DECLARG(krb5_last_req_entry **, ref),
			 DECLARG(krb5_last_req_entry **, var))
     OLDDECLARG(krb5_last_req_entry **, ref)
     OLDDECLARG(krb5_last_req_entry **, var)
{
  array_compare(ktest_equal_last_req_entry);
}

int ktest_equal_sequence_of_ticket(DECLARG(krb5_ticket **, ref),
				   DECLARG(krb5_ticket **, var))
     OLDDECLARG(krb5_ticket **, ref)
     OLDDECLARG(krb5_ticket **, var)
{
  array_compare(ktest_equal_ticket);
}

int ktest_equal_sequence_of_pa_data(DECLARG(krb5_pa_data **, ref),
				    DECLARG(krb5_pa_data **, var))
     OLDDECLARG(krb5_pa_data **, ref)
     OLDDECLARG(krb5_pa_data **, var)
{
  array_compare(ktest_equal_pa_data);
}

int ktest_equal_sequence_of_cred_info(DECLARG(krb5_cred_info **, ref),
				      DECLARG(krb5_cred_info **, var))
     OLDDECLARG(krb5_cred_info **, ref)
     OLDDECLARG(krb5_cred_info **, var)
{
  array_compare(ktest_equal_cred_info);
}

int ktest_equal_array_of_passwd_phrase_element(DECLARG(passwd_phrase_element **, ref),
					       DECLARG(passwd_phrase_element **, var))
     OLDDECLARG(passwd_phrase_element **, ref)
     OLDDECLARG(passwd_phrase_element **, var)
{
  array_compare(ktest_equal_passwd_phrase_element);
}

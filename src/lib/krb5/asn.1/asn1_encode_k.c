#include "asn1_encode_k.h"
#include "krb5_encode.h"
#include "asn1_make.h"
#include "asn1_encode.h"

/**** asn1 macros ****/
#if 0
   How to write an asn1 encoder function using these macros:

   asn1_error_code asn1_encode_krb5_substructure(asn1buf *buf,
                                                 const krb5_type *val,
                                                 int *retlen)
   {
     asn1_setup();

     asn1_addfield(val->last_field, n, asn1_type);
     asn1_addfield(rep->next_to_last_field, n-1, asn1_type);
     ...

     /* for OPTIONAL fields */
     if(rep->field_i == should_not_be_omitted)
       asn1_addfield(rep->field_i, i, asn1_type);

     /* for string fields (these encoders take an additional argument,
	the length of the string) */
     addlenfield(rep->field_length, rep->field, i-1, asn1_type);

     /* if you really have to do things yourself... */
     retval = asn1_encode_asn1_type(buf,rep->field,&length);
     if(retval) return retval;
     sum += length;
     retval = asn1_make_etag(buf, CONTEXT_SPECIFIC, tag_number, length,
			     &length);
     if(retval) return retval;
     sum += length;

     ...
     asn1_addfield(rep->second_field, 1, asn1_type);
     asn1_addfield(rep->first_field, 0, asn1_type);
     asn1_makeseq();

     asn1_cleanup();
   }
#endif

/* setup() -- create and initialize bookkeeping variables
     retval: stores error codes returned from subroutines
     length: length of the most-recently produced encoding
     sum: cumulative length of the entire encoding */
#define asn1_setup()\
  asn1_error_code retval;\
  int length, sum=0
  
/* asn1_addfield -- add a field, or component, to the encoding */
#define asn1_addfield(value,tag,encoder)\
{ retval = encoder(buf,value,&length);\
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += length;\
  retval = asn1_make_etag(buf,CONTEXT_SPECIFIC,tag,length,&length);\
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += length; }

/* asn1_addlenfield -- add a field whose length must be separately specified */
#define asn1_addlenfield(len,value,tag,encoder)\
{ retval = encoder(buf,len,value,&length);\
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += length;\
  retval = asn1_make_etag(buf,CONTEXT_SPECIFIC,tag,length,&length);\
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += length; }

/* form a sequence (by adding a sequence header to the current encoding) */
#define asn1_makeseq()\
  retval = asn1_make_sequence(buf,sum,&length);\
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += length

/* add an APPLICATION class tag to the current encoding */
#define asn1_apptag(num)\
  retval = asn1_make_etag(buf,APPLICATION,num,sum,&length);\
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += length

/* produce the final output and clean up the workspace */
#define asn1_cleanup()\
  *retlen = sum;\
  return 0

asn1_error_code asn1_encode_ui_4(buf, val, retlen)
     asn1buf * buf;
     const /*krb5_ui_4*/int val;
     int *retlen;
{
  return asn1_encode_unsigned_integer(buf,val,retlen);
}


asn1_error_code asn1_encode_msgtype(buf, val, retlen)
     asn1buf * buf;
     const /*krb5_msgtype*/int val;
     int * retlen;
{
  switch(val){
  case KRB5_AS_REQ:
    return asn1_encode_integer(buf,ASN1_KRB_AS_REQ,retlen);
  case KRB5_AS_REP:
    return asn1_encode_integer(buf,ASN1_KRB_AS_REP,retlen);
  case KRB5_TGS_REQ:
    return asn1_encode_integer(buf,ASN1_KRB_TGS_REQ,retlen);
  case KRB5_TGS_REP:
    return asn1_encode_integer(buf,ASN1_KRB_TGS_REP,retlen);
  case KRB5_AP_REQ:
    return asn1_encode_integer(buf,ASN1_KRB_AP_REQ,retlen);
  case KRB5_AP_REP:
    return asn1_encode_integer(buf,ASN1_KRB_AP_REP,retlen);
  case KRB5_SAFE:
    return asn1_encode_integer(buf,ASN1_KRB_SAFE,retlen);
  case KRB5_PRIV:
    return asn1_encode_integer(buf,ASN1_KRB_PRIV,retlen);
  case KRB5_CRED:
    return asn1_encode_integer(buf,ASN1_KRB_CRED,retlen);
  case KRB5_ERROR:
    return asn1_encode_integer(buf,ASN1_KRB_ERROR,retlen);
  default:
    return KRB5_BADMSGTYPE;
  }
}

asn1_error_code asn1_encode_realm(DECLARG(asn1buf *, buf),
				  DECLARG(const krb5_principal, val),
				  DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_principal, val)
     OLDDECLARG(int *, retlen)
{
  if(val == NULL || val->realm.data == NULL) return ASN1_MISSING_FIELD;
  return asn1_encode_generalstring(buf,val->realm.length,val->realm.data,
				   retlen);
}

asn1_error_code asn1_encode_principal_name(DECLARG(asn1buf *, buf),
					   DECLARG(const krb5_principal, val),
					   DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_principal, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();
  int n;

  if(val == NULL || val->data == NULL) return ASN1_MISSING_FIELD;

  for(n = (val->length)-1; n >= 0; n--){
    if(val->data[n].data == NULL) return ASN1_MISSING_FIELD;
    retval = asn1_encode_generalstring(buf,
				       (val->data)[n].length,
				       (val->data)[n].data,
				       &length);
    if(retval) return retval;
    sum += length;
  }
  asn1_makeseq();
  retval = asn1_make_etag(buf,CONTEXT_SPECIFIC,1,sum,&length);
  if(retval) return retval;
  sum += length;

  asn1_addfield(val->type,0,asn1_encode_integer);

  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_kerberos_time(DECLARG(asn1buf *, buf),
					  DECLARG(const krb5_timestamp, val),
					  DECLARG(int *, retlen))
     
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_timestamp, val)
     OLDDECLARG(int *, retlen)
     
{
  return asn1_encode_generaltime(buf,val,retlen);
}

asn1_error_code asn1_encode_host_address(DECLARG(asn1buf *, buf),
					 DECLARG(const krb5_address *, val),
					 DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_address *, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();

  if(val == NULL || val->contents == NULL) return ASN1_MISSING_FIELD;

  asn1_addlenfield(val->length,val->contents,1,asn1_encode_octetstring);
  asn1_addfield(val->addrtype,0,asn1_encode_integer);
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_host_addresses(DECLARG(asn1buf *, buf),
					   DECLARG(const krb5_address **, val),
					   DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_address **, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();
  int i;

  if(val == NULL || val[0] == NULL) return ASN1_MISSING_FIELD;

  for(i=0; val[i] != NULL; i++); /* go to end of array */
  for(i--; i>=0; i--){
    retval = asn1_encode_host_address(buf,val[i],&length);
    if(retval) return retval;
    sum += length;
  }
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_encrypted_data(DECLARG(asn1buf *, buf),
					   DECLARG(const krb5_enc_data *, val),
					   DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_enc_data *, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();

  if(val == NULL || val->ciphertext.data == NULL) return ASN1_MISSING_FIELD;

  asn1_addlenfield(val->ciphertext.length,val->ciphertext.data,2,asn1_encode_charstring);
  if(val->kvno)
    asn1_addfield(val->kvno,1,asn1_encode_integer);
  asn1_addfield(val->etype,0,asn1_encode_integer);

  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_krb5_flags(DECLARG(asn1buf *, buf),
				       DECLARG(const krb5_flags, val),
				       DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_flags, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();
  krb5_flags valcopy = val;
  int i;

  for(i=0; i<4; i++){
    retval = asn1buf_insert_octet(buf,valcopy&0xFF);
    if(retval) return retval;
    valcopy >>= 8;
  }
  retval = asn1buf_insert_octet(buf,0);	/* 0 padding bits */
  if(retval) return retval;
  sum = 5;

  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_BITSTRING,sum,
			 &length);
  if(retval) return retval;
  sum += length;

  *retlen = sum;
  return 0;
}

asn1_error_code asn1_encode_ap_options(DECLARG(asn1buf *, buf),
				       DECLARG(const krb5_flags, val),
				       DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_flags, val)
     OLDDECLARG(int *, retlen)
{
  return asn1_encode_krb5_flags(buf,val,retlen);
}

asn1_error_code asn1_encode_ticket_flags(DECLARG(asn1buf *, buf),
					 DECLARG(const krb5_flags, val),
					 DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_flags, val)
     OLDDECLARG(int *, retlen)
{
  return asn1_encode_krb5_flags(buf,val,retlen);
}

asn1_error_code asn1_encode_kdc_options(DECLARG(asn1buf *, buf),
					DECLARG(const krb5_flags, val),
					DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_flags, val)
     OLDDECLARG(int *, retlen)
{
  return asn1_encode_krb5_flags(buf,val,retlen);
}

asn1_error_code asn1_encode_authorization_data(DECLARG(asn1buf *, buf),
					       DECLARG(const krb5_authdata **, val),
					       DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_authdata **, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();
  int i;
  
  if(val == NULL || val[0] == NULL) return ASN1_MISSING_FIELD;
  
  for(i=0; val[i] != NULL; i++); /* get to the end of the array */
  for(i--; i>=0; i--){
    retval = asn1_encode_krb5_authdata_elt(buf,val[i],&length);
    if(retval) return retval;
    sum += length;
  }
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_krb5_authdata_elt(DECLARG(asn1buf *, buf),
					      DECLARG(const krb5_authdata *, val),
					      DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_authdata *, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();

  if(val == NULL || val->contents == NULL) return ASN1_MISSING_FIELD;

  /* ad-data[1]		OCTET STRING */
  asn1_addlenfield(val->length,val->contents,1,asn1_encode_octetstring);
  /* ad-type[0]		INTEGER */
  asn1_addfield(val->ad_type,0,asn1_encode_integer);
  /* SEQUENCE */
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_kdc_rep(DECLARG(asn1buf *, buf),
				    DECLARG(const krb5_kdc_rep *, val),
				    DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_kdc_rep *, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();

  if(val == NULL) return ASN1_MISSING_FIELD;

  asn1_addfield(&(val->enc_part),6,asn1_encode_encrypted_data);
  asn1_addfield(val->ticket,5,asn1_encode_ticket);
  asn1_addfield(val->client,4,asn1_encode_principal_name);
  asn1_addfield(val->client,3,asn1_encode_realm);
  if(val->padata != NULL && val->padata[0] != NULL)
    asn1_addfield((const krb5_pa_data**)val->padata,2,asn1_encode_sequence_of_pa_data);
  asn1_addfield(val->msg_type,1,asn1_encode_msgtype);
  asn1_addfield(KVNO,0,asn1_encode_integer);
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_enc_kdc_rep_part(DECLARG(asn1buf *, buf),
					     DECLARG(const krb5_enc_kdc_rep_part *, val),
					     DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_enc_kdc_rep_part *, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();

  if(val == NULL) return ASN1_MISSING_FIELD;

  /* caddr[11]		HostAddresses OPTIONAL */
  if(val->caddrs != NULL && val->caddrs[0] != NULL)
    asn1_addfield((const krb5_address**)(val->caddrs),11,asn1_encode_host_addresses);

  /* sname[10]		PrincipalName */
  asn1_addfield(val->server,10,asn1_encode_principal_name);

  /* srealm[9]		Realm */
  asn1_addfield(val->server,9,asn1_encode_realm);

  /* renew-till[8]	KerberosTime OPTIONAL */
  if(val->flags & TKT_FLG_RENEWABLE)
    asn1_addfield(val->times.renew_till,8,asn1_encode_kerberos_time);

  /* endtime[7]		KerberosTime */
  asn1_addfield(val->times.endtime,7,asn1_encode_kerberos_time);

  /* starttime[6]	KerberosTime OPTIONAL */
  if(val->times.starttime)
    asn1_addfield(val->times.starttime,6,asn1_encode_kerberos_time);

  /* authtime[5]	KerberosTime */
  asn1_addfield(val->times.authtime,5,asn1_encode_kerberos_time);

  /* flags[4]		TicketFlags */
  asn1_addfield(val->flags,4,asn1_encode_ticket_flags);

  /* key-expiration[3]	KerberosTime OPTIONAL */
  if(val->key_exp)
    asn1_addfield(val->key_exp,3,asn1_encode_kerberos_time);

  /* nonce[2]		INTEGER */
  asn1_addfield(val->nonce,2,asn1_encode_integer);

  /* last-req[1]	LastReq */
  asn1_addfield((const krb5_last_req_entry**)val->last_req,1,asn1_encode_last_req);

  /* key[0]		EncryptionKey */
  asn1_addfield(val->session,0,asn1_encode_encryption_key);

  /* EncKDCRepPart ::= SEQUENCE */
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_kdc_req_body(DECLARG(asn1buf *, buf),
					 DECLARG(const krb5_kdc_req *, rep),
					 DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_kdc_req *, rep)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();
  
  if(rep == NULL) return ASN1_MISSING_FIELD;

  /* additional-tickets[11]	SEQUENCE OF Ticket OPTIONAL */
  if(rep->second_ticket != NULL && rep->second_ticket[0] != NULL)
    asn1_addfield((const krb5_ticket**)rep->second_ticket,
		  11,asn1_encode_sequence_of_ticket);

  /* enc-authorization-data[10]	EncryptedData OPTIONAL, */
  /* 				-- Encrypted AuthorizationData encoding */
  if(rep->authorization_data.ciphertext.data != NULL)
    asn1_addfield(&(rep->authorization_data),10,asn1_encode_encrypted_data);

  /* addresses[9]		HostAddresses OPTIONAL, */
  if(rep->addresses != NULL && rep->addresses[0] != NULL)
    asn1_addfield((const krb5_address**)rep->addresses,9,asn1_encode_host_addresses);

  /* etype[8]			SEQUENCE OF INTEGER, -- EncryptionType, */
  /* 				-- in preference order */
  asn1_addlenfield(rep->netypes,rep->etype,8,asn1_encode_sequence_of_enctype);

  /* nonce[7]			INTEGER, */
  asn1_addfield(rep->nonce,7,asn1_encode_integer);

  /* rtime[6]			KerberosTime OPTIONAL, */
  if(rep->rtime)
    asn1_addfield(rep->rtime,6,asn1_encode_kerberos_time);

  /* till[5]			KerberosTime, */
  asn1_addfield(rep->till,5,asn1_encode_kerberos_time);

  /* from[4]			KerberosTime OPTIONAL, */
  if(rep->from)
  asn1_addfield(rep->from,4,asn1_encode_kerberos_time);

  /* sname[3]			PrincipalName OPTIONAL, */
  if(rep->server != NULL)
    asn1_addfield(rep->server,3,asn1_encode_principal_name);

  /* realm[2]			Realm, -- Server's realm */
  /* 				-- Also client's in AS-REQ */
  if(rep->kdc_options & KDC_OPT_ENC_TKT_IN_SKEY){
    if(rep->second_ticket != NULL && rep->second_ticket[0] != NULL){
      asn1_addfield(rep->second_ticket[0]->server,2,asn1_encode_realm)
    } else return ASN1_MISSING_FIELD;
  }else if(rep->server != NULL){
    asn1_addfield(rep->server,2,asn1_encode_realm);
  }else return ASN1_MISSING_FIELD;

  /* cname[1]			PrincipalName OPTIONAL, */
  /* 				-- Used only in AS-REQ */
  if(rep->client != NULL)
    asn1_addfield(rep->client,1,asn1_encode_principal_name);

  /* kdc-options[0]		KDCOptions, */
  asn1_addfield(rep->kdc_options,0,asn1_encode_kdc_options);

  /* KDC-REQ-BODY ::= SEQUENCE */
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_encryption_key(DECLARG(asn1buf *, buf),
					   DECLARG(const krb5_keyblock *, val),
					   DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_keyblock *, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();

  if(val == NULL || val->contents == NULL) return ASN1_MISSING_FIELD;

  asn1_addlenfield(val->length,val->contents,1,asn1_encode_octetstring);
  asn1_addfield(val->keytype,0,asn1_encode_integer);
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_checksum(DECLARG(asn1buf *, buf),
				     DECLARG(const krb5_checksum *, val),
				     DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_checksum *, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();

  if(val == NULL || val->contents == NULL) return ASN1_MISSING_FIELD;

  asn1_addlenfield(val->length,val->contents,1,asn1_encode_octetstring);
  asn1_addfield(val->checksum_type,0,asn1_encode_integer);
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_transited_encoding(DECLARG(asn1buf *, buf),
					       DECLARG(const krb5_transited *, val),
					       DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_transited *, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();

  if(val == NULL || val->tr_contents.data == NULL) return ASN1_MISSING_FIELD;

  asn1_addlenfield(val->tr_contents.length,val->tr_contents.data,
		   1,asn1_encode_charstring);
  asn1_addfield(val->tr_type,0,asn1_encode_integer);
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_last_req(DECLARG(asn1buf *, buf),
				     DECLARG(const krb5_last_req_entry **, val),
				     DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_last_req_entry **, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();
  int i;

  if(val == NULL || val[0] == NULL) return ASN1_MISSING_FIELD;

  for(i=0; val[i] != NULL; i++); /* go to end of array */
  for(i--; i>=0; i--){
    retval = asn1_encode_last_req_entry(buf,val[i],&length);
    if(retval) return retval;
    sum += length;
  }
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_last_req_entry(DECLARG(asn1buf *, buf),
					   DECLARG(const krb5_last_req_entry *, val),
					   DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_last_req_entry *, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();

  if(val == NULL) return ASN1_MISSING_FIELD;

  asn1_addfield(val->value,1,asn1_encode_kerberos_time);
  asn1_addfield(val->lr_type,0,asn1_encode_integer);
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_sequence_of_pa_data(DECLARG(asn1buf *, buf),
						DECLARG(const krb5_pa_data **, val),
						DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_pa_data **, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();
  int i;

  if(val == NULL || val[0] == NULL) return ASN1_MISSING_FIELD;

  for(i=0; val[i] != NULL; i++);
  for(i--; i>=0; i--){
    retval = asn1_encode_pa_data(buf,val[i],&length);
    if(retval) return retval;
    sum += length;
  }
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_pa_data(DECLARG(asn1buf *, buf),
				    DECLARG(const krb5_pa_data *, val),
				    DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_pa_data *, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();

  if(val == NULL || (val->length != 0 && val->contents == NULL))
     return ASN1_MISSING_FIELD;

  asn1_addlenfield(val->length,val->contents,2,asn1_encode_octetstring);
  asn1_addfield(val->pa_type,1,asn1_encode_integer);
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_sequence_of_ticket(DECLARG(asn1buf *, buf),
					       DECLARG(const krb5_ticket **, val),
					       DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_ticket **, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();
  int i;

  if(val == NULL || val[0] == NULL) return ASN1_MISSING_FIELD;

  for(i=0; val[i] != NULL; i++);
  for(i--; i>=0; i--){
    retval = asn1_encode_ticket(buf,val[i],&length);
    if(retval) return retval;
    sum += length;
  }
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_ticket(DECLARG(asn1buf *, buf),
				   DECLARG(const krb5_ticket *, val),
				   DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_ticket *, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();

  if(val == NULL) return ASN1_MISSING_FIELD;

  asn1_addfield(&(val->enc_part),3,asn1_encode_encrypted_data);
  asn1_addfield(val->server,2,asn1_encode_principal_name);
  asn1_addfield(val->server,1,asn1_encode_realm);
  asn1_addfield(KVNO,0,asn1_encode_integer);
  asn1_makeseq();
  asn1_apptag(1);

  asn1_cleanup();
}

asn1_error_code asn1_encode_sequence_of_enctype(DECLARG(asn1buf *, buf),
						DECLARG(const int, len),
						DECLARG(const krb5_enctype *, val),
						DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const int, len)
     OLDDECLARG(const krb5_enctype *, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();
  int i;

  if(val == NULL) return ASN1_MISSING_FIELD;

  for(i=len-1; i>=0; i--){
    retval = asn1_encode_integer(buf,val[i],&length);
    if(retval) return retval;
    sum += length;
  }
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_kdc_req(DECLARG(asn1buf *, buf),
				    DECLARG(const krb5_kdc_req *, val),
				    DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_kdc_req *, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();

  if(val == NULL) return ASN1_MISSING_FIELD;

  asn1_addfield(val,4,asn1_encode_kdc_req_body);
  if(val->padata != NULL && val->padata[0] != NULL)
    asn1_addfield((const krb5_pa_data**)val->padata,3,asn1_encode_sequence_of_pa_data);
  if(val->msg_type == KRB5_AS_REQ){
    asn1_addfield(ASN1_KRB_AS_REQ,2,asn1_encode_integer);
  }else if(val->msg_type == KRB5_TGS_REQ){
    asn1_addfield(ASN1_KRB_TGS_REQ,2,asn1_encode_integer);
  }else return KRB5_BADMSGTYPE;
  asn1_addfield(KVNO,1,asn1_encode_integer);
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_krb_safe_body(DECLARG(asn1buf *, buf),
					  DECLARG(const krb5_safe *, val),
					  DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_safe *, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();

  if(val == NULL) return ASN1_MISSING_FIELD;

  if(val->r_address != NULL)
    asn1_addfield(val->r_address,5,asn1_encode_host_address);
  asn1_addfield(val->s_address,4,asn1_encode_host_address);
  if(val->seq_number)
    asn1_addfield(val->seq_number,3,asn1_encode_integer);
  if(val->timestamp){
    asn1_addfield(val->usec,2,asn1_encode_integer);
    asn1_addfield(val->timestamp,1,asn1_encode_kerberos_time);
  }
  if(val->user_data.data == NULL) return ASN1_MISSING_FIELD;
  asn1_addlenfield(val->user_data.length,val->user_data.data,0,asn1_encode_charstring)
;

  asn1_makeseq();
  asn1_cleanup();
}

asn1_error_code asn1_encode_sequence_of_krb_cred_info(DECLARG(asn1buf *, buf),
						      DECLARG(const krb5_cred_info **, val),
						      DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_cred_info **, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();
  int i;

  if(val == NULL) return ASN1_MISSING_FIELD;

  for(i=0; val[i] != NULL; i++);
  for(i--; i>=0; i--){
    retval = asn1_encode_krb_cred_info(buf,val[i],&length);
    if(retval) return retval;
    sum += length;
  }
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_krb_cred_info(DECLARG(asn1buf *, buf),
					  DECLARG(const krb5_cred_info *, val),
					  DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_cred_info *, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();

  if(val == NULL) return ASN1_MISSING_FIELD;

  if(val->caddrs != NULL && val->caddrs[0] != NULL)
    asn1_addfield((const krb5_address**)val->caddrs,10,asn1_encode_host_addresses);
  if(val->server != NULL){
    asn1_addfield(val->server,9,asn1_encode_principal_name);
    asn1_addfield(val->server,8,asn1_encode_realm);
  }
  if(val->times.renew_till)
    asn1_addfield(val->times.renew_till,7,asn1_encode_kerberos_time);
  if(val->times.endtime)
    asn1_addfield(val->times.endtime,6,asn1_encode_kerberos_time);
  if(val->times.starttime)
    asn1_addfield(val->times.starttime,5,asn1_encode_kerberos_time);
  if(val->times.authtime)
    asn1_addfield(val->times.authtime,4,asn1_encode_kerberos_time);
  if(val->flags)
    asn1_addfield(val->flags,3,asn1_encode_ticket_flags);
  if(val->client != NULL){
    asn1_addfield(val->client,2,asn1_encode_principal_name);
    asn1_addfield(val->client,1,asn1_encode_realm);
  }
  asn1_addfield(val->session,0,asn1_encode_encryption_key);

  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_sequence_of_passwdsequence(DECLARG(asn1buf *, buf),
						       DECLARG(const passwd_phrase_element **, val),
						       DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *,buf)
     OLDDECLARG(const passwd_phrase_element **, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();
  int i;
  
  if(val == NULL || val[0] == NULL) return ASN1_MISSING_FIELD;
  
  for(i=0; val[i] != NULL; i++); /* get to the end of the array */
  for(i--; i>=0; i--){
    retval = asn1_encode_passwdsequence(buf,val[i],&length);
    if(retval) return retval;
    sum += length;
  }
  asn1_makeseq();
  asn1_cleanup();
}

asn1_error_code asn1_encode_passwdsequence(DECLARG(asn1buf *, buf),
					   DECLARG(const passwd_phrase_element *, val),
					   DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *,buf)
     OLDDECLARG(const passwd_phrase_element *, val)
     OLDDECLARG(int *, retlen)
{
  asn1_setup();
  asn1_addlenfield(val->phrase->length,val->phrase->data,1,asn1_encode_charstring);
  asn1_addlenfield(val->passwd->length,val->passwd->data,0,asn1_encode_charstring);
  asn1_makeseq();
  asn1_cleanup();
}

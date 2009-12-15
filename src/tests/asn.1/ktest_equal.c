/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include <stdlib.h>
#include <stdio.h>
#include "ktest_equal.h"

#define FALSE 0
#define TRUE 1

#define struct_equal(field,comparator)          \
    comparator(&(ref->field),&(var->field))

#define ptr_equal(field,comparator)             \
    comparator(ref->field,var->field)

#define scalar_equal(field)                     \
    ((ref->field) == (var->field))

#define len_equal(length,field,comparator)              \
    ((ref->length == var->length) &&                    \
     comparator(ref->length,ref->field,var->field))

int ktest_equal_authenticator(ref, var)
    krb5_authenticator * ref;
    krb5_authenticator * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p = p && ptr_equal(client,ktest_equal_principal_data);
    p = p && ptr_equal(checksum,ktest_equal_checksum);
    p = p && scalar_equal(cusec);
    p = p && scalar_equal(ctime);
    p = p && ptr_equal(subkey,ktest_equal_keyblock);
    p = p && scalar_equal(seq_number);
    p = p && ptr_equal(authorization_data,ktest_equal_authorization_data);
    return p;
}

int ktest_equal_principal_data(ref, var)
    krb5_principal_data * ref;
    krb5_principal_data * var;
{
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    return(struct_equal(realm,ktest_equal_data) &&
           len_equal(length,data,ktest_equal_array_of_data) &&
           scalar_equal(type));
}

int ktest_equal_authdata(ref, var)
    krb5_authdata * ref;
    krb5_authdata * var;
{
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    return(scalar_equal(ad_type) &&
           len_equal(length,contents,ktest_equal_array_of_octet));
}

int ktest_equal_checksum(ref, var)
    krb5_checksum * ref;
    krb5_checksum * var;
{
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    return(scalar_equal(checksum_type) && len_equal(length,contents,ktest_equal_array_of_octet));
}

int ktest_equal_keyblock(ref, var)
    krb5_keyblock * ref;
    krb5_keyblock * var;
{
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    return(scalar_equal(enctype) && len_equal(length,contents,ktest_equal_array_of_octet));
}

int ktest_equal_data(ref, var)
    krb5_data * ref;
    krb5_data * var;
{
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    return(len_equal(length,data,ktest_equal_array_of_char));
}

int ktest_equal_ticket(ref, var)
    krb5_ticket * ref;
    krb5_ticket * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p = p && ptr_equal(server,ktest_equal_principal_data);
    p = p && struct_equal(enc_part,ktest_equal_enc_data);
    /* enc_part2 is irrelevant, as far as the ASN.1 code is concerned */
    return p;
}

int ktest_equal_enc_data(ref, var)
    krb5_enc_data * ref;
    krb5_enc_data * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&scalar_equal(enctype);
    p=p&&scalar_equal(kvno);
    p=p&&struct_equal(ciphertext,ktest_equal_data);
    return p;
}

int ktest_equal_encryption_key(ref, var)
    krb5_keyblock * ref;
    krb5_keyblock * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p = p && scalar_equal(enctype);
    p = p && len_equal(length,contents,ktest_equal_array_of_octet);
    return p;
}

int ktest_equal_enc_tkt_part(ref, var)
    krb5_enc_tkt_part * ref;
    krb5_enc_tkt_part * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p = p && scalar_equal(flags);
    p = p && ptr_equal(session,ktest_equal_encryption_key);
    p = p && ptr_equal(client,ktest_equal_principal_data);
    p = p && struct_equal(transited,ktest_equal_transited);
    p = p && struct_equal(times,ktest_equal_ticket_times);
    p = p && ptr_equal(caddrs,ktest_equal_addresses);
    p = p && ptr_equal(authorization_data,ktest_equal_authorization_data);
    return p;
}

int ktest_equal_transited(ref, var)
    krb5_transited * ref;
    krb5_transited * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p = p && scalar_equal(tr_type);
    p = p && struct_equal(tr_contents,ktest_equal_data);
    return p;
}

int ktest_equal_ticket_times(ref, var)
    krb5_ticket_times * ref;
    krb5_ticket_times * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p = p && scalar_equal(authtime);
    p = p && scalar_equal(starttime);
    p = p && scalar_equal(endtime);
    p = p && scalar_equal(renew_till);
    return p;
}

int ktest_equal_address(ref, var)
    krb5_address * ref;
    krb5_address * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&scalar_equal(addrtype);
    p=p&&len_equal(length,contents,ktest_equal_array_of_octet);
    return p;
}

int ktest_equal_enc_kdc_rep_part(ref, var)
    krb5_enc_kdc_rep_part * ref;
    krb5_enc_kdc_rep_part * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
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

int ktest_equal_priv(ref, var)
    krb5_priv * ref;
    krb5_priv * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&struct_equal(enc_part,ktest_equal_enc_data);
    return p;
}

int ktest_equal_cred(ref, var)
    krb5_cred * ref;
    krb5_cred * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&ptr_equal(tickets,ktest_equal_sequence_of_ticket);
    p=p&&struct_equal(enc_part,ktest_equal_enc_data);
    return p;
}

int ktest_equal_error(ref, var)
    krb5_error * ref;
    krb5_error * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
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

int ktest_equal_ap_req(ref, var)
    krb5_ap_req * ref;
    krb5_ap_req * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&scalar_equal(ap_options);
    p=p&&ptr_equal(ticket,ktest_equal_ticket);
    p=p&&struct_equal(authenticator,ktest_equal_enc_data);
    return p;
}

int ktest_equal_ap_rep(ref, var)
    krb5_ap_rep * ref;
    krb5_ap_rep * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&struct_equal(enc_part,ktest_equal_enc_data);
    return p;
}

int ktest_equal_ap_rep_enc_part(ref, var)
    krb5_ap_rep_enc_part * ref;
    krb5_ap_rep_enc_part * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&scalar_equal(ctime);
    p=p&&scalar_equal(cusec);
    p=p&&ptr_equal(subkey,ktest_equal_encryption_key);
    p=p&&scalar_equal(seq_number);
    return p;
}

int ktest_equal_safe(ref, var)
    krb5_safe * ref;
    krb5_safe * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&struct_equal(user_data,ktest_equal_data);
    p=p&&scalar_equal(timestamp);
    p=p&&scalar_equal(usec);
    p=p&&scalar_equal(seq_number);
    p=p&&ptr_equal(s_address,ktest_equal_address);
    p=p&&ptr_equal(r_address,ktest_equal_address);
    p=p&&ptr_equal(checksum,ktest_equal_checksum);
    return p;
}


int ktest_equal_enc_cred_part(ref, var)
    krb5_cred_enc_part * ref;
    krb5_cred_enc_part * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&scalar_equal(nonce);
    p=p&&scalar_equal(timestamp);
    p=p&&scalar_equal(usec);
    p=p&&ptr_equal(s_address,ktest_equal_address);
    p=p&&ptr_equal(r_address,ktest_equal_address);
    p=p&&ptr_equal(ticket_info,ktest_equal_sequence_of_cred_info);
    return p;
}

int ktest_equal_enc_priv_part(ref, var)
    krb5_priv_enc_part * ref;
    krb5_priv_enc_part * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&struct_equal(user_data,ktest_equal_data);
    p=p&&scalar_equal(timestamp);
    p=p&&scalar_equal(usec);
    p=p&&scalar_equal(seq_number);
    p=p&&ptr_equal(s_address,ktest_equal_address);
    p=p&&ptr_equal(r_address,ktest_equal_address);
    return p;
}

int ktest_equal_as_rep(ref, var)
    krb5_kdc_rep * ref;
    krb5_kdc_rep * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&scalar_equal(msg_type);
    p=p&&ptr_equal(padata,ktest_equal_sequence_of_pa_data);
    p=p&&ptr_equal(client,ktest_equal_principal_data);
    p=p&&ptr_equal(ticket,ktest_equal_ticket);
    p=p&&struct_equal(enc_part,ktest_equal_enc_data);
    p=p&&ptr_equal(enc_part2,ktest_equal_enc_kdc_rep_part);
    return p;
}

int ktest_equal_tgs_rep(ref, var)
    krb5_kdc_rep * ref;
    krb5_kdc_rep * var;
{
    return ktest_equal_as_rep(ref,var);
}

int ktest_equal_as_req(ref, var)
    krb5_kdc_req * ref;
    krb5_kdc_req * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&scalar_equal(msg_type);
    p=p&&ptr_equal(padata,ktest_equal_sequence_of_pa_data);
    p=p&&scalar_equal(kdc_options);
    p=p&&ptr_equal(client,ktest_equal_principal_data);
    p=p&&ptr_equal(server,ktest_equal_principal_data);
    p=p&&scalar_equal(from);
    p=p&&scalar_equal(till);
    p=p&&scalar_equal(rtime);
    p=p&&scalar_equal(nonce);
    p=p&&len_equal(nktypes,ktype,ktest_equal_array_of_enctype);
    p=p&&ptr_equal(addresses,ktest_equal_addresses);
    p=p&&struct_equal(authorization_data,ktest_equal_enc_data);
/* This field isn't actually in the ASN.1 encoding. */
/* p=p&&ptr_equal(unenc_authdata,ktest_equal_authorization_data); */
    return p;
}

int ktest_equal_tgs_req(ref, var)
    krb5_kdc_req * ref;
    krb5_kdc_req * var;
{
    return ktest_equal_as_req(ref,var);
}

int ktest_equal_kdc_req_body(ref, var)
    krb5_kdc_req * ref;
    krb5_kdc_req * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&scalar_equal(kdc_options);
    p=p&&ptr_equal(client,ktest_equal_principal_data);
    p=p&&ptr_equal(server,ktest_equal_principal_data);
    p=p&&scalar_equal(from);
    p=p&&scalar_equal(till);
    p=p&&scalar_equal(rtime);
    p=p&&scalar_equal(nonce);
    p=p&&len_equal(nktypes,ktype,ktest_equal_array_of_enctype);
    p=p&&ptr_equal(addresses,ktest_equal_addresses);
    p=p&&struct_equal(authorization_data,ktest_equal_enc_data);
    /* This isn't part of the ASN.1 encoding. */
    /* p=p&&ptr_equal(unenc_authdata,ktest_equal_authorization_data); */
    return p;
}

int ktest_equal_last_req_entry(ref, var)
    krb5_last_req_entry * ref;
    krb5_last_req_entry * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&scalar_equal(lr_type);
    p=p&&scalar_equal(value);
    return p;
}

int ktest_equal_pa_data(ref, var)
    krb5_pa_data * ref;
    krb5_pa_data * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&scalar_equal(pa_type);
    p=p&&len_equal(length,contents,ktest_equal_array_of_octet);
    return p;
}

int ktest_equal_cred_info(ref, var)
    krb5_cred_info * ref;
    krb5_cred_info * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&ptr_equal(session,ktest_equal_keyblock);
    p=p&&ptr_equal(client,ktest_equal_principal_data);
    p=p&&ptr_equal(server,ktest_equal_principal_data);
    p=p&&scalar_equal(flags);
    p=p&&struct_equal(times,ktest_equal_ticket_times);
    p=p&&ptr_equal(caddrs,ktest_equal_addresses);

    return p;
}

int ktest_equal_passwd_phrase_element(ref, var)
    passwd_phrase_element * ref;
    passwd_phrase_element * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&ptr_equal(passwd,ktest_equal_data);
    p=p&&ptr_equal(phrase,ktest_equal_data);
    return p;
}

int ktest_equal_krb5_pwd_data(ref, var)
    krb5_pwd_data * ref;
    krb5_pwd_data * var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&scalar_equal(sequence_count);
    p=p&&ptr_equal(element,ktest_equal_array_of_passwd_phrase_element);
    return p;
}

int ktest_equal_krb5_alt_method(ref, var)
    krb5_alt_method *ref;
    krb5_alt_method *var;
{
    if (ref->method != var->method)
        return FALSE;
    if (ref->length != var->length)
        return FALSE;
    if (memcmp(ref->data, var->data, ref->length) != 0)
        return FALSE;
    return TRUE;
}

int ktest_equal_krb5_etype_info_entry(ref, var)
    krb5_etype_info_entry *ref;
    krb5_etype_info_entry *var;
{
    if (ref->etype != var->etype)
        return FALSE;
    if (ref->length != var->length)
        return FALSE;
    if (ref->length > 0 && ref->length != KRB5_ETYPE_NO_SALT)
        if (memcmp(ref->salt, var->salt, ref->length) != 0)
            return FALSE;
    return TRUE;
}

int ktest_equal_krb5_pa_enc_ts(ref, var)
    krb5_pa_enc_ts *ref;
    krb5_pa_enc_ts *var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&scalar_equal(patimestamp);
    p=p&&scalar_equal(pausec);
    return p;
}

#define equal_str(f) struct_equal(f,ktest_equal_data)

int ktest_equal_sam_challenge(ref, var)
    krb5_sam_challenge *ref;
    krb5_sam_challenge *var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&scalar_equal(sam_type);
    p=p&&scalar_equal(sam_flags);
    p=p&&scalar_equal(sam_nonce);
    p=p&&ktest_equal_checksum(&ref->sam_cksum,&var->sam_cksum);
    p=p&&equal_str(sam_track_id);
    p=p&&equal_str(sam_challenge_label);
    p=p&&equal_str(sam_challenge);
    p=p&&equal_str(sam_response_prompt);
    p=p&&equal_str(sam_pk_for_sad);
    return p;
}

int ktest_equal_sam_response(ref, var)
    krb5_sam_response *ref;
    krb5_sam_response *var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&scalar_equal(sam_type);
    p=p&&scalar_equal(sam_flags);
    p=p&&equal_str(sam_track_id);
    p=p&&struct_equal(sam_enc_key,ktest_equal_enc_data);
    p=p&&struct_equal(sam_enc_nonce_or_ts,ktest_equal_enc_data);
    p=p&&scalar_equal(sam_nonce);
    p=p&&scalar_equal(sam_patimestamp);
    return p;
}

int ktest_equal_pa_s4u_x509_user(ref, var)
    krb5_pa_s4u_x509_user *ref;
    krb5_pa_s4u_x509_user *var;
{
    int p = TRUE;
    if (ref == var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&scalar_equal(user_id.nonce);
    p=p&&ptr_equal(user_id.user,ktest_equal_principal_data);
    p=p&&struct_equal(user_id.subject_cert,ktest_equal_data);
    p=p&&scalar_equal(user_id.options);
    p=p&&struct_equal(cksum,ktest_equal_checksum);
    return p;
}

int ktest_equal_ad_kdcissued(ref, var)
    krb5_ad_kdcissued *ref;
    krb5_ad_kdcissued *var;
{
    int p = TRUE;
    if (ref == var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&struct_equal(ad_checksum,ktest_equal_checksum);
    p=p&&ptr_equal(i_principal,ktest_equal_principal_data);
    p=p&&ptr_equal(elements,ktest_equal_authorization_data);
    return p;
}

int ktest_equal_ad_signedpath_data(ref, var)
    krb5_ad_signedpath_data *ref;
    krb5_ad_signedpath_data *var;
{
    int p = TRUE;
    if (ref == var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&ptr_equal(client,ktest_equal_principal_data);
    p=p&&scalar_equal(authtime);
    p=p&&ptr_equal(delegated,ktest_equal_sequence_of_principal);
    p=p&&ptr_equal(method_data,ktest_equal_sequence_of_pa_data);
    p=p&&ptr_equal(authorization_data,ktest_equal_authorization_data);
    return p;
}

int ktest_equal_ad_signedpath(ref, var)
    krb5_ad_signedpath* ref;
    krb5_ad_signedpath* var;
{
    int p = TRUE;
    if (ref == var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&scalar_equal(enctype);
    p=p&&struct_equal(checksum,ktest_equal_checksum);
    p=p&&ptr_equal(delegated,ktest_equal_sequence_of_principal);
    p=p&&ptr_equal(method_data,ktest_equal_sequence_of_pa_data);
    return p;
}

#ifdef ENABLE_LDAP
static int equal_key_data(ref, var)
    krb5_key_data *ref;
    krb5_key_data *var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&scalar_equal(key_data_ver);
    p=p&&scalar_equal(key_data_kvno);
    p=p&&scalar_equal(key_data_type[0]);
    p=p&&scalar_equal(key_data_type[1]);
    p=p&&len_equal(key_data_length[0],key_data_contents[0],
                   ktest_equal_array_of_octet);
    p=p&&len_equal(key_data_length[1],key_data_contents[1],
                   ktest_equal_array_of_octet);
    return p;
}
static int equal_key_data_array(int n, krb5_key_data *ref, krb5_key_data *val)
{
    int i, p=TRUE;
    for (i = 0; i < n; i++) {
        p=p&&equal_key_data(ref+i, val+i);
    }
    return p;
}
int ktest_equal_ldap_sequence_of_keys(ref, var)
    ldap_seqof_key_data *ref;
    ldap_seqof_key_data *var;
{
    int p=TRUE;
    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    p=p&&scalar_equal(mkvno);
    p=p&&len_equal(n_key_data,key_data,equal_key_data_array);
    return p;
}
#endif

/**** arrays ****************************************************************/

int ktest_equal_array_of_data(length, ref, var)
    const int length;
    krb5_data * ref;
    krb5_data * var;
{
    int i,p=TRUE;

    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    for (i=0; i<(length); i++) {
        p = p && ktest_equal_data(&(ref[i]),&(var[i]));
    }
    return p;
}

int ktest_equal_array_of_octet(length, ref, var)
    const unsigned int length;
    krb5_octet * ref;
    krb5_octet * var;
{
    unsigned int i, p=TRUE;

    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    for (i=0; i<length; i++)
        p = p && (ref[i] == var[i]);
    return p;
}

int ktest_equal_array_of_char(length, ref, var)
    const unsigned int length;
    char * ref;
    char * var;
{
    unsigned int i, p=TRUE;

    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    for (i=0; i<length; i++)
        p = p && (ref[i] == var[i]);
    return p;
}

int ktest_equal_array_of_enctype(length, ref, var)
    const int length;
    krb5_enctype * ref;
    krb5_enctype * var;
{
    int i, p=TRUE;

    if (ref==var) return TRUE;
    else if (ref == NULL || var == NULL) return FALSE;
    for (i=0; i<length; i++)
        p = p && (ref[i] == var[i]);
    return p;
}

#define array_compare(comparator)                       \
    int i,p=TRUE;                                       \
    if (ref==var) return TRUE;                          \
    if (!ref || !ref[0])                                \
        return (!var || !var[0]);                       \
    if (!var || !var[0]) return FALSE;                  \
    for (i=0; ref[i] != NULL && var[i] != NULL; i++)    \
        p = p && comparator(ref[i],var[i]);             \
    if (ref[i] == NULL && var[i] == NULL) return p;     \
    else return FALSE

int ktest_equal_authorization_data(ref, var)
    krb5_authdata ** ref;
    krb5_authdata ** var;
{
    array_compare(ktest_equal_authdata);
}

int ktest_equal_addresses(ref, var)
    krb5_address ** ref;
    krb5_address ** var;
{
    array_compare(ktest_equal_address);
}

int ktest_equal_last_req(ref, var)
    krb5_last_req_entry ** ref;
    krb5_last_req_entry ** var;
{
    array_compare(ktest_equal_last_req_entry);
}

int ktest_equal_sequence_of_ticket(ref, var)
    krb5_ticket ** ref;
    krb5_ticket ** var;
{
    array_compare(ktest_equal_ticket);
}

int ktest_equal_sequence_of_pa_data(ref, var)
    krb5_pa_data ** ref;
    krb5_pa_data ** var;
{
    array_compare(ktest_equal_pa_data);
}

int ktest_equal_sequence_of_cred_info(ref, var)
    krb5_cred_info ** ref;
    krb5_cred_info ** var;
{
    array_compare(ktest_equal_cred_info);
}

int ktest_equal_sequence_of_principal(ref, var)
    krb5_principal * ref;
    krb5_principal * var;
{
    array_compare(ktest_equal_principal_data);
}

int ktest_equal_array_of_passwd_phrase_element(ref, var)
    passwd_phrase_element ** ref;
    passwd_phrase_element ** var;
{
    array_compare(ktest_equal_passwd_phrase_element);
}

int ktest_equal_etype_info(ref, var)
    krb5_etype_info_entry ** ref;
    krb5_etype_info_entry ** var;
{
    array_compare(ktest_equal_krb5_etype_info_entry);
}

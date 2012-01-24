/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/asn.1/asn1_k_encode.c */
/*
 * Copyright 1994, 2008 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "asn1_make.h"
#include "asn1_encode.h"
#include <assert.h>

DEFINT_IMMEDIATE(krb5_version, KVNO);

DEFINTTYPE(int32, krb5_int32);
DEFPTRTYPE(int32_ptr, int32);
DEFCOUNTEDSEQOFTYPE(cseqof_int32, krb5_int32, int32_ptr);

DEFUINTTYPE(uint, unsigned int);
DEFUINTTYPE(octet, krb5_octet);
DEFUINTTYPE(ui_4, krb5_ui_4);

DEFCOUNTEDDERTYPE(der, char *, unsigned int);
DEFCOUNTEDTYPE(der_data, krb5_data, data, length, der);

DEFCOUNTEDSTRINGTYPE(octetstring, unsigned char *, unsigned int,
                     asn1_encode_bytestring, ASN1_OCTETSTRING);
DEFCOUNTEDSTRINGTYPE(s_octetstring, char *, unsigned int,
                     asn1_encode_bytestring, ASN1_OCTETSTRING);
DEFCOUNTEDTYPE(ostring_data, krb5_data, data, length, s_octetstring);
DEFPTRTYPE(ostring_data_ptr, ostring_data);

DEFCOUNTEDSTRINGTYPE(generalstring, char *, unsigned int,
                     asn1_encode_bytestring, ASN1_GENERALSTRING);
DEFCOUNTEDSTRINGTYPE(u_generalstring, unsigned char *, unsigned int,
                     asn1_encode_bytestring, ASN1_GENERALSTRING);
DEFCOUNTEDTYPE(gstring_data, krb5_data, data, length, generalstring);
DEFPTRTYPE(gstring_data_ptr, gstring_data);
DEFCOUNTEDSEQOFTYPE(cseqof_gstring_data, krb5_int32, gstring_data_ptr);

DEFOFFSETTYPE(realm_of_principal_data, krb5_principal_data, realm,
              gstring_data);
DEFPTRTYPE(realm_of_principal, realm_of_principal_data);

DEFFIELD(princname_0, krb5_principal_data, type, 0, int32);
DEFCNFIELD(princname_1, krb5_principal_data, data, length, 1,
           cseqof_gstring_data);
static const struct atype_info *princname_fields[] = {
    &k5_atype_princname_0, &k5_atype_princname_1
};
DEFSEQTYPE(principal_data, krb5_principal_data, princname_fields, NULL);
DEFPTRTYPE(principal, principal_data);

static asn1_error_code
asn1_encode_kerberos_time_at(asn1buf *buf, const krb5_timestamp *val,
                             unsigned int *retlen)
{
    /* Range checking for time_t vs krb5_timestamp?  */
    time_t tval = *val;
    return asn1_encode_generaltime(buf, tval, retlen);
}
DEFPRIMITIVETYPE(kerberos_time, krb5_timestamp, asn1_encode_kerberos_time_at,
                 ASN1_GENERALTIME);

DEFFIELD(address_0, krb5_address, addrtype, 0, int32);
DEFCNFIELD(address_1, krb5_address, contents, length, 1, octetstring);
const static struct atype_info *address_fields[] = {
    &k5_atype_address_0, &k5_atype_address_1
};
DEFSEQTYPE(address, krb5_address, address_fields, NULL);
DEFPTRTYPE(address_ptr, address);

DEFNULLTERMSEQOFTYPE(seqof_host_addresses, address_ptr);
DEFPTRTYPE(ptr_seqof_host_addresses, seqof_host_addresses);

DEFFIELD(enc_data_0, krb5_enc_data, enctype, 0, int32);
DEFFIELD(enc_data_1, krb5_enc_data, kvno, 1, uint);
DEFFIELD(enc_data_2, krb5_enc_data, ciphertext, 2, ostring_data);
static const struct atype_info *encrypted_data_fields[] = {
    &k5_atype_enc_data_0, &k5_atype_enc_data_1, &k5_atype_enc_data_2
};
static unsigned int
optional_encrypted_data (const void *vptr)
{
    const krb5_enc_data *val = vptr;
    unsigned int not_present = 0;
    if (val->kvno == 0)
        not_present |= (1u << 1);
    return not_present;
}
DEFSEQTYPE(encrypted_data, krb5_enc_data, encrypted_data_fields,
           optional_encrypted_data);

/*
 * The encode_bitstring function wants an array of bytes (since PKINIT
 * may provide something that isn't 32 bits), but krb5_flags is stored
 * as a 32-bit integer in host order.
 */
static asn1_error_code
asn1_encode_krb5_flags_at(asn1buf *buf, const krb5_flags *val,
                          unsigned int *retlen)
{
    unsigned char cbuf[4], *cptr = cbuf;
    store_32_be((krb5_ui_4) *val, cbuf);
    return asn1_encode_bitstring(buf, &cptr, 4, retlen);
}
DEFPRIMITIVETYPE(krb5_flags, krb5_flags, asn1_encode_krb5_flags_at,
                 ASN1_BITSTRING);

DEFFIELD(authdata_0, krb5_authdata, ad_type, 0, int32);
DEFCNFIELD(authdata_1, krb5_authdata, contents, length, 1, octetstring);
static const struct atype_info *authdata_elt_fields[] = {
    &k5_atype_authdata_0, &k5_atype_authdata_1
};
DEFSEQTYPE(authdata_elt, krb5_authdata, authdata_elt_fields, NULL);
DEFPTRTYPE(authdata_elt_ptr, authdata_elt);
DEFNONEMPTYNULLTERMSEQOFTYPE(auth_data, authdata_elt_ptr);
DEFPTRTYPE(auth_data_ptr, auth_data);

DEFFIELD(keyblock_0, krb5_keyblock, enctype, 0, int32);
DEFCNFIELD(keyblock_1, krb5_keyblock, contents, length, 1, octetstring);
static const struct atype_info *encryption_key_fields[] = {
    &k5_atype_keyblock_0, &k5_atype_keyblock_1
};
DEFSEQTYPE(encryption_key, krb5_keyblock, encryption_key_fields, NULL);
DEFPTRTYPE(ptr_encryption_key, encryption_key);

DEFFIELD(checksum_0, krb5_checksum, checksum_type, 0, int32);
DEFCNFIELD(checksum_1, krb5_checksum, contents, length, 1, octetstring);
static const struct atype_info *checksum_fields[] = {
    &k5_atype_checksum_0, &k5_atype_checksum_1
};
DEFSEQTYPE(checksum, krb5_checksum, checksum_fields, NULL);
DEFPTRTYPE(checksum_ptr, checksum);
DEFNULLTERMSEQOFTYPE(seqof_checksum, checksum_ptr);
DEFPTRTYPE(ptr_seqof_checksum, seqof_checksum);

DEFFIELD(last_req_0, krb5_last_req_entry, lr_type, 0, int32);
DEFFIELD(last_req_1, krb5_last_req_entry, value, 1, kerberos_time);
static const struct atype_info *lr_fields[] = {
    &k5_atype_last_req_0, &k5_atype_last_req_1
};
DEFSEQTYPE(last_req_ent, krb5_last_req_entry, lr_fields, NULL);

DEFPTRTYPE(last_req_ent_ptr, last_req_ent);
DEFNONEMPTYNULLTERMSEQOFTYPE(last_req, last_req_ent_ptr);
DEFPTRTYPE(last_req_ptr, last_req);

DEFCTAGGEDTYPE(ticket_0, 0, krb5_version);
DEFFIELD(ticket_1, krb5_ticket, server, 1, realm_of_principal);
DEFFIELD(ticket_2, krb5_ticket, server, 2, principal);
DEFFIELD(ticket_3, krb5_ticket, enc_part, 3, encrypted_data);
static const struct atype_info *ticket_fields[] = {
    &k5_atype_ticket_0, &k5_atype_ticket_1, &k5_atype_ticket_2,
    &k5_atype_ticket_3
};
DEFSEQTYPE(untagged_ticket, krb5_ticket, ticket_fields, NULL);
DEFAPPTAGGEDTYPE(ticket, 1, untagged_ticket);

/* First context tag is 1, not 0. */
DEFFIELD(pa_data_1, krb5_pa_data, pa_type, 1, int32);
DEFCNFIELD(pa_data_2, krb5_pa_data, contents, length, 2, octetstring);
static const struct atype_info *pa_data_fields[] = {
    &k5_atype_pa_data_1, &k5_atype_pa_data_2
};
DEFSEQTYPE(pa_data, krb5_pa_data, pa_data_fields, 0);
DEFPTRTYPE(pa_data_ptr, pa_data);

DEFNULLTERMSEQOFTYPE(seqof_pa_data, pa_data_ptr);
DEFPTRTYPE(ptr_seqof_pa_data, seqof_pa_data);

DEFPTRTYPE(ticket_ptr, ticket);
DEFNONEMPTYNULLTERMSEQOFTYPE(seqof_ticket,ticket_ptr);
DEFPTRTYPE(ptr_seqof_ticket, seqof_ticket);

DEFFIELD(enc_kdc_rep_0, krb5_enc_kdc_rep_part, session, 0, ptr_encryption_key);
DEFFIELD(enc_kdc_rep_1, krb5_enc_kdc_rep_part, last_req, 1, last_req_ptr);
DEFFIELD(enc_kdc_rep_2, krb5_enc_kdc_rep_part, nonce, 2, int32);
DEFFIELD(enc_kdc_rep_3, krb5_enc_kdc_rep_part, key_exp, 3, kerberos_time);
DEFFIELD(enc_kdc_rep_4, krb5_enc_kdc_rep_part, flags, 4, krb5_flags);
DEFFIELD(enc_kdc_rep_5, krb5_enc_kdc_rep_part, times.authtime, 5,
         kerberos_time);
DEFFIELD(enc_kdc_rep_6, krb5_enc_kdc_rep_part, times.starttime, 6,
         kerberos_time);
DEFFIELD(enc_kdc_rep_7, krb5_enc_kdc_rep_part, times.endtime, 7,
         kerberos_time);
DEFFIELD(enc_kdc_rep_8, krb5_enc_kdc_rep_part, times.renew_till, 8,
         kerberos_time);
DEFFIELD(enc_kdc_rep_9, krb5_enc_kdc_rep_part, server, 9, realm_of_principal);
DEFFIELD(enc_kdc_rep_10, krb5_enc_kdc_rep_part, server, 10, principal);
DEFFIELD(enc_kdc_rep_11, krb5_enc_kdc_rep_part, caddrs, 11,
         ptr_seqof_host_addresses);
DEFFIELD(enc_kdc_rep_12, krb5_enc_kdc_rep_part, enc_padata, 12,
         ptr_seqof_pa_data);
static const struct atype_info *enc_kdc_rep_part_fields[] = {
    &k5_atype_enc_kdc_rep_0, &k5_atype_enc_kdc_rep_1, &k5_atype_enc_kdc_rep_2,
    &k5_atype_enc_kdc_rep_3, &k5_atype_enc_kdc_rep_4, &k5_atype_enc_kdc_rep_5,
    &k5_atype_enc_kdc_rep_6, &k5_atype_enc_kdc_rep_7, &k5_atype_enc_kdc_rep_8,
    &k5_atype_enc_kdc_rep_9, &k5_atype_enc_kdc_rep_10,
    &k5_atype_enc_kdc_rep_11, &k5_atype_enc_kdc_rep_12
};
static unsigned int
optional_enc_kdc_rep_part(const void *p)
{
    const krb5_enc_kdc_rep_part *val = p;
    unsigned int not_present = 0;
    if (val->key_exp == 0)
        not_present |= (1u << 3);
    if (val->times.starttime == 0)
        not_present |= (1u << 6);
    if (!(val->flags & TKT_FLG_RENEWABLE))
        not_present |= (1u << 8);
    if (val->caddrs == NULL || val->caddrs[0] == NULL)
        not_present |= (1u << 11);
    if (val->enc_padata == NULL)
        not_present |= (1u << 12);
    return not_present;
}
DEFSEQTYPE(enc_kdc_rep_part, krb5_enc_kdc_rep_part, enc_kdc_rep_part_fields,
           optional_enc_kdc_rep_part);

/*
 * Yuck!  Eventually push this *up* above the encoder API and make the
 * rest of the library put the realm name in one consistent place.  At
 * the same time, might as well add the msg-type field and encode both
 * AS-REQ and TGS-REQ through the same descriptor.
 */
typedef struct kdc_req_hack {
    krb5_kdc_req v;
    krb5_data *server_realm;
} kdc_req_hack;
DEFFIELD(kdc_req_0, kdc_req_hack, v.kdc_options, 0, krb5_flags);
DEFFIELD(kdc_req_1, kdc_req_hack, v.client, 1, principal);
DEFFIELD(kdc_req_2, kdc_req_hack, server_realm, 2, gstring_data_ptr);
DEFFIELD(kdc_req_3, kdc_req_hack, v.server, 3, principal);
DEFFIELD(kdc_req_4, kdc_req_hack, v.from, 4, kerberos_time);
DEFFIELD(kdc_req_5, kdc_req_hack, v.till, 5, kerberos_time);
DEFFIELD(kdc_req_6, kdc_req_hack, v.rtime, 6, kerberos_time);
DEFFIELD(kdc_req_7, kdc_req_hack, v.nonce, 7, int32);
DEFCNFIELD(kdc_req_8, kdc_req_hack, v.ktype, v.nktypes, 8, cseqof_int32);
DEFFIELD(kdc_req_9, kdc_req_hack, v.addresses, 9, ptr_seqof_host_addresses);
DEFFIELD(kdc_req_10, kdc_req_hack, v.authorization_data, 10, encrypted_data);
DEFFIELD(kdc_req_11, kdc_req_hack, v.second_ticket, 11, ptr_seqof_ticket);
static const struct atype_info *kdc_req_hack_fields[] = {
    &k5_atype_kdc_req_0, &k5_atype_kdc_req_1, &k5_atype_kdc_req_2,
    &k5_atype_kdc_req_3, &k5_atype_kdc_req_4, &k5_atype_kdc_req_5,
    &k5_atype_kdc_req_6, &k5_atype_kdc_req_7, &k5_atype_kdc_req_8,
    &k5_atype_kdc_req_9, &k5_atype_kdc_req_10, &k5_atype_kdc_req_11
};
static unsigned int
optional_kdc_req_hack(const void *p)
{
    const kdc_req_hack *val2 = p;
    const krb5_kdc_req *val = &val2->v;
    unsigned int not_present = 0;
    if (val->second_ticket == NULL || val->second_ticket[0] == NULL)
        not_present |= (1u << 11);
    if (val->authorization_data.ciphertext.data == NULL)
        not_present |= (1u << 10);
    if (val->addresses == NULL || val->addresses[0] == NULL)
        not_present |= (1u << 9);
    if (val->rtime == 0)
        not_present |= (1u << 6);
    if (val->from == 0)
        not_present |= (1u << 4);
    if (val->server == NULL)
        not_present |= (1u << 3);
    if (val->client == NULL)
        not_present |= (1u << 1);
    return not_present;
}
DEFSEQTYPE(kdc_req_body_hack, kdc_req_hack, kdc_req_hack_fields,
           optional_kdc_req_hack);
static asn1_error_code
asn1_encode_kdc_req_body(asn1buf *buf, const void *ptr, taginfo *rettag)
{
    const krb5_kdc_req *val = ptr;
    kdc_req_hack val2;
    val2.v = *val;
    if (val->kdc_options & KDC_OPT_ENC_TKT_IN_SKEY) {
        if (val->second_ticket != NULL && val->second_ticket[0] != NULL) {
            val2.server_realm = &val->second_ticket[0]->server->realm;
        } else return ASN1_MISSING_FIELD;
    } else if (val->server != NULL) {
        val2.server_realm = &val->server->realm;
    } else return ASN1_MISSING_FIELD;
    return krb5int_asn1_encode_type(buf, &val2, &k5_atype_kdc_req_body_hack,
                                    rettag);
}
DEFFNTYPE(kdc_req_body, krb5_kdc_req, asn1_encode_kdc_req_body);
/* end ugly hack */

DEFFIELD(transited_0, krb5_transited, tr_type, 0, octet);
DEFFIELD(transited_1, krb5_transited, tr_contents, 1, ostring_data);
static const struct atype_info *transited_fields[] = {
    &k5_atype_transited_0, &k5_atype_transited_1
};
DEFSEQTYPE(transited, krb5_transited, transited_fields, NULL);

DEFFIELD(safe_body_0, krb5_safe, user_data, 0, ostring_data);
DEFFIELD(safe_body_1, krb5_safe, timestamp, 1, kerberos_time);
DEFFIELD(safe_body_2, krb5_safe, usec, 2, int32);
DEFFIELD(safe_body_3, krb5_safe, seq_number, 3, uint);
DEFFIELD(safe_body_4, krb5_safe, s_address, 4, address_ptr);
DEFFIELD(safe_body_5, krb5_safe, r_address, 5, address_ptr);
static const struct atype_info *krb_safe_body_fields[] = {
    &k5_atype_safe_body_0, &k5_atype_safe_body_1, &k5_atype_safe_body_2,
    &k5_atype_safe_body_3, &k5_atype_safe_body_4, &k5_atype_safe_body_5
};
static unsigned int
optional_krb_safe_body(const void *p)
{
    const krb5_safe *val = p;
    unsigned int not_present = 0;
    if (val->timestamp == 0)
        not_present |= (1u << 1) | (1u << 2);
    if (val->seq_number == 0)
        not_present |= (1u << 3);
    if (val->r_address == NULL)
        not_present |= (1u << 5);
    return not_present;
}
DEFSEQTYPE(krb_safe_body, krb5_safe, krb_safe_body_fields,
           optional_krb_safe_body);

DEFFIELD(cred_info_0, krb5_cred_info, session, 0, ptr_encryption_key);
DEFFIELD(cred_info_1, krb5_cred_info, client, 1, realm_of_principal);
DEFFIELD(cred_info_2, krb5_cred_info, client, 2, principal);
DEFFIELD(cred_info_3, krb5_cred_info, flags, 3, krb5_flags);
DEFFIELD(cred_info_4, krb5_cred_info, times.authtime, 4, kerberos_time);
DEFFIELD(cred_info_5, krb5_cred_info, times.starttime, 5, kerberos_time);
DEFFIELD(cred_info_6, krb5_cred_info, times.endtime, 6, kerberos_time);
DEFFIELD(cred_info_7, krb5_cred_info, times.renew_till, 7, kerberos_time);
DEFFIELD(cred_info_8, krb5_cred_info, server, 8, realm_of_principal);
DEFFIELD(cred_info_9, krb5_cred_info, server, 9, principal);
DEFFIELD(cred_info_10, krb5_cred_info, caddrs, 10, ptr_seqof_host_addresses);
static const struct atype_info *krb_cred_info_fields[] = {
    &k5_atype_cred_info_0, &k5_atype_cred_info_1, &k5_atype_cred_info_2,
    &k5_atype_cred_info_3, &k5_atype_cred_info_4, &k5_atype_cred_info_5,
    &k5_atype_cred_info_6, &k5_atype_cred_info_7, &k5_atype_cred_info_8,
    &k5_atype_cred_info_9, &k5_atype_cred_info_10
};
static unsigned int
optional_krb_cred_info(const void *p)
{
    const krb5_cred_info *val = p;
    unsigned int not_present = 0;
    if (val->caddrs == NULL || val->caddrs[0] == NULL)
        not_present |= (1u << 10);
    if (val->server == NULL)
        not_present |= (1u << 9) | (1u << 8);
    if (val->times.renew_till == 0)
        not_present |= (1u << 7);
    if (val->times.endtime == 0)
        not_present |= (1u << 6);
    if (val->times.starttime == 0)
        not_present |= (1u << 5);
    if (val->times.authtime == 0)
        not_present |= (1u << 4);
    if (val->flags == 0)
        not_present |= (1u << 3);
    if (val->client == NULL)
        not_present |= (1u << 2) | (1u << 1);
    return not_present;
}
DEFSEQTYPE(cred_info, krb5_cred_info, krb_cred_info_fields,
           optional_krb_cred_info);
DEFPTRTYPE(cred_info_ptr, cred_info);
DEFNULLTERMSEQOFTYPE(seqof_cred_info, cred_info_ptr);

DEFPTRTYPE(ptrseqof_cred_info, seqof_cred_info);

DEFFIELD(etype_info_0, krb5_etype_info_entry, etype, 0, int32);
DEFCNFIELD(etype_info_1, krb5_etype_info_entry, salt, length, 1, octetstring);
static const struct atype_info *etype_info_entry_fields[] = {
    &k5_atype_etype_info_0, &k5_atype_etype_info_1
};
static unsigned int
optional_etype_info_entry(const void *vptr)
{
    const krb5_etype_info_entry *val = vptr;
    unsigned int not_present = 0;
    if (val->length == KRB5_ETYPE_NO_SALT)
        not_present |= (1u << 1);
    return not_present;
}
DEFSEQTYPE(etype_info_entry, krb5_etype_info_entry, etype_info_entry_fields,
           optional_etype_info_entry);

/* First field is the same as etype-info. */
DEFCNFIELD(etype_info2_1, krb5_etype_info_entry, salt, length, 1,
           u_generalstring);
DEFFIELD(etype_info2_2, krb5_etype_info_entry, s2kparams, 2, ostring_data);
static const struct atype_info *etype_info2_entry_fields[] = {
    &k5_atype_etype_info_0, &k5_atype_etype_info2_1, &k5_atype_etype_info2_2
};
static unsigned int
optional_etype_info2_entry(const void *vptr)
{
    const krb5_etype_info_entry *val = vptr;
    unsigned int not_present = 0;
    if (val->length == KRB5_ETYPE_NO_SALT)
        not_present |= (1u << 1);
    if (val->s2kparams.data == NULL)
        not_present |= (1u << 2);
    return not_present;
}
DEFSEQTYPE(etype_info2_entry, krb5_etype_info_entry, etype_info2_entry_fields,
           optional_etype_info2_entry);

DEFPTRTYPE(etype_info_entry_ptr, etype_info_entry);
DEFNULLTERMSEQOFTYPE(etype_info, etype_info_entry_ptr);

DEFPTRTYPE(etype_info2_entry_ptr, etype_info2_entry);
DEFNULLTERMSEQOFTYPE(etype_info2, etype_info2_entry_ptr);

DEFFIELD(sch_0, krb5_sam_challenge_2, sam_challenge_2_body, 0, der_data);
DEFFIELD(sch_1, krb5_sam_challenge_2, sam_cksum, 1, ptr_seqof_checksum);
static const struct atype_info *sam_challenge_2_fields[] = {
    &k5_atype_sch_0, &k5_atype_sch_1
};
DEFSEQTYPE(sam_challenge_2, krb5_sam_challenge_2, sam_challenge_2_fields,
           NULL);

DEFFIELD(schb_0, krb5_sam_challenge_2_body, sam_type, 0, int32);
DEFFIELD(schb_1, krb5_sam_challenge_2_body, sam_flags, 1, krb5_flags);
DEFFIELD(schb_2, krb5_sam_challenge_2_body, sam_type_name, 2, ostring_data);
DEFFIELD(schb_3, krb5_sam_challenge_2_body, sam_track_id, 3, ostring_data);
DEFFIELD(schb_4, krb5_sam_challenge_2_body, sam_challenge_label, 4,
         ostring_data);
DEFFIELD(schb_5, krb5_sam_challenge_2_body, sam_challenge, 5, ostring_data);
DEFFIELD(schb_6, krb5_sam_challenge_2_body, sam_response_prompt, 6,
         ostring_data);
DEFFIELD(schb_7, krb5_sam_challenge_2_body, sam_pk_for_sad, 7, ostring_data);
DEFFIELD(schb_8, krb5_sam_challenge_2_body, sam_nonce, 8, int32);
DEFFIELD(schb_9, krb5_sam_challenge_2_body, sam_etype, 9, int32);
static const struct atype_info *sam_challenge_2_body_fields[] = {
    &k5_atype_schb_0, &k5_atype_schb_1, &k5_atype_schb_2, &k5_atype_schb_3,
    &k5_atype_schb_4, &k5_atype_schb_5, &k5_atype_schb_6, &k5_atype_schb_7,
    &k5_atype_schb_8, &k5_atype_schb_9
};
static unsigned int
optional_sam_challenge_2_body(const void *p)
{
    const krb5_sam_challenge_2_body *val = p;
    unsigned int not_present = 0;
    if (val->sam_pk_for_sad.length == 0)
        not_present |= (1u << 7);
    if (val->sam_response_prompt.length == 0)
        not_present |= (1u << 6);
    if (val->sam_challenge.length == 0)
        not_present |= (1u << 5);
    if (val->sam_challenge_label.length == 0)
        not_present |= (1u << 4);
    if (val->sam_track_id.length == 0)
        not_present |= (1u << 3);
    if (val->sam_type_name.length == 0)
        not_present |= (1u << 2);
    return not_present;
}
DEFSEQTYPE(sam_challenge_2_body,krb5_sam_challenge_2_body,
           sam_challenge_2_body_fields,
           optional_sam_challenge_2_body);

DEFFIELD(esre_0, krb5_enc_sam_response_enc_2, sam_nonce, 0, int32);
DEFFIELD(esre_1, krb5_enc_sam_response_enc_2, sam_sad, 1, ostring_data);
static const struct atype_info *enc_sam_response_enc_2_fields[] = {
    &k5_atype_esre_0, &k5_atype_esre_1
};
static unsigned int
optional_enc_sam_response_enc_2(const void *p)
{
    const krb5_enc_sam_response_enc_2 *val = p;
    unsigned int not_present = 0;
    if (val->sam_sad.length == 0)
        not_present |= (1u << 1);
    return not_present;
}
DEFSEQTYPE(enc_sam_response_enc_2, krb5_enc_sam_response_enc_2,
           enc_sam_response_enc_2_fields, optional_enc_sam_response_enc_2);

DEFFIELD(sam_resp_0, krb5_sam_response_2, sam_type, 0, int32);
DEFFIELD(sam_resp_1, krb5_sam_response_2, sam_flags, 1, krb5_flags);
DEFFIELD(sam_resp_2, krb5_sam_response_2, sam_track_id, 2, ostring_data);
DEFFIELD(sam_resp_3, krb5_sam_response_2, sam_enc_nonce_or_sad, 3,
         encrypted_data);
DEFFIELD(sam_resp_4, krb5_sam_response_2, sam_nonce, 4, int32);
static const struct atype_info *sam_response_2_fields[] = {
    &k5_atype_sam_resp_0, &k5_atype_sam_resp_1, &k5_atype_sam_resp_2,
    &k5_atype_sam_resp_3, &k5_atype_sam_resp_4
};
static unsigned int
optional_sam_response_2(const void *p)
{
    const krb5_sam_response_2 *val = p;
    unsigned int not_present = 0;
    if (val->sam_track_id.length == 0)
        not_present |= (1u << 2);
    return not_present;
}
DEFSEQTYPE(sam_response_2, krb5_sam_response_2, sam_response_2_fields,
           optional_sam_response_2);

DEFCTAGGEDTYPE(authenticator_0, 0, krb5_version);
DEFFIELD(authenticator_1, krb5_authenticator, client, 1, realm_of_principal);
DEFFIELD(authenticator_2, krb5_authenticator, client, 2, principal);
DEFFIELD(authenticator_3, krb5_authenticator, checksum, 3, checksum_ptr);
DEFFIELD(authenticator_4, krb5_authenticator, cusec, 4, int32);
DEFFIELD(authenticator_5, krb5_authenticator, ctime, 5, kerberos_time);
DEFFIELD(authenticator_6, krb5_authenticator, subkey, 6, ptr_encryption_key);
DEFFIELD(authenticator_7, krb5_authenticator, seq_number, 7, uint);
DEFFIELD(authenticator_8, krb5_authenticator, authorization_data, 8,
         auth_data_ptr);
static const struct atype_info *krb5_authenticator_fields[] = {
    &k5_atype_authenticator_0, &k5_atype_authenticator_1,
    &k5_atype_authenticator_2, &k5_atype_authenticator_3,
    &k5_atype_authenticator_4, &k5_atype_authenticator_5,
    &k5_atype_authenticator_6, &k5_atype_authenticator_7,
    &k5_atype_authenticator_8
};
static unsigned int
optional_krb5_authenticator(const void *p)
{
    const krb5_authenticator *val = p;
    unsigned int not_present = 0;
    if (val->authorization_data == NULL || val->authorization_data[0] == NULL)
        not_present |= (1u << 8);
    if (val->seq_number == 0)
        not_present |= (1u << 7);
    if (val->subkey == NULL)
        not_present |= (1u << 6);
    if (val->checksum == NULL)
        not_present |= (1u << 3);
    return not_present;
}
DEFSEQTYPE(untagged_krb5_authenticator, krb5_authenticator,
           krb5_authenticator_fields, optional_krb5_authenticator);
DEFAPPTAGGEDTYPE(krb5_authenticator, 2, untagged_krb5_authenticator);

DEFFIELD(enc_tkt_0, krb5_enc_tkt_part, flags, 0, krb5_flags);
DEFFIELD(enc_tkt_1, krb5_enc_tkt_part, session, 1, ptr_encryption_key);
DEFFIELD(enc_tkt_2, krb5_enc_tkt_part, client, 2, realm_of_principal);
DEFFIELD(enc_tkt_3, krb5_enc_tkt_part, client, 3, principal);
DEFFIELD(enc_tkt_4, krb5_enc_tkt_part, transited, 4, transited);
DEFFIELD(enc_tkt_5, krb5_enc_tkt_part, times.authtime, 5, kerberos_time);
DEFFIELD(enc_tkt_6, krb5_enc_tkt_part, times.starttime, 6, kerberos_time);
DEFFIELD(enc_tkt_7, krb5_enc_tkt_part, times.endtime, 7, kerberos_time);
DEFFIELD(enc_tkt_8, krb5_enc_tkt_part, times.renew_till, 8, kerberos_time);
DEFFIELD(enc_tkt_9, krb5_enc_tkt_part, caddrs, 9, ptr_seqof_host_addresses);
DEFFIELD(enc_tkt_10, krb5_enc_tkt_part, authorization_data, 10, auth_data_ptr);
static const struct atype_info *enc_tkt_part_fields[] = {
    &k5_atype_enc_tkt_0, &k5_atype_enc_tkt_1, &k5_atype_enc_tkt_2,
    &k5_atype_enc_tkt_3, &k5_atype_enc_tkt_4, &k5_atype_enc_tkt_5,
    &k5_atype_enc_tkt_6, &k5_atype_enc_tkt_7, &k5_atype_enc_tkt_8,
    &k5_atype_enc_tkt_9, &k5_atype_enc_tkt_10
};
static unsigned int
optional_enc_tkt_part(const void *p)
{
    const krb5_enc_tkt_part *val = p;
    unsigned int not_present = 0;
    if (val->authorization_data == NULL || val->authorization_data[0] == NULL)
        not_present |= (1u << 10);
    if (val->caddrs == NULL || val->caddrs[0] == NULL)
        not_present |= (1u << 9);
    if (val->times.renew_till == 0)
        not_present |= (1u << 8);
    if (val->times.starttime == 0)
        not_present |= (1u << 6);
    return not_present;
}
DEFSEQTYPE(untagged_enc_tkt_part, krb5_enc_tkt_part, enc_tkt_part_fields,
           optional_enc_tkt_part);
DEFAPPTAGGEDTYPE(enc_tkt_part, 3, untagged_enc_tkt_part);

DEFAPPTAGGEDTYPE(enc_tgs_rep_part, 26, enc_kdc_rep_part);

DEFINT_IMMEDIATE(as_rep_msg_type, KRB5_AS_REP);
DEFCTAGGEDTYPE(kdc_rep_0, 0, krb5_version);
DEFCTAGGEDTYPE(as_rep_1, 1, as_rep_msg_type);
DEFFIELD(kdc_rep_2, krb5_kdc_rep, padata, 2, ptr_seqof_pa_data);
DEFFIELD(kdc_rep_3, krb5_kdc_rep, client, 3, realm_of_principal);
DEFFIELD(kdc_rep_4, krb5_kdc_rep, client, 4, principal);
DEFFIELD(kdc_rep_5, krb5_kdc_rep, ticket, 5, ticket_ptr);
DEFFIELD(kdc_rep_6, krb5_kdc_rep, enc_part, 6, encrypted_data);
static const struct atype_info *as_rep_fields[] = {
    &k5_atype_kdc_rep_0, &k5_atype_as_rep_1, &k5_atype_kdc_rep_2,
    &k5_atype_kdc_rep_3, &k5_atype_kdc_rep_4, &k5_atype_kdc_rep_5,
    &k5_atype_kdc_rep_6
};
static unsigned int
optional_kdc_rep(const void *p)
{
    const krb5_kdc_rep *val = p;
    unsigned int not_present = 0;
    if (val->padata == NULL || val->padata[0] == NULL)
        not_present |= (1u << 2);
    return not_present;
}
DEFSEQTYPE(untagged_as_rep, krb5_kdc_rep, as_rep_fields, optional_kdc_rep);
DEFAPPTAGGEDTYPE(as_rep, 11, untagged_as_rep);

/* TGS-REP ::= [APPLICATION 13] KDC-REP */
/* But KDC-REP needs to know what type it's being encapsulated in, so use a
 * separate atype.  Most fields are the same. */
DEFINT_IMMEDIATE(tgs_rep_msg_type, KRB5_TGS_REP);
DEFCTAGGEDTYPE(tgs_rep_1, 1, tgs_rep_msg_type);
static const struct atype_info *tgs_rep_fields[] = {
    &k5_atype_kdc_rep_0, &k5_atype_tgs_rep_1, &k5_atype_kdc_rep_2,
    &k5_atype_kdc_rep_3, &k5_atype_kdc_rep_4, &k5_atype_kdc_rep_5,
    &k5_atype_kdc_rep_6
};
DEFSEQTYPE(untagged_tgs_rep, krb5_kdc_rep, tgs_rep_fields, optional_kdc_rep);
DEFAPPTAGGEDTYPE(tgs_rep, 13, untagged_tgs_rep);

DEFINT_IMMEDIATE(ap_req_msg_type, ASN1_KRB_AP_REQ);
DEFCTAGGEDTYPE(ap_req_0, 0, krb5_version);
DEFCTAGGEDTYPE(ap_req_1, 1, ap_req_msg_type);
DEFFIELD(ap_req_2, krb5_ap_req, ap_options, 2, krb5_flags);
DEFFIELD(ap_req_3, krb5_ap_req, ticket, 3, ticket_ptr);
DEFFIELD(ap_req_4, krb5_ap_req, authenticator, 4, encrypted_data);
static const struct atype_info *ap_req_fields[] = {
    &k5_atype_ap_req_0, &k5_atype_ap_req_1, &k5_atype_ap_req_2,
    &k5_atype_ap_req_3, &k5_atype_ap_req_4
};
DEFSEQTYPE(untagged_ap_req, krb5_ap_req, ap_req_fields, NULL);
DEFAPPTAGGEDTYPE(ap_req, 14, untagged_ap_req);

DEFINT_IMMEDIATE(ap_rep_msg_type, ASN1_KRB_AP_REP);
DEFCTAGGEDTYPE(ap_rep_0, 0, krb5_version);
DEFCTAGGEDTYPE(ap_rep_1, 1, ap_rep_msg_type);
DEFFIELD(ap_rep_2, krb5_ap_rep, enc_part, 2, encrypted_data);
static const struct atype_info *ap_rep_fields[] = {
    &k5_atype_ap_rep_0, &k5_atype_ap_rep_1, &k5_atype_ap_rep_2
};
DEFSEQTYPE(untagged_ap_rep, krb5_ap_rep, ap_rep_fields, NULL);
DEFAPPTAGGEDTYPE(ap_rep, 15, untagged_ap_rep);

DEFFIELD(ap_rep_enc_part_0, krb5_ap_rep_enc_part, ctime, 0, kerberos_time);
DEFFIELD(ap_rep_enc_part_1, krb5_ap_rep_enc_part, cusec, 1, int32);
DEFFIELD(ap_rep_enc_part_2, krb5_ap_rep_enc_part, subkey, 2,
         ptr_encryption_key);
DEFFIELD(ap_rep_enc_part_3, krb5_ap_rep_enc_part, seq_number, 3, uint);
static const struct atype_info *ap_rep_enc_part_fields[] = {
    &k5_atype_ap_rep_enc_part_0, &k5_atype_ap_rep_enc_part_1,
    &k5_atype_ap_rep_enc_part_2, &k5_atype_ap_rep_enc_part_3
};
static unsigned int
optional_ap_rep_enc_part(const void *p)
{
    const krb5_ap_rep_enc_part *val = p;
    unsigned int not_present = 0;
    if (val->seq_number == 0)
        not_present |= (1u << 3);
    if (val->subkey == NULL)
        not_present |= (1u << 2);
    return not_present;
}
DEFSEQTYPE(untagged_ap_rep_enc_part, krb5_ap_rep_enc_part,
           ap_rep_enc_part_fields, optional_ap_rep_enc_part);
DEFAPPTAGGEDTYPE(ap_rep_enc_part, 27, untagged_ap_rep_enc_part);

/* First context tag is 1.  Fourth field is the encoding of the krb5_kdc_req
 * structure as a KDC-REQ-BODY. */
DEFINT_IMMEDIATE(as_req_msg_type, KRB5_AS_REQ);
DEFCTAGGEDTYPE(as_req_1, 1, krb5_version);
DEFCTAGGEDTYPE(as_req_2, 2, as_req_msg_type);
DEFFIELD(as_req_3, krb5_kdc_req, padata, 3, ptr_seqof_pa_data);
DEFCTAGGEDTYPE(as_req_4, 4, kdc_req_body);
static const struct atype_info *as_req_fields[] = {
    &k5_atype_as_req_1, &k5_atype_as_req_2, &k5_atype_as_req_3,
    &k5_atype_as_req_4
};
static unsigned int
optional_as_req(const void *p)
{
    const krb5_kdc_req *val = p;
    unsigned int not_present = 0;
    if (val->padata == NULL || val->padata[0] == NULL)
        not_present |= (1u << 2);
    return not_present;
}
DEFSEQTYPE(untagged_as_req, krb5_kdc_req, as_req_fields, optional_as_req);
DEFAPPTAGGEDTYPE(as_req, 10, untagged_as_req);

/* Most fields are the same as as_req. */
DEFINT_IMMEDIATE(tgs_req_msg_type, KRB5_TGS_REQ);
DEFCTAGGEDTYPE(tgs_req_2, 2, tgs_req_msg_type);
static const struct atype_info *tgs_req_fields[] = {
    &k5_atype_as_req_1, &k5_atype_tgs_req_2, &k5_atype_as_req_3,
    &k5_atype_as_req_4
};
DEFSEQTYPE(untagged_tgs_req, krb5_kdc_req, tgs_req_fields,
           optional_as_req);
DEFAPPTAGGEDTYPE(tgs_req, 12, untagged_tgs_req);

DEFINT_IMMEDIATE(safe_msg_type, ASN1_KRB_SAFE);
DEFCTAGGEDTYPE(safe_0, 0, krb5_version);
DEFCTAGGEDTYPE(safe_1, 1, safe_msg_type);
DEFCTAGGEDTYPE(safe_2, 2, krb_safe_body);
DEFFIELD(safe_3, krb5_safe, checksum, 3, checksum_ptr);
static const struct atype_info *krb5_safe_fields[] = {
    &k5_atype_safe_0, &k5_atype_safe_1, &k5_atype_safe_2, &k5_atype_safe_3
};
DEFSEQTYPE(untagged_krb5_safe, krb5_safe, krb5_safe_fields, NULL);
DEFAPPTAGGEDTYPE(krb5_safe, 20, untagged_krb5_safe);

/* Hack to encode a KRB-SAFE with a pre-specified body encoding.  The integer-
 * immediate fields are borrowed from krb5_safe_fields above. */
DEFPTRTYPE(krb_saved_safe_body_ptr, der_data);
DEFOFFSETTYPE(krb5_safe_checksum_only, krb5_safe, checksum, checksum_ptr);
DEFPTRTYPE(krb5_safe_checksum_only_ptr, krb5_safe_checksum_only);
DEFFIELD(safe_with_body_2, struct krb5_safe_with_body, body, 2,
         krb_saved_safe_body_ptr);
DEFFIELD(safe_with_body_3, struct krb5_safe_with_body, safe, 3,
         krb5_safe_checksum_only_ptr);
static const struct atype_info *krb5_safe_with_body_fields[] = {
    &k5_atype_safe_0, &k5_atype_safe_1, &k5_atype_safe_with_body_2,
    &k5_atype_safe_with_body_3
};
DEFSEQTYPE(untagged_krb5_safe_with_body, struct krb5_safe_with_body,
           krb5_safe_with_body_fields, NULL);
DEFAPPTAGGEDTYPE(krb5_safe_with_body, 20, untagged_krb5_safe_with_body);

/* Third tag is [3] instead of [2]. */
DEFINT_IMMEDIATE(priv_msg_type, ASN1_KRB_PRIV);
DEFCTAGGEDTYPE(priv_0, 0, krb5_version);
DEFCTAGGEDTYPE(priv_1, 1, priv_msg_type);
DEFFIELD(priv_3, krb5_priv, enc_part, 3, encrypted_data);
static const struct atype_info *priv_fields[] = {
    &k5_atype_priv_0, &k5_atype_priv_1, &k5_atype_priv_3
};
DEFSEQTYPE(untagged_priv, krb5_priv, priv_fields, NULL);
DEFAPPTAGGEDTYPE(krb5_priv, 21, untagged_priv);

DEFFIELD(priv_enc_part_0, krb5_priv_enc_part, user_data, 0, ostring_data);
DEFFIELD(priv_enc_part_1, krb5_priv_enc_part, timestamp, 1, kerberos_time);
DEFFIELD(priv_enc_part_2, krb5_priv_enc_part, usec, 2, int32);
DEFFIELD(priv_enc_part_3, krb5_priv_enc_part, seq_number, 3, uint);
DEFFIELD(priv_enc_part_4, krb5_priv_enc_part, s_address, 4, address_ptr);
DEFFIELD(priv_enc_part_5, krb5_priv_enc_part, r_address, 5, address_ptr);
static const struct atype_info *priv_enc_part_fields[] = {
    &k5_atype_priv_enc_part_0, &k5_atype_priv_enc_part_1,
    &k5_atype_priv_enc_part_2, &k5_atype_priv_enc_part_3,
    &k5_atype_priv_enc_part_4, &k5_atype_priv_enc_part_5
};
static unsigned int
optional_priv_enc_part(const void *p)
{
    const krb5_priv_enc_part *val = p;
    unsigned int not_present = 0;
    if (val->timestamp == 0)
        not_present |= (1u << 2) | (1u << 1);
    if (val->seq_number == 0)
        not_present |= (1u << 3);
    if (val->r_address == NULL)
        not_present |= (1u << 5);
    return not_present;
}
DEFSEQTYPE(untagged_priv_enc_part, krb5_priv_enc_part, priv_enc_part_fields,
           optional_priv_enc_part);
DEFAPPTAGGEDTYPE(priv_enc_part, 28, untagged_priv_enc_part);

DEFINT_IMMEDIATE(cred_msg_type, ASN1_KRB_CRED);
DEFCTAGGEDTYPE(cred_0, 0, krb5_version);
DEFCTAGGEDTYPE(cred_1, 1, cred_msg_type);
DEFFIELD(cred_2, krb5_cred, tickets, 2, ptr_seqof_ticket);
DEFFIELD(cred_3, krb5_cred, enc_part, 3, encrypted_data);
static const struct atype_info *cred_fields[] = {
    &k5_atype_cred_0, &k5_atype_cred_1, &k5_atype_cred_2, &k5_atype_cred_3
};
DEFSEQTYPE(untagged_cred, krb5_cred, cred_fields, NULL);
DEFAPPTAGGEDTYPE(krb5_cred, 22, untagged_cred);

DEFFIELD(enc_cred_part_0, krb5_cred_enc_part, ticket_info, 0,
         ptrseqof_cred_info);
DEFFIELD(enc_cred_part_1, krb5_cred_enc_part, nonce, 1, int32);
DEFFIELD(enc_cred_part_2, krb5_cred_enc_part, timestamp, 2, kerberos_time);
DEFFIELD(enc_cred_part_3, krb5_cred_enc_part, usec, 3, int32);
DEFFIELD(enc_cred_part_4, krb5_cred_enc_part, s_address, 4, address_ptr);
DEFFIELD(enc_cred_part_5, krb5_cred_enc_part, r_address, 5, address_ptr);
static const struct atype_info *enc_cred_part_fields[] = {
    &k5_atype_enc_cred_part_0, &k5_atype_enc_cred_part_1,
    &k5_atype_enc_cred_part_2, &k5_atype_enc_cred_part_3,
    &k5_atype_enc_cred_part_4, &k5_atype_enc_cred_part_5
};
static unsigned int
optional_enc_cred_part(const void *p)
{
    const krb5_cred_enc_part *val = p;
    unsigned int not_present = 0;
    if (val->r_address == NULL)
        not_present |= (1u << 5);
    if (val->s_address == NULL)
        not_present |= (1u << 4);
    if (val->timestamp == 0)
        not_present |= (1u << 2) | (1u << 3);
    if (val->nonce == 0)
        not_present |= (1u << 1);
    return not_present;
}
DEFSEQTYPE(untagged_enc_cred_part, krb5_cred_enc_part, enc_cred_part_fields,
           optional_enc_cred_part);
DEFAPPTAGGEDTYPE(enc_cred_part, 29, untagged_enc_cred_part);

DEFINT_IMMEDIATE(error_msg_type, ASN1_KRB_ERROR);
DEFCTAGGEDTYPE(error_0, 0, krb5_version);
DEFCTAGGEDTYPE(error_1, 1, error_msg_type);
DEFFIELD(error_2, krb5_error, ctime, 2, kerberos_time);
DEFFIELD(error_3, krb5_error, cusec, 3, int32);
DEFFIELD(error_4, krb5_error, stime, 4, kerberos_time);
DEFFIELD(error_5, krb5_error, susec, 5, int32);
DEFFIELD(error_6, krb5_error, error, 6, ui_4);
DEFFIELD(error_7, krb5_error, client, 7, realm_of_principal);
DEFFIELD(error_8, krb5_error, client, 8, principal);
DEFFIELD(error_9, krb5_error, server, 9, realm_of_principal);
DEFFIELD(error_10, krb5_error, server, 10, principal);
DEFFIELD(error_11, krb5_error, text, 11, gstring_data);
DEFFIELD(error_12, krb5_error, e_data, 12, ostring_data);
static const struct atype_info *error_fields[] = {
    &k5_atype_error_0, &k5_atype_error_1, &k5_atype_error_2, &k5_atype_error_3,
    &k5_atype_error_4, &k5_atype_error_5, &k5_atype_error_6, &k5_atype_error_7,
    &k5_atype_error_8, &k5_atype_error_9, &k5_atype_error_10,
    &k5_atype_error_11, &k5_atype_error_12
};
static unsigned int
optional_error(const void *p)
{
    const krb5_error *val = p;
    unsigned int not_present = 0;
    if (val->ctime == 0)
        not_present |= (1u << 2);
    if (val->cusec == 0)
        not_present |= (1u << 3);
    if (val->client == NULL)
        not_present |= (1u << 7) | (1u << 8);
    if (val->text.data == NULL || val->text.length == 0)
        not_present |= (1u << 11);
    if (val->e_data.data == NULL || val->e_data.length == 0)
        not_present |= (1u << 12);
    return not_present;
}
DEFSEQTYPE(untagged_krb5_error, krb5_error, error_fields, optional_error);
DEFAPPTAGGEDTYPE(krb5_error, 30, untagged_krb5_error);

DEFFIELD(pa_enc_ts_0, krb5_pa_enc_ts, patimestamp, 0, kerberos_time);
DEFFIELD(pa_enc_ts_1, krb5_pa_enc_ts, pausec, 1, int32);
static const struct atype_info *pa_enc_ts_fields[] = {
    &k5_atype_pa_enc_ts_0, &k5_atype_pa_enc_ts_1
};
static unsigned int
optional_pa_enc_ts(const void *p)
{
    const krb5_pa_enc_ts *val = p;
    unsigned int not_present = 0;
    if (val->pausec == 0)
        not_present |= (1u << 1);
    return not_present;
}
DEFSEQTYPE(pa_enc_ts, krb5_pa_enc_ts, pa_enc_ts_fields, optional_pa_enc_ts);

DEFFIELD(setpw_0, struct krb5_setpw_req, password, 0, ostring_data);
DEFFIELD(setpw_1, struct krb5_setpw_req, target, 1, principal);
DEFFIELD(setpw_2, struct krb5_setpw_req, target, 2, realm_of_principal);
static const struct atype_info *setpw_req_fields[] = {
    &k5_atype_setpw_0, &k5_atype_setpw_1, &k5_atype_setpw_2
};
DEFSEQTYPE(setpw_req, struct krb5_setpw_req, setpw_req_fields, NULL);

/* [MS-SFU] Section 2.2.1. */
DEFFIELD(pa_for_user_0, krb5_pa_for_user, user, 0, principal);
DEFFIELD(pa_for_user_1, krb5_pa_for_user, user, 1, realm_of_principal);
DEFFIELD(pa_for_user_2, krb5_pa_for_user, cksum, 2, checksum);
DEFFIELD(pa_for_user_3, krb5_pa_for_user, auth_package, 3, gstring_data);
static const struct atype_info *pa_for_user_fields[] = {
    &k5_atype_pa_for_user_0, &k5_atype_pa_for_user_1, &k5_atype_pa_for_user_2,
    &k5_atype_pa_for_user_3,
};
DEFSEQTYPE(pa_for_user, krb5_pa_for_user, pa_for_user_fields, NULL);

/* [MS-SFU] Section 2.2.2. */
DEFFIELD(s4u_userid_0, krb5_s4u_userid, nonce, 0, int32);
DEFFIELD(s4u_userid_1, krb5_s4u_userid, user, 1, principal);
DEFFIELD(s4u_userid_2, krb5_s4u_userid, user, 2, realm_of_principal);
DEFFIELD(s4u_userid_3, krb5_s4u_userid, subject_cert, 3, ostring_data);
DEFFIELD(s4u_userid_4, krb5_s4u_userid, options, 4, krb5_flags);
static const struct atype_info *s4u_userid_fields[] = {
    &k5_atype_s4u_userid_0, &k5_atype_s4u_userid_1, &k5_atype_s4u_userid_2,
    &k5_atype_s4u_userid_3, &k5_atype_s4u_userid_4
};
static unsigned int
s4u_userid_optional(const void *p)
{
    const krb5_s4u_userid *val = p;
    unsigned int not_present = 0;
    if (val->user == NULL || val->user->length == 0)
        not_present |= (1u << 1);
    if (val->subject_cert.length == 0)
        not_present |= (1u << 3);
    if (val->options == 0)
        not_present |= (1u << 4);
    return not_present;
}
DEFSEQTYPE(s4u_userid, krb5_s4u_userid, s4u_userid_fields,
           s4u_userid_optional);

DEFFIELD(pa_s4u_x509_user_0, krb5_pa_s4u_x509_user, user_id, 0, s4u_userid);
DEFFIELD(pa_s4u_x509_user_1, krb5_pa_s4u_x509_user, cksum, 1, checksum);
static const struct atype_info *pa_s4u_x509_user_fields[] = {
    &k5_atype_pa_s4u_x509_user_0, &k5_atype_pa_s4u_x509_user_1
};
DEFSEQTYPE(pa_s4u_x509_user, krb5_pa_s4u_x509_user, pa_s4u_x509_user_fields,
           NULL);

/* RFC 4537 */
DEFCOUNTEDTYPE(etype_list, krb5_etype_list, etypes, length, cseqof_int32);

/* draft-ietf-krb-wg-preauth-framework-09 */
DEFFIELD(fast_armor_0, krb5_fast_armor, armor_type, 0, int32);
DEFFIELD(fast_armor_1, krb5_fast_armor, armor_value, 1, ostring_data);
static const struct atype_info *fast_armor_fields[] = {
    &k5_atype_fast_armor_0, &k5_atype_fast_armor_1
};
DEFSEQTYPE(fast_armor, krb5_fast_armor, fast_armor_fields, NULL);
DEFPTRTYPE(ptr_fast_armor, fast_armor);

DEFFIELD(fast_armored_req_0, krb5_fast_armored_req, armor, 0, ptr_fast_armor);
DEFFIELD(fast_armored_req_1, krb5_fast_armored_req, req_checksum, 1, checksum);
DEFFIELD(fast_armored_req_2, krb5_fast_armored_req, enc_part, 2,
         encrypted_data);
static const struct atype_info *fast_armored_req_fields[] = {
    &k5_atype_fast_armored_req_0, &k5_atype_fast_armored_req_1,
    &k5_atype_fast_armored_req_2
};
static unsigned int
fast_armored_req_optional(const void *p)
{
    const krb5_fast_armored_req *val = p;
    unsigned int not_present = 0;
    if (val->armor == NULL)
        not_present |= (1u << 0);
    return not_present;
}
DEFSEQTYPE(fast_armored_req, krb5_fast_armored_req, fast_armored_req_fields,
           fast_armored_req_optional);

/* This is a CHOICE type with only one choice (so far) and we're not using a
 * distinguisher/union for it. */
DEFTAGGEDTYPE(pa_fx_fast_request, CONTEXT_SPECIFIC, CONSTRUCTED, 0, 0,
              fast_armored_req);

DEFOFFSETTYPE(fast_req_padata, krb5_kdc_req, padata, ptr_seqof_pa_data);
DEFPTRTYPE(ptr_fast_req_padata, fast_req_padata);
DEFPTRTYPE(ptr_kdc_req_body, kdc_req_body);
DEFFIELD(fast_req_0, krb5_fast_req, fast_options, 0, krb5_flags);
DEFFIELD(fast_req_1, krb5_fast_req, req_body, 1, ptr_fast_req_padata);
DEFFIELD(fast_req_2, krb5_fast_req, req_body, 2, ptr_kdc_req_body);
static const struct atype_info *fast_req_fields[] = {
    &k5_atype_fast_req_0, &k5_atype_fast_req_1, &k5_atype_fast_req_2
};
DEFSEQTYPE(fast_req, krb5_fast_req, fast_req_fields, NULL);

DEFFIELD(fast_finished_0, krb5_fast_finished, timestamp, 0, kerberos_time);
DEFFIELD(fast_finished_1, krb5_fast_finished, usec, 1, int32);
DEFFIELD(fast_finished_2, krb5_fast_finished, client, 2, realm_of_principal);
DEFFIELD(fast_finished_3, krb5_fast_finished, client, 3, principal);
DEFFIELD(fast_finished_4, krb5_fast_finished, ticket_checksum, 4, checksum);
static const struct atype_info *fast_finished_fields[] = {
    &k5_atype_fast_finished_0, &k5_atype_fast_finished_1,
    &k5_atype_fast_finished_2, &k5_atype_fast_finished_3,
    &k5_atype_fast_finished_4
};
DEFSEQTYPE(fast_finished, krb5_fast_finished, fast_finished_fields, NULL);
DEFPTRTYPE(ptr_fast_finished, fast_finished);

DEFFIELD(fast_response_0, krb5_fast_response, padata, 0, ptr_seqof_pa_data);
DEFFIELD(fast_response_1, krb5_fast_response, strengthen_key, 1,
         ptr_encryption_key);
DEFFIELD(fast_response_2, krb5_fast_response, finished, 2, ptr_fast_finished);
DEFFIELD(fast_response_3, krb5_fast_response, nonce, 3, int32);
static const struct atype_info *fast_response_fields[] = {
    &k5_atype_fast_response_0, &k5_atype_fast_response_1,
    &k5_atype_fast_response_2, &k5_atype_fast_response_3
};
static unsigned int
fast_response_optional(const void *p)
{
    unsigned int not_present = 0;
    const krb5_fast_response *val = p;
    if (val->strengthen_key == NULL)
        not_present |= (1u <<1);
    if (val->finished == NULL)
        not_present |= (1u<<2);
    return not_present;
}
DEFSEQTYPE(fast_response, krb5_fast_response, fast_response_fields,
           fast_response_optional);

DEFCTAGGEDTYPE(fast_rep_0, 0, encrypted_data);
static const struct atype_info *fast_rep_fields[] = {
    &k5_atype_fast_rep_0
};
DEFSEQTYPE(fast_rep, krb5_enc_data, fast_rep_fields, NULL);

/* This is a CHOICE type with only one choice (so far) and we're not using a
 * distinguisher/union for it. */
DEFTAGGEDTYPE(pa_fx_fast_reply, CONTEXT_SPECIFIC, CONSTRUCTED, 0, 0,
              fast_rep);

DEFFIELD(ad_kdcissued_0, krb5_ad_kdcissued, ad_checksum, 0, checksum);
DEFFIELD(ad_kdcissued_1, krb5_ad_kdcissued, i_principal, 1,
         realm_of_principal);
DEFFIELD(ad_kdcissued_2, krb5_ad_kdcissued, i_principal, 2, principal);
DEFFIELD(ad_kdcissued_3, krb5_ad_kdcissued, elements, 3, auth_data_ptr);
static const struct atype_info *ad_kdcissued_fields[] = {
    &k5_atype_ad_kdcissued_0, &k5_atype_ad_kdcissued_1,
    &k5_atype_ad_kdcissued_2, &k5_atype_ad_kdcissued_3
};
static unsigned int
ad_kdcissued_optional(const void *p)
{
    unsigned int optional = 0;
    const krb5_ad_kdcissued *val = p;
    if (val->i_principal == NULL)
        optional |= (1u << 1) | (1u << 2);
    return optional;
}
DEFSEQTYPE(ad_kdc_issued, krb5_ad_kdcissued, ad_kdcissued_fields,
           ad_kdcissued_optional);

DEFCTAGGEDTYPE(princ_plus_realm_0, 0, principal_data);
DEFCTAGGEDTYPE(princ_plus_realm_1, 1, realm_of_principal_data);
static const struct atype_info *princ_plus_realm_fields[] = {
    &k5_atype_princ_plus_realm_0, &k5_atype_princ_plus_realm_1
};
DEFSEQTYPE(princ_plus_realm_data, krb5_principal_data, princ_plus_realm_fields,
           NULL);
DEFPTRTYPE(princ_plus_realm, princ_plus_realm_data);
DEFNULLTERMSEQOFTYPE(seqof_princ_plus_realm, princ_plus_realm);
DEFPTRTYPE(ptr_seqof_princ_plus_realm, seqof_princ_plus_realm);

DEFFIELD(spdata_0, krb5_ad_signedpath_data, client, 0, princ_plus_realm);
DEFFIELD(spdata_1, krb5_ad_signedpath_data, authtime, 1, kerberos_time);
DEFFIELD(spdata_2, krb5_ad_signedpath_data, delegated, 2,
         ptr_seqof_princ_plus_realm);
DEFFIELD(spdata_3, krb5_ad_signedpath_data, method_data, 3, ptr_seqof_pa_data);
DEFFIELD(spdata_4, krb5_ad_signedpath_data, authorization_data, 4,
         auth_data_ptr);
static const struct atype_info *ad_signedpath_data_fields[] = {
    &k5_atype_spdata_0, &k5_atype_spdata_1, &k5_atype_spdata_2,
    &k5_atype_spdata_3, &k5_atype_spdata_4
};
static unsigned int
ad_signedpath_data_optional(const void *p)
{
    unsigned int not_present = 0;
    const krb5_ad_signedpath_data *val = p;
    if (val->delegated == NULL || val->delegated[0] == NULL)
        not_present |= (1u << 2);
    if (val->method_data == NULL || val->method_data[0] == NULL)
        not_present |= (1u << 3);
    if (val->authorization_data == NULL || val->authorization_data[0] == NULL)
        not_present |= (1u << 4);
    return not_present;
}
DEFSEQTYPE(ad_signedpath_data, krb5_ad_signedpath_data,
           ad_signedpath_data_fields, ad_signedpath_data_optional);

DEFFIELD(signedpath_0, krb5_ad_signedpath, enctype, 0, int32);
DEFFIELD(signedpath_1, krb5_ad_signedpath, checksum, 1, checksum);
DEFFIELD(signedpath_2, krb5_ad_signedpath, delegated, 2,
         ptr_seqof_princ_plus_realm);
DEFFIELD(signedpath_3, krb5_ad_signedpath, method_data, 3, ptr_seqof_pa_data);
static const struct atype_info *ad_signedpath_fields[] = {
    &k5_atype_signedpath_0, &k5_atype_signedpath_1, &k5_atype_signedpath_2,
    &k5_atype_signedpath_3
};
static unsigned int
ad_signedpath_optional(const void *p)
{
    unsigned int not_present = 0;
    const krb5_ad_signedpath *val = p;
    if (val->delegated == NULL || val->delegated[0] == NULL)
        not_present |= (1u << 2);
    if (val->method_data == NULL || val->method_data[0] == NULL)
        not_present |= (1u << 3);
    return not_present;
}
DEFSEQTYPE(ad_signedpath, krb5_ad_signedpath, ad_signedpath_fields,
           ad_signedpath_optional);

/* First context tag is 1, not 0. */
DEFFIELD(iakerb_header_1, krb5_iakerb_header, target_realm, 1, ostring_data);
DEFFIELD(iakerb_header_2, krb5_iakerb_header, cookie, 2, ostring_data_ptr);
static const struct atype_info *iakerb_header_fields[] = {
    &k5_atype_iakerb_header_1, &k5_atype_iakerb_header_2
};
static unsigned int
iakerb_header_optional(const void *p)
{
    unsigned int not_present = 0;
    const krb5_iakerb_header *val = p;
    if (val->cookie == NULL || val->cookie->data == NULL)
        not_present |= (1u << 1);
    return not_present;
}
DEFSEQTYPE(iakerb_header, krb5_iakerb_header, iakerb_header_fields,
           iakerb_header_optional);

/* First context tag is 1, not 0. */
DEFFIELD(iakerb_finished_0, krb5_iakerb_finished, checksum, 1, checksum);
static const struct atype_info *iakerb_finished_fields[] = {
    &k5_atype_iakerb_finished_0
};
DEFSEQTYPE(iakerb_finished, krb5_iakerb_finished, iakerb_finished_fields,
           NULL);

/* Exported complete encoders -- these produce a krb5_data with
   the encoding in the correct byte order.  */

MAKE_FULL_ENCODER(encode_krb5_authenticator, krb5_authenticator);
MAKE_FULL_ENCODER(encode_krb5_ticket, ticket);
MAKE_FULL_ENCODER(encode_krb5_encryption_key, encryption_key);
MAKE_FULL_ENCODER(encode_krb5_enc_tkt_part, enc_tkt_part);
/* XXX We currently (for backwards compatibility) encode both
   EncASRepPart and EncTGSRepPart with application tag 26.  */
MAKE_FULL_ENCODER(encode_krb5_enc_kdc_rep_part, enc_tgs_rep_part);
MAKE_FULL_ENCODER(encode_krb5_as_rep, as_rep);
MAKE_FULL_ENCODER(encode_krb5_tgs_rep, tgs_rep);
MAKE_FULL_ENCODER(encode_krb5_ap_req, ap_req);
MAKE_FULL_ENCODER(encode_krb5_ap_rep, ap_rep);
MAKE_FULL_ENCODER(encode_krb5_ap_rep_enc_part, ap_rep_enc_part);
MAKE_FULL_ENCODER(encode_krb5_as_req, as_req);
MAKE_FULL_ENCODER(encode_krb5_tgs_req, tgs_req);
MAKE_FULL_ENCODER(encode_krb5_kdc_req_body, kdc_req_body);
MAKE_FULL_ENCODER(encode_krb5_safe, krb5_safe);

/*
 * encode_krb5_safe_with_body
 *
 * Like encode_krb5_safe(), except takes a saved KRB-SAFE-BODY
 * encoding to avoid problems with re-encoding.
 */
MAKE_FULL_ENCODER(encode_krb5_safe_with_body, krb5_safe_with_body);

MAKE_FULL_ENCODER(encode_krb5_priv, krb5_priv);
MAKE_FULL_ENCODER(encode_krb5_enc_priv_part, priv_enc_part);
MAKE_FULL_ENCODER(encode_krb5_checksum, checksum);

MAKE_FULL_ENCODER(encode_krb5_cred, krb5_cred);
MAKE_FULL_ENCODER(encode_krb5_enc_cred_part, enc_cred_part);
MAKE_FULL_ENCODER(encode_krb5_error, krb5_error);
MAKE_FULL_ENCODER(encode_krb5_authdata, auth_data);
MAKE_FULL_ENCODER(encode_krb5_etype_info, etype_info);
MAKE_FULL_ENCODER(encode_krb5_etype_info2, etype_info2);
MAKE_FULL_ENCODER(encode_krb5_enc_data, encrypted_data);
MAKE_FULL_ENCODER(encode_krb5_pa_enc_ts, pa_enc_ts);
MAKE_FULL_ENCODER(encode_krb5_padata_sequence, seqof_pa_data);
/* sam preauth additions */
MAKE_FULL_ENCODER(encode_krb5_sam_challenge_2, sam_challenge_2);
MAKE_FULL_ENCODER(encode_krb5_sam_challenge_2_body,
                  sam_challenge_2_body);
MAKE_FULL_ENCODER(encode_krb5_enc_sam_response_enc_2,
                  enc_sam_response_enc_2);
MAKE_FULL_ENCODER(encode_krb5_sam_response_2, sam_response_2);
MAKE_FULL_ENCODER(encode_krb5_setpw_req, setpw_req);
MAKE_FULL_ENCODER(encode_krb5_pa_for_user, pa_for_user);
MAKE_FULL_ENCODER(encode_krb5_s4u_userid, s4u_userid);
MAKE_FULL_ENCODER(encode_krb5_pa_s4u_x509_user, pa_s4u_x509_user);
MAKE_FULL_ENCODER(encode_krb5_etype_list, etype_list);

MAKE_FULL_ENCODER(encode_krb5_pa_fx_fast_request, pa_fx_fast_request);
MAKE_FULL_ENCODER( encode_krb5_fast_req, fast_req);
MAKE_FULL_ENCODER( encode_krb5_pa_fx_fast_reply, pa_fx_fast_reply);
MAKE_FULL_ENCODER(encode_krb5_fast_response, fast_response);

MAKE_FULL_ENCODER(encode_krb5_ad_kdcissued, ad_kdc_issued);
MAKE_FULL_ENCODER(encode_krb5_ad_signedpath_data, ad_signedpath_data);
MAKE_FULL_ENCODER(encode_krb5_ad_signedpath, ad_signedpath);
MAKE_FULL_ENCODER(encode_krb5_iakerb_header, iakerb_header);
MAKE_FULL_ENCODER(encode_krb5_iakerb_finished, iakerb_finished);

/*
 * PKINIT
 */

#ifndef DISABLE_PKINIT

DEFCOUNTEDSTRINGTYPE(object_identifier, char *, unsigned int,
                     asn1_encode_bytestring, ASN1_OBJECTIDENTIFIER);
DEFCOUNTEDTYPE(oid_data, krb5_data, data, length, object_identifier);
DEFPTRTYPE(oid_data_ptr, oid_data);

/* RFC 3280.  No context tags. */
DEFOFFSETTYPE(algid_0, krb5_algorithm_identifier, algorithm, oid_data);
DEFOFFSETTYPE(algid_1, krb5_algorithm_identifier, parameters, der_data);
static const struct atype_info *algorithm_identifier_fields[] = {
    &k5_atype_algid_0, &k5_atype_algid_1
};
static unsigned int
algorithm_identifier_optional(const void *p)
{
    unsigned int not_present = 0;
    const krb5_algorithm_identifier *val = p;
    if (val->parameters.length == 0)
        not_present |= (1u << 1);
    return not_present;
}
DEFSEQTYPE(algorithm_identifier, krb5_algorithm_identifier,
           algorithm_identifier_fields, algorithm_identifier_optional);
DEFPTRTYPE(algorithm_identifier_ptr, algorithm_identifier);

DEFCTAGGEDTYPE(kdf_alg_id_0, 0, oid_data);
static const struct atype_info *kdf_alg_id_fields[] = {
    &k5_atype_kdf_alg_id_0
};
DEFSEQTYPE(kdf_alg_id, krb5_data, kdf_alg_id_fields, NULL);
DEFPTRTYPE(kdf_alg_id_ptr, kdf_alg_id);
DEFNONEMPTYNULLTERMSEQOFTYPE(supported_kdfs, kdf_alg_id_ptr);
DEFPTRTYPE(supported_kdfs_ptr, supported_kdfs);

/* KRB5PrincipalName from RFC 4556 (*not* PrincipalName from RFC 4120) */
DEFCTAGGEDTYPE(pkinit_princ_0, 0, realm_of_principal_data);
DEFCTAGGEDTYPE(pkinit_princ_1, 1, principal_data);
static const struct atype_info *pkinit_krb5_principal_name_fields[] = {
    &k5_atype_pkinit_princ_0, &k5_atype_pkinit_princ_1
};
DEFSEQTYPE(pkinit_krb5_principal_name_data, krb5_principal_data,
           pkinit_krb5_principal_name_fields, NULL);
DEFPTRTYPE(pkinit_krb5_principal_name, pkinit_krb5_principal_name_data);

/* SP80056A OtherInfo, for pkinit agility.  No context tag on first field. */
DEFTAGGEDTYPE(pkinit_krb5_principal_name_wrapped, UNIVERSAL, PRIMITIVE,
              ASN1_OCTETSTRING, 0, pkinit_krb5_principal_name);
DEFOFFSETTYPE(oinfo_notag, krb5_sp80056a_other_info, algorithm_identifier,
              algorithm_identifier);
DEFFIELD(oinfo_0, krb5_sp80056a_other_info, party_u_info, 0,
         pkinit_krb5_principal_name_wrapped);
DEFFIELD(oinfo_1, krb5_sp80056a_other_info, party_v_info, 1,
         pkinit_krb5_principal_name_wrapped);
DEFFIELD(oinfo_2, krb5_sp80056a_other_info, supp_pub_info, 2, ostring_data);
static const struct atype_info *sp80056a_other_info_fields[] = {
    &k5_atype_oinfo_notag, &k5_atype_oinfo_0, &k5_atype_oinfo_1,
    &k5_atype_oinfo_2
};
DEFSEQTYPE(sp80056a_other_info, krb5_sp80056a_other_info,
           sp80056a_other_info_fields, NULL);

/* For PkinitSuppPubInfo, for pkinit agility */
DEFFIELD(supp_pub_0, krb5_pkinit_supp_pub_info, enctype, 0, int32);
DEFFIELD(supp_pub_1, krb5_pkinit_supp_pub_info, as_req, 1, ostring_data);
DEFFIELD(supp_pub_2, krb5_pkinit_supp_pub_info, pk_as_rep, 2, ostring_data);
static const struct atype_info *pkinit_supp_pub_info_fields[] = {
    &k5_atype_supp_pub_0, &k5_atype_supp_pub_1, &k5_atype_supp_pub_2
};
DEFSEQTYPE(pkinit_supp_pub_info, krb5_pkinit_supp_pub_info,
           pkinit_supp_pub_info_fields, NULL);

MAKE_FULL_ENCODER(encode_krb5_pkinit_supp_pub_info, pkinit_supp_pub_info);
MAKE_FULL_ENCODER(encode_krb5_sp80056a_other_info, sp80056a_other_info);

/* A krb5_checksum encoded as an OCTET STRING, for PKAuthenticator. */
DEFCOUNTEDTYPE(ostring_checksum, krb5_checksum, contents, length, octetstring);

DEFFIELD(pk_authenticator_0, krb5_pk_authenticator, cusec, 0, int32);
DEFFIELD(pk_authenticator_1, krb5_pk_authenticator, ctime, 1, kerberos_time);
DEFFIELD(pk_authenticator_2, krb5_pk_authenticator, nonce, 2, int32);
DEFFIELD(pk_authenticator_3, krb5_pk_authenticator, paChecksum, 3,
         ostring_checksum);
static const struct atype_info *pk_authenticator_fields[] = {
    &k5_atype_pk_authenticator_0, &k5_atype_pk_authenticator_1,
    &k5_atype_pk_authenticator_2, &k5_atype_pk_authenticator_3
};
DEFSEQTYPE(pk_authenticator, krb5_pk_authenticator, pk_authenticator_fields,
           NULL);

DEFFIELD(pkauth9_0, krb5_pk_authenticator_draft9, kdcName, 0, principal);
DEFFIELD(pkauth9_1, krb5_pk_authenticator_draft9, kdcName, 1,
         realm_of_principal);
DEFFIELD(pkauth9_2, krb5_pk_authenticator_draft9, cusec, 2, int32);
DEFFIELD(pkauth9_3, krb5_pk_authenticator_draft9, ctime, 3, kerberos_time);
DEFFIELD(pkauth9_4, krb5_pk_authenticator_draft9, nonce, 4, int32);
static const struct atype_info *pk_authenticator_draft9_fields[] = {
    &k5_atype_pkauth9_0, &k5_atype_pkauth9_1, &k5_atype_pkauth9_2,
    &k5_atype_pkauth9_3, &k5_atype_pkauth9_4
};
DEFSEQTYPE(pk_authenticator_draft9, krb5_pk_authenticator_draft9,
           pk_authenticator_draft9_fields, NULL);

DEFCOUNTEDSTRINGTYPE(s_bitstring, char *, unsigned int, asn1_encode_bitstring,
                     ASN1_BITSTRING);
DEFCOUNTEDTYPE(bitstring_data, krb5_data, data, length, s_bitstring);

/* RFC 3280.  No context tags. */
DEFOFFSETTYPE(spki_0, krb5_subject_pk_info, algorithm, algorithm_identifier);
DEFOFFSETTYPE(spki_1, krb5_subject_pk_info, subjectPublicKey, bitstring_data);
static const struct atype_info *subject_pk_info_fields[] = {
    &k5_atype_spki_0, &k5_atype_spki_1
};
DEFSEQTYPE(subject_pk_info, krb5_subject_pk_info, subject_pk_info_fields,
           NULL);
DEFPTRTYPE(subject_pk_info_ptr, subject_pk_info);

DEFNULLTERMSEQOFTYPE(seqof_algorithm_identifier, algorithm_identifier_ptr);
DEFPTRTYPE(ptr_seqof_algorithm_identifier, seqof_algorithm_identifier);
DEFFIELD(auth_pack_0, krb5_auth_pack, pkAuthenticator, 0, pk_authenticator);
DEFFIELD(auth_pack_1, krb5_auth_pack, clientPublicValue, 1,
         subject_pk_info_ptr);
DEFFIELD(auth_pack_2, krb5_auth_pack, supportedCMSTypes, 2,
         ptr_seqof_algorithm_identifier);
DEFFIELD(auth_pack_3, krb5_auth_pack, clientDHNonce, 3, ostring_data);
DEFFIELD(auth_pack_4, krb5_auth_pack, supportedKDFs, 4, supported_kdfs_ptr);
static const struct atype_info *auth_pack_fields[] = {
    &k5_atype_auth_pack_0, &k5_atype_auth_pack_1, &k5_atype_auth_pack_2,
    &k5_atype_auth_pack_3, &k5_atype_auth_pack_4
};
static unsigned int
auth_pack_optional(const void *p)
{
    unsigned int not_present = 0;
    const krb5_auth_pack *val = p;
    if (val->clientPublicValue == NULL)
        not_present |= (1u << 1);
    if (val->supportedCMSTypes == NULL)
        not_present |= (1u << 2);
    if (val->clientDHNonce.length == 0)
        not_present |= (1u << 3);
    if (val->supportedKDFs == NULL)
        not_present |= (1u << 4);
    return not_present;
}
DEFSEQTYPE(auth_pack, krb5_auth_pack, auth_pack_fields, auth_pack_optional);

DEFFIELD(auth_pack9_0, krb5_auth_pack_draft9, pkAuthenticator, 0,
         pk_authenticator_draft9);
DEFFIELD(auth_pack9_1, krb5_auth_pack_draft9, clientPublicValue, 1,
         subject_pk_info_ptr);
static const struct atype_info *auth_pack_draft9_fields[] = {
    &k5_atype_auth_pack9_0, &k5_atype_auth_pack9_1
};
static unsigned int
auth_pack_draft9_optional(const void *p)
{
    unsigned int not_present = 0;
    const krb5_auth_pack_draft9 *val = p;
    if (val->clientPublicValue == NULL)
        not_present |= (1u << 1);
    return not_present;
}
DEFSEQTYPE(auth_pack_draft9, krb5_auth_pack_draft9, auth_pack_draft9_fields,
           auth_pack_draft9_optional);

DEFFIELD_IMPLICIT(extprinc_0, krb5_external_principal_identifier,
                  subjectName, 0, ostring_data);
DEFFIELD_IMPLICIT(extprinc_1, krb5_external_principal_identifier,
                  issuerAndSerialNumber, 1, ostring_data);
DEFFIELD_IMPLICIT(extprinc_2, krb5_external_principal_identifier,
                  subjectKeyIdentifier, 2, ostring_data);
static const struct atype_info *external_principal_identifier_fields[] = {
    &k5_atype_extprinc_0, &k5_atype_extprinc_1, &k5_atype_extprinc_2
};
static unsigned int
external_principal_identifier_optional(const void *p)
{
    unsigned int not_present = 0;
    const krb5_external_principal_identifier *val = p;
    if (val->subjectName.length == 0)
        not_present |= (1u << 0);
    if (val->issuerAndSerialNumber.length == 0)
        not_present |= (1u << 1);
    if (val->subjectKeyIdentifier.length == 0)
        not_present |= (1u << 2);
    return not_present;
}
DEFSEQTYPE(external_principal_identifier, krb5_external_principal_identifier,
           external_principal_identifier_fields,
           external_principal_identifier_optional);
DEFPTRTYPE(external_principal_identifier_ptr, external_principal_identifier);

DEFNULLTERMSEQOFTYPE(seqof_external_principal_identifier,
                     external_principal_identifier_ptr);
DEFPTRTYPE(ptr_seqof_external_principal_identifier,
           seqof_external_principal_identifier);

DEFFIELD_IMPLICIT(pa_pk_as_req_0, krb5_pa_pk_as_req, signedAuthPack, 0,
                  ostring_data);
DEFFIELD(pa_pk_as_req_1, krb5_pa_pk_as_req, trustedCertifiers, 1,
         ptr_seqof_external_principal_identifier);
DEFFIELD_IMPLICIT(pa_pk_as_req_2, krb5_pa_pk_as_req, kdcPkId, 2, ostring_data);
static const struct atype_info *pa_pk_as_req_fields[] = {
    &k5_atype_pa_pk_as_req_0, &k5_atype_pa_pk_as_req_1,
    &k5_atype_pa_pk_as_req_2
};
static unsigned int
pa_pk_as_req_optional(const void *p)
{
    unsigned int not_present = 0;
    const krb5_pa_pk_as_req *val = p;
    if (val->trustedCertifiers == NULL)
        not_present |= (1u << 1);
    if (val->kdcPkId.length == 0)
        not_present |= (1u << 2);
    return not_present;
}
DEFSEQTYPE(pa_pk_as_req, krb5_pa_pk_as_req, pa_pk_as_req_fields,
           pa_pk_as_req_optional);

/*
 * draft-ietf-cat-kerberos-pk-init-09 specifies these fields as explicitly
 * tagged KerberosName, Name, and IssuerAndSerialNumber respectively, which
 * means they should have constructed context tags.  However, our historical
 * behavior is to use primitive context-specific tags, and we don't want to
 * change that behavior without interop testing.  For the principal name, which
 * we encode ourselves, use a DEFTAGGEDTYPE to wrap the principal encoding in a
 * primitive [0] tag.  For the other two types, we have the encoding in a
 * krb5_data object; pretend that they are wrapped in IMPLICIT OCTET STRING in
 * order to wrap them in primitive [1] and [2] tags.
 */
DEFOFFSETTYPE(trusted_ca_0_untagged, union krb5_trusted_ca_choices,
              principalName, principal);
DEFTAGGEDTYPE(trusted_ca_0, CONTEXT_SPECIFIC, PRIMITIVE, 0, 0,
              trusted_ca_0_untagged);
DEFFIELD_IMPLICIT(trusted_ca_1, union krb5_trusted_ca_choices, caName, 1,
                  ostring_data);
DEFFIELD_IMPLICIT(trusted_ca_2, union krb5_trusted_ca_choices,
                  issuerAndSerial, 2, ostring_data);
static const struct atype_info *trusted_ca_alternatives[] = {
    &k5_atype_trusted_ca_0, &k5_atype_trusted_ca_1, &k5_atype_trusted_ca_2
};
DEFCHOICETYPE(trusted_ca_choice, union krb5_trusted_ca_choices,
              enum krb5_trusted_ca_selection, trusted_ca_alternatives);
DEFCOUNTEDTYPE_SIGNED(trusted_ca, krb5_trusted_ca, u, choice,
                      trusted_ca_choice);
DEFPTRTYPE(trusted_ca_ptr, trusted_ca);

DEFNULLTERMSEQOFTYPE(seqof_trusted_ca, trusted_ca_ptr);
DEFPTRTYPE(ptr_seqof_trusted_ca, seqof_trusted_ca);

/*
 * draft-ietf-cat-kerberos-pk-init-09 specifies signedAuthPack, kdcCert, and
 * EncryptionCert as explictly tagged SignedData, IssuerAndSerialNumber, and
 * IssuerAndSerialNumber, which means they should have constructed context
 * tags.  However, our historical behavior is to use a primitive context tag,
 * and we don't want to change that without interop testing.  We have the DER
 * encodings of these fields in krb5_data objects; pretend that they are
 * wrapped in IMPLICIT OCTET STRING in order to generate primitive context
 * tags.
 */
DEFFIELD_IMPLICIT(pa_pk_as_req9_0, krb5_pa_pk_as_req_draft9, signedAuthPack, 0,
                  ostring_data);
DEFFIELD(pa_pk_as_req9_1, krb5_pa_pk_as_req_draft9, trustedCertifiers, 1,
         ptr_seqof_trusted_ca);
DEFFIELD_IMPLICIT(pa_pk_as_req9_2, krb5_pa_pk_as_req_draft9, kdcCert, 2,
                  ostring_data);
DEFFIELD_IMPLICIT(pa_pk_as_req9_3, krb5_pa_pk_as_req_draft9, encryptionCert, 3,
                  ostring_data);
static const struct atype_info *pa_pk_as_req_draft9_fields[] = {
    &k5_atype_pa_pk_as_req9_0, &k5_atype_pa_pk_as_req9_1,
    &k5_atype_pa_pk_as_req9_2, &k5_atype_pa_pk_as_req9_3
};
static unsigned int
pa_pk_as_req_draft9_optional(const void *p)
{
    unsigned int not_present = 0;
    const krb5_pa_pk_as_req_draft9 *val = p;
    if (val->trustedCertifiers == NULL)
        not_present |= (1u << 1);
    if (val->kdcCert.length == 0)
        not_present |= (1u << 2);
    if (val->encryptionCert.length == 0)
        not_present |= (1u << 3);
    return not_present;
}
DEFSEQTYPE(pa_pk_as_req_draft9, krb5_pa_pk_as_req_draft9,
           pa_pk_as_req_draft9_fields, pa_pk_as_req_draft9_optional);

DEFFIELD_IMPLICIT(dh_rep_info_0, krb5_dh_rep_info, dhSignedData, 0,
                  ostring_data);
DEFFIELD(dh_rep_info_1, krb5_dh_rep_info, serverDHNonce, 1, ostring_data);
DEFFIELD(dh_rep_info_2, krb5_dh_rep_info, kdfID, 2, kdf_alg_id_ptr);
static const struct atype_info *dh_rep_info_fields[] = {
    &k5_atype_dh_rep_info_0, &k5_atype_dh_rep_info_1, &k5_atype_dh_rep_info_2
};
static unsigned int
dh_rep_info_optional(const void *p)
{
    unsigned int not_present = 0;
    const krb5_dh_rep_info *val = p;
    if (val->serverDHNonce.length == 0)
        not_present |= (1u << 1);
    if (val->kdfID == NULL)
        not_present |= (1u << 2);
    return not_present;
}
DEFSEQTYPE(dh_rep_info, krb5_dh_rep_info, dh_rep_info_fields,
           dh_rep_info_optional);

DEFFIELD(dh_key_0, krb5_kdc_dh_key_info, subjectPublicKey, 0, bitstring_data);
DEFFIELD(dh_key_1, krb5_kdc_dh_key_info, nonce, 1, int32);
DEFFIELD(dh_key_2, krb5_kdc_dh_key_info, dhKeyExpiration, 2, kerberos_time);
static const struct atype_info *kdc_dh_key_info_fields[] = {
    &k5_atype_dh_key_0, &k5_atype_dh_key_1, &k5_atype_dh_key_2
};
static unsigned int
kdc_dh_key_info_optional(const void *p)
{
    unsigned int not_present = 0;
    const krb5_kdc_dh_key_info *val = p;
    if (val->dhKeyExpiration == 0)
        not_present |= (1u << 2);
    return not_present;
}
DEFSEQTYPE(kdc_dh_key_info, krb5_kdc_dh_key_info, kdc_dh_key_info_fields,
           kdc_dh_key_info_optional);

DEFFIELD(reply_key_pack_0, krb5_reply_key_pack, replyKey, 0, encryption_key);
DEFFIELD(reply_key_pack_1, krb5_reply_key_pack, asChecksum, 1, checksum);
static const struct atype_info *reply_key_pack_fields[] = {
    &k5_atype_reply_key_pack_0, &k5_atype_reply_key_pack_1
};
DEFSEQTYPE(reply_key_pack, krb5_reply_key_pack, reply_key_pack_fields, NULL);

DEFFIELD(key_pack9_0, krb5_reply_key_pack_draft9, replyKey, 0, encryption_key);
DEFFIELD(key_pack9_1, krb5_reply_key_pack_draft9, nonce, 1, int32);
static const struct atype_info *reply_key_pack_draft9_fields[] = {
    &k5_atype_key_pack9_0, &k5_atype_key_pack9_1
};
DEFSEQTYPE(reply_key_pack_draft9, krb5_reply_key_pack_draft9,
           reply_key_pack_draft9_fields, NULL);

DEFFIELD(pa_pk_as_rep_0, union krb5_pa_pk_as_rep_choices, dh_Info, 0,
         dh_rep_info);
DEFFIELD_IMPLICIT(pa_pk_as_rep_1, union krb5_pa_pk_as_rep_choices, encKeyPack,
                  1, ostring_data);
static const struct atype_info *pa_pk_as_rep_alternatives[] = {
    &k5_atype_pa_pk_as_rep_0, &k5_atype_pa_pk_as_rep_1
};
DEFCHOICETYPE(pa_pk_as_rep_choice, union krb5_pa_pk_as_rep_choices,
              enum krb5_pa_pk_as_rep_selection, pa_pk_as_rep_alternatives);
DEFCOUNTEDTYPE_SIGNED(pa_pk_as_rep, krb5_pa_pk_as_rep, u, choice,
                      pa_pk_as_rep_choice);

/*
 * draft-ietf-cat-kerberos-pk-init-09 specifies these alternatives as
 * explicitly tagged SignedData and EnvelopedData respectively, which means
 * they should have constructed context tags.  However, our historical behavior
 * is to use primitive context tags, and we don't want to change that behavior
 * without interop testing.  We have the encodings for each alternative in a
 * krb5_data object; pretend that they are wrapped in IMPLICIT OCTET STRING in
 * order to wrap them in primitive [0] and [1] tags.
 */
DEFFIELD_IMPLICIT(pa_pk_as_rep9_0, union krb5_pa_pk_as_rep_draft9_choices,
                  dhSignedData, 0, ostring_data);
DEFFIELD_IMPLICIT(pa_pk_as_rep9_1, union krb5_pa_pk_as_rep_draft9_choices,
                  encKeyPack, 1, ostring_data);
static const struct atype_info *pa_pk_as_rep_draft9_alternatives[] = {
    &k5_atype_pa_pk_as_rep9_0, &k5_atype_pa_pk_as_rep9_1
};
DEFCHOICETYPE(pa_pk_as_rep_draft9_choice,
              union krb5_pa_pk_as_rep_draft9_choices,
              enum krb5_pa_pk_as_rep_draft9_selection,
              pa_pk_as_rep_draft9_alternatives);
DEFCOUNTEDTYPE_SIGNED(pa_pk_as_rep_draft9, krb5_pa_pk_as_rep_draft9, u, choice,
                      pa_pk_as_rep_draft9_choice);

MAKE_FULL_ENCODER(encode_krb5_pa_pk_as_req, pa_pk_as_req);
MAKE_FULL_ENCODER(encode_krb5_pa_pk_as_req_draft9, pa_pk_as_req_draft9);
MAKE_FULL_ENCODER(encode_krb5_pa_pk_as_rep, pa_pk_as_rep);
MAKE_FULL_ENCODER(encode_krb5_pa_pk_as_rep_draft9, pa_pk_as_rep_draft9);
MAKE_FULL_ENCODER(encode_krb5_auth_pack, auth_pack);
MAKE_FULL_ENCODER(encode_krb5_auth_pack_draft9, auth_pack_draft9);
MAKE_FULL_ENCODER(encode_krb5_kdc_dh_key_info, kdc_dh_key_info);
MAKE_FULL_ENCODER(encode_krb5_reply_key_pack, reply_key_pack);
MAKE_FULL_ENCODER(encode_krb5_reply_key_pack_draft9, reply_key_pack_draft9);
MAKE_FULL_ENCODER(encode_krb5_td_trusted_certifiers,
                  seqof_external_principal_identifier);
MAKE_FULL_ENCODER(encode_krb5_td_dh_parameters, seqof_algorithm_identifier);

#else /* DISABLE_PKINIT */

/* Stubs for exported pkinit encoder functions. */

krb5_error_code
encode_krb5_sp80056a_other_info(const krb5_sp80056a_other_info *rep,
                                krb5_data **code)
{
    return EINVAL;
}

krb5_error_code
encode_krb5_pkinit_supp_pub_info(const krb5_pkinit_supp_pub_info *rep,
                                 krb5_data **code)
{
    return EINVAL;
}

#endif /* not DISABLE_PKINIT */

DEFFIELD(typed_data_0, krb5_pa_data, pa_type, 0, int32);
DEFCNFIELD(typed_data_1, krb5_pa_data, contents, length, 1, octetstring);
static const struct atype_info *typed_data_fields[] = {
    &k5_atype_typed_data_0, &k5_atype_typed_data_1
};
DEFSEQTYPE(typed_data, krb5_pa_data, typed_data_fields, NULL);
DEFPTRTYPE(typed_data_ptr, typed_data);

DEFNULLTERMSEQOFTYPE(seqof_typed_data, typed_data_ptr);
MAKE_FULL_ENCODER(encode_krb5_typed_data, seqof_typed_data);

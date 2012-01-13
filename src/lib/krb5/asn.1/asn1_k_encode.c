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

DEFINTTYPE(int32, krb5_int32);
DEFPTRTYPE(int32_ptr, int32);

DEFUINTTYPE(uint, unsigned int);
DEFUINTTYPE(octet, krb5_octet);
DEFUINTTYPE(ui_4, krb5_ui_4);

DEFSTRINGTYPE(octetstring, unsigned char *, asn1_encode_bytestring,
              ASN1_OCTETSTRING);
DEFSTRINGTYPE(s_octetstring, char *, asn1_encode_bytestring, ASN1_OCTETSTRING);
DEFSTRINGTYPE(generalstring, char *, asn1_encode_bytestring,
              ASN1_GENERALSTRING);
DEFSTRINGTYPE(u_generalstring, unsigned char *, asn1_encode_bytestring,
              ASN1_GENERALSTRING);
DEFDERTYPE(der, char *);

DEFFIELDTYPE(gstring_data, krb5_data,
             FIELDOF_STRING(krb5_data, generalstring, data, length, -1, 0));
DEFPTRTYPE(gstring_data_ptr,gstring_data);

DEFFIELDTYPE(ostring_data, krb5_data,
             FIELDOF_STRING(krb5_data, s_octetstring, data, length, -1, 0));
DEFPTRTYPE(ostring_data_ptr,ostring_data);

DEFFIELDTYPE(der_data, krb5_data,
             FIELDOF_DER(krb5_data, der, data, length, uint, -1, 0));

DEFFIELDTYPE(realm_of_principal_data, krb5_principal_data,
             FIELDOF_NORM(krb5_principal_data, gstring_data, realm, -1, 0));
DEFPTRTYPE(realm_of_principal, realm_of_principal_data);

static const struct field_info princname_fields[] = {
    FIELDOF_NORM(krb5_principal_data, int32, type, 0, 0),
    FIELDOF_SEQOF_INT32(krb5_principal_data, gstring_data_ptr, data, length,
                        1, 0),
};
/*
 * krb5_principal is a typedef for krb5_principal_data*, so this is
 * effectively "encode_principal_data_at" with an address arg.
 */
DEFSEQTYPE(principal_data, krb5_principal_data, princname_fields, 0);
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

const static struct field_info address_fields[] = {
    FIELDOF_NORM(krb5_address, int32, addrtype, 0, 0),
    FIELDOF_STRING(krb5_address, octetstring, contents, length, 1, 0),
};
DEFSEQTYPE(address, krb5_address, address_fields, 0);
DEFPTRTYPE(address_ptr, address);

DEFNULLTERMSEQOFTYPE(seq_of_host_addresses, address_ptr);
DEFPTRTYPE(ptr_seqof_host_addresses, seq_of_host_addresses);

static unsigned int
optional_encrypted_data (const void *vptr)
{
    const krb5_enc_data *val = vptr;
    unsigned int optional = 0;

    if (val->kvno != 0)
        optional |= (1u << 1);

    return optional;
}

static const struct field_info encrypted_data_fields[] = {
    FIELDOF_NORM(krb5_enc_data, int32, enctype, 0, 0),
    FIELDOF_OPT(krb5_enc_data, uint, kvno, 1, 0, 1),
    FIELDOF_NORM(krb5_enc_data, ostring_data, ciphertext, 2, 0),
};
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
    unsigned char cbuf[4];
    store_32_be((krb5_ui_4) *val, cbuf);
    return asn1_encode_bitstring(buf, 4, cbuf, retlen);
}
DEFPRIMITIVETYPE(krb5_flags, krb5_flags, asn1_encode_krb5_flags_at,
                 ASN1_BITSTRING);

const static struct field_info authdata_elt_fields[] = {
    /* ad-type[0]               INTEGER */
    FIELDOF_NORM(krb5_authdata, int32, ad_type, 0, 0),
    /* ad-data[1]               OCTET STRING */
    FIELDOF_STRING(krb5_authdata, octetstring, contents, length, 1, 0),
};
DEFSEQTYPE(authdata_elt, krb5_authdata, authdata_elt_fields, 0);
DEFPTRTYPE(authdata_elt_ptr, authdata_elt);
DEFNONEMPTYNULLTERMSEQOFTYPE(auth_data, authdata_elt_ptr);
DEFPTRTYPE(auth_data_ptr, auth_data);

static const struct field_info encryption_key_fields[] = {
    FIELDOF_NORM(krb5_keyblock, int32, enctype, 0, 0),
    FIELDOF_STRING(krb5_keyblock, octetstring, contents, length, 1, 0),
};
DEFSEQTYPE(encryption_key, krb5_keyblock, encryption_key_fields, 0);
DEFPTRTYPE(ptr_encryption_key, encryption_key);

static const struct field_info checksum_fields[] = {
    FIELDOF_NORM(krb5_checksum, int32, checksum_type, 0, 0),
    FIELDOF_STRING(krb5_checksum, octetstring, contents, length, 1, 0),
};
DEFSEQTYPE(checksum, krb5_checksum, checksum_fields, 0);
DEFPTRTYPE(checksum_ptr, checksum);
DEFNULLTERMSEQOFTYPE(seq_of_checksum, checksum_ptr);
DEFPTRTYPE(ptr_seqof_checksum, seq_of_checksum);

static const struct field_info lr_fields[] = {
    FIELDOF_NORM(krb5_last_req_entry, int32, lr_type, 0, 0),
    FIELDOF_NORM(krb5_last_req_entry, kerberos_time, value, 1, 0),
};
DEFSEQTYPE(last_req_ent, krb5_last_req_entry, lr_fields, 0);

DEFPTRTYPE(last_req_ent_ptr, last_req_ent);
DEFNONEMPTYNULLTERMSEQOFTYPE(last_req, last_req_ent_ptr);
DEFPTRTYPE(last_req_ptr, last_req);

static const struct field_info ticket_fields[] = {
    FIELD_INT_IMM(KVNO, 0, 0),
    FIELDOF_NORM(krb5_ticket, realm_of_principal, server, 1, 0),
    FIELDOF_NORM(krb5_ticket, principal, server, 2, 0),
    FIELDOF_NORM(krb5_ticket, encrypted_data, enc_part, 3, 0),
};
DEFSEQTYPE(untagged_ticket, krb5_ticket, ticket_fields, 0);
DEFAPPTAGGEDTYPE(ticket, 1, untagged_ticket);

static const struct field_info pa_data_fields[] = {
    FIELDOF_NORM(krb5_pa_data, int32, pa_type, 1, 0),
    FIELDOF_STRING(krb5_pa_data, octetstring, contents, length, 2, 0),
};
DEFSEQTYPE(pa_data, krb5_pa_data, pa_data_fields, 0);
DEFPTRTYPE(pa_data_ptr, pa_data);

DEFNULLTERMSEQOFTYPE(seq_of_pa_data, pa_data_ptr);
DEFPTRTYPE(ptr_seqof_pa_data, seq_of_pa_data);

DEFPTRTYPE(ticket_ptr, ticket);
DEFNONEMPTYNULLTERMSEQOFTYPE(seq_of_ticket,ticket_ptr);
DEFPTRTYPE(ptr_seqof_ticket, seq_of_ticket);

/* EncKDCRepPart ::= SEQUENCE */
static const struct field_info enc_kdc_rep_part_fields[] = {
    /* key[0]           EncryptionKey */
    FIELDOF_NORM(krb5_enc_kdc_rep_part, ptr_encryption_key, session, 0, 0),
    /* last-req[1]      LastReq */
    FIELDOF_NORM(krb5_enc_kdc_rep_part, last_req_ptr, last_req, 1, 0),
    /* nonce[2]         INTEGER */
    FIELDOF_NORM(krb5_enc_kdc_rep_part, int32, nonce, 2, 0),
    /* key-expiration[3]        KerberosTime OPTIONAL */
    FIELDOF_OPT(krb5_enc_kdc_rep_part, kerberos_time, key_exp, 3, 0, 3),
    /* flags[4]         TicketFlags */
    FIELDOF_NORM(krb5_enc_kdc_rep_part, krb5_flags, flags, 4, 0),
    /* authtime[5]      KerberosTime */
    FIELDOF_NORM(krb5_enc_kdc_rep_part, kerberos_time, times.authtime, 5, 0),
    /* starttime[6]     KerberosTime OPTIONAL */
    FIELDOF_OPT(krb5_enc_kdc_rep_part, kerberos_time, times.starttime,
                6, 0, 6),
    /* endtime[7]               KerberosTime */
    FIELDOF_NORM(krb5_enc_kdc_rep_part, kerberos_time, times.endtime, 7, 0),
    /* renew-till[8]    KerberosTime OPTIONAL */
    FIELDOF_OPT(krb5_enc_kdc_rep_part, kerberos_time, times.renew_till,
                8, 0, 8),
    /* srealm[9]                Realm */
    FIELDOF_NORM(krb5_enc_kdc_rep_part, realm_of_principal, server, 9, 0),
    /* sname[10]                PrincipalName */
    FIELDOF_NORM(krb5_enc_kdc_rep_part, principal, server, 10, 0),
    /* caddr[11]                HostAddresses OPTIONAL */
    FIELDOF_OPT(krb5_enc_kdc_rep_part, ptr_seqof_host_addresses, caddrs,
                11, 0, 11),
    /* encrypted-pa-data[12]    SEQUENCE OF PA-DATA OPTIONAL */
    FIELDOF_OPT(krb5_enc_kdc_rep_part, ptr_seqof_pa_data, enc_padata,
                12, 0, 12),
};
static unsigned int
optional_enc_kdc_rep_part(const void *p)
{
    const krb5_enc_kdc_rep_part *val = p;
    unsigned int optional = 0;

    if (val->key_exp)
        optional |= (1u << 3);
    if (val->times.starttime)
        optional |= (1u << 6);
    if (val->flags & TKT_FLG_RENEWABLE)
        optional |= (1u << 8);
    if (val->caddrs != NULL && val->caddrs[0] != NULL)
        optional |= (1u << 11);
    if (val->enc_padata != NULL)
        optional |= (1u << 12);

    return optional;
}
DEFSEQTYPE(enc_kdc_rep_part, krb5_enc_kdc_rep_part, enc_kdc_rep_part_fields,
           optional_enc_kdc_rep_part);

/*
 * Yuck!  Eventually push this *up* above the encoder API and make the
 * rest of the library put the realm name in one consistent place.  At
 * the same time, might as well add the msg-type field and encode both
 * AS-REQ and TGS-REQ through the same descriptor.
 */
struct kdc_req_hack {
    krb5_kdc_req v;
    krb5_data *server_realm;
};
static const struct field_info kdc_req_hack_fields[] = {
    FIELDOF_NORM(struct kdc_req_hack, krb5_flags, v.kdc_options, 0, 0),
    FIELDOF_OPT(struct kdc_req_hack, principal, v.client, 1, 0, 1),
    FIELDOF_NORM(struct kdc_req_hack, gstring_data_ptr, server_realm, 2, 0),
    FIELDOF_OPT(struct kdc_req_hack, principal, v.server, 3, 0, 3),
    FIELDOF_OPT(struct kdc_req_hack, kerberos_time, v.from, 4, 0, 4),
    FIELDOF_NORM(struct kdc_req_hack, kerberos_time, v.till, 5, 0),
    FIELDOF_OPT(struct kdc_req_hack, kerberos_time, v.rtime, 6, 0, 6),
    FIELDOF_NORM(struct kdc_req_hack, int32, v.nonce, 7, 0),
    FIELDOF_SEQOF_INT32(struct kdc_req_hack, int32_ptr, v.ktype, v.nktypes,
                        8, 0),
    FIELDOF_OPT(struct kdc_req_hack, ptr_seqof_host_addresses, v.addresses,
                9, 0, 9),
    FIELDOF_OPT(struct kdc_req_hack, encrypted_data, v.authorization_data,
                10, 0, 10),
    FIELDOF_OPT(struct kdc_req_hack, ptr_seqof_ticket, v.second_ticket,
                11, 0, 11),
};
static unsigned int
optional_kdc_req_hack(const void *p)
{
    const struct kdc_req_hack *val2 = p;
    const krb5_kdc_req *val = &val2->v;
    unsigned int optional = 0;

    if (val->second_ticket != NULL && val->second_ticket[0] != NULL)
        optional |= (1u << 11);
    if (val->authorization_data.ciphertext.data != NULL)
        optional |= (1u << 10);
    if (val->addresses != NULL && val->addresses[0] != NULL)
        optional |= (1u << 9);
    if (val->rtime)
        optional |= (1u << 6);
    if (val->from)
        optional |= (1u << 4);
    if (val->server != NULL)
        optional |= (1u << 3);
    if (val->client != NULL)
        optional |= (1u << 1);

    return optional;
}
DEFSEQTYPE(kdc_req_body_hack, struct kdc_req_hack, kdc_req_hack_fields,
           optional_kdc_req_hack);
static asn1_error_code
asn1_encode_kdc_req_body(asn1buf *buf, const void *ptr, taginfo *rettag)
{
    const krb5_kdc_req *val = ptr;
    struct kdc_req_hack val2;
    val2.v = *val;
    if (val->kdc_options & KDC_OPT_ENC_TKT_IN_SKEY) {
        if (val->second_ticket != NULL && val->second_ticket[0] != NULL) {
            val2.server_realm = &val->second_ticket[0]->server->realm;
        } else return ASN1_MISSING_FIELD;
    } else if (val->server != NULL) {
        val2.server_realm = &val->server->realm;
    } else return ASN1_MISSING_FIELD;
    return krb5int_asn1_encode_type(buf, &val2,
                                    &krb5int_asn1type_kdc_req_body_hack,
                                    rettag);
}
DEFFNTYPE(kdc_req_body, krb5_kdc_req, asn1_encode_kdc_req_body);
/* end ugly hack */

DEFPTRTYPE(ptr_kdc_req_body,kdc_req_body);

static const struct field_info transited_fields[] = {
    FIELDOF_NORM(krb5_transited, octet, tr_type, 0, 0),
    FIELDOF_NORM(krb5_transited, ostring_data, tr_contents, 1, 0),
};
DEFSEQTYPE(transited, krb5_transited, transited_fields, 0);

static const struct field_info krb_safe_body_fields[] = {
    FIELDOF_NORM(krb5_safe, ostring_data, user_data, 0, 0),
    FIELDOF_OPT(krb5_safe, kerberos_time, timestamp, 1, 0, 1),
    FIELDOF_OPT(krb5_safe, int32, usec, 2, 0, 2),
    FIELDOF_OPT(krb5_safe, uint, seq_number, 3, 0, 3),
    FIELDOF_NORM(krb5_safe, address_ptr, s_address, 4, 0),
    FIELDOF_OPT(krb5_safe, address_ptr, r_address, 5, 0, 5),
};
static unsigned int
optional_krb_safe_body(const void *p)
{
    const krb5_safe *val = p;
    unsigned int optional = 0;

    if (val->timestamp) {
        optional |= (1u << 1);
        optional |= (1u << 2);
    }
    if (val->seq_number)
        optional |= (1u << 3);
    if (val->r_address != NULL)
        optional |= (1u << 5);

    return optional;
}
DEFSEQTYPE(krb_safe_body, krb5_safe, krb_safe_body_fields,
           optional_krb_safe_body);

static const struct field_info krb_cred_info_fields[] = {
    FIELDOF_NORM(krb5_cred_info, ptr_encryption_key, session, 0, 0),
    FIELDOF_OPT(krb5_cred_info, realm_of_principal, client, 1, 0, 1),
    FIELDOF_OPT(krb5_cred_info, principal, client, 2, 0, 2),
    FIELDOF_OPT(krb5_cred_info, krb5_flags, flags, 3, 0, 3),
    FIELDOF_OPT(krb5_cred_info, kerberos_time, times.authtime, 4, 0, 4),
    FIELDOF_OPT(krb5_cred_info, kerberos_time, times.starttime, 5, 0, 5),
    FIELDOF_OPT(krb5_cred_info, kerberos_time, times.endtime, 6, 0, 6),
    FIELDOF_OPT(krb5_cred_info, kerberos_time, times.renew_till, 7, 0, 7),
    FIELDOF_OPT(krb5_cred_info, realm_of_principal, server, 8, 0, 8),
    FIELDOF_OPT(krb5_cred_info, principal, server, 9, 0, 9),
    FIELDOF_OPT(krb5_cred_info, ptr_seqof_host_addresses, caddrs, 10, 0, 10),
};
static unsigned int
optional_krb_cred_info(const void *p)
{
    const krb5_cred_info *val = p;
    unsigned int optional = 0;

    if (val->caddrs != NULL && val->caddrs[0] != NULL)
        optional |= (1u << 10);
    if (val->server != NULL) {
        optional |= (1u << 9);
        optional |= (1u << 8);
    }
    if (val->times.renew_till)
        optional |= (1u << 7);
    if (val->times.endtime)
        optional |= (1u << 6);
    if (val->times.starttime)
        optional |= (1u << 5);
    if (val->times.authtime)
        optional |= (1u << 4);
    if (val->flags)
        optional |= (1u << 3);
    if (val->client != NULL) {
        optional |= (1u << 2);
        optional |= (1u << 1);
    }

    return optional;
}
DEFSEQTYPE(cred_info, krb5_cred_info, krb_cred_info_fields,
           optional_krb_cred_info);
DEFPTRTYPE(cred_info_ptr, cred_info);
DEFNULLTERMSEQOFTYPE(seq_of_cred_info, cred_info_ptr);

DEFPTRTYPE(ptrseqof_cred_info, seq_of_cred_info);



static unsigned int
optional_etype_info_entry(const void *vptr)
{
    const krb5_etype_info_entry *val = vptr;
    unsigned int optional = 0;

    if (val->length != KRB5_ETYPE_NO_SALT)
        optional |= (1u << 1);

    return optional;
}
static const struct field_info etype_info_entry_fields[] = {
    FIELDOF_NORM(krb5_etype_info_entry, int32, etype, 0, 0),
    FIELDOF_OPTSTRING(krb5_etype_info_entry, octetstring, salt, length,
                      1, 0, 1),
};
DEFSEQTYPE(etype_info_entry, krb5_etype_info_entry, etype_info_entry_fields,
           optional_etype_info_entry);

static unsigned int
optional_etype_info2_entry(const void *vptr)
{
    const krb5_etype_info_entry *val = vptr;
    unsigned int optional = 0;

    if (val->length != KRB5_ETYPE_NO_SALT)
        optional |= (1u << 1);
    if (val->s2kparams.data)
        optional |= (1u << 2);

    return optional;
}

static const struct field_info etype_info2_entry_fields[] = {
    FIELDOF_NORM(krb5_etype_info_entry, int32, etype, 0, 0),
    FIELDOF_OPTSTRING(krb5_etype_info_entry, u_generalstring, salt, length,
                      1, 0, 1),
    FIELDOF_OPT(krb5_etype_info_entry, ostring_data, s2kparams, 2, 0, 2),
};
DEFSEQTYPE(etype_info2_entry, krb5_etype_info_entry, etype_info2_entry_fields,
           optional_etype_info2_entry);

DEFPTRTYPE(etype_info_entry_ptr, etype_info_entry);
DEFNULLTERMSEQOFTYPE(etype_info, etype_info_entry_ptr);

DEFPTRTYPE(etype_info2_entry_ptr, etype_info2_entry);
DEFNULLTERMSEQOFTYPE(etype_info2, etype_info2_entry_ptr);

static const struct field_info sam_challenge_2_fields[] = {
    FIELDOF_NORM(krb5_sam_challenge_2, der_data, sam_challenge_2_body, 0, 0),
    FIELDOF_NORM(krb5_sam_challenge_2, ptr_seqof_checksum, sam_cksum, 1, 0),
};
DEFSEQTYPE(sam_challenge_2, krb5_sam_challenge_2, sam_challenge_2_fields, 0);

static const struct field_info sam_challenge_2_body_fields[] = {
    FIELDOF_NORM(krb5_sam_challenge_2_body, int32, sam_type, 0, 0),
    FIELDOF_NORM(krb5_sam_challenge_2_body, krb5_flags, sam_flags, 1, 0),
    FIELDOF_OPT(krb5_sam_challenge_2_body, ostring_data, sam_type_name,
                2, 0, 2),
    FIELDOF_OPT(krb5_sam_challenge_2_body, ostring_data, sam_track_id,
                3, 0, 3),
    FIELDOF_OPT(krb5_sam_challenge_2_body, ostring_data, sam_challenge_label,
                4, 0, 4),
    FIELDOF_OPT(krb5_sam_challenge_2_body, ostring_data, sam_challenge,
                5, 0, 5),
    FIELDOF_OPT(krb5_sam_challenge_2_body, ostring_data, sam_response_prompt,
                6, 0, 6),
    FIELDOF_OPT(krb5_sam_challenge_2_body, ostring_data, sam_pk_for_sad,
                7, 0, 7),
    FIELDOF_NORM(krb5_sam_challenge_2_body, int32, sam_nonce, 8, 0),
    FIELDOF_NORM(krb5_sam_challenge_2_body, int32, sam_etype, 9, 0),
};
static unsigned int
optional_sam_challenge_2_body(const void *p)
{
    const krb5_sam_challenge_2_body *val = p;
    unsigned int optional = 0;

    if (val->sam_pk_for_sad.length > 0) optional |= (1u << 7);
    if (val->sam_response_prompt.length > 0) optional |= (1u << 6);
    if (val->sam_challenge.length > 0) optional |= (1u << 5);
    if (val->sam_challenge_label.length > 0) optional |= (1u << 4);
    if (val->sam_track_id.length > 0) optional |= (1u << 3);
    if (val->sam_type_name.length > 0) optional |= (1u << 2);

    return optional;
}
DEFSEQTYPE(sam_challenge_2_body,krb5_sam_challenge_2_body,sam_challenge_2_body_fields,
           optional_sam_challenge_2_body);

static const struct field_info enc_sam_response_enc_2_fields[] = {
    FIELDOF_NORM(krb5_enc_sam_response_enc_2, int32, sam_nonce, 0, 0),
    FIELDOF_OPT(krb5_enc_sam_response_enc_2, ostring_data, sam_sad, 1, 0, 1),
};
static unsigned int
optional_enc_sam_response_enc_2(const void *p)
{
    const krb5_enc_sam_response_enc_2 *val = p;
    unsigned int optional = 0;

    if (val->sam_sad.length > 0) optional |= (1u << 1);

    return optional;
}
DEFSEQTYPE(enc_sam_response_enc_2, krb5_enc_sam_response_enc_2,
           enc_sam_response_enc_2_fields, optional_enc_sam_response_enc_2);

static const struct field_info sam_response_2_fields[] = {
    FIELDOF_NORM(krb5_sam_response_2, int32, sam_type, 0, 0),
    FIELDOF_NORM(krb5_sam_response_2, krb5_flags, sam_flags, 1, 0),
    FIELDOF_OPT(krb5_sam_response_2, ostring_data, sam_track_id, 2, 0, 2),
    FIELDOF_NORM(krb5_sam_response_2, encrypted_data, sam_enc_nonce_or_sad,
                 3, 0),
    FIELDOF_NORM(krb5_sam_response_2, int32, sam_nonce, 4, 0),
};
static unsigned int
optional_sam_response_2(const void *p)
{
    const krb5_sam_response_2 *val = p;
    unsigned int optional = 0;

    if (val->sam_track_id.length > 0) optional |= (1u << 2);

    return optional;
}
DEFSEQTYPE(sam_response_2, krb5_sam_response_2, sam_response_2_fields,
           optional_sam_response_2);

static const struct field_info krb5_authenticator_fields[] = {
    /* Authenticator ::= [APPLICATION 2] SEQUENCE */
    /* authenticator-vno[0]     INTEGER */
    FIELD_INT_IMM(KVNO, 0, 0),
    /* crealm[1]                        Realm */
    FIELDOF_NORM(krb5_authenticator, realm_of_principal, client, 1, 0),
    /* cname[2]                 PrincipalName */
    FIELDOF_NORM(krb5_authenticator, principal, client, 2, 0),
    /* cksum[3]                 Checksum OPTIONAL */
    FIELDOF_OPT(krb5_authenticator, checksum_ptr, checksum, 3, 0, 3),
    /* cusec[4]                 INTEGER */
    FIELDOF_NORM(krb5_authenticator, int32, cusec, 4, 0),
    /* ctime[5]                 KerberosTime */
    FIELDOF_NORM(krb5_authenticator, kerberos_time, ctime, 5, 0),
    /* subkey[6]                        EncryptionKey OPTIONAL */
    FIELDOF_OPT(krb5_authenticator, ptr_encryption_key, subkey, 6, 0, 6),
    /* seq-number[7]            INTEGER OPTIONAL */
    FIELDOF_OPT(krb5_authenticator, uint, seq_number, 7, 0, 7),
    /* authorization-data[8]    AuthorizationData OPTIONAL */
    FIELDOF_OPT(krb5_authenticator, auth_data_ptr, authorization_data,
                8, 0, 8),
};
static unsigned int
optional_krb5_authenticator(const void *p)
{
    const krb5_authenticator *val = p;
    unsigned int optional = 0;

    if (val->authorization_data != NULL && val->authorization_data[0] != NULL)
        optional |= (1u << 8);

    if (val->seq_number != 0)
        optional |= (1u << 7);

    if (val->subkey != NULL)
        optional |= (1u << 6);

    if (val->checksum != NULL)
        optional |= (1u << 3);

    return optional;
}
DEFSEQTYPE(untagged_krb5_authenticator, krb5_authenticator, krb5_authenticator_fields,
           optional_krb5_authenticator);
DEFAPPTAGGEDTYPE(krb5_authenticator, 2, untagged_krb5_authenticator);

static const struct field_info enc_tkt_part_fields[] = {
    /* EncTicketPart ::= [APPLICATION 3] SEQUENCE */
    /* flags[0]                 TicketFlags */
    FIELDOF_NORM(krb5_enc_tkt_part, krb5_flags, flags, 0, 0),
    /* key[1]                   EncryptionKey */
    FIELDOF_NORM(krb5_enc_tkt_part, ptr_encryption_key, session, 1, 0),
    /* crealm[2]                        Realm */
    FIELDOF_NORM(krb5_enc_tkt_part, realm_of_principal, client, 2, 0),
    /* cname[3]                 PrincipalName */
    FIELDOF_NORM(krb5_enc_tkt_part, principal, client, 3, 0),
    /* transited[4]             TransitedEncoding */
    FIELDOF_NORM(krb5_enc_tkt_part, transited, transited, 4, 0),
    /* authtime[5]              KerberosTime */
    FIELDOF_NORM(krb5_enc_tkt_part, kerberos_time, times.authtime, 5, 0),
    /* starttime[6]             KerberosTime OPTIONAL */
    FIELDOF_OPT(krb5_enc_tkt_part, kerberos_time, times.starttime, 6, 0, 6),
    /* endtime[7]                       KerberosTime */
    FIELDOF_NORM(krb5_enc_tkt_part, kerberos_time, times.endtime, 7, 0),
    /* renew-till[8]            KerberosTime OPTIONAL */
    FIELDOF_OPT(krb5_enc_tkt_part, kerberos_time, times.renew_till, 8, 0, 8),
    /* caddr[9]                 HostAddresses OPTIONAL */
    FIELDOF_OPT(krb5_enc_tkt_part, ptr_seqof_host_addresses, caddrs, 9, 0, 9),
    /* authorization-data[10]   AuthorizationData OPTIONAL */
    FIELDOF_OPT(krb5_enc_tkt_part, auth_data_ptr, authorization_data,
                10, 0, 10),
};
static unsigned int
optional_enc_tkt_part(const void *p)
{
    const krb5_enc_tkt_part *val = p;
    unsigned int optional = 0;

    if (val->authorization_data != NULL && val->authorization_data[0] != NULL)
        optional |= (1u << 10);
    if (val->caddrs != NULL && val->caddrs[0] != NULL)
        optional |= (1u << 9);
    if (val->times.renew_till)
        optional |= (1u << 8);
    if (val->times.starttime)
        optional |= (1u << 6);

    return optional;
}
DEFSEQTYPE(untagged_enc_tkt_part, krb5_enc_tkt_part, enc_tkt_part_fields,
           optional_enc_tkt_part);
DEFAPPTAGGEDTYPE(enc_tkt_part, 3, untagged_enc_tkt_part);

DEFAPPTAGGEDTYPE(enc_tgs_rep_part, 26, enc_kdc_rep_part);

static const struct field_info as_rep_fields[] = {
    /* AS-REP ::= [APPLICATION 11] KDC-REP */
    /* But KDC-REP needs to know what type it's being encapsulated
       in, so expand each version.  */
    FIELD_INT_IMM(KVNO, 0, 0),
    FIELD_INT_IMM(KRB5_AS_REP, 1, 0),
    FIELDOF_OPT(krb5_kdc_rep, ptr_seqof_pa_data, padata, 2, 0, 2),
    FIELDOF_NORM(krb5_kdc_rep, realm_of_principal, client, 3, 0),
    FIELDOF_NORM(krb5_kdc_rep, principal, client, 4, 0),
    FIELDOF_NORM(krb5_kdc_rep, ticket_ptr, ticket, 5, 0),
    FIELDOF_NORM(krb5_kdc_rep, encrypted_data, enc_part, 6, 0),
};
static unsigned int
optional_as_rep(const void *p)
{
    const krb5_kdc_rep *val = p;
    unsigned int optional = 0;

    if (val->padata != NULL && val->padata[0] != NULL)
        optional |= (1u << 2);

    return optional;
}
DEFSEQTYPE(untagged_as_rep, krb5_kdc_rep, as_rep_fields, optional_as_rep);
DEFAPPTAGGEDTYPE(as_rep, 11, untagged_as_rep);

static const struct field_info tgs_rep_fields[] = {
    /* TGS-REP ::= [APPLICATION 13] KDC-REP */
    /* But KDC-REP needs to know what type it's being encapsulated
       in, so expand each version.  */
    FIELD_INT_IMM(KVNO, 0, 0),
    FIELD_INT_IMM(KRB5_TGS_REP, 1, 0),
    FIELDOF_OPT(krb5_kdc_rep, ptr_seqof_pa_data, padata, 2, 0, 2),
    FIELDOF_NORM(krb5_kdc_rep, realm_of_principal, client, 3, 0),
    FIELDOF_NORM(krb5_kdc_rep, principal, client, 4, 0),
    FIELDOF_NORM(krb5_kdc_rep, ticket_ptr, ticket, 5, 0),
    FIELDOF_NORM(krb5_kdc_rep, encrypted_data, enc_part, 6, 0),
};
static unsigned int
optional_tgs_rep(const void *p)
{
    const krb5_kdc_rep *val = p;
    unsigned int optional = 0;

    if (val->padata != NULL && val->padata[0] != NULL)
        optional |= (1u << 2);

    return optional;
}
DEFSEQTYPE(untagged_tgs_rep, krb5_kdc_rep, tgs_rep_fields, optional_tgs_rep);
DEFAPPTAGGEDTYPE(tgs_rep, 13, untagged_tgs_rep);

static const struct field_info ap_req_fields[] = {
    /* AP-REQ ::=       [APPLICATION 14] SEQUENCE */
    /* pvno[0]          INTEGER */
    FIELD_INT_IMM(KVNO, 0, 0),
    /* msg-type[1]      INTEGER */
    FIELD_INT_IMM(ASN1_KRB_AP_REQ, 1, 0),
    /* ap-options[2]    APOptions */
    FIELDOF_NORM(krb5_ap_req, krb5_flags, ap_options, 2, 0),
    /* ticket[3]                Ticket */
    FIELDOF_NORM(krb5_ap_req, ticket_ptr, ticket, 3, 0),
    /* authenticator[4] EncryptedData */
    FIELDOF_NORM(krb5_ap_req, encrypted_data, authenticator, 4, 0),
};
DEFSEQTYPE(untagged_ap_req, krb5_ap_req, ap_req_fields, 0);
DEFAPPTAGGEDTYPE(ap_req, 14, untagged_ap_req);

static const struct field_info ap_rep_fields[] = {
    /* AP-REP ::=       [APPLICATION 15] SEQUENCE */
    /* pvno[0]          INTEGER */
    FIELD_INT_IMM(KVNO, 0, 0),
    /* msg-type[1]      INTEGER */
    FIELD_INT_IMM(ASN1_KRB_AP_REP, 1, 0),
    /* enc-part[2]      EncryptedData */
    FIELDOF_NORM(krb5_ap_rep, encrypted_data, enc_part, 2, 0),
};
DEFSEQTYPE(untagged_ap_rep, krb5_ap_rep, ap_rep_fields, 0);
DEFAPPTAGGEDTYPE(ap_rep, 15, untagged_ap_rep);

static const struct field_info ap_rep_enc_part_fields[] = {
    /* EncAPRepPart ::= [APPLICATION 27] SEQUENCE */
    /* ctime[0]         KerberosTime */
    FIELDOF_NORM(krb5_ap_rep_enc_part, kerberos_time, ctime, 0, 0),
    /* cusec[1]         INTEGER */
    FIELDOF_NORM(krb5_ap_rep_enc_part, int32, cusec, 1, 0),
    /* subkey[2]                EncryptionKey OPTIONAL */
    FIELDOF_OPT(krb5_ap_rep_enc_part, ptr_encryption_key, subkey, 2, 0, 2),
    /* seq-number[3]    INTEGER OPTIONAL */
    FIELDOF_OPT(krb5_ap_rep_enc_part, uint, seq_number, 3, 0, 3),
};
static unsigned int
optional_ap_rep_enc_part(const void *p)
{
    const krb5_ap_rep_enc_part *val = p;
    unsigned int optional = 0;

    if (val->seq_number)
        optional |= (1u << 3);
    if (val->subkey != NULL)
        optional |= (1u << 2);

    return optional;
}
DEFSEQTYPE(untagged_ap_rep_enc_part, krb5_ap_rep_enc_part,
           ap_rep_enc_part_fields, optional_ap_rep_enc_part);
DEFAPPTAGGEDTYPE(ap_rep_enc_part, 27, untagged_ap_rep_enc_part);

static const struct field_info as_req_fields[] = {
    /* AS-REQ ::= [APPLICATION 10] KDC-REQ */
    FIELD_INT_IMM(KVNO, 1, 0),
    FIELD_INT_IMM(KRB5_AS_REQ, 2, 0),
    FIELDOF_OPT(krb5_kdc_req, ptr_seqof_pa_data, padata, 3, 0, 3),
    FIELDOF_ENCODEAS(krb5_kdc_req, kdc_req_body, 4, 0),
};
static unsigned int
optional_as_req(const void *p)
{
    const krb5_kdc_req *val = p;
    unsigned int optional = 0;

    if (val->padata != NULL && val->padata[0] != NULL)
        optional |= (1u << 3);

    return optional;
}
DEFSEQTYPE(untagged_as_req, krb5_kdc_req, as_req_fields, optional_as_req);
DEFAPPTAGGEDTYPE(as_req, 10, untagged_as_req);

static const struct field_info tgs_req_fields[] = {
    /* TGS-REQ ::= [APPLICATION 12] KDC-REQ */
    FIELD_INT_IMM(KVNO, 1, 0),
    FIELD_INT_IMM(KRB5_TGS_REQ, 2, 0),
    FIELDOF_OPT(krb5_kdc_req, ptr_seqof_pa_data, padata, 3, 0, 3),
    FIELDOF_ENCODEAS(krb5_kdc_req, kdc_req_body, 4, 0),
};
static unsigned int
optional_tgs_req(const void *p)
{
    const krb5_kdc_req *val = p;
    unsigned int optional = 0;

    if (val->padata != NULL && val->padata[0] != NULL)
        optional |= (1u << 3);

    return optional;
}
DEFSEQTYPE(untagged_tgs_req, krb5_kdc_req, tgs_req_fields,
           optional_tgs_req);
DEFAPPTAGGEDTYPE(tgs_req, 12, untagged_tgs_req);

static const struct field_info krb5_safe_fields[] = {
    FIELD_INT_IMM(KVNO, 0, 0),
    FIELD_INT_IMM(ASN1_KRB_SAFE, 1, 0),
    FIELD_SELF(krb_safe_body, 2, 0),
    FIELDOF_NORM(krb5_safe, checksum_ptr, checksum, 3, 0),
};
DEFSEQTYPE(untagged_krb5_safe, krb5_safe, krb5_safe_fields, 0);
DEFAPPTAGGEDTYPE(krb5_safe, 20, untagged_krb5_safe);

DEFPTRTYPE(krb_saved_safe_body_ptr, der_data);
DEFFIELDTYPE(krb5_safe_checksum_only, krb5_safe,
             FIELDOF_NORM(krb5_safe, checksum_ptr, checksum, -1, 0));
DEFPTRTYPE(krb5_safe_checksum_only_ptr, krb5_safe_checksum_only);
static const struct field_info krb5_safe_with_body_fields[] = {
    FIELD_INT_IMM(KVNO, 0, 0),
    FIELD_INT_IMM(ASN1_KRB_SAFE, 1, 0),
    FIELDOF_NORM(struct krb5_safe_with_body, krb_saved_safe_body_ptr, body,
                 2, 0),
    FIELDOF_NORM(struct krb5_safe_with_body, krb5_safe_checksum_only_ptr,
                 safe, 3, 0),
};
DEFSEQTYPE(untagged_krb5_safe_with_body, struct krb5_safe_with_body,
           krb5_safe_with_body_fields, 0);
DEFAPPTAGGEDTYPE(krb5_safe_with_body, 20, untagged_krb5_safe_with_body);

static const struct field_info priv_fields[] = {
    FIELD_INT_IMM(KVNO, 0, 0),
    FIELD_INT_IMM(ASN1_KRB_PRIV, 1, 0),
    FIELDOF_NORM(krb5_priv, encrypted_data, enc_part, 3, 0),
};
DEFSEQTYPE(untagged_priv, krb5_priv, priv_fields, 0);
DEFAPPTAGGEDTYPE(krb5_priv, 21, untagged_priv);

static const struct field_info priv_enc_part_fields[] = {
    FIELDOF_NORM(krb5_priv_enc_part, ostring_data, user_data, 0, 0),
    FIELDOF_OPT(krb5_priv_enc_part, kerberos_time, timestamp, 1, 0, 1),
    FIELDOF_OPT(krb5_priv_enc_part, int32, usec, 2, 0, 2),
    FIELDOF_OPT(krb5_priv_enc_part, uint, seq_number, 3, 0, 3),
    FIELDOF_NORM(krb5_priv_enc_part, address_ptr, s_address, 4, 0),
    FIELDOF_OPT(krb5_priv_enc_part, address_ptr, r_address, 5, 0, 5),
};
static unsigned int
optional_priv_enc_part(const void *p)
{
    const krb5_priv_enc_part *val = p;
    unsigned int optional = 0;

    if (val->timestamp) {
        optional |= (1u << 2);
        optional |= (1u << 1);
    }
    if (val->seq_number)
        optional |= (1u << 3);
    if (val->r_address)
        optional |= (1u << 5);

    return optional;
}
DEFSEQTYPE(untagged_priv_enc_part, krb5_priv_enc_part, priv_enc_part_fields,
           optional_priv_enc_part);
DEFAPPTAGGEDTYPE(priv_enc_part, 28, untagged_priv_enc_part);

static const struct field_info cred_fields[] = {
    /* KRB-CRED ::= [APPLICATION 22] SEQUENCE */
    /* pvno[0]          INTEGER */
    FIELD_INT_IMM(KVNO, 0, 0),
    /* msg-type[1]      INTEGER, -- KRB_CRED */
    FIELD_INT_IMM(ASN1_KRB_CRED, 1, 0),
    /* tickets[2]       SEQUENCE OF Ticket */
    FIELDOF_NORM(krb5_cred, ptr_seqof_ticket, tickets, 2, 0),
    /* enc-part[3]      EncryptedData */
    FIELDOF_NORM(krb5_cred, encrypted_data, enc_part, 3, 0),
};
DEFSEQTYPE(untagged_cred, krb5_cred, cred_fields, 0);
DEFAPPTAGGEDTYPE(krb5_cred, 22, untagged_cred);

static const struct field_info enc_cred_part_fields[] = {
    /* EncKrbCredPart ::= [APPLICATION 29] SEQUENCE */
    /* ticket-info[0]   SEQUENCE OF KrbCredInfo */
    FIELDOF_NORM(krb5_cred_enc_part, ptrseqof_cred_info, ticket_info, 0, 0),
    /* nonce[1]         INTEGER OPTIONAL */
    FIELDOF_OPT(krb5_cred_enc_part, int32, nonce, 1, 0, 1),
    /* timestamp[2]     KerberosTime OPTIONAL */
    FIELDOF_OPT(krb5_cred_enc_part, kerberos_time, timestamp, 2, 0, 2),
    /* usec[3]          INTEGER OPTIONAL */
    FIELDOF_OPT(krb5_cred_enc_part, int32, usec, 3, 0, 3),
    /* s-address[4]     HostAddress OPTIONAL */
    FIELDOF_OPT(krb5_cred_enc_part, address_ptr, s_address, 4, 0, 4),
    /* r-address[5]     HostAddress OPTIONAL */
    FIELDOF_OPT(krb5_cred_enc_part, address_ptr, r_address, 5, 0, 5),
};
static unsigned int
optional_enc_cred_part(const void *p)
{
    const krb5_cred_enc_part *val = p;
    unsigned int optional = 0;

    if (val->r_address != NULL)
        optional |= (1u << 5);

    if (val->s_address != NULL)
        optional |= (1u << 4);

    if (val->timestamp) {
        optional |= (1u << 2);
        optional |= (1u << 3);
    }

    if (val->nonce)
        optional |= (1u << 1);

    return optional;
}
DEFSEQTYPE(untagged_enc_cred_part, krb5_cred_enc_part, enc_cred_part_fields,
           optional_enc_cred_part);
DEFAPPTAGGEDTYPE(enc_cred_part, 29, untagged_enc_cred_part);

static const struct field_info error_fields[] = {
    /* KRB-ERROR ::= [APPLICATION 30] SEQUENCE */
    /* pvno[0]          INTEGER */
    FIELD_INT_IMM(KVNO, 0, 0),
    /* msg-type[1]      INTEGER */
    FIELD_INT_IMM(ASN1_KRB_ERROR, 1, 0),
    /* ctime[2]         KerberosTime OPTIONAL */
    FIELDOF_OPT(krb5_error, kerberos_time, ctime, 2, 0, 2),
    /* cusec[3]         INTEGER OPTIONAL */
    FIELDOF_OPT(krb5_error, int32, cusec, 3, 0, 3),
    /* stime[4]         KerberosTime */
    FIELDOF_NORM(krb5_error, kerberos_time, stime, 4, 0),
    /* susec[5]         INTEGER */
    FIELDOF_NORM(krb5_error, int32, susec, 5, 0),
    /* error-code[6]    INTEGER */
    FIELDOF_NORM(krb5_error, ui_4, error, 6, 0),
    /* crealm[7]        Realm OPTIONAL */
    FIELDOF_OPT(krb5_error, realm_of_principal, client, 7, 0, 7),
    /* cname[8]         PrincipalName OPTIONAL */
    FIELDOF_OPT(krb5_error, principal, client, 8, 0, 8),
    /* realm[9]         Realm -- Correct realm */
    FIELDOF_NORM(krb5_error, realm_of_principal, server, 9, 0),
    /* sname[10]        PrincipalName -- Correct name */
    FIELDOF_NORM(krb5_error, principal, server, 10, 0),
    /* e-text[11]       GeneralString OPTIONAL */
    FIELDOF_OPT(krb5_error, gstring_data, text, 11, 0, 11),
    /* e-data[12]       OCTET STRING OPTIONAL */
    FIELDOF_OPT(krb5_error, ostring_data, e_data, 12, 0, 12),
};
static unsigned int
optional_error(const void *p)
{
    const krb5_error *val = p;
    unsigned int optional = 0;

    if (val->ctime)
        optional |= (1u << 2);
    if (val->cusec)
        optional |= (1u << 3);
    if (val->client) {
        optional |= (1u << 7);
        optional |= (1u << 8);
    }
    if (val->text.data != NULL && val->text.length > 0)
        optional |= (1u << 11);
    if (val->e_data.data != NULL && val->e_data.length > 0)
        optional |= (1u << 12);

    return optional;
}
DEFSEQTYPE(untagged_krb5_error, krb5_error, error_fields, optional_error);
DEFAPPTAGGEDTYPE(krb5_error, 30, untagged_krb5_error);

static const struct field_info pa_enc_ts_fields[] = {
    FIELDOF_NORM(krb5_pa_enc_ts, kerberos_time, patimestamp, 0, 0),
    FIELDOF_OPT(krb5_pa_enc_ts, int32, pausec, 1, 0, 1),
};
static unsigned int
optional_pa_enc_ts(const void *p)
{
    const krb5_pa_enc_ts *val = p;
    unsigned int optional = 0;

    if (val->pausec)
        optional |= (1u << 1);

    return optional;
}
DEFSEQTYPE(pa_enc_ts, krb5_pa_enc_ts, pa_enc_ts_fields, optional_pa_enc_ts);

static const struct field_info setpw_req_fields[] = {
    FIELDOF_NORM(struct krb5_setpw_req, ostring_data, password, 0, 0),
    FIELDOF_NORM(struct krb5_setpw_req, principal, target, 1, 0),
    FIELDOF_NORM(struct krb5_setpw_req, realm_of_principal, target, 2, 0),
};

DEFSEQTYPE(setpw_req, struct krb5_setpw_req, setpw_req_fields, 0);

/* [MS-SFU] Section 2.2.1. */
static const struct field_info pa_for_user_fields[] = {
    FIELDOF_NORM(krb5_pa_for_user, principal, user, 0, 0),
    FIELDOF_NORM(krb5_pa_for_user, realm_of_principal, user, 1, 0),
    FIELDOF_NORM(krb5_pa_for_user, checksum, cksum, 2, 0),
    FIELDOF_NORM(krb5_pa_for_user, gstring_data, auth_package, 3, 0),
};

DEFSEQTYPE(pa_for_user, krb5_pa_for_user, pa_for_user_fields, 0);

/* [MS-SFU] Section 2.2.2. */
static const struct field_info s4u_userid_fields[] = {
    FIELDOF_NORM(krb5_s4u_userid, int32, nonce, 0, 0),
    FIELDOF_OPT(krb5_s4u_userid, principal, user, 1, 0, 1),
    FIELDOF_NORM(krb5_s4u_userid, realm_of_principal, user, 2, 0),
    FIELDOF_OPT(krb5_s4u_userid, ostring_data, subject_cert, 3, 0, 3),
    FIELDOF_OPT(krb5_s4u_userid, krb5_flags, options, 4, 0, 4),
};

static unsigned int s4u_userid_optional (const void *p) {
    const krb5_s4u_userid *val = p;
    unsigned int optional = 0;
    if (val->user != NULL && val->user->length != 0)
        optional |= (1u)<<1;
    if (val->subject_cert.length != 0)
        optional |= (1u)<<3;
    if (val->options != 0)
        optional |= (1u)<<4;
    return optional;
}

DEFSEQTYPE(s4u_userid, krb5_s4u_userid, s4u_userid_fields, s4u_userid_optional);

static const struct field_info pa_s4u_x509_user_fields[] = {
    FIELDOF_NORM(krb5_pa_s4u_x509_user, s4u_userid, user_id, 0, 0),
    FIELDOF_NORM(krb5_pa_s4u_x509_user, checksum, cksum, 1, 0),
};

DEFSEQTYPE(pa_s4u_x509_user, krb5_pa_s4u_x509_user, pa_s4u_x509_user_fields, 0);

#if 0
/* draft-brezak-win2k-krb-authz Section 6. */
static const struct field_info pa_pac_request_fields[] = {
    FIELDOF_NORM(krb5_pa_pac_req, boolean, include_pac, 0, 0),
};

DEFSEQTYPE(pa_pac_request, krb5_pa_pac_req, pa_pac_request_fields, 0);
#endif

/* RFC 4537 */
DEFFIELDTYPE(etype_list, krb5_etype_list,
             FIELDOF_SEQOF_INT32(krb5_etype_list, int32_ptr, etypes, length,
                                 -1, 0));

/* draft-ietf-krb-wg-preauth-framework-09 */
static const struct field_info fast_armor_fields[] = {
    FIELDOF_NORM(krb5_fast_armor, int32, armor_type, 0, 0),
    FIELDOF_NORM(krb5_fast_armor, ostring_data, armor_value, 1, 0),
};

DEFSEQTYPE( fast_armor, krb5_fast_armor, fast_armor_fields, 0);
DEFPTRTYPE( ptr_fast_armor, fast_armor);

static const struct field_info fast_armored_req_fields[] = {
    FIELDOF_OPT(krb5_fast_armored_req, ptr_fast_armor, armor, 0, 0, 0),
    FIELDOF_NORM(krb5_fast_armored_req, checksum, req_checksum, 1, 0),
    FIELDOF_NORM(krb5_fast_armored_req, encrypted_data, enc_part, 2, 0),
};

static unsigned int fast_armored_req_optional (const void *p) {
    const krb5_fast_armored_req *val = p;
    unsigned int optional = 0;
    if (val->armor)
        optional |= (1u)<<0;
    return optional;
}
DEFSEQTYPE(fast_armored_req, krb5_fast_armored_req, fast_armored_req_fields,
           fast_armored_req_optional);

/* This is a CHOICE type with only one choice (so far) and we're not using a
 * distinguisher/union for it. */
DEFTAGGEDTYPE(pa_fx_fast_request, CONTEXT_SPECIFIC, CONSTRUCTED, 0, 0,
              fast_armored_req);

DEFFIELDTYPE(fast_req_padata, krb5_kdc_req,
             FIELDOF_NORM(krb5_kdc_req, ptr_seqof_pa_data, padata, -1, 0));
DEFPTRTYPE(ptr_fast_req_padata, fast_req_padata);

static const struct field_info fast_req_fields[] = {
    FIELDOF_NORM(krb5_fast_req, krb5_flags, fast_options, 0, 0),
    FIELDOF_NORM( krb5_fast_req, ptr_fast_req_padata, req_body, 1, 0),
    FIELDOF_NORM( krb5_fast_req, ptr_kdc_req_body, req_body, 2, 0),
};

DEFSEQTYPE(fast_req, krb5_fast_req, fast_req_fields, 0);


static const struct field_info fast_finished_fields[] = {
    FIELDOF_NORM( krb5_fast_finished, kerberos_time, timestamp, 0, 0),
    FIELDOF_NORM( krb5_fast_finished, int32, usec, 1, 0),
    FIELDOF_NORM( krb5_fast_finished, realm_of_principal, client, 2, 0),
    FIELDOF_NORM(krb5_fast_finished, principal, client, 3, 0),
    FIELDOF_NORM( krb5_fast_finished, checksum, ticket_checksum, 4, 0),
};

DEFSEQTYPE( fast_finished, krb5_fast_finished, fast_finished_fields, 0);

DEFPTRTYPE( ptr_fast_finished, fast_finished);

static const struct field_info fast_response_fields[] = {
    FIELDOF_NORM(krb5_fast_response, ptr_seqof_pa_data, padata, 0, 0),
    FIELDOF_OPT(krb5_fast_response, ptr_encryption_key, strengthen_key,
                1, 0, 1),
    FIELDOF_OPT(krb5_fast_response, ptr_fast_finished, finished, 2, 0, 2),
    FIELDOF_NORM(krb5_fast_response, int32, nonce, 3, 0),
};

static unsigned int
fast_response_optional (const void *p)
{
    unsigned int optional = 0;
    const krb5_fast_response *val = p;
    if (val->strengthen_key)
        optional |= (1u <<1);
    if (val->finished)
        optional |= (1u<<2);
    return optional;
}
DEFSEQTYPE( fast_response, krb5_fast_response, fast_response_fields, fast_response_optional);

static const struct field_info fast_rep_fields[] = {
    FIELDOF_ENCODEAS(krb5_enc_data, encrypted_data, 0, 0),
};
DEFSEQTYPE(fast_rep, krb5_enc_data, fast_rep_fields, 0);

/* This is a CHOICE type with only one choice (so far) and we're not using a
 * distinguisher/union for it. */
DEFTAGGEDTYPE(pa_fx_fast_reply, CONTEXT_SPECIFIC, CONSTRUCTED, 0, 0,
              fast_rep);

static const struct field_info ad_kdcissued_fields[] = {
    FIELDOF_NORM(krb5_ad_kdcissued, checksum, ad_checksum, 0, 0),
    FIELDOF_OPT(krb5_ad_kdcissued, realm_of_principal, i_principal, 1, 0, 1),
    FIELDOF_OPT(krb5_ad_kdcissued, principal, i_principal, 2, 0, 1),
    FIELDOF_NORM(krb5_ad_kdcissued, auth_data_ptr, elements, 3, 0),
};

static unsigned int
ad_kdcissued_optional(const void *p)
{
    unsigned int optional = 0;
    const krb5_ad_kdcissued *val = p;
    if (val->i_principal)
        optional |= (1u << 1);
    return optional;
}

DEFSEQTYPE(ad_kdc_issued, krb5_ad_kdcissued, ad_kdcissued_fields, ad_kdcissued_optional);

static const struct field_info princ_plus_realm_fields[] = {
    FIELDOF_ENCODEAS(krb5_principal_data, principal_data, 0, 0),
    FIELDOF_ENCODEAS(krb5_principal_data, realm_of_principal_data, 1, 0),
};

DEFSEQTYPE(princ_plus_realm_data, krb5_principal_data, princ_plus_realm_fields, 0);
DEFPTRTYPE(princ_plus_realm, princ_plus_realm_data);

DEFNULLTERMSEQOFTYPE(seq_of_princ_plus_realm, princ_plus_realm);
DEFPTRTYPE(ptr_seq_of_princ_plus_realm, seq_of_princ_plus_realm);

static const struct field_info ad_signedpath_data_fields[] = {
    FIELDOF_NORM(krb5_ad_signedpath_data, princ_plus_realm, client, 0, 0),
    FIELDOF_NORM(krb5_ad_signedpath_data, kerberos_time, authtime, 1, 0),
    FIELDOF_OPT(krb5_ad_signedpath_data, ptr_seq_of_princ_plus_realm,
                delegated, 2, 0, 2),
    FIELDOF_OPT(krb5_ad_signedpath_data, ptr_seqof_pa_data, method_data,
                3, 0, 3),
    FIELDOF_OPT(krb5_ad_signedpath_data, auth_data_ptr, authorization_data,
                4, 0, 4),
};

static unsigned int ad_signedpath_data_optional(const void *p)
{
    unsigned int optional = 0;
    const krb5_ad_signedpath_data *val = p;
    if (val->delegated && val->delegated[0])
        optional |= (1u << 2);
    if (val->method_data && val->method_data[0])
        optional |= (1u << 3);
    if (val->authorization_data && val->authorization_data[0])
        optional |= (1u << 4);
    return optional;
}

DEFSEQTYPE(ad_signedpath_data, krb5_ad_signedpath_data, ad_signedpath_data_fields, ad_signedpath_data_optional);

static const struct field_info ad_signedpath_fields[] = {
    FIELDOF_NORM(krb5_ad_signedpath, int32, enctype, 0, 0),
    FIELDOF_NORM(krb5_ad_signedpath, checksum, checksum, 1, 0),
    FIELDOF_OPT(krb5_ad_signedpath, ptr_seq_of_princ_plus_realm, delegated,
                2, 0, 2),
    FIELDOF_OPT(krb5_ad_signedpath, ptr_seqof_pa_data, method_data, 3, 0, 3),
};

static unsigned int ad_signedpath_optional(const void *p)
{
    unsigned int optional = 0;
    const krb5_ad_signedpath *val = p;
    if (val->delegated && val->delegated[0])
        optional |= (1u << 2);
    if (val->method_data && val->method_data[0])
        optional |= (1u << 3);
    return optional;
}

DEFSEQTYPE(ad_signedpath, krb5_ad_signedpath, ad_signedpath_fields, ad_signedpath_optional);

static const struct field_info iakerb_header_fields[] = {
    FIELDOF_NORM(krb5_iakerb_header, ostring_data, target_realm, 1, 0),
    FIELDOF_OPT(krb5_iakerb_header, ostring_data_ptr, cookie, 2, 0, 2),
};

static unsigned int iakerb_header_optional(const void *p)
{
    unsigned int optional = 0;
    const krb5_iakerb_header *val = p;
    if (val->cookie && val->cookie->data)
        optional |= (1u << 2);
    return optional;
}

DEFSEQTYPE(iakerb_header, krb5_iakerb_header, iakerb_header_fields, iakerb_header_optional);

static const struct field_info iakerb_finished_fields[] = {
    FIELDOF_NORM(krb5_iakerb_finished, checksum, checksum, 1, 0),
};

static unsigned int iakerb_finished_optional(const void *p)
{
    unsigned int optional = 0;
    return optional;
}

DEFSEQTYPE(iakerb_finished, krb5_iakerb_finished, iakerb_finished_fields,
           iakerb_finished_optional);

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
MAKE_FULL_ENCODER(encode_krb5_padata_sequence, seq_of_pa_data);
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

DEFSTRINGTYPE(object_identifier, char *, asn1_encode_bytestring,
              ASN1_OBJECTIDENTIFIER);
DEFFIELDTYPE(oid_data, krb5_data,
             FIELDOF_STRING(krb5_data, object_identifier, data, length,
                            -1, 0));
DEFPTRTYPE(oid_data_ptr, oid_data);

static unsigned int
algorithm_identifier_optional(const void *p)
{
    unsigned int optional = 0;
    const krb5_algorithm_identifier *val = p;
    if (val->parameters.length > 0)
        optional |= (1u << 1);
    return optional;
}

static const struct field_info algorithm_identifier_fields[] = {
    FIELDOF_NORM(krb5_algorithm_identifier, oid_data, algorithm, -1, 0),
    FIELDOF_OPT(krb5_algorithm_identifier, der_data, parameters, -1, 0, 1),
};
DEFSEQTYPE(algorithm_identifier, krb5_algorithm_identifier,
           algorithm_identifier_fields, algorithm_identifier_optional);
DEFPTRTYPE(algorithm_identifier_ptr, algorithm_identifier);

static const struct field_info kdf_alg_id_fields[] = {
    FIELDOF_ENCODEAS(krb5_data, oid_data, 0, 0)
};
DEFSEQTYPE(kdf_alg_id, krb5_data, kdf_alg_id_fields, NULL);
DEFPTRTYPE(kdf_alg_id_ptr, kdf_alg_id);
DEFNONEMPTYNULLTERMSEQOFTYPE(supported_kdfs, kdf_alg_id_ptr);
DEFPTRTYPE(supported_kdfs_ptr, supported_kdfs);

/* Krb5PrincipalName is defined in RFC 4556 and is *not* PrincipalName from RFC 4120*/
static const struct field_info pkinit_krb5_principal_name_fields[] = {
    FIELDOF_NORM(krb5_principal_data, gstring_data, realm, 0, 0),
    FIELDOF_ENCODEAS(krb5_principal_data, principal_data, 1, 0)
};


DEFSEQTYPE(pkinit_krb5_principal_name_data, krb5_principal_data, pkinit_krb5_principal_name_fields, NULL);
DEFPTRTYPE(pkinit_krb5_principal_name, pkinit_krb5_principal_name_data);
DEFOCTETWRAPTYPE(pkinit_krb5_principal_name_wrapped, pkinit_krb5_principal_name);


/* For SP80056A OtherInfo, for pkinit agility */
static const struct field_info sp80056a_other_info_fields[] = {
    FIELDOF_NORM(krb5_sp80056a_other_info, algorithm_identifier,
                 algorithm_identifier, -1, 0),
    FIELDOF_NORM(krb5_sp80056a_other_info, pkinit_krb5_principal_name_wrapped,
                 party_u_info, 0, 0),
    FIELDOF_NORM(krb5_sp80056a_other_info, pkinit_krb5_principal_name_wrapped,
                 party_v_info, 1, 0),
    FIELDOF_STRING(krb5_sp80056a_other_info, s_octetstring,
                   supp_pub_info.data, supp_pub_info.length, 2, 0),
};

DEFSEQTYPE(sp80056a_other_info, krb5_sp80056a_other_info, sp80056a_other_info_fields, NULL);

/* For PkinitSuppPubInfo, for pkinit agility */
static const struct field_info pkinit_supp_pub_info_fields[] = {
    FIELDOF_NORM(krb5_pkinit_supp_pub_info, int32, enctype, 0, 0),
    FIELDOF_STRING(krb5_pkinit_supp_pub_info, s_octetstring, as_req.data,
                   as_req.length, 1, 0),
    FIELDOF_STRING(krb5_pkinit_supp_pub_info, s_octetstring, pk_as_rep.data,
                   pk_as_rep.length, 2, 0),
};

DEFSEQTYPE(pkinit_supp_pub_info, krb5_pkinit_supp_pub_info, pkinit_supp_pub_info_fields, NULL);

MAKE_FULL_ENCODER(encode_krb5_pkinit_supp_pub_info, pkinit_supp_pub_info);
MAKE_FULL_ENCODER(encode_krb5_sp80056a_other_info, sp80056a_other_info);

/* A krb5_checksum encoded as an OCTET STRING, for PKAuthenticator. */
DEFFIELDTYPE(ostring_checksum, krb5_checksum,
             FIELDOF_STRING(krb5_checksum, octetstring, contents, length,
                            -1, 0));

static const struct field_info pk_authenticator_fields[] = {
    FIELDOF_NORM(krb5_pk_authenticator, int32, cusec, 0, 0),
    FIELDOF_NORM(krb5_pk_authenticator, kerberos_time, ctime, 1, 0),
    FIELDOF_NORM(krb5_pk_authenticator, int32, nonce, 2, 0),
    FIELDOF_NORM(krb5_pk_authenticator, ostring_checksum, paChecksum, 3, 0),
};
DEFSEQTYPE(pk_authenticator, krb5_pk_authenticator, pk_authenticator_fields,
           0);

static const struct field_info pk_authenticator_draft9_fields[] = {
    FIELDOF_NORM(krb5_pk_authenticator_draft9, principal, kdcName, 0, 0),
    FIELDOF_NORM(krb5_pk_authenticator_draft9, realm_of_principal, kdcName,
                 1, 0),
    FIELDOF_NORM(krb5_pk_authenticator_draft9, int32, cusec, 2, 0),
    FIELDOF_NORM(krb5_pk_authenticator_draft9, kerberos_time, ctime, 3, 0),
    FIELDOF_NORM(krb5_pk_authenticator_draft9, int32, nonce, 4, 0),
};
DEFSEQTYPE(pk_authenticator_draft9, krb5_pk_authenticator_draft9,
           pk_authenticator_draft9_fields, 0);

DEFSTRINGTYPE(s_bitstring, char *, asn1_encode_bitstring, ASN1_BITSTRING);
DEFFIELDTYPE(bitstring_data, krb5_data,
             FIELDOF_STRING(krb5_data, s_bitstring, data, length, -1, 0));

static const struct field_info subject_pk_info_fields[] = {
    FIELDOF_NORM(krb5_subject_pk_info, algorithm_identifier, algorithm, -1, 0),
    FIELDOF_NORM(krb5_subject_pk_info, bitstring_data, subjectPublicKey, -1, 0)
};
DEFSEQTYPE(subject_pk_info, krb5_subject_pk_info, subject_pk_info_fields, 0);
DEFPTRTYPE(subject_pk_info_ptr, subject_pk_info);

DEFNULLTERMSEQOFTYPE(seq_of_algorithm_identifier, algorithm_identifier_ptr);
DEFPTRTYPE(ptr_seqof_algorithm_identifier, seq_of_algorithm_identifier);

static unsigned int
auth_pack_optional(const void *p)
{
    unsigned int optional = 0;
    const krb5_auth_pack *val = p;
    if (val->clientPublicValue != NULL)
        optional |= (1u << 1);
    if (val->supportedCMSTypes != NULL)
        optional |= (1u << 2);
    if (val->clientDHNonce.length != 0)
        optional |= (1u << 3);
    if (val->supportedKDFs != NULL)
        optional |= (1u << 4);
    return optional;
}

static const struct field_info auth_pack_fields[] = {
    FIELDOF_NORM(krb5_auth_pack, pk_authenticator, pkAuthenticator, 0, 0),
    FIELDOF_OPT(krb5_auth_pack, subject_pk_info_ptr, clientPublicValue,
                1, 0, 1),
    FIELDOF_OPT(krb5_auth_pack, ptr_seqof_algorithm_identifier,
                supportedCMSTypes, 2, 0, 2),
    FIELDOF_OPT(krb5_auth_pack, ostring_data, clientDHNonce, 3, 0, 3),
    FIELDOF_OPT(krb5_auth_pack, supported_kdfs_ptr, supportedKDFs, 4, 0, 4),
};
DEFSEQTYPE(auth_pack, krb5_auth_pack, auth_pack_fields, auth_pack_optional);

static unsigned int
auth_pack_draft9_optional(const void *p)
{
    unsigned int optional = 0;
    const krb5_auth_pack_draft9 *val = p;
    if (val->clientPublicValue != NULL)
        optional |= (1u << 1);
    return optional;
}

static const struct field_info auth_pack_draft9_fields[] = {
    FIELDOF_NORM(krb5_auth_pack_draft9, pk_authenticator_draft9,
                 pkAuthenticator, 0, 0),
    FIELDOF_OPT(krb5_auth_pack_draft9, subject_pk_info_ptr,
                clientPublicValue, 1, 0, 1),
};
DEFSEQTYPE(auth_pack_draft9, krb5_auth_pack_draft9, auth_pack_draft9_fields,
           auth_pack_draft9_optional);

static unsigned int
external_principal_identifier_optional(const void *p)
{
    unsigned int optional = 0;
    const krb5_external_principal_identifier *val = p;
    if (val->subjectName.length > 0)
        optional |= (1u << 0);
    if (val->issuerAndSerialNumber.length > 0)
        optional |= (1u << 1);
    if (val->subjectKeyIdentifier.length > 0)
        optional |= (1u << 2);
    return optional;
}

static const struct field_info external_principal_identifier_fields[] = {
    FIELDOF_OPT(krb5_external_principal_identifier, ostring_data, subjectName,
                0, 1, 0),
    FIELDOF_OPT(krb5_external_principal_identifier, ostring_data,
                issuerAndSerialNumber, 1, 1, 1),
    FIELDOF_OPT(krb5_external_principal_identifier, ostring_data,
                subjectKeyIdentifier, 2, 1, 2),
};
DEFSEQTYPE(external_principal_identifier, krb5_external_principal_identifier,
           external_principal_identifier_fields,
           external_principal_identifier_optional);
DEFPTRTYPE(external_principal_identifier_ptr, external_principal_identifier);

DEFNULLTERMSEQOFTYPE(seq_of_external_principal_identifier,
                     external_principal_identifier_ptr);
DEFPTRTYPE(ptr_seqof_external_principal_identifier,
           seq_of_external_principal_identifier);

static unsigned int
pa_pk_as_req_optional(const void *p)
{
    unsigned int optional = 0;
    const krb5_pa_pk_as_req *val = p;
    if (val->trustedCertifiers != NULL)
        optional |= (1u << 1);
    if (val->kdcPkId.length > 0)
        optional |= (1u << 2);
    return optional;
}

static const struct field_info pa_pk_as_req_fields[] = {
    FIELDOF_NORM(krb5_pa_pk_as_req, ostring_data, signedAuthPack, 0, 1),
    FIELDOF_OPT(krb5_pa_pk_as_req, ptr_seqof_external_principal_identifier,
                trustedCertifiers, 1, 0, 1),
    FIELDOF_OPT(krb5_pa_pk_as_req, ostring_data, kdcPkId, 2, 1, 2),
};
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
DEFTAGGEDTYPE(princ_0_primitive, CONTEXT_SPECIFIC, PRIMITIVE, 0, 0, principal);
typedef union krb5_trusted_ca_choices krb5_trusted_ca_choices;
typedef enum krb5_trusted_ca_selection krb5_trusted_ca_selection;
static const struct field_info trusted_ca_alternatives[] = {
    FIELDOF_NORM(krb5_trusted_ca_choices, princ_0_primitive, principalName,
                 -1, 0),
    FIELDOF_NORM(krb5_trusted_ca_choices, ostring_data, caName, 1, 1),
    FIELDOF_NORM(krb5_trusted_ca_choices, ostring_data, issuerAndSerial, 2, 1),
};
DEFCHOICETYPE(trusted_ca_choice, krb5_trusted_ca_choices,
              trusted_ca_alternatives);
DEFINTTYPE(trusted_ca_selection, krb5_trusted_ca_selection);
DEFFIELDTYPE(trusted_ca, krb5_trusted_ca,
             FIELDOF_CHOICE(krb5_trusted_ca, trusted_ca_choice, u, choice,
                            trusted_ca_selection, -1));
DEFPTRTYPE(trusted_ca_ptr, trusted_ca);

DEFNULLTERMSEQOFTYPE(seq_of_trusted_ca, trusted_ca_ptr);
DEFPTRTYPE(ptr_seqof_trusted_ca, seq_of_trusted_ca);

static unsigned int
pa_pk_as_req_draft9_optional(const void *p)
{
    unsigned int optional = 0;
    const krb5_pa_pk_as_req_draft9 *val = p;
    if (val->trustedCertifiers != NULL)
        optional |= (1u << 1);
    if (val->kdcCert.length > 0)
        optional |= (1u << 2);
    if (val->encryptionCert.length > 0)
        optional |= (1u << 3);
    return optional;
}

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
static const struct field_info pa_pk_as_req_draft9_fields[] = {
    FIELDOF_NORM(krb5_pa_pk_as_req_draft9, ostring_data, signedAuthPack, 0, 1),
    FIELDOF_OPT(krb5_pa_pk_as_req_draft9, ptr_seqof_trusted_ca,
                trustedCertifiers, 1, 0, 1),
    FIELDOF_OPT(krb5_pa_pk_as_req_draft9, ostring_data, kdcCert, 2, 1, 2),
    FIELDOF_OPT(krb5_pa_pk_as_req_draft9, ostring_data, encryptionCert,
                3, 1, 3),
};
DEFSEQTYPE(pa_pk_as_req_draft9, krb5_pa_pk_as_req_draft9,
           pa_pk_as_req_draft9_fields, pa_pk_as_req_draft9_optional);

static unsigned int
dh_rep_info_optional(const void *p)
{
    unsigned int optional = 0;
    const krb5_dh_rep_info *val = p;
    if (val->serverDHNonce.length > 0)
        optional |= (1u << 1);
    if (val->kdfID != NULL)
        optional |= (1u << 2);
    return optional;
}

static const struct field_info dh_rep_info_fields[] = {
    FIELDOF_NORM(krb5_dh_rep_info, ostring_data, dhSignedData, 0, 1),
    FIELDOF_OPT(krb5_dh_rep_info, ostring_data, serverDHNonce, 1, 0, 1),
    FIELDOF_OPT(krb5_dh_rep_info, kdf_alg_id_ptr, kdfID, 2, 0, 2),
};
DEFSEQTYPE(dh_rep_info, krb5_dh_rep_info,
           dh_rep_info_fields, dh_rep_info_optional);

static unsigned int
kdc_dh_key_info_optional(const void *p)
{
    unsigned int optional = 0;
    const krb5_kdc_dh_key_info *val = p;
    if (val->dhKeyExpiration != 0)
        optional |= (1u << 2);
    return optional;
}

static const struct field_info kdc_dh_key_info_fields[] = {
    FIELDOF_NORM(krb5_kdc_dh_key_info, bitstring_data, subjectPublicKey, 0, 0),
    FIELDOF_NORM(krb5_kdc_dh_key_info, int32, nonce, 1, 0),
    FIELDOF_OPT(krb5_kdc_dh_key_info, kerberos_time, dhKeyExpiration, 2, 0, 2),
};
DEFSEQTYPE(kdc_dh_key_info, krb5_kdc_dh_key_info, kdc_dh_key_info_fields,
           kdc_dh_key_info_optional);


static const struct field_info reply_key_pack_fields[] = {
    FIELDOF_NORM(krb5_reply_key_pack, encryption_key, replyKey, 0, 0),
    FIELDOF_NORM(krb5_reply_key_pack, checksum, asChecksum, 1, 0),
};
DEFSEQTYPE(reply_key_pack, krb5_reply_key_pack, reply_key_pack_fields, 0);

static const struct field_info reply_key_pack_draft9_fields[] = {
    FIELDOF_NORM(krb5_reply_key_pack_draft9, encryption_key, replyKey, 0, 0),
    FIELDOF_NORM(krb5_reply_key_pack_draft9, int32, nonce, 1, 0),
};
DEFSEQTYPE(reply_key_pack_draft9, krb5_reply_key_pack_draft9,
           reply_key_pack_draft9_fields, 0);

typedef union krb5_pa_pk_as_rep_choices krb5_pa_pk_as_rep_choices;
typedef enum krb5_pa_pk_as_rep_selection krb5_pa_pk_as_rep_selection;
static const struct field_info pa_pk_as_rep_alternatives[] = {
    FIELDOF_NORM(krb5_pa_pk_as_rep_choices, dh_rep_info, dh_Info, 0, 0),
    FIELDOF_NORM(krb5_pa_pk_as_rep_choices, ostring_data, encKeyPack, 1, 1),
};
DEFCHOICETYPE(pa_pk_as_rep_choice, krb5_pa_pk_as_rep_choices,
              pa_pk_as_rep_alternatives);
DEFINTTYPE(pa_pk_as_rep_selection, krb5_pa_pk_as_rep_selection);
DEFFIELDTYPE(pa_pk_as_rep, krb5_pa_pk_as_rep,
             FIELDOF_CHOICE(krb5_pa_pk_as_rep, pa_pk_as_rep_choice, u, choice,
                            pa_pk_as_rep_selection, -1));

/*
 * draft-ietf-cat-kerberos-pk-init-09 specifies these alternatives as
 * explicitly tagged SignedData and EnvelopedData respectively, which means
 * they should have constructed context tags.  However, our historical behavior
 * is to use primitive context tags, and we don't want to change that behavior
 * without interop testing.  We have the encodings for each alternative in a
 * krb5_data object; pretend that they are wrapped in IMPLICIT OCTET STRING in
 * order to wrap them in primitive [0] and [1] tags.
 */
typedef union krb5_pa_pk_as_rep_draft9_choices
krb5_pa_pk_as_rep_draft9_choices;
typedef enum krb5_pa_pk_as_rep_draft9_selection
krb5_pa_pk_as_rep_draft9_selection;
static const struct field_info pa_pk_as_rep_draft9_alternatives[] = {
    FIELDOF_NORM(krb5_pa_pk_as_rep_draft9_choices, ostring_data, dhSignedData,
                 0, 1),
    FIELDOF_NORM(krb5_pa_pk_as_rep_draft9_choices, ostring_data, encKeyPack,
                 1, 1),
};
DEFCHOICETYPE(pa_pk_as_rep_draft9_choice, krb5_pa_pk_as_rep_draft9_choices,
              pa_pk_as_rep_draft9_alternatives);
DEFINTTYPE(pa_pk_as_rep_draft9_selection, krb5_pa_pk_as_rep_draft9_selection);
DEFFIELDTYPE(pa_pk_as_rep_draft9, krb5_pa_pk_as_rep_draft9,
             FIELDOF_CHOICE(krb5_pa_pk_as_rep_draft9,
                            pa_pk_as_rep_draft9_choice, u, choice,
                            pa_pk_as_rep_draft9_selection, -1));

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
                  seq_of_external_principal_identifier);
MAKE_FULL_ENCODER(encode_krb5_td_dh_parameters, seq_of_algorithm_identifier);

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

static const struct field_info typed_data_fields[] = {
    FIELDOF_NORM(krb5_pa_data, int32, pa_type, 0, 0),
    FIELDOF_STRING(krb5_pa_data, octetstring, contents, length, 1, 0),
};
DEFSEQTYPE(typed_data, krb5_pa_data, typed_data_fields, 0);
DEFPTRTYPE(typed_data_ptr, typed_data);

DEFNULLTERMSEQOFTYPE(seq_of_typed_data, typed_data_ptr);
MAKE_FULL_ENCODER(encode_krb5_typed_data, seq_of_typed_data);

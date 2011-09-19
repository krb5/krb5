/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/asn.1/asn1_k_decode.c */
/*
 * Copyright 1994, 2007, 2008 by the Massachusetts Institute of Technology.
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

#include "asn1_k_decode.h"
#include "asn1_k_decode_macros.h"
#include "asn1_decode.h"
#include "asn1_get.h"
#include "asn1_misc.h"

integer_convert(asn1_decode_int,int)
integer_convert(asn1_decode_int32,krb5_int32)
integer_convert(asn1_decode_kvno,krb5_kvno)
integer_convert(asn1_decode_enctype,krb5_enctype)
integer_convert(asn1_decode_cksumtype,krb5_cksumtype)
integer_convert(asn1_decode_octet,krb5_octet)
integer_convert(asn1_decode_addrtype,krb5_addrtype)
integer_convert(asn1_decode_authdatatype,krb5_authdatatype)
unsigned_integer_convert(asn1_decode_ui_2,krb5_ui_2)
unsigned_integer_convert(asn1_decode_ui_4,krb5_ui_4)

/* scalars */
asn1_error_code
asn1_decode_kerberos_time(asn1buf *buf, krb5_timestamp *val)
{
    time_t      t;
    asn1_error_code retval;

    retval =  asn1_decode_generaltime(buf,&t);
    if (retval)
        return retval;

    *val = t;
    return 0;
}

asn1_error_code
asn1_decode_seqnum(asn1buf *buf, krb5_ui_4 *val)
{
    asn1_error_code retval;
    unsigned long n;

    retval = asn1_decode_maybe_unsigned(buf, &n);
    if (retval) return retval;
    *val = (krb5_ui_4)n & 0xffffffff;
    return 0;
}

asn1_error_code
asn1_decode_msgtype(asn1buf *buf, krb5_msgtype *val)
{
    asn1_error_code retval;
    unsigned long n;

    retval = asn1_decode_unsigned_integer(buf,&n);
    if (retval) return retval;

    *val = (krb5_msgtype) n;
    return 0;
}


/* structures */
asn1_error_code
asn1_decode_realm(asn1buf *buf, krb5_principal *val)
{
    return asn1_decode_generalstring(buf,
                                     &((*val)->realm.length),
                                     &((*val)->realm.data));
}

asn1_error_code
asn1_decode_principal_name(asn1buf *buf, krb5_principal *val)
{
    int size = 0, i;
    krb5_data *array = NULL, *new_array;

    setup();
    { begin_structure();
        get_field((*val)->type,0,asn1_decode_int32);

        { sequence_of_no_tagvars(&subbuf);
            while (asn1buf_remains(&seqbuf,seqofindef) > 0) {
                unsigned int len;
                char *str;

                new_array = realloc(array, (size + 1) * sizeof(krb5_data));
                if (new_array == NULL) clean_return(ENOMEM);
                array = new_array;
                retval = asn1_decode_generalstring(&seqbuf, &len, &str);
                if (retval) clean_return(retval);
                array[size].data = str;
                array[size].length = len;
                size++;
            }
            end_sequence_of_no_tagvars(&subbuf);
        }
        if (indef) {
            get_eoc();
        }
        next_tag();
        end_structure();
    }
    (*val)->data = array;
    (*val)->length = size;
    (*val)->magic = KV5M_PRINCIPAL;
    return 0;
error_out:
    for (i = 0; i < size; i++)
        free(array[i].data);
    free(array);
    return retval;
}

asn1_error_code
asn1_decode_checksum(asn1buf *buf, krb5_checksum *val)
{
    setup();
    val->contents = NULL;
    { begin_structure();
        get_field(val->checksum_type,0,asn1_decode_cksumtype);
        get_lenfield(val->length,val->contents,1,asn1_decode_octetstring);
        end_structure();
        val->magic = KV5M_CHECKSUM;
    }
    return 0;
error_out:
    free(val->contents);
    return retval;
}

asn1_error_code
asn1_decode_checksum_ptr(asn1buf *buf, krb5_checksum **valptr)
{
    decode_ptr(krb5_checksum *, asn1_decode_checksum);
}

asn1_error_code
asn1_decode_encryption_key(asn1buf *buf, krb5_keyblock *val)
{
    setup();
    val->contents = NULL;
    { begin_structure();
        get_field(val->enctype,0,asn1_decode_enctype);
        get_lenfield(val->length,val->contents,1,asn1_decode_octetstring);
        end_structure();
        val->magic = KV5M_KEYBLOCK;
    }
    return 0;
error_out:
    free(val->contents);
    return retval;
}

asn1_error_code
asn1_decode_encryption_key_ptr(asn1buf *buf, krb5_keyblock **valptr)
{
    decode_ptr(krb5_keyblock *, asn1_decode_encryption_key);
}

asn1_error_code
asn1_decode_encrypted_data(asn1buf *buf, krb5_enc_data *val)
{
    setup();
    val->ciphertext.data = NULL;
    { begin_structure();
        get_field(val->enctype,0,asn1_decode_enctype);
        opt_field(val->kvno,1,asn1_decode_kvno,0);
        get_lenfield(val->ciphertext.length,val->ciphertext.data,2,asn1_decode_charstring);
        end_structure();
        val->magic = KV5M_ENC_DATA;
    }
    return 0;
error_out:
    free(val->ciphertext.data);
    val->ciphertext.data = NULL;
    return retval;
}

asn1_error_code
asn1_decode_krb5_flags(asn1buf *buf, krb5_flags *val)
{
    asn1_error_code retval;
    asn1_octet unused, o;
    taginfo t;
    unsigned int i;
    krb5_flags f=0;
    unsigned int length;

    retval = asn1_get_tag_2(buf, &t);
    if (retval) return retval;
    if (t.asn1class != UNIVERSAL || t.construction != PRIMITIVE ||
        t.tagnum != ASN1_BITSTRING)
        return ASN1_BAD_ID;
    length = t.length;

    retval = asn1buf_remove_octet(buf,&unused); /* # of padding bits */
    if (retval) return retval;

    /* Number of unused bits must be between 0 and 7. */
    if (unused > 7) return ASN1_BAD_FORMAT;
    length--;

    for (i = 0; i < length; i++) {
        retval = asn1buf_remove_octet(buf,&o);
        if (retval) return retval;
        /* ignore bits past number 31 */
        if (i < 4)
            f = (f<<8) | ((krb5_flags)o&0xFF);
    }
    if (length <= 4) {
        /* Mask out unused bits, but only if necessary. */
        f &= ~(krb5_flags)0 << unused;
    }
    /* left-justify */
    if (length < 4)
        f <<= (4 - length) * 8;
    *val = f;
    return 0;
}

asn1_error_code
asn1_decode_ticket_flags(asn1buf *buf, krb5_flags *val)
{ return asn1_decode_krb5_flags(buf,val); }

asn1_error_code
asn1_decode_ap_options(asn1buf *buf, krb5_flags *val)
{ return asn1_decode_krb5_flags(buf,val); }

asn1_error_code
asn1_decode_kdc_options(asn1buf *buf, krb5_flags *val)
{ return asn1_decode_krb5_flags(buf,val); }

asn1_error_code
asn1_decode_transited_encoding(asn1buf *buf, krb5_transited *val)
{
    setup();
    val->tr_contents.data = NULL;
    { begin_structure();
        get_field(val->tr_type,0,asn1_decode_octet);
        get_lenfield(val->tr_contents.length,val->tr_contents.data,1,asn1_decode_charstring);
        end_structure();
        val->magic = KV5M_TRANSITED;
    }
    return 0;
error_out:
    krb5_free_data_contents(NULL, &val->tr_contents);
    return retval;
}

asn1_error_code
asn1_decode_enc_kdc_rep_part(asn1buf *buf, krb5_enc_kdc_rep_part *val)
{
    setup();
    val->session = NULL;
    val->last_req = NULL;
    val->server = NULL;
    val->caddrs = NULL;
    val->enc_padata = NULL;
    { begin_structure();
        get_field(val->session,0,asn1_decode_encryption_key_ptr);
        get_field(val->last_req,1,asn1_decode_last_req);
        get_field(val->nonce,2,asn1_decode_int32);
        opt_field(val->key_exp,3,asn1_decode_kerberos_time,0);
        get_field(val->flags,4,asn1_decode_ticket_flags);
        get_field(val->times.authtime,5,asn1_decode_kerberos_time);
        /* Set to authtime if missing */
        opt_field(val->times.starttime,6,asn1_decode_kerberos_time,val->times.authtime);
        get_field(val->times.endtime,7,asn1_decode_kerberos_time);
        opt_field(val->times.renew_till,8,asn1_decode_kerberos_time,0);
        alloc_principal(val->server);
        get_field(val->server,9,asn1_decode_realm);
        get_field(val->server,10,asn1_decode_principal_name);
        opt_field(val->caddrs,11,asn1_decode_host_addresses,NULL);
        opt_field(val->enc_padata,12,asn1_decode_sequence_of_pa_data,NULL);
        end_structure();
        val->magic = KV5M_ENC_KDC_REP_PART;
    }
    return 0;
error_out:
    krb5_free_keyblock(NULL, val->session);
    krb5_free_last_req(NULL, val->last_req);
    krb5_free_principal(NULL, val->server);
    krb5_free_addresses(NULL, val->caddrs);
    krb5_free_pa_data(NULL, val->enc_padata);
    val->session = NULL;
    val->last_req = NULL;
    val->server = NULL;
    val->caddrs = NULL;
    return retval;
}

asn1_error_code
asn1_decode_ticket(asn1buf *buf, krb5_ticket *val)
{
    setup();
    unsigned int applen;
    apptag(1);
    val->server = NULL;
    val->enc_part.ciphertext.data = NULL;
    val->enc_part2 = NULL;
    { begin_structure();
        { krb5_kvno vno;
            get_field(vno,0,asn1_decode_kvno);
            if (vno != KVNO) clean_return(KRB5KDC_ERR_BAD_PVNO); }
        alloc_principal(val->server);
        get_field(val->server,1,asn1_decode_realm);
        get_field(val->server,2,asn1_decode_principal_name);
        get_field(val->enc_part,3,asn1_decode_encrypted_data);
        end_structure();
        val->magic = KV5M_TICKET;
    }
    if (!applen) {
        taginfo t;
        retval = asn1_get_tag_2(buf, &t);
        if (retval) clean_return(retval);
    }
    return 0;
error_out:
    krb5_free_principal(NULL, val->server);
    krb5_free_data_contents(NULL, &val->enc_part.ciphertext);
    val->server = NULL;
    return retval;
}

asn1_error_code
asn1_decode_ticket_ptr(asn1buf *buf, krb5_ticket **valptr)
{
    decode_ptr(krb5_ticket *, asn1_decode_ticket);
}

asn1_error_code
asn1_decode_krb_safe_body(asn1buf *buf, krb5_safe *val)
{
    setup();
    val->user_data.data = NULL;
    val->r_address = NULL;
    val->s_address = NULL;
    val->checksum = NULL;
    { begin_structure();
        get_lenfield(val->user_data.length,val->user_data.data,0,asn1_decode_charstring);
        opt_field(val->timestamp,1,asn1_decode_kerberos_time,0);
        opt_field(val->usec,2,asn1_decode_int32,0);
        opt_field(val->seq_number,3,asn1_decode_seqnum,0);
        get_field(val->s_address,4,asn1_decode_host_address_ptr);
        if (tagnum == 5) {
            get_field(val->r_address,5,asn1_decode_host_address_ptr);
        }
        end_structure();
        val->magic = KV5M_SAFE;
    }
    return 0;
error_out:
    krb5_free_data_contents(NULL, &val->user_data);
    krb5_free_address(NULL, val->r_address);
    krb5_free_address(NULL, val->s_address);
    val->r_address = NULL;
    val->s_address = NULL;
    return retval;
}

asn1_error_code
asn1_decode_host_address(asn1buf *buf, krb5_address *val)
{
    setup();
    val->contents = NULL;
    { begin_structure();
        get_field(val->addrtype,0,asn1_decode_addrtype);
        get_lenfield(val->length,val->contents,1,asn1_decode_octetstring);
        end_structure();
        val->magic = KV5M_ADDRESS;
    }
    return 0;
error_out:
    free(val->contents);
    val->contents = NULL;
    return retval;
}

asn1_error_code
asn1_decode_host_address_ptr(asn1buf *buf, krb5_address **valptr)
{
    decode_ptr(krb5_address *, asn1_decode_host_address);
}

asn1_error_code
asn1_decode_kdc_rep(asn1buf *buf, krb5_kdc_rep *val)
{
    setup();
    val->padata = NULL;
    val->client = NULL;
    val->ticket = NULL;
    val->enc_part.ciphertext.data = NULL;
    val->enc_part2 = NULL;
    { begin_structure();
        { krb5_kvno pvno;
            get_field(pvno,0,asn1_decode_kvno);
            if (pvno != KVNO) clean_return(KRB5KDC_ERR_BAD_PVNO); }
        get_field(val->msg_type,1,asn1_decode_msgtype);
        opt_field(val->padata,2,asn1_decode_sequence_of_pa_data,NULL);
        alloc_principal(val->client);
        get_field(val->client,3,asn1_decode_realm);
        get_field(val->client,4,asn1_decode_principal_name);
        get_field(val->ticket,5,asn1_decode_ticket_ptr);
        get_field(val->enc_part,6,asn1_decode_encrypted_data);
        end_structure();
        val->magic = KV5M_KDC_REP;
    }
    return 0;
error_out:
    krb5_free_pa_data(NULL, val->padata);
    krb5_free_principal(NULL, val->client);
    krb5_free_ticket(NULL, val->ticket);
    krb5_free_data_contents(NULL, &val->enc_part.ciphertext);
    val->padata = NULL;
    val->client = NULL;
    val->ticket = NULL;
    val->enc_part.ciphertext.data = NULL;
    return retval;
}


/* arrays */
#define get_element(element,decoder)            \
    retval = decoder(&seqbuf,&element);         \
    if (retval) clean_return(retval)

/*
 * Function body for array decoders.  freefn is expected to look like
 * a krb5_free_ function, so we pass a null first argument.
 */
#define decode_array_body(type,decoder,freefn)                  \
    asn1_error_code retval;                                     \
    type *elt = NULL, **array;                                  \
    int size = 0, i;                                            \
                                                                \
    array = *val = NULL;                                        \
    { sequence_of(buf);                                         \
        while (asn1buf_remains(&seqbuf,seqofindef) > 0) {       \
            get_element(elt,decoder);                           \
            array_append(&array,size,elt,type);                 \
            elt = NULL;                                         \
        }                                                       \
        if (array == NULL)                                      \
            array = malloc(sizeof(type*));                      \
        array[size] = NULL;                                     \
        end_sequence_of(buf);                                   \
    }                                                           \
    *val = array;                                               \
    return 0;                                                   \
error_out:                                                      \
if (elt)                                                        \
    freefn(NULL,elt);                                           \
for (i = 0; i < size; i++)                                      \
    freefn(NULL,array[i]);                                      \
free(array);                                                    \
return retval

static void *
array_expand (void *array, int n_elts, size_t elt_size)
{
    size_t new_size;

    if (n_elts <= 0)
        return NULL;
    if ((unsigned int) n_elts > SIZE_MAX / elt_size)
        return NULL;
    new_size = n_elts * elt_size;
    if (new_size == 0)
        return NULL;
    if (new_size / elt_size != (unsigned int) n_elts)
        return NULL;
    return realloc(array, new_size);
}

#define array_append(array,size,element,type)                           \
    {                                                                   \
        void *new_array = array_expand(*(array), (size)+2, sizeof(type*)); \
        if (new_array == NULL) clean_return(ENOMEM);                    \
        *(array) = new_array;                                           \
        (*(array))[(size)++] = elt;                                     \
    }


static void
free_authdata_elt(void *dummy, krb5_authdata *val)
{
    free(val->contents);
    free(val);
}

asn1_error_code
asn1_decode_authorization_data(asn1buf *buf, krb5_authdata ***val)
{
    decode_array_body(krb5_authdata,asn1_decode_authdata_elt_ptr,
                      free_authdata_elt);
}

asn1_error_code
asn1_decode_authdata_elt(asn1buf *buf, krb5_authdata *val)
{
    setup();
    val->contents = NULL;
    { begin_structure();
        get_field(val->ad_type,0,asn1_decode_authdatatype);
        get_lenfield(val->length,val->contents,1,asn1_decode_octetstring);
        end_structure();
        val->magic = KV5M_AUTHDATA;
    }
    return 0;
error_out:
    free(val->contents);
    val->contents = NULL;
    return retval;
}

static asn1_error_code
asn1_peek_authdata_elt(asn1buf *buf, krb5_authdatatype *val)
{
    setup();
    *val = 0;
    { begin_structure();
        get_field(*val, 0, asn1_decode_authdatatype);
        end_structure();
    }
    return 0;
error_out:
    return retval;
}

asn1_error_code
asn1_peek_authorization_data(asn1buf *buf, unsigned int *num,
                             krb5_authdatatype **val)
{
    int size = 0;
    krb5_authdatatype *array = NULL, *new_array;

    asn1_error_code retval;
    { sequence_of(buf);
        while (asn1buf_remains(&seqbuf,seqofindef) > 0) {
            size++;
            new_array = realloc(array,size*sizeof(krb5_authdatatype));
            if (new_array == NULL) clean_return(ENOMEM);
            array = new_array;
            retval = asn1_peek_authdata_elt(&seqbuf,&array[size-1]);
            if (retval) clean_return(retval);
        }
        end_sequence_of(buf);
    }
    *num = size;
    *val = array;
    return 0;
error_out:
    free(array);
    return retval;
}

asn1_error_code
asn1_decode_authdata_elt_ptr(asn1buf *buf, krb5_authdata **valptr)
{
    decode_ptr(krb5_authdata *, asn1_decode_authdata_elt);
}

asn1_error_code
asn1_decode_host_addresses(asn1buf *buf, krb5_address ***val)
{
    decode_array_body(krb5_address,asn1_decode_host_address_ptr,
                      krb5_free_address);
}

asn1_error_code
asn1_decode_sequence_of_ticket(asn1buf *buf, krb5_ticket ***val)
{
    decode_array_body(krb5_ticket,asn1_decode_ticket_ptr,krb5_free_ticket);
}

static void
free_cred_info(void *dummy, krb5_cred_info *val)
{
    krb5_free_keyblock(NULL, val->session);
    krb5_free_principal(NULL, val->client);
    krb5_free_principal(NULL, val->server);
    krb5_free_addresses(NULL, val->caddrs);
    free(val);
}

asn1_error_code
asn1_decode_sequence_of_krb_cred_info(asn1buf *buf, krb5_cred_info ***val)
{
    decode_array_body(krb5_cred_info,asn1_decode_krb_cred_info_ptr,
                      free_cred_info);
}

asn1_error_code
asn1_decode_krb_cred_info(asn1buf *buf, krb5_cred_info *val)
{
    setup();
    val->session = NULL;
    val->client = NULL;
    val->server = NULL;
    val->caddrs = NULL;
    { begin_structure();
        get_field(val->session,0,asn1_decode_encryption_key_ptr);
        if (tagnum == 1) {
            alloc_principal(val->client);
            opt_field(val->client,1,asn1_decode_realm,NULL);
            opt_field(val->client,2,asn1_decode_principal_name,NULL); }
        opt_field(val->flags,3,asn1_decode_ticket_flags,0);
        opt_field(val->times.authtime,4,asn1_decode_kerberos_time,0);
        opt_field(val->times.starttime,5,asn1_decode_kerberos_time,0);
        opt_field(val->times.endtime,6,asn1_decode_kerberos_time,0);
        opt_field(val->times.renew_till,7,asn1_decode_kerberos_time,0);
        if (tagnum == 8) {
            alloc_principal(val->server);
            opt_field(val->server,8,asn1_decode_realm,NULL);
            opt_field(val->server,9,asn1_decode_principal_name,NULL); }
        opt_field(val->caddrs,10,asn1_decode_host_addresses,NULL);
        end_structure();
        val->magic = KV5M_CRED_INFO;
    }
    return 0;
error_out:
    krb5_free_keyblock(NULL, val->session);
    krb5_free_principal(NULL, val->client);
    krb5_free_principal(NULL, val->server);
    krb5_free_addresses(NULL, val->caddrs);
    val->session = NULL;
    val->client = NULL;
    val->server = NULL;
    val->caddrs = NULL;
    return retval;
}

asn1_error_code
asn1_decode_krb_cred_info_ptr(asn1buf *buf, krb5_cred_info **valptr)
{
    decode_ptr(krb5_cred_info *, asn1_decode_krb_cred_info);
}

static void
free_pa_data(void *dummy, krb5_pa_data *val)
{
    free(val->contents);
    free(val);
}

asn1_error_code
asn1_decode_sequence_of_pa_data(asn1buf *buf, krb5_pa_data ***val)
{
    decode_array_body(krb5_pa_data,asn1_decode_pa_data_ptr,free_pa_data);
}

asn1_error_code
asn1_decode_pa_data(asn1buf *buf, krb5_pa_data *val)
{
    setup();
    val->contents = NULL;
    { begin_structure();
        get_field(val->pa_type,1,asn1_decode_int32);
        get_lenfield(val->length,val->contents,2,asn1_decode_octetstring);
        end_structure();
        val->magic = KV5M_PA_DATA;
    }
    return 0;
error_out:
    free(val->contents);
    val->contents = NULL;
    return retval;
}

asn1_error_code
asn1_decode_pa_data_ptr(asn1buf *buf, krb5_pa_data **valptr)
{
    decode_ptr(krb5_pa_data *, asn1_decode_pa_data);
}

static void
free_last_req_entry(void *dummy, krb5_last_req_entry *val)
{
    free(val);
}

asn1_error_code
asn1_decode_last_req(asn1buf *buf, krb5_last_req_entry ***val)
{
    decode_array_body(krb5_last_req_entry,asn1_decode_last_req_entry_ptr,
                      free_last_req_entry);
}

asn1_error_code
asn1_decode_last_req_entry(asn1buf *buf, krb5_last_req_entry *val)
{
    setup();
    { begin_structure();
        get_field(val->lr_type,0,asn1_decode_int32);
        get_field(val->value,1,asn1_decode_kerberos_time);
        end_structure();
        val->magic = KV5M_LAST_REQ_ENTRY;
#ifdef KRB5_GENEROUS_LR_TYPE
        /* If we are only a single byte wide and negative - fill in the
           other bits */
        if ((val->lr_type & 0xffffff80U) == 0x80) val->lr_type |= 0xffffff00U;
#endif
    }
    return 0;
error_out:
    return retval;
}

asn1_error_code
asn1_decode_last_req_entry_ptr(asn1buf *buf, krb5_last_req_entry **valptr)
{
    decode_ptr(krb5_last_req_entry *, asn1_decode_last_req_entry);
}

asn1_error_code
asn1_decode_sequence_of_enctype(asn1buf *buf, int *num, krb5_enctype **val)
{
    int size = 0;
    krb5_enctype *array = NULL, *new_array;

    asn1_error_code retval;
    { sequence_of(buf);
        while (asn1buf_remains(&seqbuf,seqofindef) > 0) {
            size++;
            new_array = realloc(array,size*sizeof(krb5_enctype));
            if (new_array == NULL) clean_return(ENOMEM);
            array = new_array;
            retval = asn1_decode_enctype(&seqbuf,&array[size-1]);
            if (retval) clean_return(retval);
        }
        end_sequence_of(buf);
    }
    *num = size;
    *val = array;
    return 0;
error_out:
    free(array);
    return retval;
}

asn1_error_code
asn1_decode_sequence_of_checksum(asn1buf *buf, krb5_checksum ***val)
{
    decode_array_body(krb5_checksum, asn1_decode_checksum_ptr,
                      krb5_free_checksum);
}

static void
free_etype_info_entry(void *dummy, krb5_etype_info_entry *val)
{
    krb5_free_data_contents(NULL, &val->s2kparams);
    free(val->salt);
    free(val);
}

static asn1_error_code
asn1_decode_etype_info2_entry(asn1buf *buf, krb5_etype_info_entry *val)
{
    char *salt = NULL;
    krb5_octet *params = NULL;
    setup();
    val->salt = NULL;
    val->s2kparams.data = NULL;
    { begin_structure();
        get_field(val->etype,0,asn1_decode_enctype);
        if (tagnum == 1) {
            get_lenfield(val->length,salt,1,asn1_decode_generalstring);
            val->salt = (krb5_octet *) salt;
            salt = NULL;
        } else
            val->length = KRB5_ETYPE_NO_SALT;
        if ( tagnum ==2) {
            get_lenfield( val->s2kparams.length, params,
                          2, asn1_decode_octetstring);
            val->s2kparams.data = ( char *) params;
            params = NULL;
        } else
            val->s2kparams.length = 0;
        end_structure();
        val->magic = KV5M_ETYPE_INFO_ENTRY;
    }
    return 0;
error_out:
    free(salt);
    free(params);
    krb5_free_data_contents(NULL, &val->s2kparams);
    free(val->salt);
    val->salt = NULL;
    return retval;
}

static asn1_error_code
asn1_decode_etype_info2_entry_ptr(asn1buf *buf, krb5_etype_info_entry **valptr)
{
    decode_ptr(krb5_etype_info_entry *, asn1_decode_etype_info2_entry);
}

static asn1_error_code
asn1_decode_etype_info2_entry_1_3(asn1buf *buf, krb5_etype_info_entry *val)
{
    krb5_octet *params = NULL;

    setup();
    val->salt = NULL;
    val->s2kparams.data = NULL;
    { begin_structure();
        get_field(val->etype,0,asn1_decode_enctype);
        if (tagnum == 1) {
            get_lenfield(val->length,val->salt,1,asn1_decode_octetstring);
        } else
            val->length = KRB5_ETYPE_NO_SALT;
        if ( tagnum ==2) {
            get_lenfield( val->s2kparams.length, params,
                          2, asn1_decode_octetstring);
            val->s2kparams.data = ( char *) params;
            params = NULL;
        } else
            val->s2kparams.length = 0;
        end_structure();
        val->magic = KV5M_ETYPE_INFO_ENTRY;
    }
    return 0;
error_out:
    krb5_free_data_contents(NULL, &val->s2kparams);
    free(params);
    free(val->salt);
    val->salt = NULL;
    return retval;
}

static asn1_error_code
asn1_decode_etype_info2_entry_1_3_ptr(asn1buf *buf,
                                      krb5_etype_info_entry **valptr)
{
    decode_ptr(krb5_etype_info_entry *, asn1_decode_etype_info2_entry_1_3);
}

static asn1_error_code
asn1_decode_etype_info_entry(asn1buf *buf, krb5_etype_info_entry *val)
{
    setup();
    val->salt = NULL;
    val->s2kparams.data = NULL;
    { begin_structure();
        get_field(val->etype,0,asn1_decode_enctype);
        if (tagnum == 1) {
            get_lenfield(val->length,val->salt,1,asn1_decode_octetstring);
        } else
            val->length = KRB5_ETYPE_NO_SALT;
        val->s2kparams.length = 0;

        end_structure();
        val->magic = KV5M_ETYPE_INFO_ENTRY;
    }
    return 0;
error_out:
    free(val->salt);
    val->salt = NULL;
    return retval;
}

static asn1_error_code
asn1_decode_etype_info_entry_ptr(asn1buf *buf, krb5_etype_info_entry **valptr)
{
    decode_ptr(krb5_etype_info_entry *, asn1_decode_etype_info_entry);
}

asn1_error_code
asn1_decode_etype_info(asn1buf *buf, krb5_etype_info_entry ***val )
{
    decode_array_body(krb5_etype_info_entry,asn1_decode_etype_info_entry_ptr,
                      free_etype_info_entry);
}

static asn1_error_code
decode_etype_info2_13(asn1buf *buf, krb5_etype_info_entry ***val)
{
    decode_array_body(krb5_etype_info_entry,
                      asn1_decode_etype_info2_entry_1_3_ptr,
                      free_etype_info_entry);
}

asn1_error_code
asn1_decode_etype_info2(asn1buf *buf, krb5_etype_info_entry ***val ,
                        krb5_boolean v1_3_behavior)
{
    if (v1_3_behavior)
        return decode_etype_info2_13(buf, val);
    else {
        decode_array_body(krb5_etype_info_entry,
                          asn1_decode_etype_info2_entry_ptr,
                          free_etype_info_entry);
    }
}

asn1_error_code
asn1_decode_passwdsequence(asn1buf *buf, passwd_phrase_element *val)
{
    setup();
    val->passwd = NULL;
    val->phrase = NULL;
    { begin_structure();
        alloc_data(val->passwd);
        get_lenfield(val->passwd->length,val->passwd->data,
                     0,asn1_decode_charstring);
        val->passwd->magic = KV5M_DATA;
        alloc_data(val->phrase);
        get_lenfield(val->phrase->length,val->phrase->data,
                     1,asn1_decode_charstring);
        val->phrase->magic = KV5M_DATA;
        end_structure();
        val->magic = KV5M_PASSWD_PHRASE_ELEMENT;
    }
    return 0;
error_out:
    krb5_free_data(NULL, val->passwd);
    krb5_free_data(NULL, val->phrase);
    val->passwd = NULL;
    val->phrase = NULL;
    return 0;
}

asn1_error_code
asn1_decode_passwdsequence_ptr(asn1buf *buf, passwd_phrase_element **valptr)
{
    decode_ptr(passwd_phrase_element *, asn1_decode_passwdsequence);
}

asn1_error_code
asn1_decode_sequence_of_passwdsequence(asn1buf *buf,
                                       passwd_phrase_element ***val)
{
    decode_array_body(passwd_phrase_element,asn1_decode_passwdsequence_ptr,
                      krb5_free_passwd_phrase_element);
}
asn1_error_code
asn1_decode_setpw_req(asn1buf *buf, krb5_data *newpasswd,
                      krb5_principal *principal)
{
    krb5_principal princ = NULL;
    setup();
    *principal = NULL;

    newpasswd->data = NULL;
    { begin_structure();
        get_lenfield(newpasswd->length, newpasswd->data, 0, asn1_decode_charstring);
        if (tagnum == 1) {
            alloc_principal(princ);
            opt_field(princ, 1, asn1_decode_principal_name, 0);
            opt_field(princ, 2, asn1_decode_realm, 0);
        }
        end_structure();
    }
    *principal = princ;
    return 0;
error_out:
    krb5_free_data_contents(NULL, newpasswd);
    krb5_free_principal(NULL, princ);
    return retval;
}

asn1_error_code
asn1_decode_pa_for_user(asn1buf *buf, krb5_pa_for_user *val)
{
    setup();
    val->user = NULL;
    val->cksum.contents = NULL;
    val->auth_package.data = NULL;
    { begin_structure();
        alloc_principal(val->user);
        get_field(val->user,0,asn1_decode_principal_name);
        get_field(val->user,1,asn1_decode_realm);
        get_field(val->cksum,2,asn1_decode_checksum);
        get_lenfield(val->auth_package.length,val->auth_package.data,3,asn1_decode_generalstring);
        end_structure();
    }
    return 0;
error_out:
    krb5_free_principal(NULL, val->user);
    krb5_free_checksum_contents(NULL, &val->cksum);
    krb5_free_data_contents(NULL, &val->auth_package);
    val->user = NULL;
    return retval;
}

asn1_error_code
asn1_decode_s4u_userid(asn1buf *buf, krb5_s4u_userid *val)
{
    setup();
    val->nonce = 0;
    val->user = NULL;
    val->subject_cert.data = NULL;
    val->options = 0;
    { begin_structure();
        get_field(val->nonce,0,asn1_decode_int32);
        alloc_principal(val->user);
        opt_field(val->user,1,asn1_decode_principal_name,0);
        get_field(val->user,2,asn1_decode_realm);
        opt_lenfield(val->subject_cert.length,val->subject_cert.data,3,asn1_decode_charstring);
        opt_field(val->options,4,asn1_decode_krb5_flags,0);
        end_structure();
    }
    return 0;
error_out:
    krb5_free_principal(NULL, val->user);
    krb5_free_data_contents(NULL, &val->subject_cert);
    val->user = NULL;
    val->subject_cert.data = NULL;
    return retval;
}

asn1_error_code
asn1_decode_pa_s4u_x509_user(asn1buf *buf, krb5_pa_s4u_x509_user *val)
{
    setup();
    val->cksum.contents = NULL;
    { begin_structure();
        get_field(val->user_id,0,asn1_decode_s4u_userid);
        get_field(val->cksum,1,asn1_decode_checksum);
        end_structure();
    }
    return 0;
error_out:
    krb5_free_s4u_userid_contents(NULL, &val->user_id);
    krb5_free_checksum_contents(NULL, &val->cksum);
    return retval;
}

asn1_error_code
asn1_decode_pa_pac_req(asn1buf *buf, krb5_pa_pac_req *val)
{
    setup();
    { begin_structure();
        get_field(val->include_pac,0,asn1_decode_boolean);
        end_structure();
    }
    return 0;
error_out:
    return retval;
}

asn1_error_code
asn1_decode_ad_kdcissued(asn1buf *buf, krb5_ad_kdcissued *val)
{
    setup();
    val->ad_checksum.contents = NULL;
    val->i_principal = NULL;
    val->elements = NULL;
    {begin_structure();
        get_field(val->ad_checksum, 0, asn1_decode_checksum);
        if (tagnum == 1) {
            alloc_principal(val->i_principal);
            opt_field(val->i_principal, 1, asn1_decode_realm, 0);
            opt_field(val->i_principal, 2, asn1_decode_principal_name, 0);
        }
        get_field(val->elements, 3, asn1_decode_authorization_data);
        end_structure();
    }
    return 0;
error_out:
    krb5_free_checksum_contents(NULL, &val->ad_checksum);
    krb5_free_principal(NULL, val->i_principal);
    krb5_free_authdata(NULL, val->elements);
    return retval;
}

static asn1_error_code asn1_decode_princ_plus_realm
(asn1buf *buf, krb5_principal *valptr)
{
    setup();
    alloc_principal((*valptr));
    { begin_structure();
        get_field((*valptr), 0, asn1_decode_principal_name);
        get_field((*valptr), 1, asn1_decode_realm);
        end_structure();
    }
    return 0;
error_out:
    krb5_free_principal(NULL, *valptr);
    *valptr = NULL;
    return retval;
}

static asn1_error_code
asn1_decode_sequence_of_princ_plus_realm(asn1buf *buf, krb5_principal **val)
{
    decode_array_body(krb5_principal_data,asn1_decode_princ_plus_realm,krb5_free_principal);
}

asn1_error_code
asn1_decode_ad_signedpath(asn1buf *buf, krb5_ad_signedpath *val)
{
    setup();
    val->enctype = ENCTYPE_NULL;
    val->checksum.contents = NULL;
    val->delegated = NULL;
    {
        begin_structure();
        get_field(val->enctype, 0, asn1_decode_enctype);
        get_field(val->checksum, 1, asn1_decode_checksum);
        opt_field(val->delegated, 2, asn1_decode_sequence_of_princ_plus_realm,
                  NULL);
        opt_field(val->method_data, 3, asn1_decode_sequence_of_pa_data, NULL);
        end_structure();
    }
    return 0;
error_out:
    krb5_free_checksum_contents(NULL, &val->checksum);
    return retval;
}

asn1_error_code asn1_decode_iakerb_header
(asn1buf *buf, krb5_iakerb_header *val)
{
    setup();
    val->target_realm.data = NULL;
    val->target_realm.length = 0;
    val->cookie = NULL;
    {
        begin_structure();
        get_lenfield(val->target_realm.length, val->target_realm.data,
                     1, asn1_decode_charstring);
        if (tagnum == 2) {
            alloc_data(val->cookie);
            get_lenfield(val->cookie->length, val->cookie->data,
                         2, asn1_decode_charstring);
        }
        end_structure();
    }
    return 0;
error_out:
    krb5_free_data_contents(NULL, &val->target_realm);
    krb5_free_data(NULL, val->cookie);
    return retval;
}

asn1_error_code asn1_decode_iakerb_finished
(asn1buf *buf, krb5_iakerb_finished *val)
{
    setup();
    val->checksum.contents = NULL;
    {
        begin_structure();
        get_field(val->checksum, 1, asn1_decode_checksum);
        end_structure();
    }
    return 0;
error_out:
    krb5_free_checksum_contents(NULL, &val->checksum);
    return retval;
}

#ifndef DISABLE_PKINIT
/* PKINIT */

asn1_error_code
asn1_decode_external_principal_identifier(
    asn1buf *buf,
    krb5_external_principal_identifier *val)
{
    setup();
    val->subjectName.data = NULL;
    val->issuerAndSerialNumber.data = NULL;
    val->subjectKeyIdentifier.data = NULL;
    {
        begin_structure();
        opt_implicit_octet_string(val->subjectName.length, val->subjectName.data, 0);
        opt_implicit_octet_string(val->issuerAndSerialNumber.length, val->issuerAndSerialNumber.data, 1);
        opt_implicit_octet_string(val->subjectKeyIdentifier.length, val->subjectKeyIdentifier.data, 2);
        end_structure();
    }
    return 0;
error_out:
    free(val->subjectName.data);
    free(val->issuerAndSerialNumber.data);
    free(val->subjectKeyIdentifier.data);
    val->subjectName.data = NULL;
    val->issuerAndSerialNumber.data = NULL;
    val->subjectKeyIdentifier.data = NULL;
    return retval;
}

asn1_error_code
asn1_decode_external_principal_identifier_ptr(
    asn1buf *buf,
    krb5_external_principal_identifier **valptr)
{
    decode_ptr(krb5_external_principal_identifier *,
               asn1_decode_external_principal_identifier);
}

static void
free_external_principal_identifier(void *dummy,
                                   krb5_external_principal_identifier *val)
{
    free(val->subjectName.data);
    free(val->issuerAndSerialNumber.data);
    free(val->subjectKeyIdentifier.data);
    free(val);
}

asn1_error_code
asn1_decode_sequence_of_external_principal_identifier(
    asn1buf *buf,
    krb5_external_principal_identifier ***val)
{
    decode_array_body(krb5_external_principal_identifier,
                      asn1_decode_external_principal_identifier_ptr,
                      free_external_principal_identifier);
}

#if 0   /* XXX   This needs to be tested!!! XXX */
asn1_error_code
asn1_decode_trusted_ca(asn1buf *buf, krb5_trusted_ca *val)
{
    setup();
    val->choice = choice_trusted_cas_UNKNOWN;
    {
        char *start, *end;
        size_t alloclen;

        begin_explicit_choice();
        if (t.tagnum == choice_trusted_cas_principalName) {
            val->choice = choice_trusted_cas_principalName;
        } else if (t.tagnum == choice_trusted_cas_caName) {
            val->choice = choice_trusted_cas_caName;
            val->u.caName.data = NULL;
            start = subbuf.next;
            {
                sequence_of_no_tagvars(&subbuf);
                unused_var(size);
                end_sequence_of_no_tagvars(&subbuf);
            }
            end = subbuf.next;
            alloclen = end - start;
            val->u.caName.data = malloc(alloclen);
            if (val->u.caName.data == NULL)
                clean_return(ENOMEM);
            memcpy(val->u.caName.data, start, alloclen);
            val->u.caName.length = alloclen;
            next_tag();
        } else if (t.tagnum == choice_trusted_cas_issuerAndSerial) {
            val->choice = choice_trusted_cas_issuerAndSerial;
            val->u.issuerAndSerial.data = NULL;
            start = subbuf.next;
            {
                sequence_of_no_tagvars(&subbuf);
                unused_var(size);
                end_sequence_of_no_tagvars(&subbuf);
            }
            end = subbuf.next;
            alloclen = end - start;
            val->u.issuerAndSerial.data = malloc(alloclen);
            if (val->u.issuerAndSerial.data == NULL)
                clean_return(ENOMEM);
            memcpy(val->u.issuerAndSerial.data, start, alloclen);
            val->u.issuerAndSerial.length = alloclen;
            next_tag();
        } else clean_return(ASN1_BAD_ID);
        end_explicit_choice();
    }
    return 0;
error_out:
    if (val->choice == choice_trusted_cas_caName)
        free(val->u.caName.data);
    else if (val->choice == choice_trusted_cas_issuerAndSerial)
        free(val->u.issuerAndSerial.data);
    val->choice = choice_trusted_cas_UNKNOWN;
    return retval;
}
#else
asn1_error_code
asn1_decode_trusted_ca(asn1buf *buf, krb5_trusted_ca *val)
{
    setup();
    val->choice = choice_trusted_cas_UNKNOWN;
    { begin_choice();
        if (tagnum == choice_trusted_cas_principalName) {
            val->choice = choice_trusted_cas_principalName;
            val->u.principalName = NULL;
            asn1_decode_krb5_principal_name(&subbuf, &(val->u.principalName));
        } else if (tagnum == choice_trusted_cas_caName) {
            val->choice = choice_trusted_cas_caName;
            val->u.caName.data = NULL;
            get_implicit_octet_string(val->u.caName.length, val->u.caName.data, choice_trusted_cas_caName);
        } else if (tagnum == choice_trusted_cas_issuerAndSerial) {
            val->choice = choice_trusted_cas_issuerAndSerial;
            val->u.issuerAndSerial.data = NULL;
            get_implicit_octet_string(val->u.issuerAndSerial.length, val->u.issuerAndSerial.data,
                                      choice_trusted_cas_issuerAndSerial);
        } else clean_return(ASN1_BAD_ID);
        end_choice();
    }
    return 0;
error_out:
    if (val->choice == choice_trusted_cas_caName)
        free(val->u.caName.data);
    else if (val->choice == choice_trusted_cas_issuerAndSerial)
        free(val->u.issuerAndSerial.data);
    val->choice = choice_trusted_cas_UNKNOWN;
    return retval;
}
#endif /* if 0 */

asn1_error_code
asn1_decode_trusted_ca_ptr(asn1buf *buf, krb5_trusted_ca **valptr)
{
    decode_ptr(krb5_trusted_ca *, asn1_decode_trusted_ca);
}

static void
free_trusted_ca(void *dummy, krb5_trusted_ca *val)
{
    if (val->choice == choice_trusted_cas_caName)
        free(val->u.caName.data);
    else if (val->choice == choice_trusted_cas_issuerAndSerial)
        free(val->u.issuerAndSerial.data);
    free(val);
}

asn1_error_code
asn1_decode_sequence_of_trusted_ca(asn1buf *buf, krb5_trusted_ca ***val)
{
    decode_array_body(krb5_trusted_ca, asn1_decode_trusted_ca_ptr,
                      free_trusted_ca);
}

static asn1_error_code
asn1_decode_kdf_alg_id_ptr(asn1buf *buf, krb5_octet_data **valptr)
{
    decode_ptr(krb5_octet_data *, asn1_decode_kdf_alg_id);
}

asn1_error_code
asn1_decode_dh_rep_info(asn1buf *buf, krb5_dh_rep_info *val)
{
    setup();
    val->dhSignedData.data = NULL;
    val->serverDHNonce.data = NULL;
    val->kdfID = NULL;
    { begin_structure();
        get_implicit_octet_string(val->dhSignedData.length, val->dhSignedData.data, 0);

        opt_lenfield(val->serverDHNonce.length, val->serverDHNonce.data, 1, asn1_decode_octetstring);
        opt_field(val->kdfID, 2, asn1_decode_kdf_alg_id_ptr, NULL);
        end_structure();
    }
    return 0;
error_out:
    free(val->dhSignedData.data);
    free(val->serverDHNonce.data);
    krb5_free_octet_data(NULL, val->kdfID);
    val->kdfID = NULL;
    val->dhSignedData.data = NULL;
    val->serverDHNonce.data = NULL;
    return retval;
}

asn1_error_code
asn1_decode_pk_authenticator(asn1buf *buf, krb5_pk_authenticator *val)
{
    setup();
    val->paChecksum.contents = NULL;
    { begin_structure();
        get_field(val->cusec, 0, asn1_decode_int32);
        get_field(val->ctime, 1, asn1_decode_kerberos_time);
        get_field(val->nonce, 2, asn1_decode_int32);
        opt_lenfield(val->paChecksum.length, val->paChecksum.contents, 3, asn1_decode_octetstring);
        end_structure();
    }
    return 0;
error_out:
    krb5_free_checksum_contents(NULL, &val->paChecksum);
    return retval;
}

asn1_error_code
asn1_decode_pk_authenticator_draft9(asn1buf *buf,
                                    krb5_pk_authenticator_draft9 *val)
{
    setup();
    val->kdcName = NULL;
    val->kdcRealm.data = NULL;
    { begin_structure();
        alloc_principal(val->kdcName);
        get_field(val->kdcName, 0, asn1_decode_principal_name);
        get_field(val->kdcName, 1, asn1_decode_realm);
        get_field(val->cusec, 2, asn1_decode_int32);
        get_field(val->ctime, 3, asn1_decode_kerberos_time);
        get_field(val->nonce, 4, asn1_decode_int32);
        end_structure();
    }
    return 0;
error_out:
    krb5_free_principal(NULL, val->kdcName);
    return retval;
}

asn1_error_code
asn1_decode_algorithm_identifier(asn1buf *buf, krb5_algorithm_identifier *val)
{
    setup();
    val->algorithm.data = NULL;
    val->parameters.data = NULL;
    { begin_structure_no_tag();
        /*
         * Forbid indefinite encoding because we don't read enough tag
         * information from the trailing octets ("ANY DEFINED BY") to
         * synchronize EOC tags, etc.
         */
        if (seqindef) clean_return(ASN1_BAD_FORMAT);
        /*
         * Set up tag variables because we don't actually call anything
         * that fetches tag info for us; it's all buried in the decoder
         * primitives.
         */
        tagnum = ASN1_TAGNUM_CEILING;
        asn1class = UNIVERSAL;
        construction = PRIMITIVE;
        taglen = 0;
        indef = 0;
        retval = asn1_decode_oid(&subbuf, &val->algorithm.length,
                                 &val->algorithm.data);
        if (retval) clean_return(retval);
        val->parameters.length = 0;
        val->parameters.data = NULL;

        assert(subbuf.next >= subbuf.base);
        if (length > (size_t)(subbuf.next - subbuf.base)) {
            unsigned int size = length - (subbuf.next - subbuf.base);
            retval = asn1buf_remove_octetstring(&subbuf, size,
                                                &val->parameters.data);
            if (retval) clean_return(retval);
            val->parameters.length = size;
        }

        end_structure();
    }
    return 0;
error_out:
    free(val->algorithm.data);
    free(val->parameters.data);
    val->algorithm.data = NULL;
    val->parameters.data = NULL;
    return retval;
}

asn1_error_code
asn1_decode_algorithm_identifier_ptr(asn1buf *buf,
                                     krb5_algorithm_identifier **valptr)
{
    decode_ptr(krb5_algorithm_identifier *, asn1_decode_algorithm_identifier);
}

asn1_error_code
asn1_decode_subject_pk_info(asn1buf *buf, krb5_subject_pk_info *val)
{
    asn1_octet unused;
    setup();
    val->algorithm.algorithm.data = NULL;
    val->algorithm.parameters.data = NULL;
    val->subjectPublicKey.data = NULL;
    { begin_structure_no_tag();

        retval = asn1_decode_algorithm_identifier(&subbuf, &val->algorithm);
        if (retval) clean_return(retval);

        /* SubjectPublicKey encoded as a BIT STRING */
        next_tag();
        if (asn1class != UNIVERSAL || construction != PRIMITIVE ||
            tagnum != ASN1_BITSTRING)
            clean_return(ASN1_BAD_ID);

        retval = asn1buf_remove_octet(&subbuf, &unused);
        if (retval) clean_return(retval);

        /* Number of unused bits must be between 0 and 7. */
        /* What to do if unused is not zero? */
        if (unused > 7) clean_return(ASN1_BAD_FORMAT);
        taglen--;

        val->subjectPublicKey.length = 0;
        val->subjectPublicKey.data = NULL;
        retval = asn1buf_remove_octetstring(&subbuf, taglen,
                                            &val->subjectPublicKey.data);
        if (retval) clean_return(retval);
        val->subjectPublicKey.length = taglen;
        /*
         * We didn't call any macro that does next_tag(); do so now to
         * preload tag of any trailing encodings.
         */
        next_tag();
        end_structure();
    }
    return 0;
error_out:
    free(val->algorithm.algorithm.data);
    free(val->algorithm.parameters.data);
    free(val->subjectPublicKey.data);
    val->algorithm.algorithm.data = NULL;
    val->algorithm.parameters.data = NULL;
    val->subjectPublicKey.data = NULL;
    return 0;
}

static void
free_algorithm_identifier(void *dummy, krb5_algorithm_identifier *val)
{
    free(val->algorithm.data);
    free(val->parameters.data);
    free(val);
}

asn1_error_code
asn1_decode_sequence_of_algorithm_identifier(asn1buf *buf,
                                             krb5_algorithm_identifier ***val)
{
    decode_array_body(krb5_algorithm_identifier,
                      asn1_decode_algorithm_identifier_ptr,
                      free_algorithm_identifier);
}

asn1_error_code
asn1_decode_kdc_dh_key_info(asn1buf *buf, krb5_kdc_dh_key_info *val)
{
    setup();
    val->subjectPublicKey.data = NULL;
    { begin_structure();
        retval = asn1buf_remove_octetstring(&subbuf, taglen, &val->subjectPublicKey.data);
        if (retval) clean_return(retval);
        val->subjectPublicKey.length = taglen;
        next_tag();
        get_field(val->nonce, 1, asn1_decode_int32);
        opt_field(val->dhKeyExpiration, 2, asn1_decode_kerberos_time, 0);
        end_structure();
    }
    return 0;
error_out:
    free(val->subjectPublicKey.data);
    val->subjectPublicKey.data = NULL;
    return retval;
}

asn1_error_code
asn1_decode_reply_key_pack (asn1buf *buf, krb5_reply_key_pack *val)
{
    setup();
    val->replyKey.contents = NULL;
    val->asChecksum.contents = NULL;
    { begin_structure();
        get_field(val->replyKey, 0, asn1_decode_encryption_key);
        get_field(val->asChecksum, 1, asn1_decode_checksum);
        end_structure();
    }
    return 0;
error_out:
    free(val->replyKey.contents);
    free(val->asChecksum.contents);
    val->replyKey.contents = NULL;
    val->asChecksum.contents = NULL;
    return retval;
}

asn1_error_code
asn1_decode_reply_key_pack_draft9 (asn1buf *buf,
                                   krb5_reply_key_pack_draft9 *val)
{
    setup();
    val->replyKey.contents = NULL;
    { begin_structure();
        get_field(val->replyKey, 0, asn1_decode_encryption_key);
        get_field(val->nonce, 1, asn1_decode_int32);
        end_structure();
    }
    return 0;
error_out:
    free(val->replyKey.contents);
    val->replyKey.contents = NULL;
    return retval;
}

asn1_error_code
asn1_decode_krb5_principal_name (asn1buf *buf, krb5_principal *val)
{
    int i;
    setup();
    (*val)->realm.data = NULL;
    (*val)->data = NULL;
    { begin_structure();
        get_field(*val, 0, asn1_decode_realm);
        get_field(*val, 1, asn1_decode_principal_name);
        end_structure();
    }
    return 0;
error_out:
    krb5_free_data_contents(NULL, &(*val)->realm);
    if ((*val)->data) {
        for (i = 0; i < (*val)->length; i++)
            krb5_free_data_contents(NULL, &(*val)->data[i]);
        free((*val)->data);
    }
    (*val)->realm.data = NULL;
    (*val)->data = NULL;
    return retval;
}

asn1_error_code
asn1_decode_pa_pk_as_rep(asn1buf *buf, krb5_pa_pk_as_rep *val)
{
    setup();
    val->choice = choice_pa_pk_as_rep_UNKNOWN;
    { begin_choice();
        if (tagnum == choice_pa_pk_as_rep_dhInfo) {
            val->choice = choice_pa_pk_as_rep_dhInfo;
            val->u.dh_Info.dhSignedData.data = NULL;
            val->u.dh_Info.serverDHNonce.data = NULL;
            get_field_body(val->u.dh_Info, asn1_decode_dh_rep_info);
        } else if (tagnum == choice_pa_pk_as_rep_encKeyPack) {
            val->choice = choice_pa_pk_as_rep_encKeyPack;
            val->u.encKeyPack.data = NULL;
            get_implicit_octet_string(val->u.encKeyPack.length, val->u.encKeyPack.data,
                                      choice_pa_pk_as_rep_encKeyPack);
        } else {
            val->choice = choice_pa_pk_as_rep_UNKNOWN;
        }
        end_choice();
    }
    return 0;
error_out:
    if (val->choice == choice_pa_pk_as_rep_dhInfo) {
        free(val->u.dh_Info.dhSignedData.data);
        free(val->u.dh_Info.serverDHNonce.data);
    } else if (val->choice == choice_pa_pk_as_rep_encKeyPack) {
        free(val->u.encKeyPack.data);
    }
    val->choice = choice_pa_pk_as_rep_UNKNOWN;
    return retval;
}

asn1_error_code
asn1_decode_pa_pk_as_rep_draft9(asn1buf *buf, krb5_pa_pk_as_rep_draft9 *val)
{
    setup();
    val->choice = choice_pa_pk_as_rep_draft9_UNKNOWN;
    { begin_structure();
        if (tagnum == choice_pa_pk_as_rep_draft9_dhSignedData) {
            val->choice = choice_pa_pk_as_rep_draft9_dhSignedData;
            val->u.dhSignedData.data = NULL;
            get_lenfield(val->u.dhSignedData.length, val->u.dhSignedData.data,
                         choice_pa_pk_as_rep_draft9_dhSignedData, asn1_decode_octetstring);
        } else if (tagnum == choice_pa_pk_as_rep_draft9_encKeyPack) {
            val->choice = choice_pa_pk_as_rep_draft9_encKeyPack;
            val->u.encKeyPack.data = NULL;
            get_lenfield(val->u.encKeyPack.length, val->u.encKeyPack.data,
                         choice_pa_pk_as_rep_draft9_encKeyPack, asn1_decode_octetstring);
        } else {
            val->choice = choice_pa_pk_as_rep_draft9_UNKNOWN;
        }
        end_structure();
    }
    return 0;
error_out:
    if (val->choice == choice_pa_pk_as_rep_draft9_dhSignedData)
        free(val->u.dhSignedData.data);
    else if (val->choice == choice_pa_pk_as_rep_draft9_encKeyPack)
        free(val->u.encKeyPack.data);
    val->choice = choice_pa_pk_as_rep_draft9_UNKNOWN;
    return retval;
}

asn1_error_code
asn1_decode_kdf_alg_id( asn1buf *buf, krb5_octet_data *val)
{
    setup();
    val->data = NULL;
    { begin_structure();
        get_lenfield(val->length,val->data,0,asn1_decode_oid);
        end_structure();
    }
    return 0;
error_out:
    free(val->data);
    return retval;
}

asn1_error_code
asn1_decode_sequence_of_kdf_alg_id(asn1buf *buf,
                                   krb5_octet_data ***val)
{
    decode_array_body(krb5_octet_data, asn1_decode_kdf_alg_id_ptr,
                      krb5_free_octet_data);
}

#endif /* DISABLE_PKINIT */

static void free_typed_data(void *dummy, krb5_typed_data *val)
{
    free(val->data);
    free(val);
}

asn1_error_code
asn1_decode_sequence_of_typed_data(asn1buf *buf, krb5_typed_data ***val)
{
    decode_array_body(krb5_typed_data,asn1_decode_typed_data_ptr,
                      free_typed_data);
}

asn1_error_code
asn1_decode_typed_data(asn1buf *buf, krb5_typed_data *val)
{
    setup();
    val->data = NULL;
    { begin_structure();
        get_field(val->type,0,asn1_decode_int32);
        get_lenfield(val->length,val->data,1,asn1_decode_octetstring);
        end_structure();
    }
    return 0;
error_out:
    free(val->data);
    val->data = NULL;
    return retval;
}

asn1_error_code
asn1_decode_typed_data_ptr(asn1buf *buf, krb5_typed_data **valptr)
{
    decode_ptr(krb5_typed_data *, asn1_decode_typed_data);
}

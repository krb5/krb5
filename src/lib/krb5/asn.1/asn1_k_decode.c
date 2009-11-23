/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * src/lib/krb5/asn.1/asn1_k_decode.c
 *
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
#include "asn1_decode.h"
#include "asn1_get.h"
#include "asn1_misc.h"

#define clean_return(val) { retval = val; goto error_out; }

/* Declare useful decoder variables. */
#define setup()                                 \
    asn1_error_code retval;                     \
    asn1_class asn1class;                       \
    asn1_construction construction;             \
    asn1_tagnum tagnum;                         \
    unsigned int length, taglen

#define unused_var(x) if (0) { x = 0; x = x - x; }

/* This is used for prefetch of next tag in sequence. */
#define next_tag()                                                      \
    { taginfo t2;                                                       \
        retval = asn1_get_tag_2(&subbuf, &t2);                          \
        if (retval) clean_return(retval);                               \
        /* Copy out to match previous functionality, until better integrated.  */ \
        asn1class = t2.asn1class;                                       \
        construction = t2.construction;                                 \
        tagnum = t2.tagnum;                                             \
        taglen = t2.length;                                             \
        indef = t2.indef;                                               \
    }

static asn1_error_code
asn1_get_eoc_tag (asn1buf *buf)
{
    asn1_error_code retval;
    taginfo t;

    retval = asn1_get_tag_2(buf, &t);
    if (retval)
        return retval;
    if (t.asn1class != UNIVERSAL || t.tagnum || t.indef)
        return ASN1_MISSING_EOC;
    return 0;
}

/* Force check for EOC tag. */
#define get_eoc()                               \
    {                                           \
        retval = asn1_get_eoc_tag(&subbuf);     \
        if (retval) clean_return(retval);       \
    }

#define alloc_field(var)                        \
    var = calloc(1, sizeof(*var));              \
    if ((var) == NULL) clean_return(ENOMEM)

/*
 * Allocate a principal and initialize enough fields for
 * krb5_free_principal to have defined behavior.
 */
#define alloc_principal(var)                    \
    alloc_field(var);                           \
    var->realm.data = NULL;                     \
    var->data = NULL

/*
 * Allocate a data structure and initialize enough fields for
 * krb5_free_data to have defined behavior.
 */
#define alloc_data(var)                         \
    alloc_field(var);                           \
    var->data = NULL

/* Fetch an expected APPLICATION class tag and verify. */
#define apptag(tagexpect)                                               \
    {                                                                   \
        taginfo t1;                                                     \
        retval = asn1_get_tag_2(buf, &t1);                              \
        if (retval) clean_return(retval);                               \
        if (t1.asn1class != APPLICATION || t1.construction != CONSTRUCTED || \
            t1.tagnum != (tagexpect)) clean_return(ASN1_BAD_ID);        \
        /* Copy out to match previous functionality, until better integrated.  */ \
        asn1class = t1.asn1class;                                       \
        construction = t1.construction;                                 \
        tagnum = t1.tagnum;                                             \
        applen = t1.length;                                             \
    }

/**** normal fields ****/

/*
 * get_field_body
 *
 * Get bare field.  This also prefetches the next tag.  The call to
 * get_eoc() assumes that any values fetched by this macro are
 * enclosed in a context-specific tag.
 */
#define get_field_body(var, decoder)            \
    retval = decoder(&subbuf, &(var));          \
    if (retval) clean_return(retval);           \
    if (!taglen && indef) { get_eoc(); }        \
    next_tag()

/*
 * error_if_bad_tag
 *
 * Checks that the next tag is the expected one; returns with an error
 * if not.
 */
#define error_if_bad_tag(tagexpect)                                     \
    if (tagnum != (tagexpect)) { clean_return((tagnum < (tagexpect)) ? ASN1_MISPLACED_FIELD : ASN1_MISSING_FIELD); }

/*
 * get_field
 *
 * Get field having an expected context specific tag.  This assumes
 * that context-specific tags are monotonically increasing in its
 * verification of tag numbers.
 */
#define get_field(var, tagexpect, decoder)                              \
    error_if_bad_tag(tagexpect);                                        \
    if ((asn1class != CONTEXT_SPECIFIC || construction != CONSTRUCTED)  \
        && (tagnum || taglen || asn1class != UNIVERSAL))                \
        clean_return(ASN1_BAD_ID);                                      \
    get_field_body(var,decoder)

/*
 * opt_field
 *
 * Get an optional field with an expected context specific tag.
 * Assumes that OPTVAL will have the default value, thus failing to
 * distinguish between absent optional values and present optional
 * values that happen to have the value of OPTVAL.
 */
#define opt_field(var, tagexpect, decoder, optvalue)                    \
    if (asn1buf_remains(&subbuf, seqindef)) {                           \
        if ((asn1class != CONTEXT_SPECIFIC || construction != CONSTRUCTED) \
            && (tagnum || taglen || asn1class != UNIVERSAL))            \
            clean_return(ASN1_BAD_ID);                                  \
        if (tagnum == (tagexpect)) {                                    \
            get_field_body(var, decoder);                               \
        } else var = optvalue;                                          \
    }

/**** fields w/ length ****/

/* similar to get_field_body */
#define get_lenfield_body(len, var, decoder)    \
    retval = decoder(&subbuf, &(len), &(var));  \
    if (retval) clean_return(retval);           \
    if (!taglen && indef) { get_eoc(); }        \
    next_tag()

/* similar to get_field_body */
#define get_lenfield(len, var, tagexpect, decoder)                      \
    error_if_bad_tag(tagexpect);                                        \
    if ((asn1class != CONTEXT_SPECIFIC || construction != CONSTRUCTED)  \
        && (tagnum || taglen || asn1class != UNIVERSAL))                \
        clean_return(ASN1_BAD_ID);                                      \
    get_lenfield_body(len, var, decoder)

/* similar to opt_field */
#define opt_lenfield(len, var, tagexpect, decoder)      \
    if (tagnum == (tagexpect)) {                        \
        get_lenfield_body(len, var, decoder);           \
    } else { len = 0; var = 0; }

/*
 * Deal with implicitly tagged fields
 */
#define get_implicit_octet_string(len, var, tagexpect)                  \
    if (tagnum != (tagexpect)) clean_return(ASN1_MISSING_FIELD);        \
    if (asn1class != CONTEXT_SPECIFIC || construction != PRIMITIVE)     \
        clean_return(ASN1_BAD_ID);                                      \
    retval = asn1buf_remove_octetstring(&subbuf, taglen, &(var));       \
    if (retval) clean_return(retval);                                   \
    (len) = taglen;                                                     \
    next_tag()

#define opt_implicit_octet_string(len, var, tagexpect)                  \
    if (tagnum == (tagexpect)) {                                        \
        if (asn1class != CONTEXT_SPECIFIC || construction != PRIMITIVE) \
            clean_return(ASN1_BAD_ID);                                  \
        retval = asn1buf_remove_octetstring(&subbuf, taglen, &(var));   \
        if (retval) clean_return(retval);                               \
        (len) = taglen;                                                 \
        next_tag();                                                     \
    } else { (len) = 0; (var) = NULL; }

/*
 * begin_structure
 *
 * Declares some variables for decoding SEQUENCE types.  This is meant
 * to be called in an inner block that ends with a call to
 * end_structure().
 */
#define begin_structure()                                       \
    asn1buf subbuf;                                             \
    int seqindef;                                               \
    int indef;                                                  \
    retval = asn1_get_sequence(buf, &length, &seqindef);        \
    if (retval) clean_return(retval);                           \
    retval = asn1buf_imbed(&subbuf, buf, length, seqindef);     \
    if (retval) clean_return(retval);                           \
    next_tag()

/*
 * This is used for structures which have no tagging.
 * It is the same as begin_structure() except next_tag()
 * is not called.
 */
#define begin_structure_no_tag()                                \
    asn1buf subbuf;                                             \
    int seqindef;                                               \
    int indef;                                                  \
    retval = asn1_get_sequence(buf, &length, &seqindef);        \
    if (retval) clean_return(retval);                           \
    retval = asn1buf_imbed(&subbuf, buf, length, seqindef);     \
    if (retval) clean_return(retval)

/* skip trailing garbage */
#define end_structure()                                         \
    retval = asn1buf_sync(buf, &subbuf, asn1class, tagnum,      \
                          length, indef, seqindef);             \
    if (retval) clean_return(retval)

/*
 * begin_choice
 *
 * Declares some variables for decoding CHOICE types.  This is meant
 * to be called in an inner block that ends with a call to
 * end_choice().
 */
#define begin_choice()                                          \
    asn1buf subbuf;                                             \
    int seqindef;                                               \
    int indef;                                                  \
    taginfo t;                                                  \
    retval = asn1_get_tag_2(buf, &t);                           \
    if (retval) clean_return(retval);                           \
    tagnum = t.tagnum;                                          \
    taglen = t.length;                                          \
    indef = t.indef;                                            \
    length = t.length;                                          \
    seqindef = t.indef;                                         \
    asn1class = t.asn1class;                                    \
    construction = t.construction;                              \
    retval = asn1buf_imbed(&subbuf, buf, length, seqindef);     \
    if (retval) clean_return(retval)

/* skip trailing garbage */
#define end_choice()                                            \
    length -= t.length;                                         \
    retval = asn1buf_sync(buf, &subbuf, t.asn1class, t.tagnum,  \
                          length, t.indef, seqindef);           \
    if (retval) clean_return(retval)

/*
 * sequence_of
 *
 * Declares some variables for decoding SEQUENCE OF types.  This is
 * meant to be called in an inner block that ends with a call to
 * end_sequence_of().
 */
#define sequence_of(buf)                        \
    unsigned int length, taglen;                \
    asn1_class asn1class;                       \
    asn1_construction construction;             \
    asn1_tagnum tagnum;                         \
    int indef;                                  \
    sequence_of_common(buf)

/*
 * sequence_of_no_tagvars
 *
 * This is meant for use inside decoder functions that have an outer
 * sequence structure and thus declares variables of different names
 * than does sequence_of() to avoid shadowing.
 */
#define sequence_of_no_tagvars(buf)             \
    sequence_of_common(buf)

/*
 * sequence_of_common
 *
 * Fetches the outer SEQUENCE OF length info into {length,seqofindef}
 * and imbeds an inner buffer seqbuf.  Unlike begin_structure(), it
 * does not prefetch the next tag.
 */
#define sequence_of_common(buf)                                 \
    asn1buf seqbuf;                                             \
    int seqofindef;                                             \
    retval = asn1_get_sequence(buf, &length, &seqofindef);      \
    if (retval) clean_return(retval);                           \
    retval = asn1buf_imbed(&seqbuf, buf, length, seqofindef);   \
    if (retval) clean_return(retval)

/*
 * end_sequence_of
 *
 * Attempts to fetch an EOC tag, if any, and to sync over trailing
 * garbage, if any.
 */
#define end_sequence_of(buf)                                            \
    {                                                                   \
        taginfo t4;                                                     \
        retval = asn1_get_tag_2(&seqbuf, &t4);                          \
        if (retval) clean_return(retval);                               \
        /* Copy out to match previous functionality, until better integrated.  */ \
        asn1class = t4.asn1class;                                       \
        construction = t4.construction;                                 \
        tagnum = t4.tagnum;                                             \
        taglen = t4.length;                                             \
        indef = t4.indef;                                               \
    }                                                                   \
        retval = asn1buf_sync(buf, &seqbuf, asn1class, tagnum,          \
                              length, indef, seqofindef);               \
        if (retval) clean_return(retval);

/*
 * end_sequence_of_no_tagvars
 *
 * Like end_sequence_of(), but uses the different (non-shadowing)
 * variable names.
 */
static asn1_error_code
end_sequence_of_no_tagvars_helper(asn1buf *buf, asn1buf *seqbufp,
                                  int seqofindef)
{
    taginfo t;
    asn1_error_code retval;

    retval = asn1_get_tag_2(seqbufp, &t);
    if (retval)
        return retval;
    retval = asn1buf_sync(buf, seqbufp, t.asn1class, t.tagnum,
                          t.length, t.indef, seqofindef);
    return retval;
}
#define end_sequence_of_no_tagvars(buf)                                 \
    retval = end_sequence_of_no_tagvars_helper(buf, &seqbuf, seqofindef); \
    if (retval) clean_return(retval)

/*
 * Function body for a pointer decoder, which allocates a pointer
 * field and invokes a structure decoder to fill it in.  Pointer
 * decoders always fill in their output parameters with NULL (on
 * error) or a valid constructed structure, making cleanup easier on
 * callers.
 */
#define decode_ptr(type, structure_decoder)     \
    type val;                                   \
    asn1_error_code retval;                     \
                                                \
    *valptr = NULL;                             \
    val = calloc(1, sizeof(*val));              \
    if (!val)                                   \
        return ENOMEM;                          \
    retval = structure_decoder(buf, val);       \
    if (retval) {                               \
        free(val);                              \
        return retval;                          \
    }                                           \
    *valptr = val;                              \
    return 0;

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

#define integer_convert(fname,ktype)                    \
    asn1_error_code fname(asn1buf * buf, ktype * val)   \
    {                                                   \
        asn1_error_code retval;                         \
        long n;                                         \
        retval = asn1_decode_integer(buf,&n);           \
        if (retval) return retval;                      \
        *val = (ktype)n;                                \
        return 0;                                       \
    }
#define unsigned_integer_convert(fname,ktype)           \
    asn1_error_code fname(asn1buf * buf, ktype * val)   \
    {                                                   \
        asn1_error_code retval;                         \
        unsigned long n;                                \
        retval = asn1_decode_unsigned_integer(buf,&n);  \
        if (retval) return retval;                      \
        *val = (ktype)n;                                \
        return 0;                                       \
    }
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
asn1_decode_kdc_req(asn1buf *buf, krb5_kdc_req *val)
{
    setup();
    val->padata = NULL;
    { begin_structure();
        { krb5_kvno kvno;
            get_field(kvno,1,asn1_decode_kvno);
            if (kvno != KVNO) clean_return(KRB5KDC_ERR_BAD_PVNO); }
        get_field(val->msg_type,2,asn1_decode_msgtype);
        opt_field(val->padata,3,asn1_decode_sequence_of_pa_data,NULL);
        get_field(*val,4,asn1_decode_kdc_req_body);
        end_structure();
        val->magic = KV5M_KDC_REQ;
    }
    return 0;
error_out:
    krb5_free_pa_data(NULL, val->padata);
    val->padata = NULL;
    return retval;
}

asn1_error_code
asn1_decode_kdc_req_body(asn1buf *buf, krb5_kdc_req *val)
{
    setup();
    val->client = NULL;
    val->server = NULL;
    val->ktype = NULL;
    val->addresses = NULL;
    val->authorization_data.ciphertext.data = NULL;
    val->unenc_authdata = NULL;
    val->second_ticket = NULL;
    {
        krb5_principal psave;
        begin_structure();
        get_field(val->kdc_options,0,asn1_decode_kdc_options);
        if (tagnum == 1) { alloc_principal(val->client); }
        opt_field(val->client,1,asn1_decode_principal_name,NULL);
        alloc_principal(val->server);
        get_field(val->server,2,asn1_decode_realm);
        if (val->client != NULL) {
            retval = asn1_krb5_realm_copy(val->client,val->server);
            if (retval) clean_return(retval); }

        /* If opt_field server is missing, memory reference to server is
           lost and results in memory leak */
        psave = val->server;
        opt_field(val->server,3,asn1_decode_principal_name,NULL);
        if (val->server == NULL) {
            if (psave->realm.data) {
                free(psave->realm.data);
                psave->realm.data = NULL;
                psave->realm.length=0;
            }
            free(psave);
        }
        opt_field(val->from,4,asn1_decode_kerberos_time,0);
        get_field(val->till,5,asn1_decode_kerberos_time);
        opt_field(val->rtime,6,asn1_decode_kerberos_time,0);
        get_field(val->nonce,7,asn1_decode_int32);
        get_lenfield(val->nktypes,val->ktype,8,asn1_decode_sequence_of_enctype);
        opt_field(val->addresses,9,asn1_decode_host_addresses,0);
        if (tagnum == 10) {
            get_field(val->authorization_data,10,asn1_decode_encrypted_data); }
        else {
            val->authorization_data.magic = KV5M_ENC_DATA;
            val->authorization_data.enctype = 0;
            val->authorization_data.kvno = 0;
            val->authorization_data.ciphertext.data = NULL;
            val->authorization_data.ciphertext.length = 0;
        }
        opt_field(val->second_ticket,11,asn1_decode_sequence_of_ticket,NULL);
        end_structure();
        val->magic = KV5M_KDC_REQ;
    }
    return 0;
error_out:
    krb5_free_principal(NULL, val->client);
    krb5_free_principal(NULL, val->server);
    free(val->ktype);
    krb5_free_addresses(NULL, val->addresses);
    krb5_free_data_contents(NULL, &val->authorization_data.ciphertext);
    krb5_free_tickets(NULL, val->second_ticket);
    val->client = NULL;
    val->server = NULL;
    val->ktype = NULL;
    val->addresses = NULL;
    val->unenc_authdata = NULL;
    val->second_ticket = NULL;
    return retval;
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
asn1_decode_sam_flags(asn1buf *buf, krb5_flags *val)
{
    return asn1_decode_krb5_flags(buf,val);
}

#define opt_string(val,n,fn) opt_lenfield((val).length,(val).data,n,fn)
#define opt_cksum(var,tagexpect,decoder)        \
    if (tagnum == (tagexpect)) {                \
        get_field_body(var,decoder); }          \
    else var.length = 0

asn1_error_code
asn1_decode_sam_challenge(asn1buf *buf, krb5_sam_challenge *val)
{
    setup();
    val->sam_type_name.data = NULL;
    val->sam_track_id.data = NULL;
    val->sam_challenge_label.data = NULL;
    val->sam_response_prompt.data = NULL;
    val->sam_pk_for_sad.data = NULL;
    val->sam_cksum.contents = NULL;
    { begin_structure();
        get_field(val->sam_type,0,asn1_decode_int32);
        get_field(val->sam_flags,1,asn1_decode_sam_flags);
        opt_string(val->sam_type_name,2,asn1_decode_charstring);
        opt_string(val->sam_track_id,3,asn1_decode_charstring);
        opt_string(val->sam_challenge_label,4,asn1_decode_charstring);
        opt_string(val->sam_challenge,5,asn1_decode_charstring);
        opt_string(val->sam_response_prompt,6,asn1_decode_charstring);
        opt_string(val->sam_pk_for_sad,7,asn1_decode_charstring);
        opt_field(val->sam_nonce,8,asn1_decode_int32,0);
        opt_cksum(val->sam_cksum,9,asn1_decode_checksum);
        end_structure();
        val->magic = KV5M_SAM_CHALLENGE;
    }
    return 0;
error_out:
    krb5_free_sam_challenge_contents(NULL, val);
    return retval;
}
asn1_error_code
asn1_decode_sam_challenge_2(asn1buf *buf, krb5_sam_challenge_2 *val)
{
    krb5_checksum **cksump;
    setup();
    val->sam_challenge_2_body.data = NULL;
    val->sam_cksum = NULL;
    { char *save, *end;
        size_t alloclen;
        begin_structure();
        if (tagnum != 0) clean_return(ASN1_MISSING_FIELD);
        if (asn1class != CONTEXT_SPECIFIC || construction != CONSTRUCTED)
            clean_return(ASN1_BAD_ID);
        save = subbuf.next;
        { sequence_of_no_tagvars(&subbuf);
            end_sequence_of_no_tagvars(&subbuf);
        }
        end = subbuf.next;
        alloclen = end - save;
        val->sam_challenge_2_body.data = malloc(alloclen);
        if (!val->sam_challenge_2_body.data)
            clean_return(ENOMEM);
        val->sam_challenge_2_body.length = alloclen;
        memcpy(val->sam_challenge_2_body.data, save, alloclen);
        next_tag();
        get_field(val->sam_cksum, 1, asn1_decode_sequence_of_checksum);
        end_structure();
    }
    return 0;
error_out:
    krb5_free_data_contents(NULL, &val->sam_challenge_2_body);
    if (val->sam_cksum) {
        for (cksump = val->sam_cksum; *cksump; cksump++)
            krb5_free_checksum(NULL, *cksump);
        free(val->sam_cksum);
        val->sam_cksum = NULL;
    }
    return retval;
}
asn1_error_code
asn1_decode_sam_challenge_2_body(asn1buf *buf, krb5_sam_challenge_2_body *val)
{
    setup();
    val->sam_type_name.data = NULL;
    val->sam_track_id.data = NULL;
    val->sam_challenge_label.data = NULL;
    val->sam_challenge.data = NULL;
    val->sam_response_prompt.data = NULL;
    val->sam_pk_for_sad.data = NULL;
    { begin_structure();
        get_field(val->sam_type,0,asn1_decode_int32);
        get_field(val->sam_flags,1,asn1_decode_sam_flags);
        opt_string(val->sam_type_name,2,asn1_decode_charstring);
        opt_string(val->sam_track_id,3,asn1_decode_charstring);
        opt_string(val->sam_challenge_label,4,asn1_decode_charstring);
        opt_string(val->sam_challenge,5,asn1_decode_charstring);
        opt_string(val->sam_response_prompt,6,asn1_decode_charstring);
        opt_string(val->sam_pk_for_sad,7,asn1_decode_charstring);
        get_field(val->sam_nonce,8,asn1_decode_int32);
        get_field(val->sam_etype, 9, asn1_decode_int32);
        end_structure();
        val->magic = KV5M_SAM_CHALLENGE;
    }
    return 0;
error_out:
    krb5_free_sam_challenge_2_body_contents(NULL, val);
    return retval;
}
asn1_error_code
asn1_decode_enc_sam_key(asn1buf *buf, krb5_sam_key *val)
{
    setup();
    val->sam_key.contents = NULL;
    { begin_structure();
        get_field(val->sam_key,0,asn1_decode_encryption_key);
        end_structure();
        val->magic = KV5M_SAM_KEY;
    }
    return 0;
error_out:
    krb5_free_keyblock_contents(NULL, &val->sam_key);
    return retval;
}

asn1_error_code
asn1_decode_enc_sam_response_enc(asn1buf *buf, krb5_enc_sam_response_enc *val)
{
    setup();
    val->sam_sad.data = NULL;
    { begin_structure();
        opt_field(val->sam_nonce,0,asn1_decode_int32,0);
        opt_field(val->sam_timestamp,1,asn1_decode_kerberos_time,0);
        opt_field(val->sam_usec,2,asn1_decode_int32,0);
        opt_string(val->sam_sad,3,asn1_decode_charstring);
        end_structure();
        val->magic = KV5M_ENC_SAM_RESPONSE_ENC;
    }
    return 0;
error_out:
    krb5_free_enc_sam_response_enc_contents(NULL, val);
    return retval;
}

asn1_error_code
asn1_decode_enc_sam_response_enc_2(asn1buf *buf, krb5_enc_sam_response_enc_2 *val)
{
    setup();
    val->sam_sad.data = NULL;
    { begin_structure();
        get_field(val->sam_nonce,0,asn1_decode_int32);
        opt_string(val->sam_sad,1,asn1_decode_charstring);
        end_structure();
        val->magic = KV5M_ENC_SAM_RESPONSE_ENC_2;
    }
    return 0;
error_out:
    krb5_free_enc_sam_response_enc_2_contents(NULL, val);
    return retval;
}

#define opt_encfield(fld,tag,fn)                \
    if (tagnum == tag) {                        \
        get_field(fld,tag,fn); }                \
    else {                                      \
        fld.magic = 0;                          \
        fld.enctype = 0;                        \
        fld.kvno = 0;                           \
        fld.ciphertext.data = NULL;             \
        fld.ciphertext.length = 0;              \
    }

asn1_error_code
asn1_decode_sam_response(asn1buf *buf, krb5_sam_response *val)
{
    setup();
    val->sam_track_id.data = NULL;
    val->sam_enc_key.ciphertext.data = NULL;
    val->sam_enc_nonce_or_ts.ciphertext.data = NULL;
    { begin_structure();
        get_field(val->sam_type,0,asn1_decode_int32);
        get_field(val->sam_flags,1,asn1_decode_sam_flags);
        opt_string(val->sam_track_id,2,asn1_decode_charstring);
        opt_encfield(val->sam_enc_key,3,asn1_decode_encrypted_data);
        get_field(val->sam_enc_nonce_or_ts,4,asn1_decode_encrypted_data);
        opt_field(val->sam_nonce,5,asn1_decode_int32,0);
        opt_field(val->sam_patimestamp,6,asn1_decode_kerberos_time,0);
        end_structure();
        val->magic = KV5M_SAM_RESPONSE;
    }
    return 0;
error_out:
    krb5_free_sam_response_contents(NULL, val);
    return retval;
}

asn1_error_code
asn1_decode_sam_response_2(asn1buf *buf, krb5_sam_response_2 *val)
{
    setup();
    val->sam_track_id.data = NULL;
    val->sam_enc_nonce_or_sad.ciphertext.data = NULL;
    { begin_structure();
        get_field(val->sam_type,0,asn1_decode_int32);
        get_field(val->sam_flags,1,asn1_decode_sam_flags);
        opt_string(val->sam_track_id,2,asn1_decode_charstring);
        get_field(val->sam_enc_nonce_or_sad,3,asn1_decode_encrypted_data);
        get_field(val->sam_nonce,4,asn1_decode_int32);
        end_structure();
        val->magic = KV5M_SAM_RESPONSE;
    }
    return 0;
error_out:
    krb5_free_sam_response_2_contents(NULL, val);
    return retval;
}


asn1_error_code
asn1_decode_predicted_sam_response(asn1buf *buf,
                                   krb5_predicted_sam_response *val)
{
    setup();
    val->sam_key.contents = NULL;
    val->client = NULL;
    val->msd.data = NULL;
    { begin_structure();
        get_field(val->sam_key,0,asn1_decode_encryption_key);
        get_field(val->sam_flags,1,asn1_decode_sam_flags);
        get_field(val->stime,2,asn1_decode_kerberos_time);
        get_field(val->susec,3,asn1_decode_int32);
        alloc_principal(val->client);
        get_field(val->client,4,asn1_decode_realm);
        get_field(val->client,5,asn1_decode_principal_name);
        opt_string(val->msd,6,asn1_decode_charstring); /* should be octet */
        end_structure();
        val->magic = KV5M_PREDICTED_SAM_RESPONSE;
    }
    return 0;
error_out:
    krb5_free_predicted_sam_response_contents(NULL, val);
    return retval;
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
asn1_decode_fast_armor(asn1buf *buf, krb5_fast_armor *val)
{
    setup();
    val->armor_value.data = NULL;
    {begin_structure();
        get_field(val->armor_type, 0, asn1_decode_int32);
        get_lenfield(val->armor_value.length, val->armor_value.data,
                     1, asn1_decode_charstring);
        end_structure();
    }
    return 0;
error_out:
    krb5_free_data_contents( NULL, &val->armor_value);
    return retval;
}

asn1_error_code
asn1_decode_fast_armor_ptr(asn1buf *buf, krb5_fast_armor **valptr)
{
    decode_ptr(krb5_fast_armor *, asn1_decode_fast_armor);
}

asn1_error_code
asn1_decode_fast_finished(asn1buf *buf, krb5_fast_finished *val)
{
    setup();
    val->client = NULL;
    val->ticket_checksum.contents = NULL;
    {begin_structure();
        get_field(val->timestamp, 0, asn1_decode_kerberos_time);
        get_field(val->usec, 1, asn1_decode_int32);
        alloc_field(val->client);
        get_field(val->client, 2, asn1_decode_realm);
        get_field(val->client, 3, asn1_decode_principal_name);
        get_field(val->ticket_checksum, 4, asn1_decode_checksum);
        end_structure();
    }
    return 0;
error_out:
    krb5_free_principal(NULL, val->client);
    krb5_free_checksum_contents( NULL, &val->ticket_checksum);
    return retval;
}
asn1_error_code
asn1_decode_fast_finished_ptr(asn1buf *buf, krb5_fast_finished **valptr)
{
    decode_ptr( krb5_fast_finished *, asn1_decode_fast_finished);
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

asn1_error_code
asn1_decode_pa_pk_as_req(asn1buf *buf, krb5_pa_pk_as_req *val)
{
    setup();
    val->signedAuthPack.data = NULL;
    val->trustedCertifiers = NULL;
    val->kdcPkId.data = NULL;
    {
        begin_structure();
        get_implicit_octet_string(val->signedAuthPack.length, val->signedAuthPack.data, 0);
        opt_field(val->trustedCertifiers, 1, asn1_decode_sequence_of_external_principal_identifier, NULL);
        opt_implicit_octet_string(val->kdcPkId.length, val->kdcPkId.data, 2);
        end_structure();
    }
    return 0;
error_out:
    free(val->signedAuthPack.data);
    free(val->trustedCertifiers);
    free(val->kdcPkId.data);
    val->signedAuthPack.data = NULL;
    val->trustedCertifiers = NULL;
    val->kdcPkId.data = NULL;
    return retval;
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
#endif

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

asn1_error_code
asn1_decode_pa_pk_as_req_draft9(asn1buf *buf, krb5_pa_pk_as_req_draft9 *val)
{
    int i;
    setup();
    val->signedAuthPack.data = NULL;
    val->kdcCert.data = NULL;
    val->encryptionCert.data = NULL;
    val->trustedCertifiers = NULL;
    { begin_structure();
        get_implicit_octet_string(val->signedAuthPack.length, val->signedAuthPack.data, 0);
        opt_field(val->trustedCertifiers, 1, asn1_decode_sequence_of_trusted_ca, NULL);
        opt_lenfield(val->kdcCert.length, val->kdcCert.data, 2, asn1_decode_octetstring);
        opt_lenfield(val->encryptionCert.length, val->encryptionCert.data, 2, asn1_decode_octetstring);
        end_structure();
    }
    return 0;
error_out:
    free(val->signedAuthPack.data);
    free(val->kdcCert.data);
    free(val->encryptionCert.data);
    if (val->trustedCertifiers) {
        for (i = 0; val->trustedCertifiers[i]; i++)
            free_trusted_ca(NULL, val->trustedCertifiers[i]);
        free(val->trustedCertifiers);
    }
    val->signedAuthPack.data = NULL;
    val->kdcCert.data = NULL;
    val->encryptionCert.data = NULL;
    val->trustedCertifiers = NULL;
    return retval;
}

asn1_error_code
asn1_decode_dh_rep_info(asn1buf *buf, krb5_dh_rep_info *val)
{
    setup();
    val->dhSignedData.data = NULL;
    val->serverDHNonce.data = NULL;
    { begin_structure();
        get_implicit_octet_string(val->dhSignedData.length, val->dhSignedData.data, 0);

        opt_lenfield(val->serverDHNonce.length, val->serverDHNonce.data, 1, asn1_decode_octetstring);
        end_structure();
    }
    return 0;
error_out:
    free(val->dhSignedData.data);
    free(val->serverDHNonce.data);
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
asn1_decode_auth_pack(asn1buf *buf, krb5_auth_pack *val)
{
    int i;
    setup();
    val->clientPublicValue = NULL;
    val->pkAuthenticator.paChecksum.contents = NULL;
    val->supportedCMSTypes = NULL;
    val->clientDHNonce.data = NULL;
    { begin_structure();
        get_field(val->pkAuthenticator, 0, asn1_decode_pk_authenticator);
        if (tagnum == 1) {
            alloc_field(val->clientPublicValue);
            val->clientPublicValue->algorithm.algorithm.data = NULL;
            val->clientPublicValue->algorithm.parameters.data = NULL;
            val->clientPublicValue->subjectPublicKey.data = NULL;
        }
        /* can't call opt_field because it does decoder(&subbuf, &(val)); */
        if (asn1buf_remains(&subbuf, seqindef)) {
            if ((asn1class != CONTEXT_SPECIFIC || construction != CONSTRUCTED)
                && (tagnum || taglen || asn1class != UNIVERSAL))
                clean_return(ASN1_BAD_ID);
            if (tagnum == 1) {
                retval = asn1_decode_subject_pk_info(&subbuf,
                                                     val->clientPublicValue);
                if (retval) clean_return(retval);
                if (!taglen && indef) { get_eoc(); }
                next_tag();
            } else val->clientPublicValue = NULL;
        }
        /* can't call opt_field because it does decoder(&subbuf, &(val)); */
        if (asn1buf_remains(&subbuf, seqindef)) {
            if (tagnum == 2) {
                retval = asn1_decode_sequence_of_algorithm_identifier(&subbuf, &val->supportedCMSTypes);
                if (retval) clean_return(retval);
                if (!taglen && indef) { get_eoc(); }
                next_tag();
            } else val->supportedCMSTypes = NULL;
        }
        opt_lenfield(val->clientDHNonce.length, val->clientDHNonce.data, 3, asn1_decode_octetstring);
        end_structure();
    }
    return 0;
error_out:
    if (val->clientPublicValue) {
        free(val->clientPublicValue->algorithm.algorithm.data);
        free(val->clientPublicValue->algorithm.parameters.data);
        free(val->clientPublicValue->subjectPublicKey.data);
        free(val->clientPublicValue);
    }
    free(val->pkAuthenticator.paChecksum.contents);
    if (val->supportedCMSTypes) {
        for (i = 0; val->supportedCMSTypes[i]; i++)
            free_algorithm_identifier(NULL, val->supportedCMSTypes[i]);
        free(val->supportedCMSTypes);
    }
    free(val->clientDHNonce.data);
    val->clientPublicValue = NULL;
    val->pkAuthenticator.paChecksum.contents = NULL;
    val->supportedCMSTypes = NULL;
    val->clientDHNonce.data = NULL;
    return retval;
}

asn1_error_code
asn1_decode_auth_pack_draft9(asn1buf *buf, krb5_auth_pack_draft9 *val)
{
    setup();
    val->pkAuthenticator.kdcName = NULL;
    val->clientPublicValue = NULL;
    { begin_structure();
        get_field(val->pkAuthenticator, 0, asn1_decode_pk_authenticator_draft9);
        if (tagnum == 1) {
            alloc_field(val->clientPublicValue);
            val->clientPublicValue->algorithm.algorithm.data = NULL;
            val->clientPublicValue->algorithm.parameters.data = NULL;
            val->clientPublicValue->subjectPublicKey.data = NULL;
            /* can't call opt_field because it does decoder(&subbuf, &(val)); */
            if (asn1buf_remains(&subbuf, seqindef)) {
                if ((asn1class != CONTEXT_SPECIFIC || construction != CONSTRUCTED)
                    && (tagnum || taglen || asn1class != UNIVERSAL))
                    clean_return(ASN1_BAD_ID);
                if (tagnum == 1) {
                    retval = asn1_decode_subject_pk_info(&subbuf,
                                                         val->clientPublicValue);
                    if (retval) clean_return(retval);
                    if (!taglen && indef) { get_eoc(); }
                    next_tag();
                } else val->clientPublicValue = NULL;
            }
        }
        end_structure();
    }
    return 0;
error_out:
    free(val->pkAuthenticator.kdcName);
    if (val->clientPublicValue) {
        free(val->clientPublicValue->algorithm.algorithm.data);
        free(val->clientPublicValue->algorithm.parameters.data);
        free(val->clientPublicValue->subjectPublicKey.data);
        free(val->clientPublicValue);
    }
    val->pkAuthenticator.kdcName = NULL;
    val->clientPublicValue = NULL;
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

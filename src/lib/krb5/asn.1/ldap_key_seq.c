/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* ... copyright ... */

/*
 * Novell key-format scheme:
 *
 * KrbKeySet ::= SEQUENCE {
 * attribute-major-vno       [0] UInt16,
 * attribute-minor-vno       [1] UInt16,
 * kvno                      [2] UInt32,
 * mkvno                     [3] UInt32 OPTIONAL,
 * keys                      [4] SEQUENCE OF KrbKey,
 * ...
 * }
 *
 * KrbKey ::= SEQUENCE {
 * salt      [0] KrbSalt OPTIONAL,
 * key       [1] EncryptionKey,
 * s2kparams [2] OCTET STRING OPTIONAL,
 *  ...
 * }
 *
 * KrbSalt ::= SEQUENCE {
 * type      [0] Int32,
 * salt      [1] OCTET STRING OPTIONAL
 * }
 *
 * EncryptionKey ::= SEQUENCE {
 * keytype   [0] Int32,
 * keyvalue  [1] OCTET STRING
 * }
 *
 */

#include <k5-int.h>
#include <kdb.h>

#include "krbasn1.h"
#include "asn1_encode.h"
#include "asn1_decode.h"
#include "asn1_make.h"
#include "asn1_get.h"
#include "asn1_k_encode.h"

#ifdef ENABLE_LDAP

/************************************************************************/
/* Encode the Principal's keys                                          */
/************************************************************************/

/*
 * Imports from asn1_k_encode.c.
 * XXX Must be manually synchronized for now.
 */
IMPORT_TYPE(octetstring, unsigned char *);
IMPORT_TYPE(int32, krb5_int32);

DEFINTTYPE(int16, krb5_int16);
DEFINTTYPE(ui_2, krb5_ui_2);

static const struct field_info krbsalt_fields[] = {
    FIELDOF_NORM(krb5_key_data, int16, key_data_type[1], 0),
    FIELDOF_OPTSTRINGL(krb5_key_data, octetstring, key_data_contents[1],
                       ui_2, key_data_length[1], 1, 1),
};
static unsigned int
optional_krbsalt (const void *p)
{
    const krb5_key_data *k = p;
    unsigned int optional = 0;

    if (k->key_data_length[1] > 0)
        optional |= (1u << 1);

    return optional;
}
DEFSEQTYPE(krbsalt, krb5_key_data, krbsalt_fields, optional_krbsalt);
static const struct field_info encryptionkey_fields[] = {
    FIELDOF_NORM(krb5_key_data, int16, key_data_type[0], 0),
    FIELDOF_STRINGL(krb5_key_data, octetstring, key_data_contents[0],
                    ui_2, key_data_length[0], 1),
};
DEFSEQTYPE(encryptionkey, krb5_key_data, encryptionkey_fields, 0);

static const struct field_info key_data_fields[] = {
    FIELDOF_ENCODEAS(krb5_key_data, krbsalt, 0),
    FIELDOF_ENCODEAS(krb5_key_data, encryptionkey, 1),
#if 0 /* We don't support this field currently.  */
    FIELDOF_blah(krb5_key_data, s2kparams, ...),
#endif
};
DEFSEQTYPE(key_data, krb5_key_data, key_data_fields, 0);
DEFPTRTYPE(ptr_key_data, key_data);

DEFFIELDTYPE(key_data_kvno, krb5_key_data,
             FIELDOF_NORM(krb5_key_data, int16, key_data_kvno, -1));
DEFPTRTYPE(ptr_key_data_kvno, key_data_kvno);

static const struct field_info ldap_key_seq_fields[] = {
    FIELD_INT_IMM(1, 0),
    FIELD_INT_IMM(1, 1),
    FIELDOF_NORM(ldap_seqof_key_data, ptr_key_data_kvno, key_data, 2),
    FIELDOF_NORM(ldap_seqof_key_data, int32, mkvno, 3), /* mkvno */
    FIELDOF_SEQOF_LEN(ldap_seqof_key_data, ptr_key_data, key_data, n_key_data,
                      int16, 4),
};
DEFSEQTYPE(ldap_key_seq, ldap_seqof_key_data, ldap_key_seq_fields, 0);

/* Export a function to do the whole encoding.  */
MAKE_FULL_ENCODER(krb5int_ldap_encode_sequence_of_keys, ldap_key_seq);

/************************************************************************/
/* Decode the Principal's keys                                          */
/************************************************************************/

#define cleanup(err)                            \
    {                                           \
        ret = err;                              \
        goto last;                              \
    }

#define checkerr                                \
    if (ret != 0)                               \
        goto last

#define safe_syncbuf(outer,inner,buflen)                \
    if (! ((inner)->next == (inner)->bound + 1 &&       \
           (inner)->next == (outer)->next + buflen))    \
        cleanup (ASN1_BAD_LENGTH);                      \
    asn1buf_sync((outer), (inner), 0, 0, 0, 0, 0);

static asn1_error_code
decode_tagged_integer (asn1buf *buf, asn1_tagnum expectedtag, long *val)
{
    int buflen;
    asn1_error_code ret = 0;
    asn1buf tmp, subbuf;
    taginfo t;

    /* Work on a copy of 'buf' */
    ret = asn1buf_imbed(&tmp, buf, 0, 1); checkerr;
    ret = asn1_get_tag_2(&tmp, &t); checkerr;
    if (t.tagnum != expectedtag)
        cleanup (ASN1_MISSING_FIELD);

    buflen = t.length;
    ret = asn1buf_imbed(&subbuf, &tmp, t.length, 0); checkerr;
    ret = asn1_decode_integer(&subbuf, val); checkerr;

    safe_syncbuf(&tmp, &subbuf, buflen);
    *buf = tmp;

last:
    return ret;
}

#if 0 /* not currently used */
static asn1_error_code
decode_tagged_unsigned_integer (asn1buf *buf, int expectedtag, unsigned long *val)
{
    int buflen;
    asn1_error_code ret = 0;
    asn1buf tmp, subbuf;
    taginfo t;

    /* Work on a copy of 'buf' */
    ret = asn1buf_imbed(&tmp, buf, 0, 1); checkerr;
    ret = asn1_get_tag_2(&tmp, &t); checkerr;
    if (t.tagnum != expectedtag)
        cleanup (ASN1_MISSING_FIELD);

    buflen = t.length;
    ret = asn1buf_imbed(&subbuf, &tmp, t.length, 0); checkerr;
    ret = asn1_decode_unsigned_integer(&subbuf, val); checkerr;

    safe_syncbuf(&tmp, &subbuf, buflen);
    *buf = tmp;

last:
    return ret;
}
#endif

static asn1_error_code
decode_tagged_octetstring (asn1buf *buf, asn1_tagnum expectedtag,
                           unsigned int *len,
                           asn1_octet **val)
{
    int buflen;
    asn1_error_code ret = 0;
    asn1buf tmp, subbuf;
    taginfo t;

    *val = NULL;

    /* Work on a copy of 'buf' */
    ret = asn1buf_imbed(&tmp, buf, 0, 1); checkerr;
    ret = asn1_get_tag_2(&tmp, &t); checkerr;
    if (t.tagnum != expectedtag)
        cleanup (ASN1_MISSING_FIELD);

    buflen = t.length;
    ret = asn1buf_imbed(&subbuf, &tmp, t.length, 0); checkerr;
    ret = asn1_decode_octetstring (&subbuf, len, val); checkerr;

    safe_syncbuf(&tmp, &subbuf, buflen);
    *buf = tmp;

last:
    if (ret != 0)
        free (*val);
    return ret;
}

static asn1_error_code
asn1_decode_key(asn1buf *buf, krb5_key_data *key)
{
    int full_buflen, seqindef;
    unsigned int length;
    asn1_error_code ret;
    asn1buf subbuf;
    taginfo t;

    key->key_data_contents[0] = NULL;
    key->key_data_contents[1] = NULL;

    ret = asn1_get_sequence(buf, &length, &seqindef); checkerr;
    full_buflen = length;
    ret = asn1buf_imbed(&subbuf, buf, length, seqindef); checkerr;

    asn1_get_tag_2(&subbuf, &t);
    /* Salt */
    if (t.tagnum == 0) {
        int salt_buflen;
        asn1buf slt;
        long keytype;
        unsigned int keylen;

        key->key_data_ver = 2;
        asn1_get_sequence(&subbuf, &length, &seqindef);
        salt_buflen = length;
        asn1buf_imbed(&slt, &subbuf, length, seqindef);

        ret = decode_tagged_integer (&slt, 0, &keytype);
        key->key_data_type[1] = keytype; /* XXX range check?? */
        checkerr;

        if (asn1buf_remains(&slt, 0) != 0) { /* Salt value is optional */
            ret = decode_tagged_octetstring (&slt, 1, &keylen,
                                             &key->key_data_contents[1]);
            checkerr;
        } else
            keylen = 0;
        safe_syncbuf (&subbuf, &slt, salt_buflen);
        key->key_data_length[1] = keylen; /* XXX range check?? */

        ret = asn1_get_tag_2(&subbuf, &t); checkerr;
    } else
        key->key_data_ver = 1;

    /* Key */
    {
        int key_buflen;
        asn1buf kbuf;
        long lval;
        unsigned int ival;

        if (t.tagnum != 1)
            cleanup (ASN1_MISSING_FIELD);

        ret = asn1_get_sequence(&subbuf, &length, &seqindef); checkerr;
        key_buflen = length;
        ret = asn1buf_imbed(&kbuf, &subbuf, length, seqindef); checkerr;

        ret = decode_tagged_integer (&kbuf, 0, &lval);
        checkerr;
        key->key_data_type[0] = lval; /* XXX range check? */

        ret = decode_tagged_octetstring (&kbuf, 1, &ival,
                                         &key->key_data_contents[0]); checkerr;
        key->key_data_length[0] = ival; /* XXX range check? */

        safe_syncbuf (&subbuf, &kbuf, key_buflen);
    }

    safe_syncbuf (buf, &subbuf, full_buflen);

last:
    if (ret != 0) {
        free (key->key_data_contents[0]);
        key->key_data_contents[0] = NULL;
        free (key->key_data_contents[1]);
        key->key_data_contents[1] = NULL;
    }
    return ret;
}

krb5_error_code
krb5int_ldap_decode_sequence_of_keys (krb5_data *in, ldap_seqof_key_data **rep)
{
    ldap_seqof_key_data *repval;
    krb5_key_data **out;
    krb5_int16 *n_key_data;
    int *mkvno;

    asn1_error_code ret;
    asn1buf buf, subbuf;
    int seqindef;
    unsigned int length;
    taginfo t;
    int kvno, maj, min;
    long lval;

    repval = calloc(1,sizeof(ldap_seqof_key_data));
    *rep = repval;
    out = &repval->key_data;
    n_key_data = &repval->n_key_data;
    mkvno = &repval->mkvno;

    *n_key_data = 0;
    *out = NULL;

    ret = asn1buf_wrap_data(&buf, in); checkerr;

    ret = asn1_get_sequence(&buf, &length, &seqindef); checkerr;
    ret = asn1buf_imbed(&subbuf, &buf, length, seqindef); checkerr;

    /* attribute-major-vno */
    ret = decode_tagged_integer (&subbuf, 0, &lval); checkerr;
    maj = lval;                 /* XXX range check? */

    /* attribute-minor-vno */
    ret = decode_tagged_integer (&subbuf, 1, &lval); checkerr;
    min = lval;                 /* XXX range check? */

    if (maj != 1 || min != 1)
        cleanup (ASN1_BAD_FORMAT);

    /* kvno (assuming all keys in array have same version) */
    ret = decode_tagged_integer (&subbuf, 2, &lval); checkerr;
    kvno = lval;                /* XXX range check? */

    /* mkvno (optional) */
    ret = decode_tagged_integer (&subbuf, 3, &lval); checkerr;
    *mkvno = lval;              /* XXX range check? */

    ret = asn1_get_tag_2(&subbuf, &t); checkerr;

    /* Sequence of keys */
    {
        int i, seq_buflen;
        asn1buf keyseq;
        if (t.tagnum != 4)
            cleanup (ASN1_MISSING_FIELD);
        ret = asn1_get_sequence(&subbuf, &length, &seqindef); checkerr;
        seq_buflen = length;
        ret = asn1buf_imbed(&keyseq, &subbuf, length, seqindef); checkerr;
        for (i = 1, *out = NULL; ; i++) {
            krb5_key_data *tmp;
            tmp = (krb5_key_data *) realloc (*out, i * sizeof (krb5_key_data));
            if (tmp == NULL)
                cleanup (ENOMEM);
            *out = tmp;
            (*out)[i - 1].key_data_kvno = kvno;
            ret = asn1_decode_key(&keyseq, &(*out)[i - 1]); checkerr;
            (*n_key_data)++;
            if (asn1buf_remains(&keyseq, 0) == 0)
                break; /* Not freeing the last key structure */
        }
        safe_syncbuf (&subbuf, &keyseq, seq_buflen);
    }

    /*
     * There could be other data inside the outermost sequence ... tags we don't
     * know about. So, not invoking "safe_syncbuf(&buf,&subbuf)"
     */

last:
    if (ret != 0) {
        int i;
        for (i = 0; i < *n_key_data; i++) {
            free ((*out)[i].key_data_contents[0]);
            free ((*out)[i].key_data_contents[1]);
        }
        free (*out);
        *out = NULL;
    }

    return ret;
}
#endif

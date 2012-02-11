/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/asn.1/asn1_encode.c */
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

#include "asn1_encode.h"

/**** Functions for encoding primitive types ****/

asn1_error_code
k5_asn1_encode_bool(asn1buf *buf, asn1_intmax val, size_t *len_out)
{
    asn1_octet bval = val ? 0xFF : 0x00;

    *len_out = 1;
    return asn1buf_insert_octet(buf, bval);
}

asn1_error_code
k5_asn1_encode_int(asn1buf *buf, asn1_intmax val, size_t *len_out)
{
    asn1_error_code ret;
    size_t len = 0;
    long valcopy;
    int digit;

    valcopy = val;
    do {
        digit = valcopy & 0xFF;
        ret = asn1buf_insert_octet(buf, digit);
        if (ret)
            return ret;
        len++;
        valcopy = valcopy >> 8;
    } while (valcopy != 0 && valcopy != ~0);

    if (val > 0 && (digit & 0x80) == 0x80) { /* make sure the high bit is */
        ret = asn1buf_insert_octet(buf, 0);  /* of the proper signed-ness */
        if (ret)
            return ret;
        len++;
    } else if (val < 0 && (digit & 0x80) != 0x80) {
        ret = asn1buf_insert_octet(buf, 0xFF);
        if (ret)
            return ret;
        len++;
    }


    *len_out = len;
    return 0;
}

asn1_error_code
k5_asn1_encode_uint(asn1buf *buf, asn1_uintmax val, size_t *len_out)
{
    asn1_error_code ret;
    size_t len = 0;
    asn1_uintmax valcopy;
    int digit;

    valcopy = val;
    do {
        digit = valcopy & 0xFF;
        ret = asn1buf_insert_octet(buf, digit);
        if (ret)
            return ret;
        len++;
        valcopy = valcopy >> 8;
    } while (valcopy != 0);

    if (digit & 0x80) {                     /* make sure the high bit is */
        ret = asn1buf_insert_octet(buf, 0); /* of the proper signed-ness */
        if (ret)
            return ret;
        len++;
    }

    *len_out = len;
    return 0;
}

asn1_error_code
k5_asn1_encode_bytestring(asn1buf *buf, unsigned char *const *val, size_t len,
                          size_t *len_out)
{
    if (len > 0 && val == NULL)
        return ASN1_MISSING_FIELD;
    *len_out = len;
    return asn1buf_insert_octetstring(buf, len, *val);
}

asn1_error_code
k5_asn1_encode_generaltime(asn1buf *buf, time_t val, size_t *len_out)
{
    struct tm *gtime, gtimebuf;
    char s[16];
    unsigned char *sp;
    time_t gmt_time = val;
    int len;

    /*
     * Time encoding: YYYYMMDDhhmmssZ
     */
    if (gmt_time == 0) {
        sp = (unsigned char *)"19700101000000Z";
    } else {
        /*
         * Sanity check this just to be paranoid, as gmtime can return NULL,
         * and some bogus implementations might overrun on the sprintf.
         */
#ifdef HAVE_GMTIME_R
#ifdef GMTIME_R_RETURNS_INT
        if (gmtime_r(&gmt_time, &gtimebuf) != 0)
            return ASN1_BAD_GMTIME;
#else
        if (gmtime_r(&gmt_time, &gtimebuf) == NULL)
            return ASN1_BAD_GMTIME;
#endif
#else /* HAVE_GMTIME_R */
        gtime = gmtime(&gmt_time);
        if (gtime == NULL)
            return ASN1_BAD_GMTIME;
        memcpy(&gtimebuf, gtime, sizeof(gtimebuf));
#endif /* HAVE_GMTIME_R */
        gtime = &gtimebuf;

        if (gtime->tm_year > 8099 || gtime->tm_mon > 11 ||
            gtime->tm_mday > 31 || gtime->tm_hour > 23 ||
            gtime->tm_min > 59 || gtime->tm_sec > 59)
            return ASN1_BAD_GMTIME;
        len = snprintf(s, sizeof(s), "%04d%02d%02d%02d%02d%02dZ",
                       1900 + gtime->tm_year, gtime->tm_mon + 1,
                       gtime->tm_mday, gtime->tm_hour,
                       gtime->tm_min, gtime->tm_sec);
        if (SNPRINTF_OVERFLOW(len, sizeof(s)))
            /* Shouldn't be possible given above tests.  */
            return ASN1_BAD_GMTIME;
        sp = (unsigned char *)s;
    }

    return k5_asn1_encode_bytestring(buf, &sp, 15, len_out);
}

asn1_error_code
k5_asn1_encode_bitstring(asn1buf *buf, unsigned char *const *val, size_t len,
                         size_t *len_out)
{
    asn1_error_code ret;

    ret = asn1buf_insert_octetstring(buf, len, *val);
    if (ret)
        return ret;
    *len_out = len + 1;
    return asn1buf_insert_octet(buf, '\0');
}

/* Encode a DER tag into buf with the tag and length parameters in t.  Place
 * the length of the encoded tag in *retlen. */
static asn1_error_code
make_tag(asn1buf *buf, const taginfo *t, size_t *retlen)
{
    asn1_error_code ret;
    asn1_tagnum tag_copy;
    size_t sum = 0, length, len_copy;

    if (t->tagnum > ASN1_TAGNUM_MAX)
        return ASN1_OVERFLOW;

    /* Encode the length of the content within the tag. */
    if (t->length < 128) {
        ret = asn1buf_insert_octet(buf, t->length & 0x7F);
        if (ret)
            return ret;
        length = 1;
    } else {
        length = 0;
        for (len_copy = t->length; len_copy != 0; len_copy >>= 8) {
            ret = asn1buf_insert_octet(buf, len_copy & 0xFF);
            if (ret)
                return ret;
            length++;
        }
        ret = asn1buf_insert_octet(buf, 0x80 | (length & 0x7F));
        if (ret)
            return ret;
        length++;
    }
    sum += length;

    /* Encode the tag and construction bit. */
    if (t->tagnum < 31) {
        ret = asn1buf_insert_octet(buf,
                                   t->asn1class | t->construction | t->tagnum);
        if (ret)
            return ret;
        length = 1;
    } else {
        tag_copy = t->tagnum;
        length = 0;
        ret = asn1buf_insert_octet(buf, tag_copy & 0x7F);
        if (ret)
            return ret;
        tag_copy >>= 7;
        length++;

        for (; tag_copy != 0; tag_copy >>= 7) {
            ret = asn1buf_insert_octet(buf, 0x80 | (tag_copy & 0x7F));
            if (ret)
                return ret;
            length++;
        }

        ret = asn1buf_insert_octet(buf, t->asn1class | t->construction | 0x1F);
        if (ret)
            return ret;
        length++;
    }
    sum += length;

    *retlen = sum;
    return 0;
}

#ifdef POINTERS_ARE_ALL_THE_SAME
#define LOADPTR(PTR, TYPE) (*(const void *const *)(PTR))
#else
#define LOADPTR(PTR, PTRINFO)                                           \
    (assert((PTRINFO)->loadptr != NULL), (PTRINFO)->loadptr(PTR))
#endif

static size_t
get_nullterm_sequence_len(const void *valp, const struct atype_info *seq)
{
    size_t i;
    const struct atype_info *a;
    const struct ptr_info *ptr;
    const void *elt, *eltptr;

    a = seq;
    i = 0;
    assert(a->type == atype_ptr);
    assert(seq->size != 0);
    ptr = a->tinfo;

    while (1) {
        eltptr = (const char *)valp + i * seq->size;
        elt = LOADPTR(eltptr, ptr);
        if (elt == NULL)
            break;
        i++;
    }
    return i;
}
static asn1_error_code
encode_sequence_of(asn1buf *buf, size_t seqlen, const void *val,
                   const struct atype_info *eltinfo, size_t *len_out);

static asn1_error_code
encode_nullterm_sequence_of(asn1buf *buf, const void *val,
                            const struct atype_info *type,
                            int can_be_empty, size_t *len_out)
{
    size_t len = get_nullterm_sequence_len(val, type);

    if (!can_be_empty && len == 0)
        return ASN1_MISSING_FIELD;
    return encode_sequence_of(buf, len, val, type, len_out);
}

static asn1_intmax
load_int(const void *val, size_t size)
{
    switch (size) {
    case 1: return *(signed char *)val;
    case 2: return *(krb5_int16 *)val;
    case 4: return *(krb5_int32 *)val;
    case 8: return *(INT64_TYPE *)val;
    default: abort();
    }
}

static asn1_uintmax
load_uint(const void *val, size_t size)
{
    switch (size) {
    case 1: return *(unsigned char *)val;
    case 2: return *(krb5_ui_2 *)val;
    case 4: return *(krb5_ui_4 *)val;
    case 8: return *(UINT64_TYPE *)val;
    default: abort();
    }
}

static asn1_error_code
load_count(const void *val, const struct counted_info *counted,
           size_t *count_out)
{
    const void *countptr = (const char *)val + counted->lenoff;

    assert(sizeof(size_t) <= sizeof(asn1_uintmax));
    if (counted->lensigned) {
        asn1_intmax xlen = load_int(countptr, counted->lensize);
        if (xlen < 0 || (asn1_uintmax)xlen > SIZE_MAX)
            return EINVAL;
        *count_out = xlen;
    } else {
        asn1_uintmax xlen = load_uint(countptr, counted->lensize);
        if ((size_t)xlen != xlen || xlen > SIZE_MAX)
            return EINVAL;
        *count_out = xlen;
    }
    return 0;
}

/* Split a DER encoding into tag and contents.  Insert the contents into buf,
 * then return the length of the contents and the tag. */
static asn1_error_code
split_der(asn1buf *buf, unsigned char *const *der, size_t len,
          taginfo *tag_out)
{
    asn1buf der_buf;
    krb5_data der_data = make_data(*der, len);
    asn1_error_code ret;

    ret = asn1buf_wrap_data(&der_buf, &der_data);
    if (ret)
        return ret;
    ret = asn1_get_tag_2(&der_buf, tag_out);
    if (ret)
        return ret;
    if ((size_t)asn1buf_remains(&der_buf, 0) != tag_out->length)
        return EINVAL;
    return asn1buf_insert_bytestring(buf, tag_out->length,
                                     *der + len - tag_out->length);
}

static asn1_error_code
encode_sequence(asn1buf *buf, const void *val, const struct seq_info *seq,
                size_t *len_out);
static asn1_error_code
encode_cntype(asn1buf *buf, const void *val, size_t len,
              const struct cntype_info *c, taginfo *tag_out);

/* Encode a value (contents only, no outer tag) according to a type, and return
 * its encoded tag information. */
static asn1_error_code
encode_atype(asn1buf *buf, const void *val, const struct atype_info *a,
             taginfo *tag_out)
{
    asn1_error_code ret;

    if (val == NULL)
        return ASN1_MISSING_FIELD;

    switch (a->type) {
    case atype_fn: {
        const struct fn_info *fn = a->tinfo;
        assert(fn->enc != NULL);
        return fn->enc(buf, val, tag_out);
    }
    case atype_sequence:
        assert(a->tinfo != NULL);
        ret = encode_sequence(buf, val, a->tinfo, &tag_out->length);
        if (ret)
            return ret;
        tag_out->asn1class = UNIVERSAL;
        tag_out->construction = CONSTRUCTED;
        tag_out->tagnum = ASN1_SEQUENCE;
        break;
    case atype_ptr: {
        const struct ptr_info *ptr = a->tinfo;
        assert(ptr->basetype != NULL);
        return encode_atype(buf, LOADPTR(val, ptr), ptr->basetype, tag_out);
    }
    case atype_offset: {
        const struct offset_info *off = a->tinfo;
        assert(off->basetype != NULL);
        return encode_atype(buf, (const char *)val + off->dataoff,
                            off->basetype, tag_out);
    }
    case atype_optional: {
        const struct optional_info *opt = a->tinfo;
        assert(opt->is_present != NULL);
        if (opt->is_present(val))
            return encode_atype(buf, val, opt->basetype, tag_out);
        else
            return ASN1_OMITTED;
    }
    case atype_counted: {
        const struct counted_info *counted = a->tinfo;
        const void *dataptr = (const char *)val + counted->dataoff;
        size_t count;
        assert(counted->basetype != NULL);
        ret = load_count(val, counted, &count);
        if (ret)
            return ret;
        return encode_cntype(buf, dataptr, count, counted->basetype, tag_out);
    }
    case atype_nullterm_sequence_of:
    case atype_nonempty_nullterm_sequence_of:
        assert(a->tinfo != NULL);
        ret = encode_nullterm_sequence_of(buf, val, a->tinfo,
                                          a->type ==
                                          atype_nullterm_sequence_of,
                                          &tag_out->length);
        if (ret)
            return ret;
        tag_out->asn1class = UNIVERSAL;
        tag_out->construction = CONSTRUCTED;
        tag_out->tagnum = ASN1_SEQUENCE;
        break;
    case atype_tagged_thing: {
        const struct tagged_info *tag = a->tinfo;
        ret = encode_atype(buf, val, tag->basetype, tag_out);
        if (ret)
            return ret;
        if (!tag->implicit) {
            size_t tlen;
            ret = make_tag(buf, tag_out, &tlen);
            if (ret)
                return ret;
            tag_out->length += tlen;
            tag_out->construction = tag->construction;
        }
        tag_out->asn1class = tag->tagtype;
        tag_out->tagnum = tag->tagval;
        break;
    }
    case atype_int:
        ret = k5_asn1_encode_int(buf, load_int(val, a->size),
                                 &tag_out->length);
        if (ret)
            return ret;
        tag_out->asn1class = UNIVERSAL;
        tag_out->construction = PRIMITIVE;
        tag_out->tagnum = ASN1_INTEGER;
        break;
    case atype_uint:
        ret = k5_asn1_encode_uint(buf, load_uint(val, a->size),
                                  &tag_out->length);
        if (ret)
            return ret;
        tag_out->asn1class = UNIVERSAL;
        tag_out->construction = PRIMITIVE;
        tag_out->tagnum = ASN1_INTEGER;
        break;
    case atype_int_immediate: {
        const int *iptr = a->tinfo;
        ret = k5_asn1_encode_int(buf, *iptr, &tag_out->length);
        if (ret)
            return ret;
        tag_out->asn1class = UNIVERSAL;
        tag_out->construction = PRIMITIVE;
        tag_out->tagnum = ASN1_INTEGER;
        break;
    }
    default:
        assert(a->type > atype_min);
        assert(a->type < atype_max);
        abort();
    }

    return 0;
}

static asn1_error_code
encode_atype_and_tag(asn1buf *buf, const void *val, const struct atype_info *a,
                     size_t *len_out)
{
    taginfo t;
    asn1_error_code ret;
    size_t tlen;

    ret = encode_atype(buf, val, a, &t);
    if (ret)
        return ret;
    ret = make_tag(buf, &t, &tlen);
    if (ret)
        return ret;
    *len_out = t.length + tlen;
    return 0;
}

/*
 * Encode an object and count according to a cntype_info structure.  val is a
 * pointer to the object being encoded, which in most cases is itself a
 * pointer (but is a union in the cntype_choice case).
 */
static asn1_error_code
encode_cntype(asn1buf *buf, const void *val, size_t count,
              const struct cntype_info *c, taginfo *tag_out)
{
    asn1_error_code ret;

    switch (c->type) {
    case cntype_string: {
        const struct string_info *string = c->tinfo;
        assert(string->enc != NULL);
        ret = string->enc(buf, val, count, &tag_out->length);
        if (ret)
            return ret;
        tag_out->asn1class = UNIVERSAL;
        tag_out->construction = PRIMITIVE;
        tag_out->tagnum = string->tagval;
        break;
    }
    case cntype_der:
        return split_der(buf, val, count, tag_out);
    case cntype_seqof: {
        const struct atype_info *a = c->tinfo;
        const struct ptr_info *ptr = a->tinfo;
        assert(a->type == atype_ptr);
        val = LOADPTR(val, ptr);
        ret = encode_sequence_of(buf, count, val, ptr->basetype,
                                 &tag_out->length);
        if (ret)
            return ret;
        tag_out->asn1class = UNIVERSAL;
        tag_out->construction = CONSTRUCTED;
        tag_out->tagnum = ASN1_SEQUENCE;
        break;
    }
    case cntype_choice: {
        const struct choice_info *choice = c->tinfo;
        if (count >= choice->n_options)
            return ASN1_MISSING_FIELD;
        return encode_atype(buf, val, choice->options[count], tag_out);
    }

    default:
        assert(c->type > cntype_min);
        assert(c->type < cntype_max);
        abort();
    }

    return 0;
}

static asn1_error_code
encode_sequence(asn1buf *buf, const void *val, const struct seq_info *seq,
                size_t *len_out)
{
    asn1_error_code ret;
    size_t i, len, sum = 0;

    for (i = seq->n_fields; i > 0; i--) {
        ret = encode_atype_and_tag(buf, val, seq->fields[i - 1], &len);
        if (ret == ASN1_OMITTED)
            continue;
        else if (ret != 0)
            return ret;
        sum += len;
    }
    *len_out = sum;
    return 0;
}

static asn1_error_code
encode_sequence_of(asn1buf *buf, size_t seqlen, const void *val,
                   const struct atype_info *eltinfo, size_t *len_out)
{
    asn1_error_code ret;
    size_t sum = 0, i, len;
    const void *eltptr;

    assert(eltinfo->size != 0);
    for (i = seqlen; i > 0; i--) {
        eltptr = (const char *)val + (i - 1) * eltinfo->size;
        ret = encode_atype_and_tag(buf, eltptr, eltinfo, &len);
        if (ret)
            return ret;
        sum += len;
    }
    *len_out = sum;
    return 0;
}

asn1_error_code
k5_asn1_encode_atype(asn1buf *buf, const void *val, const struct atype_info *a,
                     taginfo *tag_out)
{
    return encode_atype(buf, val, a, tag_out);
}

krb5_error_code
k5_asn1_full_encode(const void *rep, const struct atype_info *a,
                    krb5_data **code_out)
{
    size_t len;
    asn1_error_code ret;
    asn1buf *buf = NULL;
    krb5_data *d;

    *code_out = NULL;

    if (rep == NULL)
        return ASN1_MISSING_FIELD;
    ret = asn1buf_create(&buf);
    if (ret)
        return ret;
    ret = encode_atype_and_tag(buf, rep, a, &len);
    if (ret)
        goto cleanup;
    ret = asn12krb5_buf(buf, &d);
    if (ret)
        goto cleanup;
    *code_out = d;
cleanup:
    asn1buf_destroy(&buf);
    return ret;
}

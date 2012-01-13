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

/* ASN.1 primitive encoders */

#include "asn1_encode.h"
#include "asn1_make.h"

asn1_error_code
asn1_encode_boolean(asn1buf *buf, asn1_intmax val, unsigned int *retlen)
{
    asn1_octet bval = val ? 0xFF : 0x00;

    *retlen = 1;
    return asn1buf_insert_octet(buf, bval);
}

asn1_error_code
asn1_encode_integer(asn1buf *buf, asn1_intmax val, unsigned int *retlen)
{
    asn1_error_code retval;
    unsigned int length = 0;
    long valcopy;
    int digit;

    valcopy = val;
    do {
        digit = (int) (valcopy&0xFF);
        retval = asn1buf_insert_octet(buf,(asn1_octet) digit);
        if (retval) return retval;
        length++;
        valcopy = valcopy >> 8;
    } while (valcopy != 0 && valcopy != ~0);

    if ((val > 0) && ((digit&0x80) == 0x80)) { /* make sure the high bit is */
        retval = asn1buf_insert_octet(buf,0); /* of the proper signed-ness */
        if (retval) return retval;
        length++;
    } else if ((val < 0) && ((digit&0x80) != 0x80)) {
        retval = asn1buf_insert_octet(buf,0xFF);
        if (retval) return retval;
        length++;
    }


    *retlen = length;
    return 0;
}

asn1_error_code
asn1_encode_unsigned_integer(asn1buf *buf, asn1_uintmax val,
                             unsigned int *retlen)
{
    asn1_error_code retval;
    unsigned int length = 0;
    unsigned long valcopy;
    int digit;

    valcopy = val;
    do {
        digit = (int) (valcopy&0xFF);
        retval = asn1buf_insert_octet(buf,(asn1_octet) digit);
        if (retval) return retval;
        length++;
        valcopy = valcopy >> 8;
    } while (valcopy != 0);

    if (digit&0x80) {                     /* make sure the high bit is */
        retval = asn1buf_insert_octet(buf,0); /* of the proper signed-ness */
        if (retval) return retval;
        length++;
    }

    *retlen = length;
    return 0;
}

asn1_error_code
asn1_encode_bytestring(asn1buf *buf, unsigned int len, const void *val,
                       unsigned int *retlen)
{
    if (len > 0 && val == NULL) return ASN1_MISSING_FIELD;
    *retlen = len;
    return asn1buf_insert_octetstring(buf, len, val);
}

asn1_error_code
asn1_encode_generaltime(asn1buf *buf, time_t val, unsigned int *retlen)
{
    struct tm *gtime, gtimebuf;
    char s[16], *sp;
    time_t gmt_time = val;

    /*
     * Time encoding: YYYYMMDDhhmmssZ
     */
    if (gmt_time == 0) {
        sp = "19700101000000Z";
    } else {
        int len;

        /*
         * Sanity check this just to be paranoid, as gmtime can return NULL,
         * and some bogus implementations might overrun on the sprintf.
         */
#ifdef HAVE_GMTIME_R
# ifdef GMTIME_R_RETURNS_INT
        if (gmtime_r(&gmt_time, &gtimebuf) != 0)
            return ASN1_BAD_GMTIME;
# else
        if (gmtime_r(&gmt_time, &gtimebuf) == NULL)
            return ASN1_BAD_GMTIME;
# endif
#else
        gtime = gmtime(&gmt_time);
        if (gtime == NULL)
            return ASN1_BAD_GMTIME;
        memcpy(&gtimebuf, gtime, sizeof(gtimebuf));
#endif
        gtime = &gtimebuf;

        if (gtime->tm_year > 8099 || gtime->tm_mon > 11 ||
            gtime->tm_mday > 31 || gtime->tm_hour > 23 ||
            gtime->tm_min > 59 || gtime->tm_sec > 59)
            return ASN1_BAD_GMTIME;
        len = snprintf(s, sizeof(s), "%04d%02d%02d%02d%02d%02dZ",
                       1900+gtime->tm_year, gtime->tm_mon+1,
                       gtime->tm_mday, gtime->tm_hour,
                       gtime->tm_min, gtime->tm_sec);
        if (SNPRINTF_OVERFLOW(len, sizeof(s)))
            /* Shouldn't be possible given above tests.  */
            return ASN1_BAD_GMTIME;
        sp = s;
    }

    return asn1_encode_bytestring(buf, 15, sp, retlen);
}

asn1_error_code
asn1_encode_bitstring(asn1buf *buf, unsigned int len, const void *val,
                      unsigned int *retlen)
{
    asn1_error_code retval;

    retval = asn1buf_insert_octetstring(buf, len, val);
    if (retval) return retval;
    *retlen = len + 1;
    return asn1buf_insert_octet(buf, '\0');
}

/*
 * ASN.1 constructed type encoder engine
 *
 * Two entry points here:
 *
 * krb5int_asn1_encode_type: Incrementally adds the contents-only encoding of
 * an object to an already-initialized asn1buf, and returns its tag
 * information.
 *
 * krb5int_asn1_do_full_encode: Returns a completed encoding, in the
 * correct byte order, in an allocated krb5_data.
 */

#ifdef POINTERS_ARE_ALL_THE_SAME
#define LOADPTR(PTR,TYPE)                       \
    (*(const void *const *)(PTR))
#else
#define LOADPTR(PTR,PTRINFO)                                            \
    (assert((PTRINFO)->loadptr != NULL), (PTRINFO)->loadptr(PTR))
#endif

static unsigned int
get_nullterm_sequence_len(const void *valp, const struct atype_info *seq)
{
    unsigned int i;
    const struct atype_info *a;
    const struct ptr_info *ptr;
    const void *elt, *eltptr;

    a = seq;
    i = 0;
    assert(a->type == atype_ptr);
    assert(seq->size != 0);
    ptr = a->tinfo;

    while (1) {
        eltptr = (const char *) valp + i * seq->size;
        elt = LOADPTR(eltptr, ptr);
        if (elt == NULL)
            break;
        i++;
    }
    return i;
}
static asn1_error_code
encode_sequence_of(asn1buf *buf, unsigned int seqlen, const void *val,
                   const struct atype_info *eltinfo,
                   unsigned int *retlen);

static asn1_error_code
encode_nullterm_sequence_of(asn1buf *buf, const void *val,
                            const struct atype_info *type,
                            int can_be_empty,
                            unsigned int *retlen)
{
    unsigned int length = get_nullterm_sequence_len(val, type);
    if (!can_be_empty && length == 0) return ASN1_MISSING_FIELD;
    return encode_sequence_of(buf, length, val, type, retlen);
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
just_encode_sequence(asn1buf *buf, const void *val,
                     const struct seq_info *seq,
                     unsigned int *retlen);
static asn1_error_code
encode_a_field(asn1buf *buf, const void *val, const struct field_info *field,
               taginfo *rettag);

/* Encode a value (contents only, no outer tag) according to a type, and return
 * its encoded tag information. */
asn1_error_code
krb5int_asn1_encode_type(asn1buf *buf, const void *val,
                         const struct atype_info *a, taginfo *rettag)
{
    asn1_error_code retval;

    switch (a->type) {
    case atype_primitive: {
        const struct primitive_info *prim = a->tinfo;
        assert(prim->enc != NULL);
        retval = prim->enc(buf, val, &rettag->length);
        if (retval) return retval;
        rettag->asn1class = UNIVERSAL;
        rettag->construction = PRIMITIVE;
        rettag->tagnum = prim->tagval;
        break;
    }
    case atype_fn: {
        const struct fn_info *fn = a->tinfo;
        assert(fn->enc != NULL);
        return fn->enc(buf, val, rettag);
    }
    case atype_sequence:
        assert(a->tinfo != NULL);
        retval = just_encode_sequence(buf, val, a->tinfo, &rettag->length);
        if (retval)
            return retval;
        rettag->asn1class = UNIVERSAL;
        rettag->construction = CONSTRUCTED;
        rettag->tagnum = ASN1_SEQUENCE;
        break;
    case atype_ptr: {
        const struct ptr_info *ptr = a->tinfo;
        assert(ptr->basetype != NULL);
        return krb5int_asn1_encode_type(buf, LOADPTR(val, ptr), ptr->basetype,
                                        rettag);
    }
    case atype_field:
        assert(a->tinfo != NULL);
        return encode_a_field(buf, val, a->tinfo, rettag);
    case atype_nullterm_sequence_of:
    case atype_nonempty_nullterm_sequence_of:
        assert(a->tinfo != NULL);
        retval = encode_nullterm_sequence_of(buf, val, a->tinfo,
                                             a->type ==
                                             atype_nullterm_sequence_of,
                                             &rettag->length);
        if (retval)
            return retval;
        rettag->asn1class = UNIVERSAL;
        rettag->construction = CONSTRUCTED;
        rettag->tagnum = ASN1_SEQUENCE;
        break;
    case atype_tagged_thing: {
        const struct tagged_info *tag = a->tinfo;
        retval = krb5int_asn1_encode_type(buf, val, tag->basetype, rettag);
        if (retval)
            return retval;
        if (!tag->implicit) {
            unsigned int tlen;
            retval = asn1_make_tag(buf, rettag->asn1class,
                                   rettag->construction, rettag->tagnum,
                                   rettag->length, &tlen);
            if (retval)
                return retval;
            rettag->length += tlen;
            rettag->construction = tag->construction;
        }
        rettag->asn1class = tag->tagtype;
        rettag->tagnum = tag->tagval;
        break;
    }
    case atype_int: {
        retval = asn1_encode_integer(buf, load_int(val, a->size),
                                     &rettag->length);
        if (retval)
            return retval;
        rettag->asn1class = UNIVERSAL;
        rettag->construction = PRIMITIVE;
        rettag->tagnum = ASN1_INTEGER;
        break;
    }
    case atype_uint: {
        retval = asn1_encode_unsigned_integer(buf, load_uint(val, a->size),
                                              &rettag->length);
        if (retval)
            return retval;
        rettag->asn1class = UNIVERSAL;
        rettag->construction = PRIMITIVE;
        rettag->tagnum = ASN1_INTEGER;
        break;
    }
    case atype_min:
    case atype_max:
    case atype_string:          /* only usable with field_string */
    case atype_der:             /* only usable with field_der */
    case atype_choice:          /* only usable with field_choice */
    default:
        assert(a->type > atype_min);
        assert(a->type < atype_max);
        assert(a->type != atype_string);
        assert(a->type != atype_der);
        assert(a->type != atype_choice);
        abort();
    }

    return 0;
}

static asn1_error_code
encode_type_and_tag(asn1buf *buf, const void *val, const struct atype_info *a,
                    unsigned int *retlen)
{
    taginfo t;
    asn1_error_code retval;
    unsigned int tlen;

    retval = krb5int_asn1_encode_type(buf, val, a, &t);
    if (retval)
        return retval;
    retval = asn1_make_tag(buf, t.asn1class, t.construction, t.tagnum,
                           t.length, &tlen);
    if (retval)
        return retval;
    *retlen = t.length + tlen;
    return 0;
}

static asn1_error_code
get_field_len(const void *val, const struct field_info *field,
              unsigned int *retlen)
{
    const void *lenptr = (const char *)val + field->lenoff;

    assert(field->lentype != NULL);
    assert(field->lentype->type == atype_int ||
           field->lentype->type == atype_uint);
    assert(sizeof(int) <= sizeof(asn1_intmax));
    assert(sizeof(unsigned int) <= sizeof(asn1_uintmax));
    if (field->lentype->type == atype_int) {
        asn1_intmax xlen = load_int(lenptr, field->lentype->size);
        if (xlen < 0)
            return EINVAL;
        if ((unsigned int)xlen != (asn1_uintmax)xlen)
            return EINVAL;
        if ((unsigned int)xlen > UINT_MAX)
            return EINVAL;
        *retlen = (unsigned int)xlen;
    } else {
        asn1_uintmax xlen = load_uint(lenptr, field->lentype->size);
        if ((unsigned int)xlen != xlen)
            return EINVAL;
        if (xlen > UINT_MAX)
            return EINVAL;
        *retlen = (unsigned int)xlen;
    }
    return 0;
}

/* Split a DER encoding into tag and contents.  Insert the contents into buf,
 * then return the length of the contents and the tag. */
static asn1_error_code
split_der(asn1buf *buf, const unsigned char *der, unsigned int len,
          taginfo *rettag)
{
    asn1buf der_buf;
    krb5_data der_data = make_data((unsigned char *)der, len);
    asn1_error_code retval;

    retval = asn1buf_wrap_data(&der_buf, &der_data);
    if (retval)
        return retval;
    retval = asn1_get_tag_2(&der_buf, rettag);
    if (retval)
        return retval;
    if ((unsigned int)asn1buf_remains(&der_buf, 0) != rettag->length)
        return EINVAL;
    return asn1buf_insert_bytestring(buf, rettag->length,
                                     der + len - rettag->length);
}

/* Encode part of a value (contents only, no tag) according to a field
 * descriptor and return its encoded length and tag. */
static asn1_error_code
encode_a_field(asn1buf *buf, const void *val, const struct field_info *field,
               taginfo *rettag)
{
    asn1_error_code retval;

    if (val == NULL) return ASN1_MISSING_FIELD;
    assert(!(field->tag_implicit && field->tag < 0));

    switch (field->ftype) {
    case field_immediate: {
        retval = asn1_encode_integer(buf, (asn1_intmax) field->dataoff,
                                     &rettag->length);
        if (retval)
            return retval;
        rettag->asn1class = UNIVERSAL;
        rettag->construction = PRIMITIVE;
        rettag->tagnum = ASN1_INTEGER;
        break;
    }
    case field_sequenceof_len: {
        const void *dataptr = (const char *)val + field->dataoff;
        unsigned int slen;
        const struct ptr_info *ptrinfo;

        /*
         * The field holds a pointer to the array of objects.  So the
         * address we compute is a pointer-to-pointer, and that's what
         * field->atype must help us dereference.
         */
        assert(field->atype->type == atype_ptr);
        ptrinfo = field->atype->tinfo;
        dataptr = LOADPTR(dataptr, ptrinfo);
        retval = get_field_len(val, field, &slen);
        if (retval)
            return retval;
        if (slen != 0 && dataptr == NULL)
            return ASN1_MISSING_FIELD;
        retval = encode_sequence_of(buf, slen, dataptr, ptrinfo->basetype,
                                    &rettag->length);
        if (retval)
            return retval;
        rettag->asn1class = UNIVERSAL;
        rettag->construction = CONSTRUCTED;
        rettag->tagnum = ASN1_SEQUENCE;
        break;
    }
    case field_normal: {
        const void *dataptr = (const char *)val + field->dataoff;
        retval = krb5int_asn1_encode_type(buf, dataptr, field->atype, rettag);
        if (retval)
            return retval;
        break;
    }
    case field_string: {
        const void *dataptr = (const char *)val + field->dataoff;
        const struct atype_info *a;
        unsigned int slen;
        const struct string_info *string;

        a = field->atype;
        assert(a->type == atype_string);
        retval = get_field_len(val, field, &slen);
        if (retval)
            return retval;
        string = a->tinfo;
        dataptr = LOADPTR(dataptr, string);
        if (dataptr == NULL && slen != 0)
            return ASN1_MISSING_FIELD;
        assert(string->enclen != NULL);
        retval = string->enclen(buf, slen, dataptr, &rettag->length);
        if (retval)
            return retval;
        rettag->asn1class = UNIVERSAL;
        rettag->construction = PRIMITIVE;
        rettag->tagnum = string->tagval;
        break;
    }
    case field_der: {
        const void *dataptr = (const char *)val + field->dataoff;
        const struct atype_info *a;
        unsigned int slen;
        const struct ptr_info *ptr;

        a = field->atype;
        assert(a->type == atype_der);
        retval = get_field_len(val, field, &slen);
        if (retval)
            return retval;
        ptr = a->tinfo;
        dataptr = LOADPTR(dataptr, ptr);
        if (dataptr == NULL && slen != 0)
            return ASN1_MISSING_FIELD;
        retval = split_der(buf, dataptr, slen, rettag);
        if (retval)
            return retval;
        break;
    }
    case field_choice: {
        const void *dataptr = (const char *)val + field->dataoff;
        unsigned int choice;
        const struct seq_info *seq;

        assert(field->atype->type == atype_choice);
        seq = field->atype->tinfo;
        retval = get_field_len(val, field, &choice);
        if (retval)
            return retval;
        if (choice > seq->n_fields)
            return ASN1_MISSING_FIELD;
        retval = encode_a_field(buf, dataptr, &seq->fields[choice], rettag);
        if (retval)
            return retval;
        break;
    }
    default:
        assert(field->ftype > field_min);
        assert(field->ftype < field_max);
        assert(__LINE__ == 0);
        abort();
    }

    if (field->tag >= 0) {
        if (!field->tag_implicit) {
            unsigned int tlen;
            retval = asn1_make_tag(buf, rettag->asn1class,
                                   rettag->construction, rettag->tagnum,
                                   rettag->length, &tlen);
            if (retval)
                return retval;
            rettag->length += tlen;
            rettag->construction = CONSTRUCTED;
        }
        rettag->asn1class = CONTEXT_SPECIFIC;
        rettag->tagnum = field->tag;
    }
    return 0;
}

static asn1_error_code
encode_fields(asn1buf *buf, const void *val,
              const struct field_info *fields, size_t nfields,
              unsigned int optional,
              unsigned int *retlen)
{
    size_t i;
    unsigned int sum = 0;
    for (i = nfields; i > 0; i--) {
        const struct field_info *f = fields+i-1;
        taginfo t;
        asn1_error_code retval;

        if (f->opt != -1 && !((1u << f->opt) & optional))
            continue;
        retval = encode_a_field(buf, val, f, &t);
        if (retval)
            return retval;
        sum += t.length;
        retval = asn1_make_tag(buf, t.asn1class, t.construction, t.tagnum,
                               t.length, &t.length);
        if (retval)
            return retval;
        sum += t.length;
    }
    *retlen = sum;
    return 0;
}

static asn1_error_code
just_encode_sequence(asn1buf *buf, const void *val,
                     const struct seq_info *seq,
                     unsigned int *retlen)
{
    unsigned int optional;

    /* If any fields might be optional, get a bitmask of optional fields. */
    optional = (seq->optional == NULL) ? 0 : seq->optional(val);
    return encode_fields(buf, val, seq->fields, seq->n_fields, optional,
                         retlen);
}

static asn1_error_code
encode_sequence_of(asn1buf *buf, unsigned int seqlen, const void *val,
                   const struct atype_info *eltinfo,
                   unsigned int *retlen)
{
    asn1_error_code retval;
    unsigned int sum = 0, i;

    for (i = seqlen; i > 0; i--) {
        const void *eltptr;
        unsigned int length;
        const struct atype_info *a = eltinfo;

        assert(eltinfo->size != 0);
        eltptr = (const char *)val + (i - 1) * eltinfo->size;
        retval = encode_type_and_tag(buf, eltptr, a, &length);
        if (retval)
            return retval;
        sum += length;
    }
    *retlen = sum;
    return 0;
}

krb5_error_code
krb5int_asn1_do_full_encode(const void *rep, krb5_data **code,
                            const struct atype_info *a)
{
    unsigned int length;
    asn1_error_code retval;
    asn1buf *buf = NULL;
    krb5_data *d;

    *code = NULL;

    if (rep == NULL)
        return ASN1_MISSING_FIELD;

    retval = asn1buf_create(&buf);
    if (retval)
        return retval;

    retval = encode_type_and_tag(buf, rep, a, &length);
    if (retval)
        goto cleanup;
    retval = asn12krb5_buf(buf, &d);
    if (retval)
        goto cleanup;
    *code = d;
cleanup:
    asn1buf_destroy(&buf);
    return retval;
}

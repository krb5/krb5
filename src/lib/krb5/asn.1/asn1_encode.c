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
asn1_encode_bytestring(asn1buf *buf, unsigned char *const *val,
                       unsigned int len, unsigned int *retlen)
{
    if (len > 0 && val == NULL) return ASN1_MISSING_FIELD;
    *retlen = len;
    return asn1buf_insert_octetstring(buf, len, *val);
}

asn1_error_code
asn1_encode_generaltime(asn1buf *buf, time_t val, unsigned int *retlen)
{
    struct tm *gtime, gtimebuf;
    char s[16];
    unsigned char *sp;
    time_t gmt_time = val;

    /*
     * Time encoding: YYYYMMDDhhmmssZ
     */
    if (gmt_time == 0) {
        sp = (unsigned char *)"19700101000000Z";
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
        sp = (unsigned char *)s;
    }

    return asn1_encode_bytestring(buf, &sp, 15, retlen);
}

asn1_error_code
asn1_encode_bitstring(asn1buf *buf, unsigned char *const *val,
                      unsigned int len, unsigned int *retlen)
{
    asn1_error_code retval;

    retval = asn1buf_insert_octetstring(buf, len, *val);
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
load_count(const void *val, const struct counted_info *counted,
           unsigned int *retcount)
{
    const void *lenptr = (const char *)val + counted->lenoff;

    assert(sizeof(int) <= sizeof(asn1_intmax));
    assert(sizeof(unsigned int) <= sizeof(asn1_uintmax));
    if (counted->lensigned) {
        asn1_intmax xlen = load_int(lenptr, counted->lensize);
        if (xlen < 0)
            return EINVAL;
        if ((unsigned int)xlen != (asn1_uintmax)xlen)
            return EINVAL;
        if ((unsigned int)xlen > UINT_MAX)
            return EINVAL;
        *retcount = (unsigned int)xlen;
    } else {
        asn1_uintmax xlen = load_uint(lenptr, counted->lensize);
        if ((unsigned int)xlen != xlen)
            return EINVAL;
        if (xlen > UINT_MAX)
            return EINVAL;
        *retcount = (unsigned int)xlen;
    }
    return 0;
}

/* Split a DER encoding into tag and contents.  Insert the contents into buf,
 * then return the length of the contents and the tag. */
static asn1_error_code
split_der(asn1buf *buf, unsigned char *const *der, unsigned int len,
          taginfo *rettag)
{
    asn1buf der_buf;
    krb5_data der_data = make_data(*der, len);
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
                                     *der + len - rettag->length);
}

static asn1_error_code
encode_sequence(asn1buf *buf, const void *val, const struct seq_info *seq,
                unsigned int *retlen);
static asn1_error_code
encode_cntype(asn1buf *buf, const void *val, unsigned int len,
              const struct cntype_info *c, taginfo *rettag);

/* Encode a value (contents only, no outer tag) according to a type, and return
 * its encoded tag information. */
asn1_error_code
krb5int_asn1_encode_type(asn1buf *buf, const void *val,
                         const struct atype_info *a, taginfo *rettag)
{
    asn1_error_code retval;

    if (val == NULL)
        return ASN1_MISSING_FIELD;

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
        retval = encode_sequence(buf, val, a->tinfo, &rettag->length);
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
    case atype_offset: {
        const struct offset_info *off = a->tinfo;
        assert(off->basetype != NULL);
        return krb5int_asn1_encode_type(buf, (const char *)val + off->dataoff,
                                        off->basetype, rettag);
    }
    case atype_counted: {
        const struct counted_info *counted = a->tinfo;
        const void *dataptr = (const char *)val + counted->dataoff;
        unsigned int len;
        assert(counted->basetype != NULL);
        retval = load_count(val, counted, &len);
        if (retval)
            return retval;
        return encode_cntype(buf, dataptr, len, counted->basetype, rettag);
    }
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
    case atype_int:
        retval = asn1_encode_integer(buf, load_int(val, a->size),
                                     &rettag->length);
        if (retval)
            return retval;
        rettag->asn1class = UNIVERSAL;
        rettag->construction = PRIMITIVE;
        rettag->tagnum = ASN1_INTEGER;
        break;
    case atype_uint:
        retval = asn1_encode_unsigned_integer(buf, load_uint(val, a->size),
                                              &rettag->length);
        if (retval)
            return retval;
        rettag->asn1class = UNIVERSAL;
        rettag->construction = PRIMITIVE;
        rettag->tagnum = ASN1_INTEGER;
        break;
    case atype_int_immediate: {
        const int *iptr = a->tinfo;
        retval = asn1_encode_integer(buf, *iptr, &rettag->length);
        if (retval)
            return retval;
        rettag->asn1class = UNIVERSAL;
        rettag->construction = PRIMITIVE;
        rettag->tagnum = ASN1_INTEGER;
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

/*
 * Encode an object and count according to a cntype_info structure.  val is a
 * pointer to the object being encoded, which in most cases is itself a
 * pointer (but is a union in the cntype_choice case).
 */
static asn1_error_code
encode_cntype(asn1buf *buf, const void *val, unsigned int count,
              const struct cntype_info *c, taginfo *rettag)
{
    asn1_error_code retval;

    switch (c->type) {
    case cntype_string: {
        const struct string_info *string = c->tinfo;
        assert(string->enc != NULL);
        retval = string->enc(buf, val, count, &rettag->length);
        if (retval)
            return retval;
        rettag->asn1class = UNIVERSAL;
        rettag->construction = PRIMITIVE;
        rettag->tagnum = string->tagval;
        break;
    }
    case cntype_der:
        return split_der(buf, val, count, rettag);
    case cntype_seqof: {
        const struct atype_info *a = c->tinfo;
        const struct ptr_info *ptr = a->tinfo;
        assert(a->type == atype_ptr);
        val = LOADPTR(val, ptr);
        retval = encode_sequence_of(buf, count, val, ptr->basetype,
                                    &rettag->length);
        if (retval)
            return retval;
        rettag->asn1class = UNIVERSAL;
        rettag->construction = CONSTRUCTED;
        rettag->tagnum = ASN1_SEQUENCE;
        break;
    }
    case cntype_choice: {
        const struct choice_info *choice = c->tinfo;
        if (count > choice->n_options)
            return ASN1_MISSING_FIELD;
        return krb5int_asn1_encode_type(buf, val, choice->options[count],
                                        rettag);
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
                unsigned int *retlen)
{
    asn1_error_code retval;
    unsigned int not_present, length, sum = 0;
    size_t i;
    const struct atype_info *a;

    /* If any fields might be optional, get a bitmask of fields not present. */
    not_present = (seq->optional == NULL) ? 0 : seq->optional(val);
    for (i = seq->n_fields; i > 0; i--) {
        a = seq->fields[i - 1];
        if ((1u << (i - 1)) & not_present)
            continue;
        retval = encode_type_and_tag(buf, val, a, &length);
        if (retval)
            return retval;
        sum += length;
    }
    *retlen = sum;
    return 0;
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

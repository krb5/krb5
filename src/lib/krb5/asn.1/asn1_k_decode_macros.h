/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/asn.1/asn1_k_decode_macros.h */
/*
 * Copyright 1994, 2007, 2008, 2010 by the Massachusetts Institute of Technology.
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

#ifndef ASN1_DECODE_KRB5_MACROS_H
#define ASN1_DECODE_KRB5_MACROS_H

#include "asn1_k_decode.h"
#include "asn1_decode.h"
#include "asn1_get.h"
#include "asn1_misc.h"

#if __GNUC__ >= 3
#define KRB5_ATTR_UNUSED __attribute__((unused))
#else
#define KRB5_ATTR_UNUSED
#endif

#define clean_return(val) { retval = val; goto error_out; }

/* Declare useful decoder variables. */
#define setup()                                         \
    asn1_error_code retval;                             \
    asn1_class asn1class;                               \
    asn1_construction construction KRB5_ATTR_UNUSED;    \
    asn1_tagnum tagnum;                                 \
    unsigned int length, taglen KRB5_ATTR_UNUSED

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
    int indef KRB5_ATTR_UNUSED;                                 \
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
#define sequence_of(buf)                                \
    unsigned int length, taglen KRB5_ATTR_UNUSED ;      \
    asn1_class asn1class;                               \
    asn1_construction construction KRB5_ATTR_UNUSED ;   \
    asn1_tagnum tagnum;                                 \
    int indef;                                          \
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
static inline asn1_error_code
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
#endif

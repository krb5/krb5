/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/asn.1/krb5_decode_macros.h */
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

#ifndef KRB5_DECODE_MACROS_H
#define KRB5_DECODE_MACROS_H

#include "asn1_k_decode.h"
#include "asn1_decode.h"
#include "asn1_get.h"
#include "asn1_misc.h"

#if __GNUC__ >= 3
#define KRB5_ATTR_UNUSED __attribute__((unused))
#else
#define KRB5_ATTR_UNUSED
#endif

/* setup *********************************************************/
/* set up variables */
/*
 * the setup* macros can return, but are always used at function start
 * and thus need no malloc cleanup
 */
#define setup_buf_only(type)                    \
    asn1_error_code retval;                     \
    asn1buf buf;                                \
    type rep = NULL;                            \
                                                \
    *repptr = NULL;                             \
    retval = asn1buf_wrap_data(&buf,code);      \
    if (retval) return retval

#define setup_no_tagnum(type)                           \
    asn1_class asn1class KRB5_ATTR_UNUSED;              \
    asn1_construction construction KRB5_ATTR_UNUSED;    \
    setup_buf_only(type)

#define setup_no_length(type)                   \
    asn1_tagnum tagnum KRB5_ATTR_UNUSED;        \
    setup_no_tagnum(type)

#define setup(type)                             \
    unsigned int length;                        \
    setup_no_length(type)

/* helper macros for cleanup */
#define clean_return(val) { retval = val; goto error_out; }

/* alloc_field is the first thing to allocate storage that may need cleanup */
#define alloc_field(var)                        \
    var = calloc(1,sizeof(*var));               \
    if ((var) == NULL) clean_return(ENOMEM)

/*
 * Allocate a principal and initialize enough fields for
 * krb5_free_principal to have defined behavior.
 */
#define alloc_principal(var)                    \
    alloc_field(var);                           \
    var->realm.data = NULL;                     \
    var->data = NULL

/* process encoding header ***************************************/
/* decode tag and check that it == [APPLICATION tagnum] */
#define check_apptag(tagexpect)                                         \
    {                                                                   \
        taginfo t1;                                                     \
        retval = asn1_get_tag_2(&buf, &t1);                             \
        if (retval) clean_return (retval);                              \
        if (t1.asn1class != APPLICATION || t1.construction != CONSTRUCTED) \
            clean_return(ASN1_BAD_ID);                                  \
        if (t1.tagnum != (tagexpect)) clean_return(KRB5_BADMSGTYPE);    \
        asn1class = t1.asn1class;                                       \
        construction = t1.construction;                                 \
        tagnum = t1.tagnum;                                             \
    }



/* process a structure *******************************************/

/* decode an explicit tag and place the number in tagnum */
#define next_tag_from_buf(buf)                  \
    { taginfo t2;                               \
        retval = asn1_get_tag_2(&(buf), &t2);   \
        if (retval) clean_return(retval);       \
        asn1class = t2.asn1class;               \
        construction = t2.construction;         \
        tagnum = t2.tagnum;                     \
        indef = t2.indef;                       \
        taglen = t2.length;                     \
    }
#define next_tag() next_tag_from_buf(subbuf)


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

#define get_eoc()                               \
    {                                           \
        retval = asn1_get_eoc_tag(&subbuf);     \
        if (retval) clean_return(retval);       \
    }

/* decode sequence header and initialize tagnum with the first field */
#define begin_structure()                                       \
    unsigned int taglen KRB5_ATTR_UNUSED;                       \
    asn1buf subbuf;                                             \
    int seqindef;                                               \
    int indef;                                                  \
    retval = asn1_get_sequence(&buf,&length,&seqindef);         \
    if (retval) clean_return(retval);                           \
    retval = asn1buf_imbed(&subbuf,&buf,length,seqindef);       \
    if (retval) clean_return(retval);                           \
    next_tag()

#define end_structure()                                         \
    retval = asn1buf_sync(&buf,&subbuf,asn1class,               \
                          tagnum,length,indef,seqindef);        \
    if (retval) clean_return(retval)

/* process fields *******************************************/
/* normal fields ************************/
#define get_field_body(var,decoder)             \
    retval = decoder(&subbuf,&(var));           \
    if (retval) clean_return(retval);           \
    if (indef) { get_eoc(); }                   \
    next_tag()

/*
 * error_if_bad_tag
 *
 * Checks that the next tag is the expected one; returns with an error
 * if not.
 */
#define error_if_bad_tag(tagexpect)                                     \
    if (tagnum != (tagexpect)) { clean_return ((tagnum < (tagexpect)) ? ASN1_MISPLACED_FIELD : ASN1_MISSING_FIELD); }

/*
 * decode a field (<[UNIVERSAL id]> <length> <contents>)
 *  check that the id number == tagexpect then
 *  decode into var
 *  get the next tag
 */
#define get_field(var,tagexpect,decoder)                                \
    error_if_bad_tag(tagexpect);                                        \
    if (asn1class != CONTEXT_SPECIFIC || construction != CONSTRUCTED)   \
        clean_return(ASN1_BAD_ID);                                      \
    get_field_body(var,decoder)

/* decode (or skip, if not present) an optional field */
#define opt_field(var,tagexpect,decoder)                                \
    if (asn1buf_remains(&subbuf, seqindef)) {                           \
        if (asn1class != CONTEXT_SPECIFIC || construction != CONSTRUCTED) \
            clean_return(ASN1_BAD_ID);                                  \
        if (tagnum == (tagexpect)) {                                    \
            get_field_body(var,decoder);                                \
        }                                                               \
    }

/* field w/ accompanying length *********/
#define get_lenfield_body(len,var,decoder)      \
    retval = decoder(&subbuf,&(len),&(var));    \
    if (retval) clean_return(retval);           \
    if (indef) { get_eoc(); }                   \
    next_tag()

/* decode a field w/ its length (for string types) */
#define get_lenfield(len,var,tagexpect,decoder)                         \
    error_if_bad_tag(tagexpect);                                        \
    if (asn1class != CONTEXT_SPECIFIC || construction != CONSTRUCTED)   \
        clean_return(ASN1_BAD_ID);                                      \
    get_lenfield_body(len,var,decoder)

/* decode an optional field w/ length */
#define opt_lenfield(len,var,tagexpect,decoder)                         \
    if (asn1buf_remains(&subbuf, seqindef)) {                           \
        if (asn1class != CONTEXT_SPECIFIC || construction != CONSTRUCTED) \
            clean_return(ASN1_BAD_ID);                                  \
        if (tagnum == (tagexpect)) {                                    \
            get_lenfield_body(len,var,decoder);                         \
        }                                                               \
    }


/* clean up ******************************************************/
/* finish up */
/* to make things less painful, assume the cleanup is passed rep */
#define cleanup(cleanup_routine)                \
    *repptr = rep;                              \
    return 0;                                   \
error_out:                                      \
if (rep)                                        \
    cleanup_routine(rep);                       \
return retval;

#define cleanup_none()                          \
    *repptr = rep;                              \
    return 0;                                   \
error_out:                                      \
return retval;

#define cleanup_manual()                        \
    *repptr = rep;                              \
    return 0;

#define free_field(rep,f) free((rep)->f)
#define clear_field(rep,f) (rep)->f = 0

#endif

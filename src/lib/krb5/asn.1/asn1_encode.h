/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/asn.1/asn1_encode.h */
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

#ifndef __ASN1_ENCODE_H__
#define __ASN1_ENCODE_H__

#include "k5-int.h"
#include "krbasn1.h"
#include "asn1buf.h"
#include "asn1_get.h"
#include <time.h>

/*
 * Overview
 *
 *   Each of these procedures inserts the encoding of an ASN.1
 *   primitive in a coding buffer.
 *
 * Operations
 *
 *   asn1_encode_boolean
 *   asn1_encode_integer
 *   asn1_encode_unsigned_integer
 *   asn1_encode_bytestring
 *   asn1_encode_generaltime
 *   asn1_encode_bitstring
 */

asn1_error_code asn1_encode_boolean(asn1buf *buf, asn1_intmax val,
                                    unsigned int *retlen);
asn1_error_code asn1_encode_integer(asn1buf *buf, asn1_intmax val,
                                    unsigned int *retlen);
/*
 * requires  *buf is allocated
 * modifies  *buf, *retlen
 * effects   Inserts the encoding of val into *buf and returns
 *            the length of the encoding in *retlen.
 *           Returns ENOMEM to signal an unsuccesful attempt
 *            to expand the buffer.
 */

asn1_error_code asn1_encode_unsigned_integer(asn1buf *buf, asn1_uintmax val,
                                             unsigned int *retlen);
/*
 * requires  *buf is allocated
 * modifies  *buf, *retlen
 * effects   Inserts the encoding of val into *buf and returns
 *            the length of the encoding in *retlen.
 *           Returns ENOMEM to signal an unsuccesful attempt
 *            to expand the buffer.
 */

asn1_error_code asn1_encode_bytestring(asn1buf *buf, unsigned int len,
                                       const void *val, unsigned int *retlen);
/*
 * requires  *buf is allocated
 * modifies  *buf, *retlen
 * effects   Inserts the encoding of val into *buf and returns
 *            the length of the encoding in *retlen.
 *           Returns ENOMEM to signal an unsuccesful attempt
 *            to expand the buffer.
 */

asn1_error_code asn1_encode_null(asn1buf *buf, int *retlen);
/*
 * requires  *buf is allocated
 * modifies  *buf, *retlen
 * effects   Inserts the encoding of NULL into *buf and returns
 *            the length of the encoding in *retlen.
 *           Returns ENOMEM to signal an unsuccesful attempt
 *            to expand the buffer.
 */

asn1_error_code asn1_encode_generaltime(asn1buf *buf, time_t val,
                                        unsigned int *retlen);
/*
 * requires  *buf is allocated
 * modifies  *buf, *retlen
 * effects   Inserts the encoding of val into *buf and returns
 *            the length of the encoding in *retlen.
 *           Returns ENOMEM to signal an unsuccesful attempt
 *            to expand the buffer.
 * Note: The encoding of GeneralizedTime is YYYYMMDDhhmmZ
 */

asn1_error_code asn1_encode_bitstring(asn1buf *buf, unsigned int len,
                                      const void *val,
                                      unsigned int *retlen);
/*
 * requires  *buf is allocated,  val has a length of len characters
 * modifies  *buf, *retlen
 * effects   Inserts the encoding of val into *buf and returns
 *            the length of the encoding in *retlen.
 *           Returns ENOMEM to signal an unsuccesful attempt
 *            to expand the buffer.
 */

/*
 * Type descriptor info.
 *
 * In this context, a "type" is a combination of a C data type
 * and an ASN.1 encoding scheme for it.  So we would have to define
 * different "types" for:
 *
 * * unsigned char* encoded as octet string
 * * char* encoded as octet string
 * * char* encoded as generalstring
 * * krb5_data encoded as octet string
 * * krb5_data encoded as generalstring
 * * int32_t encoded as integer
 * * unsigned char encoded as integer
 *
 * Perhaps someday some kind of flags could be defined so that minor
 * variations on the C types could be handled via common routines.
 *
 * The handling of strings is pretty messy.  Currently, we have a
 * separate kind of encoder function that takes an extra length
 * parameter.  Perhaps we should just give up on that, always deal
 * with just a single location, and handle strings by via encoder
 * functions for krb5_data, keyblock, etc.
 *
 * We wind up with a lot of load-time relocations being done, which is
 * a bit annoying.  Be careful about "fixing" that at the cost of too
 * much run-time performance.  It might work to have a master "module"
 * descriptor with pointers to various arrays (type descriptors,
 * strings, field descriptors, functions) most of which don't need
 * relocation themselves, and replace most of the pointers with table
 * indices.
 *
 * It's a work in progress.
 */

enum atype_type {
    /*
     * For bounds checking only.  By starting with values above 1, we
     * guarantee that zero-initialized storage will be recognized as
     * invalid.
     */
    atype_min = 1,
    /* Encoder function (contents-only) to be called with address of <thing>
     * and wrapped with a universal primitive tag.  tinfo is a struct
     * primitive_info *. */
    atype_primitive,
    /*
     * Encoder function to be called with address of <thing>.  The encoder
     * function must generate a sequence without the sequence tag.  tinfo is a
     * struct fn_info *.  Used only by kdc_req_body.
     */
    atype_fn,
    /*
     * Encoder function (contents only) to be called with address of <thing>
     * and a length (unsigned int), and wrapped with a universal primitive tag.
     * tinfo is a struct string_info *.  Only usable with the field_string
     * field type.
     */
    atype_string,
    /*
     * Pre-made DER encoding stored at the address of <thing>.  tinfo is a
     * struct ptr_info * with the basetype field ignored.  Only usable with the
     * field_der field type.
     */
    atype_der,
    /*
     * Pointer to actual thing to be encoded.  tinfo is a struct ptr_info *.
     *
     * Most of the fields are related only to the C type -- size, how
     * to fetch a pointer in a type-safe fashion -- but since the base
     * type descriptor encapsulates the encoding as well, different
     * encodings for the same C type may require different pointer-to
     * types as well.
     *
     * Must not refer to atype_fn_len.
     */
    atype_ptr,
    /* Sequence.  tinfo is a struct seq_info *. */
    atype_sequence,
    /*
     * Choice.  tinfo is a struct seq_info *, with the optional field ignored.
     * Only usable with the field_choice field type.  Cannot be used with an
     * implicit context tag.
     */
    atype_choice,
    /*
     * Sequence-of, with pointer to base type descriptor, represented
     * as a null-terminated array of pointers (and thus the "base"
     * type descriptor is actually an atype_ptr node).  tinfo is a
     * struct atype_info * giving the base type.
     */
    atype_nullterm_sequence_of,
    atype_nonempty_nullterm_sequence_of,
    /*
     * Encode this object using a single field descriptor.  tinfo is a struct
     * field_info *.  The presence of this type may mean the atype/field
     * breakdown needs revision....
     *
     * Main expected uses: Encode realm component of principal as a
     * GENERALSTRING.  Pluck data and length fields out of a structure
     * and encode a counted SEQUENCE OF.
     */
    atype_field,
    /* Tagged version of another type.  tinfo is a struct tagged_info *. */
    atype_tagged_thing,
    /* Signed or unsigned integer.  tinfo is NULL. */
    atype_int,
    atype_uint,
    /* Unused except for bounds checking.  */
    atype_max
};

struct atype_info {
    enum atype_type type;
    size_t size;                /* Used for sequence-of processing */
    const void *tinfo;          /* Points to type-specific structure */
};

struct primitive_info {
    asn1_error_code (*enc)(asn1buf *, const void *, unsigned int *);
    unsigned int tagval;
};

struct fn_info {
    asn1_error_code (*enc)(asn1buf *, const void *, taginfo *);
};

struct string_info {
    asn1_error_code (*enclen)(asn1buf *, unsigned int, const void *,
                              unsigned int *);
    const void *(*loadptr)(const void *);
    unsigned int tagval;
};

struct ptr_info {
    const void *(*loadptr)(const void *);
    const struct atype_info *basetype;
};

struct tagged_info {
    unsigned int tagval : 16, tagtype : 8, construction : 6, implicit : 1;
    const struct atype_info *basetype;
};

/*
 * The various DEF*TYPE macros must:
 *
 * + Define a type named aux_typedefname_##DESCNAME, for use in any
 *   types derived from the type being defined.
 *
 * + Define an atype_info struct named krb5int_asn1type_##DESCNAME
 *
 * + Define a type-specific structure, referenced by the tinfo field
 *   of the atype_info structure.
 *
 * + Define any extra stuff needed in the type descriptor, like
 *   pointer-load functions.
 *
 * + Accept a following semicolon syntactically, to keep Emacs parsing
 *   (and indentation calculating) code happy.
 *
 * Nothing else should directly define the atype_info structures.
 */

/*
 * Define a type using a primitive (content-only) encoder function.
 *
 * Because we need a single, consistent type for the descriptor structure
 * field, we use the function pointer type that uses void*, and create a
 * wrapper function in DEFFNXTYPE.  The supplied function is static and not
 * used otherwise, so the compiler can merge it with the wrapper function if
 * the optimizer is good enough.
 */
#define DEFPRIMITIVETYPE(DESCNAME, CTYPENAME, ENCFN, TAG)               \
    typedef CTYPENAME aux_typedefname_##DESCNAME;                       \
    static asn1_error_code                                              \
    aux_encfn_##DESCNAME(asn1buf *buf, const void *val,                 \
                         unsigned int *retlen)                          \
    {                                                                   \
        return ENCFN(buf,                                               \
                     (const aux_typedefname_##DESCNAME *)val,           \
                     retlen);                                           \
    }                                                                   \
    static const struct primitive_info aux_info_##DESCNAME = {          \
        aux_encfn_##DESCNAME, TAG                                       \
    };                                                                  \
    const struct atype_info krb5int_asn1type_##DESCNAME = {             \
        atype_primitive, sizeof(CTYPENAME), &aux_info_##DESCNAME        \
    }
/* Define a type using an explicit (with tag) encoder function. */
#define DEFFNTYPE(DESCNAME, CTYPENAME, ENCFN)                           \
    typedef CTYPENAME aux_typedefname_##DESCNAME;                       \
    static const struct fn_info aux_info_##DESCNAME = {                 \
        ENCFN                                                           \
    };                                                                  \
    const struct atype_info krb5int_asn1type_##DESCNAME = {             \
        atype_fn, sizeof(CTYPENAME), &aux_info_##DESCNAME               \
    }
/*
 * XXX The handling of data+length fields really needs reworking.
 * A type descriptor probably isn't the right way.
 *
 * Also, the C type is likely to be one of char*, unsigned char*,
 * or (maybe) void*.  An enumerator or reference to an external
 * function would be more compact.
 *
 * The supplied encoder function takes as an argument the data pointer
 * loaded from the indicated location, not the address of the field.
 * This isn't consistent with DEFFN[X]TYPE above, but all of the uses
 * of DEFFNLENTYPE are for string encodings, and that's how our
 * string-encoding primitives work.  So be it.
 */
#ifdef POINTERS_ARE_ALL_THE_SAME
#define DEFSTRINGTYPE(DESCNAME, CTYPENAME, ENCFN, TAGVAL)       \
    typedef CTYPENAME aux_typedefname_##DESCNAME;               \
    static const struct string_info aux_info_##DESCNAME = {     \
        ENCFN, NULL, TAGVAL                                     \
    }                                                           \
    const struct atype_info krb5int_asn1type_##DESCNAME = {     \
        atype_string, 0, &aux_info_##DESCNAME                   \
    }
#else
#define DEFSTRINGTYPE(DESCNAME, CTYPENAME, ENCFN, TAGVAL)       \
    typedef CTYPENAME aux_typedefname_##DESCNAME;               \
    static const void *loadptr_for_##DESCNAME(const void *pv)   \
    {                                                           \
        const aux_typedefname_##DESCNAME *p = pv;               \
        return *p;                                              \
    }                                                           \
    static const struct string_info aux_info_##DESCNAME = {     \
        ENCFN, loadptr_for_##DESCNAME, TAGVAL                   \
    };                                                          \
    const struct atype_info krb5int_asn1type_##DESCNAME = {     \
        atype_string, 0, &aux_info_##DESCNAME                   \
    }
#endif
/* Not used enough to justify a POINTERS_ARE_ALL_THE_SAME version. */
#define DEFDERTYPE(DESCNAME, CTYPENAME)                         \
    typedef CTYPENAME aux_typedefname_##DESCNAME;               \
    static const void *loadptr_for_##DESCNAME(const void *pv)   \
    {                                                           \
        const aux_typedefname_##DESCNAME *p = pv;               \
        return *p;                                              \
    }                                                           \
    static const struct ptr_info aux_info_##DESCNAME = {        \
        loadptr_for_##DESCNAME                                  \
    };                                                          \
    const struct atype_info krb5int_asn1type_##DESCNAME = {     \
        atype_der, 0, &aux_info_##DESCNAME                      \
    }
/*
 * A sequence, defined by the indicated series of fields, and an
 * optional function indicating which fields are present.
 */
#define DEFSEQTYPE(DESCNAME, CTYPENAME, FIELDS, OPT)                    \
    typedef CTYPENAME aux_typedefname_##DESCNAME;                       \
    static const struct seq_info aux_seqinfo_##DESCNAME = {             \
        OPT, FIELDS, sizeof(FIELDS)/sizeof(FIELDS[0])                   \
    };                                                                  \
    const struct atype_info krb5int_asn1type_##DESCNAME = {             \
        atype_sequence, sizeof(CTYPENAME), &aux_seqinfo_##DESCNAME      \
    }
/* A choice, selected from the indicated series of fields. */
#define DEFCHOICETYPE(DESCNAME, CTYPENAME, FIELDS)                      \
    typedef CTYPENAME aux_typedefname_##DESCNAME;                       \
    static const struct seq_info aux_seqinfo_##DESCNAME = {             \
        NULL, FIELDS, sizeof(FIELDS)/sizeof(FIELDS[0])                  \
    };                                                                  \
    const struct atype_info krb5int_asn1type_##DESCNAME = {             \
        atype_choice, sizeof(CTYPENAME), &aux_seqinfo_##DESCNAME        \
    }
/* Integer types.  */
#define DEFINTTYPE(DESCNAME, CTYPENAME)                         \
    typedef CTYPENAME aux_typedefname_##DESCNAME;               \
    const struct atype_info krb5int_asn1type_##DESCNAME = {     \
        atype_int, sizeof(CTYPENAME), NULL                      \
    }
#define DEFUINTTYPE(DESCNAME, CTYPENAME)                        \
    typedef CTYPENAME aux_typedefname_##DESCNAME;               \
    const struct atype_info krb5int_asn1type_##DESCNAME = {     \
        atype_uint, sizeof(CTYPENAME), NULL                     \
    }
/* Pointers to other types, to be encoded as those other types.  */
#ifdef POINTERS_ARE_ALL_THE_SAME
#define DEFPTRTYPE(DESCNAME,BASEDESCNAME)                               \
    typedef aux_typedefname_##BASEDESCNAME * aux_typedefname_##DESCNAME; \
    static const struct ptr_info aux_info_##DESCNAME = {                \
        NULL, &krb5int_asn1type_##BASEDESCNAME                          \
    };                                                                  \
    const struct atype_info krb5int_asn1type_##DESCNAME = {             \
        atype_ptr, sizeof(aux_typedefname_##DESCNAME),                  \
        &aux_info_##DESCNAME                                            \
    }
#else
#define DEFPTRTYPE(DESCNAME,BASEDESCNAME)                               \
    typedef aux_typedefname_##BASEDESCNAME * aux_typedefname_##DESCNAME; \
    static const void *                                                 \
    loadptr_for_##BASEDESCNAME##_from_##DESCNAME(const void *p)         \
    {                                                                   \
        const aux_typedefname_##DESCNAME *inptr = p;                    \
        const aux_typedefname_##BASEDESCNAME *retptr;                   \
        retptr = *inptr;                                                \
        return retptr;                                                  \
    }                                                                   \
    static const struct ptr_info aux_info_##DESCNAME = {                \
        loadptr_for_##BASEDESCNAME##_from_##DESCNAME,                   \
        &krb5int_asn1type_##BASEDESCNAME                                \
    };                                                                  \
    const struct atype_info krb5int_asn1type_##DESCNAME = {             \
        atype_ptr, sizeof(aux_typedefname_##DESCNAME),                  \
        &aux_info_##DESCNAME                                            \
    }
#endif
/*
 * This encodes a pointer-to-pointer-to-thing where the passed-in
 * value points to a null-terminated list of pointers to objects to be
 * encoded, and encodes a (possibly empty) SEQUENCE OF these objects.
 *
 * BASEDESCNAME is a descriptor name for the pointer-to-thing
 * type.
 *
 * When dealing with a structure containing a
 * pointer-to-pointer-to-thing field, make a DEFPTRTYPE of this type,
 * and use that type for the structure field.
 */
#define DEFNULLTERMSEQOFTYPE(DESCNAME,BASEDESCNAME)                     \
    typedef aux_typedefname_##BASEDESCNAME aux_typedefname_##DESCNAME;  \
    const struct atype_info krb5int_asn1type_##DESCNAME = {             \
        atype_nullterm_sequence_of, sizeof(aux_typedefname_##DESCNAME), \
        &krb5int_asn1type_##BASEDESCNAME                                \
    }
#define DEFNONEMPTYNULLTERMSEQOFTYPE(DESCNAME,BASEDESCNAME)             \
    typedef aux_typedefname_##BASEDESCNAME aux_typedefname_##DESCNAME;  \
    const struct atype_info krb5int_asn1type_##DESCNAME = {             \
        atype_nonempty_nullterm_sequence_of,                            \
        sizeof(aux_typedefname_##DESCNAME),                             \
        &krb5int_asn1type_##BASEDESCNAME                                \
    }
/*
 * Encode a thing (probably sub-fields within the structure) as a
 * single object.
 */
#define DEFFIELDTYPE(DESCNAME, CTYPENAME, FIELDINFO)                    \
    typedef CTYPENAME aux_typedefname_##DESCNAME;                       \
    static const struct field_info aux_fieldinfo_##DESCNAME = FIELDINFO; \
    const struct atype_info krb5int_asn1type_##DESCNAME = {             \
        atype_field, sizeof(CTYPENAME), &aux_fieldinfo_##DESCNAME       \
    }
/* Objects with an explicit or implicit tag.  (Implicit tags will ignore the
 * construction field.) */
#define DEFTAGGEDTYPE(DESCNAME, CLASS, CONSTRUCTION, TAG, IMPLICIT, BASEDESC) \
    typedef aux_typedefname_##BASEDESC aux_typedefname_##DESCNAME;      \
    static const struct tagged_info aux_info_##DESCNAME = {             \
        TAG, CLASS, CONSTRUCTION, IMPLICIT, &krb5int_asn1type_##BASEDESC \
    };                                                                  \
    const struct atype_info krb5int_asn1type_##DESCNAME = {             \
        atype_tagged_thing, sizeof(aux_typedefname_##DESCNAME),         \
        &aux_info_##DESCNAME                                            \
    }
/* Objects with an explicit APPLICATION tag added.  */
#define DEFAPPTAGGEDTYPE(DESCNAME, TAG, BASEDESC)                       \
        DEFTAGGEDTYPE(DESCNAME, APPLICATION, CONSTRUCTED, TAG, 0, BASEDESC)

/**
 * An encoding wrapped in an octet string
 */
#define DEFOCTETWRAPTYPE(DESCNAME, BASEDESC)                            \
    typedef aux_typedefname_##BASEDESC aux_typedefname_##DESCNAME;      \
    static const struct tagged_info aux_info_##DESCNAME = {             \
        ASN1_OCTETSTRING, UNIVERSAL, PRIMITIVE, 0,                      \
        &krb5int_asn1type_##BASEDESC                                    \
    };                                                                  \
    const struct atype_info krb5int_asn1type_##DESCNAME = {             \
        atype_tagged_thing, sizeof(aux_typedefname_##DESCNAME),         \
        &aux_info_##DESCNAME                                            \
    }

/*
 * Declare an externally-defined type.  This is a hack we should do
 * away with once we move to generating code from a script.  For now,
 * this macro is unfortunately not compatible with the defining macros
 * above, since you can't do the typedefs twice and we need the
 * declarations to produce typedefs.  (We could eliminate the typedefs
 * from the DEF* macros, but then every DEF* macro use, even the ones
 * for internal type nodes we only use to build other types, would
 * need an accompanying declaration which explicitly lists the
 * type.)
 */
#define IMPORT_TYPE(DESCNAME, CTYPENAME)                        \
    typedef CTYPENAME aux_typedefname_##DESCNAME;               \
    extern const struct atype_info krb5int_asn1type_##DESCNAME

/* Partially encode the contents of a type and return its tag information.
 * Used only by asn1_encode_kdc_req_body. */
asn1_error_code
krb5int_asn1_encode_type(asn1buf *buf, const void *val,
                         const struct atype_info *a, taginfo *rettag);

/*
 * Sequence field descriptor.
 *
 * Currently we assume everything is a single object with a type
 * descriptor, and then we bolt on some ugliness on the side for
 * handling strings with length fields.
 *
 * Anything with "interesting" encoding handling, like a sequence-of
 * or a pointer to the actual value to encode, is handled via opaque
 * types with their own encoder functions.  Most of that should
 * eventually change.
 */

enum field_type {
    /* Unused except for range checking.  */
    field_min = 1,
    /* Field ATYPE describes processing of field at DATAOFF.  */
    field_normal,
    /*
     * Encode an "immediate" integer value stored in DATAOFF, with no
     * reference to the data structure.
     */
    field_immediate,
    /*
     * Encode some kind of string field encoded with pointer and
     * length.  (A GENERALSTRING represented as a null-terminated C
     * string would be handled as field_normal.)
     */
    field_string,
    /* Insert a DER encoding given by the pointer and length. */
    field_der,
    /*
     * LENOFF indicates a value describing the length of the array at
     * DATAOFF, encoded as a sequence-of with the element type
     * described by ATYPE.
     */
    field_sequenceof_len,
    /*
     * LENOFF indicates a distinguisher and DATAOFF indicates a union base
     * address.  ATYPE is an atype_choice type pointing to a seq_info
     * containing a field type for each choice element.
     */
    field_choice,
    /* Unused except for range checking.  */
    field_max
};
/* To do: Consider using bitfields.  */
struct field_info {
    /* Type of the field.  */
    unsigned int /* enum field_type */ ftype : 3;

    /*
     * Use of DATAOFF and LENOFF are described by the value in FTYPE.
     * Generally DATAOFF will be the offset from the supplied pointer
     * at which we find the object to be encoded.
     */
    unsigned int dataoff : 9, lenoff : 9;

    /*
     * If TAG is non-negative, a context tag with that value is added
     * to the encoding of the thing.  (XXX This would encode more
     * compactly as an unsigned bitfield value tagnum+1, with 0=no
     * tag.)  The tag is omitted for optional fields that are not
     * present.  If tag_implicit is set, then the context tag replaces
     * the outer tag of the field, and uses the same construction bit
     * as the outer tag would have used.
     *
     * It's a bit illogical to combine the tag and other field info,
     * since really a sequence field could have zero or several
     * context tags, and of course a tag could be used elsewhere.  But
     * the normal mode in the Kerberos ASN.1 description is to use one
     * context tag on each sequence field, so for now let's address
     * that case primarily and work around the other cases (thus tag<0
     * means skip tagging).
     */
    signed int tag : 5;
    unsigned int tag_implicit : 1;

    /*
     * If OPT is non-negative and the sequence header structure has a
     * function pointer describing which fields are present, OPT is
     * the bit position indicating whether the currently-described
     * element is present.  (XXX Similar encoding issue.)
     *
     * Note: Most of the time, I'm using the same number here as for
     * the context tag.  This is just because it's easier for me to
     * keep track while working on the code by hand.  The *only*
     * meaningful correlation is of this value and the bits set by the
     * "optional" function when examining the data structure.
     */
    signed int opt : 5;

    /*
     * For some values of FTYPE, this describes the type of the
     * object(s) to be encoded.
     */
    const struct atype_info *atype;

    /*
     * We use different types for "length" fields in different places.
     * So we need a good way to retrieve the various kinds of lengths
     * in a compatible way.  This may be a string length, or the
     * length of an array of objects to encode in a SEQUENCE OF.
     *
     * In case the field is signed and negative, or larger than
     * size_t, return SIZE_MAX as an error indication.  We'll assume
     * for now that we'll never have 4G-1 (or 2**64-1, or on tiny
     * systems, 65535) sized values.  On most if not all systems we
     * care about, SIZE_MAX is equivalent to "all of addressable
     * memory" minus one byte.  That wouldn't leave enough extra room
     * for the structure we're encoding, so it's pretty safe to assume
     * SIZE_MAX won't legitimately come up on those systems.
     *
     * If this code gets ported to a segmented architecture or other
     * system where it might be possible... figure it out then.
     */
    const struct atype_info *lentype;
};

/*
 * Normal or optional sequence fields at a particular offset, encoded
 * as indicated by the listed DESCRiptor.
 */
#define FIELDOF_OPT(TYPE,DESCR,FIELDNAME,TAG,IMPLICIT,OPT)              \
    {                                                                   \
        field_normal, OFFOF(TYPE, FIELDNAME, aux_typedefname_##DESCR),  \
            0, TAG, IMPLICIT, OPT, &krb5int_asn1type_##DESCR            \
            }
#define FIELDOF_NORM(TYPE,DESCR,FIELDNAME,TAG,IMPLICIT) \
    FIELDOF_OPT(TYPE,DESCR,FIELDNAME,TAG,IMPLICIT,-1)
/*
 * If encoding a subset of the fields of the current structure (for
 * example, a flat structure describing data that gets encoded as a
 * sequence containing one or more sequences), use ENCODEAS, no struct
 * field name(s), and the indicated type descriptor must support the
 * current struct type.
 */
#define FIELDOF_ENCODEAS(TYPE,DESCR,TAG,IMPLICIT)       \
    FIELDOF_ENCODEAS_OPT(TYPE,DESCR,TAG,IMPLICIT,-1)
#define FIELDOF_ENCODEAS_OPT(TYPE,DESCR,TAG,IMPLICIT,OPT)               \
    {                                                                   \
        field_normal,                                                   \
            0 * sizeof(0 ? (TYPE *)0 : (aux_typedefname_##DESCR *) 0),  \
            0, TAG, IMPLICIT, OPT, &krb5int_asn1type_##DESCR            \
            }

/*
 * Reinterpret some subset of the structure itself as something
 * else.
 */
#define FIELD_SELF(DESCR, TAG, IMPLICIT)                        \
    { field_normal, 0, 0, TAG, IMPLICIT, -1, &krb5int_asn1type_##DESCR }

#define FIELDOF_OPTSTRINGL(STYPE,DESC,PTRFIELD,LENDESC,LENFIELD,TAG,IMP,OPT) \
    {                                                                   \
        field_string,                                                   \
            OFFOF(STYPE, PTRFIELD, aux_typedefname_##DESC),             \
            OFFOF(STYPE, LENFIELD, aux_typedefname_##LENDESC),          \
            TAG, IMP, OPT,                                              \
            &krb5int_asn1type_##DESC, &krb5int_asn1type_##LENDESC       \
            }
#define FIELDOF_OPTSTRING(STYPE,DESC,PTRFIELD,LENFIELD,TAG,IMPLICIT,OPT) \
    FIELDOF_OPTSTRINGL(STYPE,DESC,PTRFIELD,uint,LENFIELD,TAG,IMPLICIT,OPT)
#define FIELDOF_STRINGL(STYPE,DESC,PTRFIELD,LENDESC,LENFIELD,TAG,IMPLICIT) \
    FIELDOF_OPTSTRINGL(STYPE,DESC,PTRFIELD,LENDESC,LENFIELD,TAG,IMPLICIT,-1)
#define FIELDOF_STRING(STYPE,DESC,PTRFIELD,LENFIELD,TAG,IMPLICIT)       \
    FIELDOF_OPTSTRING(STYPE,DESC,PTRFIELD,LENFIELD,TAG,IMPLICIT,-1)
#define FIELD_INT_IMM(VALUE,TAG,IMPLICIT)                       \
    { field_immediate, VALUE, 0, TAG, IMPLICIT, -1, 0, }

#define FIELDOF_OPTDER(STYPE,DESC,PTRFIELD,LENFIELD,LENTYPE,TAG,IMPLICIT,OPT) \
    { field_der,                                                        \
            OFFOF(STYPE, PTRFIELD, aux_typedefname_##DESC),             \
            OFFOF(STYPE, LENFIELD, aux_typedefname_##LENTYPE),          \
            TAG, IMPLICIT, OPT,                                         \
            &krb5int_asn1type_##DESC, &krb5int_asn1type_##LENTYPE       \
    }
#define FIELDOF_DER(STYPE,DESC,PTRFIELD,LENFIELD,LENTYPE,TAG,IMPLICIT)  \
    FIELDOF_OPTDER(STYPE,DESC,PTRFIELD,LENFIELD,LENTYPE,TAG,IMPLICIT,-1)

#define FIELDOF_SEQOF_LEN(STYPE,DESC,PTRFIELD,LENFIELD,LENTYPE,TAG,IMPLICIT) \
    {                                                                   \
        field_sequenceof_len,                                           \
            OFFOF(STYPE, PTRFIELD, aux_typedefname_##DESC),             \
            OFFOF(STYPE, LENFIELD, aux_typedefname_##LENTYPE),          \
            TAG, IMPLICIT, -1,                                          \
            &krb5int_asn1type_##DESC, &krb5int_asn1type_##LENTYPE       \
            }
#define FIELDOF_SEQOF_INT32(STYPE,DESC,PTRFIELD,LENFIELD,TAG,IMPLICIT)  \
    FIELDOF_SEQOF_LEN(STYPE,DESC,PTRFIELD,LENFIELD,int32,TAG,IMPLICIT)

#define FIELDOF_OPTCHOICE(STYPE,DESC,PTRFIELD,CHOICEFIELD,LENTYPE,TAG,OPT) \
    { \
        field_choice,                                                   \
            OFFOF(STYPE, PTRFIELD, aux_typedefname_##DESC),             \
            OFFOF(STYPE, CHOICEFIELD, aux_typedefname_##LENTYPE),       \
            TAG, 0, OPT,                                                \
            &krb5int_asn1type_##DESC, &krb5int_asn1type_##LENTYPE       \
            }
#define FIELDOF_CHOICE(STYPE,DESC,PTRFIELD,CHOICEFIELD,LENTYPE,TAG)     \
    FIELDOF_OPTCHOICE(STYPE,DESC,PTRFIELD,CHOICEFIELD,LENTYPE,TAG,-1)

struct seq_info {
    /*
     * If present, returns a bitmask indicating which fields are
     * present.  See the "opt" field in struct field_info.
     */
    unsigned int (*optional)(const void *);
    /* Indicates an array of sequence field descriptors.  */
    const struct field_info *fields;
    size_t n_fields;
    /* Missing: Extensibility handling.  (New field type?)  */
};

extern krb5_error_code
krb5int_asn1_do_full_encode(const void *rep, krb5_data **code,
                            const struct atype_info *a);

#define MAKE_FULL_ENCODER(FNAME, DESC)                                  \
    krb5_error_code FNAME(const aux_typedefname_##DESC *rep,            \
                          krb5_data **code)                             \
    {                                                                   \
        return krb5int_asn1_do_full_encode(rep, code,                   \
                                           &krb5int_asn1type_##DESC);   \
    }                                                                   \
    extern int dummy /* gobble semicolon */

#include <stddef.h>
/*
 * Ugly hack!
 * Like "offsetof", but with type checking.
 */
#define WARN_IF_TYPE_MISMATCH(LVALUE, TYPE)     \
    (sizeof(0 ? (TYPE *) 0 : &(LVALUE)))
#define OFFOF(TYPE,FIELD,FTYPE)                                 \
    (offsetof(TYPE, FIELD)                                      \
     + 0 * WARN_IF_TYPE_MISMATCH(((TYPE*)0)->FIELD, FTYPE))

#endif

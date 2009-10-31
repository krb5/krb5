/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/krb5/krb/ser_eblk.c
 *
 * Copyright 1995, 2008 by the Massachusetts Institute of Technology.
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
 *
 */

#if 0 /* i don't believe this is used anywhere --marc */

/*
 * ser_eblk.c - Serialize a krb5_encblock structure.
 */
#include "k5-int.h"

/*
 * Routines to deal with externalizing the krb5_encrypt_block:
 *      krb5_encrypt_block_size();
 *      krb5_encrypt_block_externalize();
 *      krb5_encrypt_block_internalize();
 */
static krb5_error_code krb5_encrypt_block_size
(krb5_context, krb5_pointer, size_t *);
static krb5_error_code krb5_encrypt_block_externalize
(krb5_context, krb5_pointer, krb5_octet **, size_t *);
static krb5_error_code krb5_encrypt_block_internalize
(krb5_context,krb5_pointer *, krb5_octet **, size_t *);

/* Local data */
static const krb5_ser_entry krb5_encrypt_block_ser_entry = {
    KV5M_ENCRYPT_BLOCK,                 /* Type                 */
    krb5_encrypt_block_size,            /* Sizer routine        */
    krb5_encrypt_block_externalize,     /* Externalize routine  */
    krb5_encrypt_block_internalize      /* Internalize routine  */
};

/*
 * krb5_encrypt_block_size()    - Determine the size required to externalize
 *                                the krb5_encrypt_block.
 */
static krb5_error_code
krb5_encrypt_block_size(kcontext, arg, sizep)
    krb5_context        kcontext;
    krb5_pointer        arg;
    size_t              *sizep;
{
    krb5_error_code     kret;
    krb5_encrypt_block  *encrypt_block;
    size_t              required;

    /*
     * NOTE: This ASSuMES that enctype are sufficient to recreate
     * the _krb5_cryptosystem_entry.  If this is not true, then something else
     * had better be encoded here.
     *
     * krb5_encrypt_block base requirements:
     *  krb5_int32                      for KV5M_ENCRYPT_BLOCK
     *  krb5_int32                      for enctype
     *  krb5_int32                      for private length
     *  encrypt_block->priv_size        for private contents
     *  krb5_int32                      for KV5M_ENCRYPT_BLOCK
     */
    kret = EINVAL;
    if ((encrypt_block = (krb5_encrypt_block *) arg)) {
        required = (sizeof(krb5_int32) +
                    sizeof(krb5_int32) +
                    sizeof(krb5_int32) +
                    sizeof(krb5_int32) +
                    sizeof(krb5_int32) +
                    (size_t) encrypt_block->priv_size);
        if (encrypt_block->key)
            kret = krb5_size_opaque(kcontext,
                                    KV5M_KEYBLOCK,
                                    (krb5_pointer) encrypt_block->key,
                                    &required);
        else
            kret = 0;
        if (!kret)
            *sizep += required;
    }
    return(kret);
}

/*
 * krb5_encrypt_block_externalize()     - Externalize the krb5_encrypt_block.
 */
static krb5_error_code
krb5_encrypt_block_externalize(kcontext, arg, buffer, lenremain)
    krb5_context        kcontext;
    krb5_pointer        arg;
    krb5_octet          **buffer;
    size_t              *lenremain;
{
    krb5_error_code     kret;
    krb5_encrypt_block  *encrypt_block;
    size_t              required;
    krb5_octet          *bp;
    size_t              remain;

    required = 0;
    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    if ((encrypt_block = (krb5_encrypt_block *) arg)) {
        kret = ENOMEM;
        if (!krb5_encrypt_block_size(kcontext, arg, &required) &&
            (required <= remain)) {
            /* Our identifier */
            (void) krb5_ser_pack_int32(KV5M_ENCRYPT_BLOCK, &bp, &remain);

            /* Our enctype */
            (void) krb5_ser_pack_int32((krb5_int32) encrypt_block->
                                       crypto_entry->proto_enctype,
                                       &bp, &remain);

            /* Our length */
            (void) krb5_ser_pack_int32((krb5_int32) encrypt_block->priv_size,
                                       &bp, &remain);

            /* Our private data */
            (void) krb5_ser_pack_bytes(encrypt_block->priv,
                                       (size_t) encrypt_block->priv_size,
                                       &bp, &remain);

            /* Finally, the key data */
            if (encrypt_block->key)
                kret = krb5_externalize_opaque(kcontext,
                                               KV5M_KEYBLOCK,
                                               (krb5_pointer)
                                               encrypt_block->key,
                                               &bp,
                                               &remain);
            else
                kret = 0;

            if (!kret) {
                /* Write trailer */
                (void) krb5_ser_pack_int32(KV5M_ENCRYPT_BLOCK, &bp, &remain);
                *buffer = bp;
                *lenremain = remain;
            }
        }
    }
    return(kret);
}

/*
 * krb5_encrypt_block_internalize()     - Internalize the krb5_encrypt_block.
 */
static krb5_error_code
krb5_encrypt_block_internalize(kcontext, argp, buffer, lenremain)
    krb5_context        kcontext;
    krb5_pointer        *argp;
    krb5_octet          **buffer;
    size_t              *lenremain;
{
    krb5_error_code     kret;
    krb5_encrypt_block  *encrypt_block;
    krb5_int32          ibuf;
    krb5_enctype        ktype;
    krb5_octet          *bp;
    size_t              remain;

    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    /* Read our magic number */
    if (krb5_ser_unpack_int32(&ibuf, &bp, &remain))
        ibuf = 0;
    if (ibuf == KV5M_ENCRYPT_BLOCK) {
        kret = ENOMEM;

        /* Get an encrypt_block */
        if ((remain >= (3*sizeof(krb5_int32))) &&
            (encrypt_block = (krb5_encrypt_block *)
             calloc(1, sizeof(krb5_encrypt_block)))) {
            /* Get the enctype */
            (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
            ktype = (krb5_enctype) ibuf;

            /* Use the ktype to determine the crypto_system entry. */
            krb5_use_enctype(kcontext, encrypt_block, ktype);

            /* Get the length */
            (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
            encrypt_block->priv_size = (int) ibuf;

            /* Get the string */
            if (!ibuf ||
                ((encrypt_block->priv = (void *) malloc((size_t) (ibuf))) &&
                 !(kret = krb5_ser_unpack_bytes((krb5_octet *)
                                                encrypt_block->priv,
                                                (size_t)
                                                encrypt_block->priv_size,
                                                &bp, &remain)))) {
                kret = krb5_internalize_opaque(kcontext,
                                               KV5M_KEYBLOCK,
                                               (krb5_pointer *)
                                               &encrypt_block->key,
                                               &bp,
                                               &remain);
                if (kret == EINVAL)
                    kret = 0;

                if (!kret) {
                    kret = krb5_ser_unpack_int32(&ibuf, &bp, &remain);
                    if (!kret && (ibuf == KV5M_ENCRYPT_BLOCK)) {
                        *buffer = bp;
                        *lenremain = remain;
                        encrypt_block->magic = KV5M_ENCRYPT_BLOCK;
                        *argp = (krb5_pointer) encrypt_block;
                    }
                    else
                        kret = EINVAL;
                }
            }
            if (kret) {
                if (encrypt_block->priv)
                    free(encrypt_block->priv);
                free(encrypt_block);
            }
        }
    }
    return(kret);
}

/*
 * Register the encblock serializer.
 */
krb5_error_code
krb5_ser_encrypt_block_init(kcontext)
    krb5_context        kcontext;
{
    return(krb5_register_serializer(kcontext, &krb5_encrypt_block_ser_entry));
}

#endif

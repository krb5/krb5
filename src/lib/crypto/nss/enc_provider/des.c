/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/nss/enc_provider/des.c
 *
 * Copyright (C) 2009 by the Massachusetts Institute of Technology.
 * Copyright (C) 2010 Red Hat, Inc.
 * All rights reserved.
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

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "k5-int.h"
#include "nss_gen.h"
#include <aead.h>
#include <rand2key.h>
#include "des_int.h"


static krb5_error_code
k5_des_encrypt_iov(krb5_key key, const krb5_data *ivec,
                   krb5_crypto_iov *data, size_t num_data)
{
    krb5_error_code ret;

    ret = k5_nss_gen_import(key, CKM_DES_CBC, CKA_ENCRYPT);
    if (ret != 0)
        return ret;
    return k5_nss_gen_block_iov(key, CKM_DES_CBC, CKA_ENCRYPT,
                                ivec, data, num_data);
}

static krb5_error_code
k5_des_decrypt_iov(krb5_key key,
           const krb5_data *ivec,
           krb5_crypto_iov *data,
           size_t num_data)
{
    krb5_error_code ret;

    ret = k5_nss_gen_import(key, CKM_DES_CBC, CKA_ENCRYPT);
    if (ret != 0)
        return ret;
    return k5_nss_gen_block_iov(key, CKM_DES_CBC, CKA_DECRYPT,
                                ivec, data, num_data);
}

const struct krb5_enc_provider krb5int_enc_des = {
    8,
    7, KRB5_MIT_DES_KEYSIZE,
    k5_des_encrypt_iov,
    k5_des_decrypt_iov,
    NULL,
    krb5int_des_make_key,
    krb5int_des_init_state,
    krb5int_default_free_state,
    k5_nss_gen_cleanup
};

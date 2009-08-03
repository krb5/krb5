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
#include "rsa-md4.h"
#include "hash_provider.h"

static krb5_error_code
k5_md4_hash(unsigned int icount, const krb5_data *input,
	    krb5_data *output)
{
    krb5_MD4_CTX ctx;
    unsigned int i;

    if (output->length != RSA_MD4_CKSUM_LENGTH)
	return(KRB5_CRYPTO_INTERNAL);

    krb5_MD4Init(&ctx);
    for (i=0; i<icount; i++)
	krb5_MD4Update(&ctx, (unsigned char *) input[i].data, input[i].length);
    krb5_MD4Final(&ctx);

    memcpy(output->data, ctx.digest, RSA_MD4_CKSUM_LENGTH);

    return(0);
}

const struct krb5_hash_provider krb5int_hash_md4 = {
    RSA_MD4_CKSUM_LENGTH,
    64,
    k5_md4_hash
};

/*
 * lib/crypto/des/finish_key.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 */

#include "k5-int.h"
#include "des_int.h"

/*
	does any necessary clean-up on the eblock (such as releasing
	resources held by eblock->priv).

	returns: errors
 */

krb5_error_code
mit_des_finish_key (eblock)
    krb5_encrypt_block FAR * eblock;
{
    if (eblock->priv) {
	memset((char *)eblock->priv, 0, (size_t) eblock->priv_size);
	free(eblock->priv);
    }
    eblock->priv = 0;
    eblock->priv_size = 0;
    /* free/clear other stuff here? */
    return 0;
}

/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_finish_key_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#include <krb5/mit-des.h>

/*
	does any necessary clean-up on the eblock (such as releasing
	resources held by eblock->priv).

	returns: errors
 */

krb5_error_code mit_des_finish_key (DECLARG(krb5_encrypt_block *,eblock))
OLDDECLARG(krb5_encrypt_block *,eblock)
{
    memset((char *)eblock->priv, 0, sizeof(mit_des_key_schedule));
    free(eblock->priv);
    eblock->priv = 0;
    /* free/clear other stuff here? */
    return 0;
}

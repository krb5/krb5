/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_fin_rndkey_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/mit-des.h>
#include <krb5/ext-proto.h>

/*
        free any resources held by "seed" and assigned by init_random_key()
 */

krb5_error_code mit_des_finish_random_key (DECLARG(krb5_pointer *, seed))
OLDDECLARG(krb5_pointer *, seed)
{
    bzero( (char *)*seed, sizeof(mit_des_random_key_seed) );
    free((char *)*seed);
    *seed = 0;
    return 0;		/* XXX init_random_key */
}

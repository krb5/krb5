/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_free_host_realm()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_free_hstrl_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

#include <krb5/ext-proto.h>
#include <stdio.h>
#include <krb5/libos-proto.h>

/*
 Frees the storage taken by a realm list returned by krb5_get_local_realm.
 */

krb5_error_code
krb5_free_host_realm(realmlist)
char * const *realmlist;
{
    /* same format, so why duplicate code? */
    return krb5_free_krbhst(realmlist);
}

/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_copy_authenticator()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_copy_checksum_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

#include <krb5/ext-proto.h>

static krb5_error_code
krb5_copy_checksum(ckfrom, ckto)
const krb5_checksum *ckfrom;
krb5_checksum **ckto;
{
    krb5_error_code retval;
    krb5_checksum *tempto;

    if (!(tempto = (krb5_checksum *)malloc(sizeof(*tempto))))
	return ENOMEM;
    *tempto = *ckfrom;

    if (!(tempto->contents =
	  (krb5_octet *)malloc(tempto->length))) {
	xfree(tempto);
	return ENOMEM;
    }
    memcpy((char *) tempto->contents, (char *) ckfrom->contents,
	   ckfrom->length);

    *ckto = tempto;
    return 0;
}

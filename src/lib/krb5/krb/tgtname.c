/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_tgtname()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_tgtname_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/kdb.h>
#include <errno.h>

static krb5_data tgtdata = {sizeof(TGTNAME), TGTNAME};

/* This is an internal-only function, used by krb5_get_cred_from_kdc() */

krb5_error_code
krb5_tgtname(server, client, tgtprinc)
const krb5_principal server, client;
krb5_principal *tgtprinc;
{
    krb5_principal retprinc;
    krb5_error_code retval;

    if (!(retprinc = (krb5_data **)calloc(4, sizeof(krb5_data *))))
	return ENOMEM;
    if (retval = krb5_copy_data(krb5_princ_realm(server), &retprinc[0])) {
	xfree(retprinc);
	return retval;
    }
    if (retval = krb5_copy_data(&tgtdata, &retprinc[1])) {
	krb5_free_data(retprinc[0]);
	xfree(retprinc);
	return retval;
    }
    if (retval = krb5_copy_data(krb5_princ_realm(client), &retprinc[2])) {
	krb5_free_data(retprinc[0]);
	krb5_free_data(retprinc[1]);
	xfree(retprinc);
	return retval;
    }
    *tgtprinc = retprinc;
    return 0;
}

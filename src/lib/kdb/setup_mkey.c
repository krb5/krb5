/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_kdb_setup_mkey()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_setup_mkey_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/ext-proto.h>
#include <errno.h>

/*
 * Given a key name and a realm name, construct a principal which can be used
 * to fetch the master key from the database.
 */

krb5_error_code
krb5_db_setup_mkey_name(keyname, realm, principal)
const char *keyname;
const char *realm;
krb5_principal *principal;
{
    krb5_principal retprinc;
    int keylen = strlen(keyname);
    int rlen = strlen(realm);
    
    retprinc = (krb5_principal) calloc(3, sizeof(krb5_data));
    if (!retprinc)
	return ENOMEM;
    retprinc[0] = (krb5_data *) malloc(sizeof(krb5_data));
    if (!retprinc[0]) {
	goto freeprinc;
    }
    retprinc[1] = (krb5_data *) malloc(sizeof(krb5_data));
    if (!retprinc[1]) {
	goto free0;
    }
    if (!(retprinc[0]->data = malloc(rlen))) {
	goto free1;
    }
    if (!(retprinc[1]->data = malloc(keylen))) {
	xfree(retprinc[0]->data);
	goto free1;
    }
    bcopy(realm, retprinc[0]->data, rlen);
    retprinc[0]->length = rlen;

    bcopy(keyname, retprinc[1]->data, keylen);
    retprinc[1]->length = keylen;

    return 0;

 free1:
    xfree(retprinc[1]);
 free0:
    xfree(retprinc[0]);
 freeprinc:
    xfree(retprinc);
    return ENOMEM;
}

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
 * krb5_kdb_setup_mkey()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_setup_mkey_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/ext-proto.h>

/*
 * Given a key name and a realm name, construct a principal which can be used
 * to fetch the master key from the database.
 * 
 * If the key name is NULL, the default key name will be used.
 */

#define	REALM_SEP_STRING	"@"

krb5_error_code
krb5_db_setup_mkey_name(keyname, realm, fullname, principal)
const char *keyname;
const char *realm;
char **fullname;
krb5_principal *principal;
{
    krb5_error_code retval;
    int keylen;
    int rlen = strlen(realm);
    char *fname;
    
    if (!keyname)
	keyname = KRB5_KDB_M_NAME;	/* XXX external? */

    keylen = strlen(keyname);
	 
    fname = malloc(keylen+rlen+2);
    if (!fname)
	return ENOMEM;

    strcpy(fname, keyname);
    strcat(fname, REALM_SEP_STRING);
    strcat(fname, realm);

    if (retval = krb5_parse_name(fname, principal))
	return retval;
    if (fullname)
	*fullname = fname;
    else
	free(fname);
    return 0;
}

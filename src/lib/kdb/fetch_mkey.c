/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_db_fetch_mkey():
 * Fetch a database master key from somewhere.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_fetch_mkey_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <errno.h>
#include <stdio.h>
#include <krb5/libos-proto.h>
#include <krb5/ext-proto.h>

/* these are available to other funcs, and the pointers may be reassigned */

char *krb5_mkey_pwd_prompt1 = KRB5_KDC_MKEY_1;
char *krb5_mkey_pwd_prompt2 = KRB5_KDC_MKEY_2;

/*
 * Get the KDC database master key from somewhere, filling it into *key.
 *
 * key->keytype should be set to the desired key type.
 *
 * if fromkeyboard is TRUE, then the master key is read as a password
 * from the user's terminal.  In this case,
 * eblock should point to a block with an appropriate string_to_key function.
 *
 * mname is the name of the key sought; this can be used by the string_to_key
 * function or by some other method to isolate the desired key.
 *
 */

krb5_error_code
krb5_db_fetch_mkey(DECLARG(krb5_principal, mname),
		   DECLARG(krb5_encrypt_block *, eblock),
		   DECLARG(krb5_boolean, fromkeyboard),
		   DECLARG(krb5_keyblock *,key))
OLDDECLARG(krb5_principal, mname)
OLDDECLARG(krb5_encrypt_block *, eblock)
OLDDECLARG(krb5_boolean, fromkeyboard)
OLDDECLARG(krb5_keyblock *,key)
{
    krb5_error_code retval;
    char password[BUFSIZ];
    krb5_data pwd;
    int size = sizeof(password);

    if (fromkeyboard) {
	if (retval = krb5_read_password(krb5_mkey_pwd_prompt1,
					krb5_mkey_pwd_prompt2,
					password,
					&size))
	    return(retval);

	pwd.data = password;
	pwd.length = size;
	retval = (*eblock->crypto_entry->string_to_key)(key->keytype,
							key,
							&pwd,
							mname);
	bzero(password, sizeof(password)); /* erase it */
	return retval;

    } else {
	/* from somewhere else */
	return EOPNOTSUPP;		/* XXX */
    }
}

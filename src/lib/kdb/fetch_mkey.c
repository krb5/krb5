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
#include <krb5/krb5_err.h>
#include <krb5/kdb5_err.h>
#include <krb5/kdb.h>
#include <errno.h>
#include <stdio.h>
#include <krb5/libos-proto.h>
#include <krb5/ext-proto.h>
#include "kdbint.h"
#include <sys/param.h>			/* XXX for MAXPATHLEN */

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
 * if twice is TRUE, the password is read twice for verification.
 *
 * mname is the name of the key sought; this can be used by the string_to_key
 * function or by some other method to isolate the desired key.
 *
 */

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

krb5_error_code
krb5_db_fetch_mkey(DECLARG(krb5_principal, mname),
		   DECLARG(krb5_encrypt_block *, eblock),
		   DECLARG(krb5_boolean, fromkeyboard),
		   DECLARG(krb5_boolean, twice),
		   DECLARG(krb5_keyblock *,key))
OLDDECLARG(krb5_principal, mname)
OLDDECLARG(krb5_encrypt_block *, eblock)
OLDDECLARG(krb5_boolean, fromkeyboard)
OLDDECLARG(krb5_boolean, twice)
OLDDECLARG(krb5_keyblock *,key)
{
    krb5_error_code retval;
    char password[BUFSIZ];
    krb5_data pwd;
    int size = sizeof(password);


    if (fromkeyboard) {
	if (retval = krb5_read_password(krb5_mkey_pwd_prompt1,
					twice ? krb5_mkey_pwd_prompt2 : 0,
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
	krb5_keytype keytype;
	char defkeyfile[MAXPATHLEN+1];
	krb5_data *realm = krb5_princ_realm(mname);
	FILE *kf;

	retval = 0;
	(void) strcpy(defkeyfile, DEFAULT_KEYFILE_STUB);
	(void) strncat(defkeyfile, realm->data,
		       min(sizeof(defkeyfile)-sizeof(DEFAULT_KEYFILE_STUB)-1,
			   realm->length));
	(void) strcat(defkeyfile, "");
	
	if (!(kf = fopen(defkeyfile, "r")))
	    return KRB5_KDB_CANTREAD_STORED;
	if (fread((krb5_pointer) &keytype, sizeof(keytype), 1, kf) != 1) {
	    retval = KRB5_KDB_CANTREAD_STORED;
	    goto errout;
	}
	if (keytype != key->keytype) {
	    retval = KRB5_KDB_BADSTORED_MKEY;
	    goto errout;
	}
	if (fread((krb5_pointer) &key->length,
		  sizeof(key->length), 1, kf) != 1) {
	    retval = KRB5_KDB_CANTREAD_STORED;
	    goto errout;
	}
	if (!key->length || key->length < 0) {
	    retval = KRB5_KDB_BADSTORED_MKEY;
	    goto errout;
	}
	if (!(key->contents = (krb5_octet *)malloc(key->length))) {
	    retval = ENOMEM;
	    goto errout;
	}
	if (fread((krb5_pointer) key->contents,
		  sizeof(key->contents[0]), key->length, kf) != key->length)
	    retval = KRB5_KDB_CANTREAD_STORED;
	else
	    retval = 0;
    errout:
	(void) fclose(kf);
	return retval;
    }
}

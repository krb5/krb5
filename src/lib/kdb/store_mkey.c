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
 * krb5_db_store_mkey():
 * Store a database master key in a file.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_store_mkey_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/los-proto.h>
#include <krb5/ext-proto.h>
#include "kdbint.h"
#include <krb5/sysincl.h>		/* for MAXPATHLEN */

/*
 * Put the KDC database master key into a file.  If keyfile is NULL,
 * then a default name derived from the principal name mname is used.
 */

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

krb5_error_code
krb5_db_store_mkey(keyfile, mname, key)
char *keyfile;
krb5_principal mname;
krb5_keyblock *key;
{
    FILE *kf;
    krb5_error_code retval = 0;
    char defkeyfile[MAXPATHLEN+1];
    krb5_data *realm = krb5_princ_realm(mname);
#if defined(unix) || defined(__unix__)
    int oumask;
#endif

    if (!keyfile) {
	(void) strcpy(defkeyfile, DEFAULT_KEYFILE_STUB);
	(void) strncat(defkeyfile, realm->data,
		       min(sizeof(defkeyfile)-sizeof(DEFAULT_KEYFILE_STUB)-1,
			   realm->length));
	(void) strcat(defkeyfile, "");
	keyfile = defkeyfile;
    }

#if defined(unix) || defined(__unix__)
    oumask = umask(077);
#endif
    if (!(kf = fopen(keyfile, "w"))) {
#if defined(unix) || defined(__unix__)
	(void) umask(oumask);
#endif
	return errno;
    }
    if ((fwrite((krb5_pointer) &key->keytype,
		sizeof(key->keytype), 1, kf) != 1) ||
	(fwrite((krb5_pointer) &key->length,
		sizeof(key->length), 1, kf) != 1) ||
	(fwrite((krb5_pointer) key->contents,
		sizeof(key->contents[0]), key->length, kf) != key->length)) {
	retval = errno;
	(void) fclose(kf);
    }
    if (fclose(kf) == EOF)
	retval = errno;
#if defined(unix) || defined(__unix__)
    (void) umask(oumask);
#endif
    return retval;
}

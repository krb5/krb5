/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_kdb_encrypt_key(), krb5_kdb_decrypt_key functions
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_encrypt_key_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/kdb5_err.h>
#include <krb5/ext-proto.h>
#include <errno.h>

/*
 * Encrypt a key for storage in the database.  "eblock" is used
 * to encrypt the key in "in" into "out"; the storage pointed to by "out"
 * is allocated before use.
 */

krb5_error_code
krb5_kdb_encrypt_key(eblock, in, out)
krb5_encrypt_block *eblock;
const krb5_keyblock *in;
krb5_keyblock *out;
{
    /* encrypted rep has the real (unencrypted) key length stored
       along with the encrypted key */

    krb5_error_code retval;

    out->keytype = in->keytype;
    out->length = krb5_encrypt_size(in->length, eblock->crypto_entry);
    out->length += sizeof(out->length);
    out->contents = (krb5_octet *)malloc(out->length);
    if (!out->contents) {
	out->contents = 0;
	out->length = 0;
	return ENOMEM;
    }
    /* copy in real length */
    bcopy((char *)&in->length, (char *)out->contents, sizeof(out->length));
    /* and arrange for encrypted key */
    if (retval = (*eblock->crypto_entry->
		  encrypt_func)((krb5_pointer) in->contents,
				(krb5_pointer) (((char *) out->contents) +
						sizeof(out->length)),
				in->length, eblock, 0)) {
	free((char *)out->contents);
	out->contents = 0;
	out->length = 0;
    }
    return retval;
}

/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_kdb_encrypt_key(), krb5_kdb_decrypt_key functions
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_decrypt_key_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>


/*
 * Decrypt a key from storage in the database.  "eblock" is used
 * to decrypt the key in "in" into "out"; the storage pointed to by "out"
 * is allocated before use.
 */

krb5_error_code
krb5_kdb_decrypt_key(eblock, in, out)
krb5_encrypt_block *eblock;
const krb5_encrypted_keyblock *in;
krb5_keyblock *out;
{
    krb5_error_code retval;

    /* the encrypted version is stored as the unencrypted key length
       (in host byte order), followed by the encrypted key.
     */
    out->keytype = in->keytype;
    out->length = krb5_encrypt_size(in->length-sizeof(in->length),
				    eblock->crypto_entry);
    out->contents = (krb5_octet *)malloc(out->length);
    if (!out->contents) {
	out->contents = 0;
	out->length = 0;
	return ENOMEM;
    }
    /* copy out the real length count */
    memcpy((char *)&out->length, (char *)in->contents, sizeof(out->length));

    /* remember the contents of the encrypted version has a sizeof(in->length)
       integer length of the real embedded key, followed by the
       encrypted key, so the offset here is needed */
    if (retval = krb5_decrypt((krb5_pointer) (((char *) in->contents) +
					      sizeof(in->length)),
			      (krb5_pointer) out->contents,
			      in->length-sizeof(in->length), eblock, 0)) {
	free((char *)out->contents);
	out->contents = 0;
	out->length = 0;
	return retval;
    }
    if (out->length < 0) {
	free((char *)out->contents);
	out->contents = 0;
	out->length = 0;
	return KRB5_KDB_INVALIDKEYSIZE;
    }
    return retval;
}

/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * krb5_kdb_encrypt_key(), krb5_kdb_decrypt_key functions
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_encrypt_key_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/kdb.h>

/*
 * Encrypt a key for storage in the database.  "eblock" is used
 * to encrypt the key in "in" into "out"; the storage pointed to by "out"
 * is allocated before use.
 */

krb5_error_code
krb5_kdb_encrypt_key(eblock, in, out)
krb5_encrypt_block *eblock;
const krb5_keyblock *in;
krb5_encrypted_keyblock *out;
{
    /* encrypted rep has the real (unencrypted) key length stored
       along with the encrypted key */

    krb5_error_code retval;
    krb5_keyblock tmpin;

    out->keytype = in->keytype;
    out->length = krb5_encrypt_size(in->length, eblock->crypto_entry);

    /* because of checksum space requirements imposed by the encryption
       interface, we need to copy the input key into a larger area. */
    tmpin.length = in->length;
    tmpin.contents = (krb5_octet *)malloc(out->length);
    if (!tmpin.contents) {
	out->length = 0;
	return ENOMEM;
    }
    memcpy((char *)tmpin.contents, (const char *)in->contents, tmpin.length);

    out->length += sizeof(out->length);
    out->contents = (krb5_octet *)malloc(out->length);
    if (!out->contents) {
	xfree(tmpin.contents);
	out->contents = 0;
	out->length = 0;
	return ENOMEM;
    }
    /* copy in real length */
    memcpy((char *)out->contents, (const char *)&tmpin.length,
	   sizeof(out->length));
    /* and arrange for encrypted key */
    retval = krb5_encrypt((krb5_pointer) tmpin.contents,
			  (krb5_pointer) (((char *) out->contents) +
					  sizeof(out->length)),
			  tmpin.length, eblock, 0);
    xfree(tmpin.contents);
    if (retval) {
	xfree(out->contents);
	out->contents = 0;
	out->length = 0;
    }
    return retval;
}

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
static char rcsid_decrypt_key_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/kdb5_err.h>
#include <krb5/ext-proto.h>
#include <errno.h>


krb5_error_code
krb5_kdb_decrypt_key(in, out, eblock)
krb5_keyblock *in;
krb5_keyblock *out;
krb5_encrypt_block *eblock;
{
    krb5_error_code retval;

    *out = *in;
    out->length = krb5_encrypt_size(in->length, eblock->crypto_entry);
    out->contents = (krb5_octet *)malloc(out->length);
    if (!out->contents) {
	out->contents = 0;
	out->length = 0;
	return ENOMEM;
    }
    if (retval = (*eblock->crypto_entry->
		  decrypt_func)((krb5_pointer) in->contents,
				(krb5_pointer) out->contents,
				in->length, eblock)) {
	free((char *)out->contents);
	out->contents = 0;
	out->length = 0;
	return retval;
    }
    out->length -= sizeof(out->length);
    if (out->length < 0) {
	free((char *)out->contents);
	out->contents = 0;
	out->length = 0;
	return KRB5_KDB_INVALIDKEYSIZE;
    }
    /* shift key down to beginning of contents, and ignore extra wasted
       space */
    bcopy(out->contents, ((krb5_pointer) out->contents ) + sizeof(out->length),
	  out->length);
    return retval;
}

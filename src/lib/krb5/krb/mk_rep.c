/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_mk_rep()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_mk_rep_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/asn1.h>

#include <krb5/libos.h>
#include <krb5/libos-proto.h>

#include <krb5/ext-proto.h>

/*
 Formats a KRB_AP_REP message into outbuf.

 The reply in repl is encrypted under the key in kblock, and the resulting
 message encoded and left in outbuf.

 The outbuf buffer storage is allocated, and should be freed by the
 caller when finished.

 returns system errors
*/

krb5_error_code
krb5_mk_rep(repl, kblock, outbuf)
const krb5_ap_rep_enc_part *repl;
const krb5_keyblock *kblock;
krb5_data *outbuf;
{
    krb5_error_code retval;
    krb5_data *scratch;
    krb5_ap_rep reply;
    krb5_enctype etype;
    krb5_encrypt_block eblock;
    krb5_data *toutbuf;

    /* verify a valid etype is available */
    if (!valid_keytype(kblock->keytype))
	return KRB5_PROG_KEYTYPE_NOSUPP;

    etype = krb5_keytype_array[kblock->keytype]->system->proto_enctype;

    if (!valid_etype(etype))
	return KRB5_PROG_ETYPE_NOSUPP;

    /* encode it before encrypting */
    if (retval = encode_krb5_ap_rep_enc_part(repl, &scratch))
	return retval;

#define cleanup_scratch() { (void) memset(scratch->data, 0, scratch->length); \
krb5_free_data(scratch); }

    /* put together an eblock for this encryption */

    eblock.crypto_entry = krb5_csarray[etype]->system;
    reply.enc_part.etype = etype;
    reply.enc_part.kvno = 0;		/* XXX user set? */

    reply.enc_part.ciphertext.length = krb5_encrypt_size(scratch->length,
							 eblock.crypto_entry);
    /* add padding area, and zero it */
    if (!(scratch->data = realloc(scratch->data,
				  reply.enc_part.ciphertext.length))) {
	/* may destroy scratch->data */
	xfree(scratch);
	return ENOMEM;
    }
    memset(scratch->data + scratch->length, 0,
	  reply.enc_part.ciphertext.length - scratch->length);
    if (!(reply.enc_part.ciphertext.data =
	  malloc(reply.enc_part.ciphertext.length))) {
	retval = ENOMEM;
	goto clean_scratch;
    }

#define cleanup_encpart() {\
(void) memset(reply.enc_part.ciphertext.data, 0,\
	     reply.enc_part.ciphertext.length); \
free(reply.enc_part.ciphertext.data); \
reply.enc_part.ciphertext.length = 0; reply.enc_part.ciphertext.data = 0;}

    /* do any necessary key pre-processing */
    if (retval = krb5_process_key(&eblock, kblock)) {
	goto clean_encpart;
    }

#define cleanup_prockey() {(void) krb5_finish_key(&eblock);}

    /* call the encryption routine */
    if (retval = krb5_encrypt((krb5_pointer) scratch->data,
			      (krb5_pointer) reply.enc_part.ciphertext.data,
			      scratch->length, &eblock, 0)) {
	goto clean_prockey;
    }

    /* encrypted part now assembled-- do some cleanup */
    cleanup_scratch();

    if (retval = krb5_finish_key(&eblock)) {
	cleanup_encpart();
	return retval;
    }

    if (!(retval = encode_krb5_ap_rep(&reply, &toutbuf))) {
	*outbuf = *toutbuf;
	xfree(toutbuf);
    }
    cleanup_encpart();
    return retval;

 clean_prockey:
    cleanup_prockey();
 clean_encpart:
    cleanup_encpart();
 clean_scratch:
    cleanup_scratch();

    return retval;
}

#include <string.h>
#include "shs.h"

#define PAD_SZ	64


krb5_error_code
hmac_sha(text, text_len, key, key_len, digest)
    krb5_octet	* text;			/* pointer to data stream */
    int		text_len;		/* length of data stream */
    krb5_octet	* key;			/* pointer to authentication key */
    int		key_len;		/* length of authentication key */
    krb5_octet	* digest;		/* caller digest to be filled in */
{
    SHS_INFO context;
    krb5_octet k_ipad[PAD_SZ];	/* inner padding - key XORd with ipad */
    krb5_octet k_opad[PAD_SZ];	/* outer padding - key XORd with opad */
    int i;
 
    /* sanity check parameters */
    if (!text || !key || !digest)
	/* most heinous, probably should log something */
	return EINVAL;

    /* if key is longer than 64 bytes reset it to key=MD5(key) */
    if (key_len > sizeof(k_ipad)) {
	shsInit(&context);
	shsUpdate(&context, key, key_len);
	shsFinal(&context);

	memcpy(digest, context.digest, SHS_DIGESTSIZE);
	key = digest;
	key_len = SHS_DIGESTSIZE;
    }
 
    /*
     * the HMAC_SHA transform looks like:
     *
     * SHA(K XOR opad, SHA(K XOR ipad, text))
     *
     * where K is an n byte key
     * ipad is the byte 0x36 repeated 64 times
     * opad is the byte 0x5c repeated 64 times
     * and text is the data being protected
     */
 
    /* start out by storing key in pads */
    memset(k_ipad, 0x36, sizeof(k_ipad));
    memset(k_opad, 0x5c, sizeof(k_opad));

    /* XOR key with ipad and opad values */
    for (i = 0; i < key_len; i++) {
	k_ipad[i] ^= key[i];
	k_opad[i] ^= key[i];
    }

    /*
     * perform inner SHA
     */
    shsInit(&context);
    shsUpdate(&context, k_ipad, sizeof(k_ipad));
    shsUpdate(&context, text, text_len);
    shsFinal(&context);

    memcpy(digest, context.digest, SHS_DIGESTSIZE);
    
    /*
     * perform outer SHA
     */
    shsInit(&context);
    shsUpdate(&context, k_opad, sizeof(k_opad));
    shsUpdate(&context, digest, SHS_DIGESTSIZE);
    shsFinal(&context);

    memcpy(digest, context.digest, SHS_DIGESTSIZE);

    return 0;
}

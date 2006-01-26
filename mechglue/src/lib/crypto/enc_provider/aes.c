#include "k5-int.h"
#include "enc_provider.h"
#include "aes.h"

#if 0
aes_rval aes_blk_len(unsigned int blen, aes_ctx cx[1]);
aes_rval aes_enc_key(const unsigned char in_key[], unsigned int klen, aes_ctx cx[1]);
aes_rval aes_enc_blk(const unsigned char in_blk[], unsigned char out_blk[], const aes_ctx cx[1]);
aes_rval aes_dec_key(const unsigned char in_key[], unsigned int klen, aes_ctx cx[1]);
aes_rval aes_dec_blk(const unsigned char in_blk[], unsigned char out_blk[], const aes_ctx cx[1]);
#endif

#define CHECK_SIZES 0

#if 0
static void printd (const char *descr, krb5_data *d) {
    int i, j;
    const int r = 16;

    printf("%s:", descr);

    for (i = 0; i < d->length; i += r) {
	printf("\n  %04x: ", i);
	for (j = i; j < i + r && j < d->length; j++)
	    printf(" %02x", 0xff & d->data[j]);
#ifdef SHOW_TEXT
	for (; j < i + r; j++)
	    printf("   ");
	printf("   ");
	for (j = i; j < i + r && j < d->length; j++) {
	    int c = 0xff & d->data[j];
	    printf("%c", isprint(c) ? c : '.');
	}
#endif
    }
    printf("\n");
}
#endif

#define enc(OUT, IN, CTX) (aes_enc_blk((IN),(OUT),(CTX)) == aes_good ? (void) 0 : abort())
#define dec(OUT, IN, CTX) (aes_dec_blk((IN),(OUT),(CTX)) == aes_good ? (void) 0 : abort())

static void xorblock(char *out, const char *in)
{
    int z;
    for (z = 0; z < BLOCK_SIZE; z++)
	out[z] ^= in[z];
}

krb5_error_code
krb5int_aes_encrypt(const krb5_keyblock *key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output)
{
    aes_ctx ctx;
    unsigned char tmp[BLOCK_SIZE], tmp2[BLOCK_SIZE], tmp3[BLOCK_SIZE];
    int nblocks = 0, blockno;

/*    CHECK_SIZES; */

    if (aes_enc_key(key->contents, key->length, &ctx) != aes_good)
	abort();

    if (ivec)
	memcpy(tmp, ivec->data, BLOCK_SIZE);
    else
	memset(tmp, 0, BLOCK_SIZE);

    nblocks = (input->length + BLOCK_SIZE - 1) / BLOCK_SIZE;

    if (nblocks == 1) {
	/* XXX Used for DK function.  */
	enc(output->data, input->data, &ctx);
    } else {
	unsigned int nleft;

	for (blockno = 0; blockno < nblocks - 2; blockno++) {
	    xorblock(tmp, input->data + blockno * BLOCK_SIZE);
	    enc(tmp2, tmp, &ctx);
	    memcpy(output->data + blockno * BLOCK_SIZE, tmp2, BLOCK_SIZE);

	    /* Set up for next block.  */
	    memcpy(tmp, tmp2, BLOCK_SIZE);
	}
	/* Do final CTS step for last two blocks (the second of which
	   may or may not be incomplete).  */
	xorblock(tmp, input->data + (nblocks - 2) * BLOCK_SIZE);
	enc(tmp2, tmp, &ctx);
	nleft = input->length - (nblocks - 1) * BLOCK_SIZE;
	memcpy(output->data + (nblocks - 1) * BLOCK_SIZE, tmp2, nleft);
	memcpy(tmp, tmp2, BLOCK_SIZE);

	memset(tmp3, 0, sizeof(tmp3));
	memcpy(tmp3, input->data + (nblocks - 1) * BLOCK_SIZE, nleft);
	xorblock(tmp, tmp3);
	enc(tmp2, tmp, &ctx);
	memcpy(output->data + (nblocks - 2) * BLOCK_SIZE, tmp2, BLOCK_SIZE);
	if (ivec)
	    memcpy(ivec->data, tmp2, BLOCK_SIZE);
    }

    return 0;
}

krb5_error_code
krb5int_aes_decrypt(const krb5_keyblock *key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output)
{
    aes_ctx ctx;
    unsigned char tmp[BLOCK_SIZE], tmp2[BLOCK_SIZE], tmp3[BLOCK_SIZE];
    int nblocks = 0, blockno;

    CHECK_SIZES;

    if (aes_dec_key(key->contents, key->length, &ctx) != aes_good)
	abort();

    if (ivec)
	memcpy(tmp, ivec->data, BLOCK_SIZE);
    else
	memset(tmp, 0, BLOCK_SIZE);

    nblocks = (input->length + BLOCK_SIZE - 1) / BLOCK_SIZE;

    if (nblocks == 1) {
	if (input->length < BLOCK_SIZE)
	    abort();
	dec(output->data, input->data, &ctx);
    } else {

	for (blockno = 0; blockno < nblocks - 2; blockno++) {
	    dec(tmp2, input->data + blockno * BLOCK_SIZE, &ctx);
	    xorblock(tmp2, tmp);
	    memcpy(output->data + blockno * BLOCK_SIZE, tmp2, BLOCK_SIZE);
	    memcpy(tmp, input->data + blockno * BLOCK_SIZE, BLOCK_SIZE);
	}
	/* Do last two blocks, the second of which (next-to-last block
	   of plaintext) may be incomplete.  */
	dec(tmp2, input->data + (nblocks - 2) * BLOCK_SIZE, &ctx);
	/* Set tmp3 to last ciphertext block, padded.  */
	memset(tmp3, 0, sizeof(tmp3));
	memcpy(tmp3, input->data + (nblocks - 1) * BLOCK_SIZE,
	       input->length - (nblocks - 1) * BLOCK_SIZE);
	/* Set tmp2 to last (possibly partial) plaintext block, and
	   save it.  */
	xorblock(tmp2, tmp3);
	memcpy(output->data + (nblocks - 1) * BLOCK_SIZE, tmp2,
	       input->length - (nblocks - 1) * BLOCK_SIZE);
	/* Maybe keep the trailing part, and copy in the last
	   ciphertext block.  */
	memcpy(tmp2, tmp3, input->length - (nblocks - 1) * BLOCK_SIZE);
	/* Decrypt, to get next to last plaintext block xor previous
	   ciphertext.  */
	dec(tmp3, tmp2, &ctx);
	xorblock(tmp3, tmp);
	memcpy(output->data + (nblocks - 2) * BLOCK_SIZE, tmp3, BLOCK_SIZE);
	if (ivec)
	    memcpy(ivec->data, input->data + (nblocks - 2) * BLOCK_SIZE,
		   BLOCK_SIZE);
    }

    return 0;
}

static krb5_error_code
k5_aes_make_key(const krb5_data *randombits, krb5_keyblock *key)
{
    if (key->length != 16 && key->length != 32)
	return(KRB5_BAD_KEYSIZE);
    if (randombits->length != key->length)
	return(KRB5_CRYPTO_INTERNAL);

    key->magic = KV5M_KEYBLOCK;

    memcpy(key->contents, randombits->data, randombits->length);
    return(0);
}

static krb5_error_code
krb5int_aes_init_state (const krb5_keyblock *key, krb5_keyusage usage,
			krb5_data *state)
{
    state->length = 16;
    state->data = (void *) malloc(16);
    if (state->data == NULL)
	return ENOMEM;
    memset(state->data, 0, state->length);
    return 0;
}

const struct krb5_enc_provider krb5int_enc_aes128 = {
    16,
    16, 16,
    krb5int_aes_encrypt,
    krb5int_aes_decrypt,
    k5_aes_make_key,
    krb5int_aes_init_state,
    krb5int_default_free_state
};

const struct krb5_enc_provider krb5int_enc_aes256 = {
    16,
    32, 32,
    krb5int_aes_encrypt,
    krb5int_aes_decrypt,
    k5_aes_make_key,
    krb5int_aes_init_state,
    krb5int_default_free_state
};

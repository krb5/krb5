/* arcfour.c 
 *
 * Copyright (c) 2000 by Computer Science Laboratory,
 *                       Rensselaer Polytechnic Institute
 *
 * #include STD_DISCLAIMER
 */

#include "k5-int.h"
#include "arcfour-int.h"
#include "enc_provider.h"
/* gets the next byte from the PRNG */
#if ((__GNUC__ >= 2) )
static __inline__ unsigned int k5_arcfour_byte(ArcfourContext *);
#else
static unsigned int k5_arcfour_byte(ArcfourContext *);
#endif /* gcc inlines*/

/* Initializes the context and sets the key. */
static krb5_error_code k5_arcfour_init(ArcfourContext *ctx, const unsigned char *key, 
		  unsigned int keylen);

/* Encrypts/decrypts data. */
static void k5_arcfour_crypt(ArcfourContext *ctx, unsigned char *dest, 
		     const unsigned char *src, unsigned int len);

/* Interface layer to kerb5 crypto layer */
static krb5_error_code
k5_arcfour_docrypt(const krb5_keyblock *, const krb5_data *,
		   const krb5_data *, krb5_data *);

/* from a random bitstrem, construct a key */
static krb5_error_code
k5_arcfour_make_key(const krb5_data *, krb5_keyblock *);

static const unsigned char arcfour_weakkey1[] = {0x00, 0x00, 0xfd};
static const unsigned char arcfour_weakkey2[] = {0x03, 0xfd, 0xfc};
static const krb5_data arcfour_weakkeys[] = {
    {KV5M_DATA, sizeof (arcfour_weakkey1),
     (char * ) arcfour_weakkey1},
    {KV5M_DATA, sizeof (arcfour_weakkey2),
     (char * ) arcfour_weakkey2},
    {KV5M_DATA, 0, 0}
};

/*xxx we really should check for c9x here and use inline on 
 * more than just gcc. */
#if ((__GNUC__ >= 2) )
static __inline__ unsigned int k5_arcfour_byte(ArcfourContext * ctx)
#else
static unsigned int k5_arcfour_byte(ArcfourContext * ctx)
#endif /* gcc inlines*/
{
  unsigned int x;
  unsigned int y;
  unsigned int sx, sy;
  unsigned char *state;

  state = ctx->state;
  x = (ctx->x + 1) & 0xff;
  sx = state[x];
  y = (sx + ctx->y) & 0xff;
  sy = state[y];
  ctx->x = x;
  ctx->y = y;
  state[y] = sx;
  state[x] = sy;
  return state[(sx + sy) & 0xff];
}

static void k5_arcfour_crypt(ArcfourContext *ctx, unsigned char *dest, 
		     const unsigned char *src, unsigned int len)
{
  unsigned int i;
  for (i = 0; i < len; i++)
    dest[i] = src[i] ^ k5_arcfour_byte(ctx);
}


static krb5_error_code
k5_arcfour_init(ArcfourContext *ctx, const unsigned char *key, 
		  unsigned int key_len)
{
  unsigned int t, u;
  unsigned int keyindex;
  unsigned int stateindex;
  unsigned char* state;
  unsigned int counter;

  if (key_len != 16)
    return KRB5_BAD_MSIZE;     /*this is probably not the correct error code
				 to return */
  for(counter=0;arcfour_weakkeys[counter].length >0; counter++)
    if (memcmp(key, arcfour_weakkeys[counter].data,
	       arcfour_weakkeys[counter].length) == 0)
      return KRB5DES_WEAK_KEY; /* most certainly not the correct error */

  state = &ctx->state[0];
  ctx->x = 0;
  ctx->y = 0;
  for (counter = 0; counter < 256; counter++)
    state[counter] = counter;
  keyindex = 0;
  stateindex = 0;
  for (counter = 0; counter < 256; counter++)
    {
      t = state[counter];
      stateindex = (stateindex + key[keyindex] + t) & 0xff;
      u = state[stateindex];
      state[stateindex] = t;
      state[counter] = u;
      if (++keyindex >= key_len)
	keyindex = 0;
    }
  return 0;
}


/* The workhorse of the arcfour system, this impliments the cipher */
static krb5_error_code
k5_arcfour_docrypt(const krb5_keyblock *key, const krb5_data *state,
	       const krb5_data *input, krb5_data *output)
{
  ArcfourContext *arcfour_ctx;
  ArcFourCipherState *cipher_state;
  int ret;

  if (key->length != 16)
    return(KRB5_BAD_KEYSIZE);
  if (state && (state->length != sizeof (ArcFourCipherState)))
    return(KRB5_BAD_MSIZE);
  if (input->length != output->length)
    return(KRB5_BAD_MSIZE);

  if (state) {
    cipher_state = (ArcFourCipherState *) state->data;
    arcfour_ctx=&cipher_state->ctx;
    if (cipher_state->initialized == 0) {
      if ((ret=k5_arcfour_init(arcfour_ctx, key->contents, key->length))) {
	return ret;
      }
      cipher_state->initialized = 1;
    }
    k5_arcfour_crypt(arcfour_ctx, (unsigned char *) output->data, (const unsigned char *) input->data, input->length);
  }
  else {
    arcfour_ctx=malloc(sizeof (ArcfourContext));
    if (arcfour_ctx == NULL)
      return ENOMEM;
    if ((ret=k5_arcfour_init(arcfour_ctx, key->contents, key->length))) {
      free(arcfour_ctx);
      return (ret);
    }
    k5_arcfour_crypt(arcfour_ctx, (unsigned char * ) output->data,
		     (const unsigned char * ) input->data, input->length);
    memset(arcfour_ctx, 0, sizeof (ArcfourContext));
    free(arcfour_ctx);
  }
  
  return 0;
}

static krb5_error_code
k5_arcfour_make_key(const krb5_data *randombits, krb5_keyblock *key)
{
    if (key->length != 16)
	return(KRB5_BAD_KEYSIZE);
    if (randombits->length != 16)
	return(KRB5_CRYPTO_INTERNAL);

    key->magic = KV5M_KEYBLOCK;
    key->length = 16;

    memcpy(key->contents, randombits->data, randombits->length);

    return(0);
}

static krb5_error_code
k5_arcfour_init_state (const krb5_keyblock *key,
		       krb5_keyusage keyusage, krb5_data *new_state)
{
  /* Note that we can't actually set up the state here  because the key
   * will change  between now and when encrypt is called
   * because  it is data dependent.  Yeah, this has strange
   * properties. --SDH
   */
  new_state->length = sizeof (ArcFourCipherState);
  new_state->data = malloc (new_state->length);
  if (new_state->data) {
    memset (new_state->data, 0 , new_state->length);
    /* That will set initialized to zero*/
  }else {
    return (ENOMEM);
  }
  return 0;
}

/* Since the arcfour cipher is identical going forwards and backwards, 
   we just call "docrypt" directly
*/
const struct krb5_enc_provider krb5int_enc_arcfour = {
    /* This seems to work... although I am not sure what the
       implications are in other places in the kerberos library */
    1,
    /* Keysize is arbitrary in arcfour, but the constraints of the
       system, and to attempt to work with the MSFT system forces us
       to 16byte/128bit.  Since there is no parity in the key, the
       byte and length are the same.  */
    16, 16,
    k5_arcfour_docrypt,
    k5_arcfour_docrypt,
    k5_arcfour_make_key,
    k5_arcfour_init_state, /*xxx not implemented yet*/
    krb5int_default_free_state
};

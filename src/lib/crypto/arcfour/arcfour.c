/*

ARCFOUR cipher (based on a cipher posted on the Usenet in Spring-95).
This cipher is widely believed and has been tested to be equivalent
with the RC4 cipher from RSA Data Security, Inc.  (RC4 is a trademark
of RSA Data Security)

*/
#include "k5-int.h"
#include "arcfour-int.h"
const unsigned char *l40 = "fortybits";

void
krb5_arcfour_encrypt_length(enc, hash, inputlen, length)
     krb5_const struct krb5_enc_provider *enc;
     krb5_const struct krb5_hash_provider *hash;
     size_t inputlen;
     size_t *length;
{
  size_t blocksize, hashsize;

  (*(enc->block_size))(&blocksize);
  (*(hash->hash_size))(&hashsize);


  /* checksum + (confounder + inputlen, in even blocksize) */
  *length = hashsize + krb5_roundup(8 + inputlen, blocksize);
}

static krb5_keyusage arcfour_translate_usage(krb5_keyusage usage)
{
  return usage;
}

krb5_error_code
krb5_arcfour_encrypt(enc, hash, key, usage, ivec, input, output)
     krb5_const struct krb5_enc_provider *enc;
     krb5_const struct krb5_hash_provider *hash;
     krb5_const krb5_keyblock *key;
     krb5_keyusage usage;
     krb5_const krb5_data *ivec;
     krb5_const krb5_data *input;
     krb5_data *output;
{
  krb5_keyblock k1, k2, k3;
  krb5_data d1, d2, d3, salt, plaintext, checksum, ciphertext, confounder;
  krb5_keyusage ms_usage;
  size_t keylength, keybytes, blocksize, hashsize;
  krb5_error_code ret;

  (*(enc->block_size))(&blocksize);
  (*(enc->keysize))(&keybytes, &keylength);
  (*(hash->hash_size))(&hashsize);
  
  d1.length=keybytes;
  d1.data=malloc(d1.length);
  if (d1.data == NULL)
    return (ENOMEM);
  memcpy(&k1, key, sizeof (krb5_keyblock));
  k1.length=d1.length;
  k1.contents=d1.data;

  d2.length=keybytes;
  d2.data=malloc(d2.length);
  if (d2.data == NULL) {
    free(d1.data);
    return (ENOMEM);
  }
  memcpy(&k2, key, sizeof (krb5_keyblock));
  k2.length=d2.length;
  k2.contents=d2.data;

  d3.length=keybytes;
  d3.data=malloc(d3.length);
  if (d3.data == NULL) {
    free(d1.data);
    free(d2.data);
    return (ENOMEM);
  }
  memcpy(&k3, key, sizeof (krb5_keyblock));
  k3.length=d3.length;
  k3.contents=d3.data;
  
  salt.length=14;
  salt.data=malloc(salt.length);
  if (salt.data == NULL) {
    free(d1.data);
    free(d2.data);
    free(d3.data);
    return (ENOMEM);
  }

  /* is "input" already blocksize aligned?  if it is, then we need this
     step, otherwise we do not */
  plaintext.length=krb5_roundup(input->length+CONFOUNDERLENGTH,blocksize);
  plaintext.data=malloc(plaintext.length);
  if (plaintext.data == NULL) {
    free(d1.data);
    free(d2.data);
    free(d3.data);
    free(salt.data);
    return(ENOMEM);
  }

  /* setup convienient pointers into the allocated data */
  checksum.length=hashsize;
  checksum.data=output->data;
  ciphertext.length=krb5_roundup(input->length+CONFOUNDERLENGTH,blocksize);
  ciphertext.data=output->data+hashsize;
  confounder.length=CONFOUNDERLENGTH;
  confounder.data=plaintext.data;
  
  /* begin the encryption, computer K1 */
  ms_usage=arcfour_translate_usage(usage);
  if (key->enctype == ENCTYPE_ARCFOUR_HMAC_EXP) {
    strncpy(salt.data, l40, salt.length);
    salt.data[10]=ms_usage & 0xff;
    salt.data[11]=(ms_usage >> 8) & 0xff;
    salt.data[12]=(ms_usage >> 16) & 0xff;
    salt.data[13]=(ms_usage >> 24) & 0xff;
  } else {
    salt.length=4;
    salt.data[0]=ms_usage & 0xff;
    salt.data[1]=(ms_usage >> 8) & 0xff;
    salt.data[2]=(ms_usage >> 16) & 0xff;
    salt.data[3]=(ms_usage >> 24) & 0xff;
  }
  krb5_hmac(hash, key, 1, &salt, &d1);

  memcpy(k2.contents, k1.contents, k2.length);

  if (key->enctype==ENCTYPE_ARCFOUR_HMAC)
    memset(k1.contents+7, 0xab, 9);

  ret=krb5_c_random_make_octets(/* XXX */ 0, &confounder);
  memcpy(plaintext.data+confounder.length, input->data, input->length);
  if (ret)
    goto cleanup;

  krb5_hmac(hash, &k2, 1, &plaintext, &checksum);

  krb5_hmac(hash, &k1, 1, &checksum, &d3);

  ret=(*(enc->encrypt))(&k3, ivec, &plaintext, &ciphertext);
    
 cleanup:
  memset(d1.data, 0, d1.length);
  memset(d2.data, 0, d2.length);
  memset(d3.data, 0, d3.length);
  memset(salt.data, 0, salt.length);
  memset(plaintext.data, 0, plaintext.length);

  free(d1.data);
  free(d2.data);
  free(d3.data);
  free(salt.data);
  free(plaintext.data);
  return (ret);
}

/* This is the arcfour-hmac decryption routine */
krb5_error_code
krb5_arcfour_decrypt(enc, hash, key, usage, ivec, input, output)
     krb5_const struct krb5_enc_provider *enc;
     krb5_const struct krb5_hash_provider *hash;
     krb5_const krb5_keyblock *key;
     krb5_keyusage usage;
     krb5_const krb5_data *ivec;
     krb5_const krb5_data *input;
     krb5_data *output;
{
  krb5_keyblock k1,k2,k3;
  krb5_data d1,d2,d3,salt,ciphertext,plaintext,checksum;
  krb5_keyusage ms_usage;
  size_t keybytes, keylength, hashsize, blocksize;
  krb5_error_code ret;

  (*(enc->block_size))(&blocksize);
  (*(enc->keysize))(&keybytes, &keylength);
  (*(hash->hash_size))(&hashsize);

  d1.length=keybytes;
  d1.data=malloc(d1.length);
  if (d1.data == NULL)
    return (ENOMEM);
  memcpy(&k1, key, sizeof (krb5_keyblock));
  k1.length=d1.length;
  k1.contents=d1.data;
  
  d2.length=keybytes;
  d2.data=malloc(d2.length);
  if (d2.data == NULL) {
    free(d1.data);
    return (ENOMEM);
  }
  memcpy(&k2, key, sizeof(krb5_keyblock));
  k2.length=d2.length;
  k2.contents=d2.data;

  d3.length=keybytes;
  d3.data=malloc(d3.length);
  if  (d3.data == NULL) {
    free(d1.data);
    free(d2.data);
    return (ENOMEM);
  }
  memcpy(&k3, key, sizeof(krb5_keyblock));
  k3.length=d3.length;
  k3.contents=d3.data;

  salt.length=14;
  salt.data=malloc(salt.length);
  if(salt.data==NULL) {
    free(d1.data);
    free(d2.data);
    free(d3.data);
  }

  ciphertext.length=input->length-hashsize;
  ciphertext.data=input->data+hashsize;
  plaintext.length=ciphertext.length;
  plaintext.data=malloc(plaintext.length);
  if (plaintext.data == NULL) {
    free(d1.data);
    free(d2.data);
    free(d3.data);
    free(salt.data);
  }

  checksum.length=hashsize;
  checksum.data=input->data;

  /* compute the salt */
  ms_usage=arcfour_translate_usage(usage);
  if (key->enctype == ENCTYPE_ARCFOUR_HMAC_EXP) {
    strncpy(salt.data, l40, salt.length);
    salt.data[10]=ms_usage & 0xff;
    salt.data[11]=(ms_usage>>8) & 0xff;
    salt.data[12]=(ms_usage>>16) & 0xff;
    salt.data[13]=(ms_usage>>24) & 0xff;
  } else {
    salt.length=4;
    salt.data[0]=ms_usage & 0xff;
    salt.data[1]=(ms_usage>>8) & 0xff;
    salt.data[2]=(ms_usage>>16) & 0xff;
    salt.data[3]=(ms_usage>>24) & 0xff;
  }
  ret=krb5_hmac(hash, key, 1, &salt, &d1);
  if (ret)
    goto cleanup;

  memcpy(k2.contents, k1.contents, k2.length);

  if (key->enctype == ENCTYPE_ARCFOUR_HMAC_EXP)
    memset(k1.contents+7, 0xab, 9);
  
  ret = krb5_hmac(hash, &k1, 1, &checksum, &d3);
  if (ret)
    goto cleanup;

  ret=(*(enc->decrypt))(&k3, ivec, &ciphertext, &plaintext);
  if (ret)
    goto cleanup;

  ret=krb5_hmac(hash, &k2, 1, &plaintext, &d1);
  if (ret)
    goto cleanup;

  if (memcmp(checksum.data, d1.data, hashsize) != 0) {
    ret=KRB5KRB_AP_ERR_BAD_INTEGRITY;
    goto cleanup;
  }

  memcpy(output->data, plaintext.data+CONFOUNDERLENGTH,
	 (plaintext.length-CONFOUNDERLENGTH));
  output->length=plaintext.length-CONFOUNDERLENGTH;

 cleanup:
  memset(d1.data, 0, d1.length);
  memset(d2.data, 0, d2.length);
  memset(d3.data, 0, d2.length);
  memset(salt.data, 0, salt.length);
  memset(plaintext.data, 0, plaintext.length);

  free(d1.data);
  free(d2.data);
  free(d3.data);
  free(salt.data);
  free(plaintext.data);
  return (ret);
}

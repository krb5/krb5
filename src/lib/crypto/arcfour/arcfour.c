/*

ARCFOUR cipher (based on a cipher posted on the Usenet in Spring-95).
This cipher is widely believed and has been tested to be equivalent
with the RC4 cipher from RSA Data Security, Inc.  (RC4 is a trademark
of RSA Data Security)

*/
#include "k5-int.h"
#include "arcfour-int.h"
static const char *const l40 = "fortybits";

void
krb5_arcfour_encrypt_length(const struct krb5_enc_provider *enc,
			    const struct krb5_hash_provider *hash,
			    size_t inputlen, size_t *length)
{
  size_t blocksize, hashsize;

  blocksize = enc->block_size;
  hashsize = hash->hashsize;

  /* checksum + (confounder + inputlen, in even blocksize) */
  *length = hashsize + krb5_roundup(8 + inputlen, blocksize);
}

 krb5_keyusage
 krb5int_arcfour_translate_usage(krb5_keyusage usage)
{
  switch (usage) {
  case 1:			/* AS-REQ PA-ENC-TIMESTAMP padata timestamp,  */
    return 1;
  case 2:			/* ticket from kdc */
    return 2;
  case 3:			/* as-rep encrypted part */
    return 8;
  case 4:			/* tgs-req authz data */
    return 4;
  case 5:			/* tgs-req authz data in subkey */
    return 5;
  case 6:			/* tgs-req authenticator cksum */
    return 6;			
case 7:				/* tgs-req authenticator */
  return 7;
    case 8:
    return 8;
  case 9:			/* tgs-rep encrypted with subkey */
    return 8;
  case 10:			/* ap-rep authentication cksum */
    return 10;			/* xxx  Microsoft never uses this*/
  case 11:			/* app-req authenticator */
    return 11;
  case 12:			/* app-rep encrypted part */
    return 12;
  case 23: /* sign wrap token*/
    return 13;
  default:
      return usage;
}
}

krb5_error_code
krb5_arcfour_encrypt(const struct krb5_enc_provider *enc,
		     const struct krb5_hash_provider *hash,
		     const krb5_keyblock *key, krb5_keyusage usage,
		     const krb5_data *ivec, const krb5_data *input,
		     krb5_data *output)
{
  krb5_keyblock k1, k2, k3;
  krb5_data d1, d2, d3, salt, plaintext, checksum, ciphertext, confounder;
  krb5_keyusage ms_usage;
  size_t keylength, keybytes, blocksize, hashsize;
  krb5_error_code ret;

  blocksize = enc->block_size;
  keybytes = enc->keybytes;
  keylength = enc->keylength;
  hashsize = hash->hashsize;
  
  d1.length=keybytes;
  d1.data=malloc(d1.length);
  if (d1.data == NULL)
    return (ENOMEM);
  memcpy(&k1, key, sizeof (krb5_keyblock));
  k1.length=d1.length;
  k1.contents= (void *) d1.data;

  d2.length=keybytes;
  d2.data=malloc(d2.length);
  if (d2.data == NULL) {
    free(d1.data);
    return (ENOMEM);
  }
  memcpy(&k2, key, sizeof (krb5_keyblock));
  k2.length=d2.length;
  k2.contents=(void *) d2.data;

  d3.length=keybytes;
  d3.data=malloc(d3.length);
  if (d3.data == NULL) {
    free(d1.data);
    free(d2.data);
    return (ENOMEM);
  }
  memcpy(&k3, key, sizeof (krb5_keyblock));
  k3.length=d3.length;
  k3.contents= (void *) d3.data;
  
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
  output->length = plaintext.length+hashsize;
  
  /* begin the encryption, computer K1 */
  ms_usage=krb5int_arcfour_translate_usage(usage);
  if (key->enctype == ENCTYPE_ARCFOUR_HMAC_EXP) {
    strncpy(salt.data, l40, salt.length);
    store_32_le(ms_usage, salt.data+10);
  } else {
    salt.length=4;
    store_32_le(ms_usage, salt.data);
  }
  krb5_hmac(hash, key, 1, &salt, &d1);

  memcpy(k2.contents, k1.contents, k2.length);

  if (key->enctype==ENCTYPE_ARCFOUR_HMAC_EXP)
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
krb5_arcfour_decrypt(const struct krb5_enc_provider *enc,
		     const struct krb5_hash_provider *hash,
		     const krb5_keyblock *key, krb5_keyusage usage,
		     const krb5_data *ivec, const krb5_data *input,
		     krb5_data *output)
{
  krb5_keyblock k1,k2,k3;
  krb5_data d1,d2,d3,salt,ciphertext,plaintext,checksum;
  krb5_keyusage ms_usage;
  size_t keybytes, keylength, hashsize, blocksize;
  krb5_error_code ret;

  blocksize = enc->block_size;
  keybytes = enc->keybytes;
  keylength = enc->keylength;
  hashsize = hash->hashsize;

  d1.length=keybytes;
  d1.data=malloc(d1.length);
  if (d1.data == NULL)
    return (ENOMEM);
  memcpy(&k1, key, sizeof (krb5_keyblock));
  k1.length=d1.length;
  k1.contents= (void *) d1.data;
  
  d2.length=keybytes;
  d2.data=malloc(d2.length);
  if (d2.data == NULL) {
    free(d1.data);
    return (ENOMEM);
  }
  memcpy(&k2, key, sizeof(krb5_keyblock));
  k2.length=d2.length;
  k2.contents= (void *) d2.data;

  d3.length=keybytes;
  d3.data=malloc(d3.length);
  if  (d3.data == NULL) {
    free(d1.data);
    free(d2.data);
    return (ENOMEM);
  }
  memcpy(&k3, key, sizeof(krb5_keyblock));
  k3.length=d3.length;
  k3.contents= (void *) d3.data;

  salt.length=14;
  salt.data=malloc(salt.length);
  if(salt.data==NULL) {
    free(d1.data);
    free(d2.data);
    free(d3.data);
    return (ENOMEM);
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
    return (ENOMEM);
  }

  checksum.length=hashsize;
  checksum.data=input->data;

  /* compute the salt */
  ms_usage=krb5int_arcfour_translate_usage(usage);
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


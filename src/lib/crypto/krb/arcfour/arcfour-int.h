/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*

  ARCFOUR cipher (based on a cipher posted on the Usenet in Spring-95).
  This cipher is widely believed and has been tested to be equivalent
  with the RC4 cipher from RSA Data Security, Inc.  (RC4 is a trademark
  of RSA Data Security)

*/
#ifndef ARCFOUR_INT_H
#define ARCFOUR_INT_H

#include "arcfour.h"

#define CONFOUNDERLENGTH 8

krb5_keyusage
krb5int_arcfour_translate_usage(krb5_keyusage usage);

krb5_error_code
krb5int_arcfour_usage_key(const struct krb5_enc_provider *enc,
                          const struct krb5_hash_provider *hash,
                          const krb5_keyblock *session_keyblock,
                          krb5_keyusage usage,
                          krb5_keyblock *out);

krb5_error_code
krb5int_arcfour_enc_key(const struct krb5_enc_provider *enc,
                        const struct krb5_hash_provider *hash,
                        const krb5_keyblock *usage_keyblock,
                        const krb5_data *checksum, krb5_keyblock *out);

#endif /* ARCFOUR_INT_H */

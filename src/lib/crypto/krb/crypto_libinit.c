/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include <assert.h>
#include "k5-int.h"

// MAKE_INIT_FUNCTION(cryptoint_initialize_library);
// MAKE_FINI_FUNCTION(cryptoint_cleanup_library);

extern int krb5int_prng_init(krb5_context);
extern void krb5int_prng_cleanup (krb5_context);

/*
 * Initialize the crypto library.
 */

int cryptoint_initialize_library (krb5_context ctx)
{
    return krb5int_prng_init(ctx);
}

int krb5int_crypto_init(krb5_context ctx)
{
  //  return CALL_INIT_FUNCTION(cryptoint_initialize_library);
return  cryptoint_initialize_library ( ctx);
}

/*
 * Clean up the crypto library state
 */

void cryptoint_cleanup_library (krb5_context ctx)
{
// ??? temp ???    if (!INITIALIZER_RAN(cryptoint_initialize_library))
//        return;
    krb5int_prng_cleanup (ctx);
}

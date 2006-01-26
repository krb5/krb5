#include <assert.h>
#include "k5-int.h"

MAKE_INIT_FUNCTION(cryptoint_initialize_library);
MAKE_FINI_FUNCTION(cryptoint_cleanup_library);

extern int krb5int_prng_init(void);
extern void krb5int_prng_cleanup (void);

/*
 * Initialize the crypto library.
 */

int cryptoint_initialize_library (void)
{
    return krb5int_prng_init();
}

int krb5int_crypto_init(void)
{
    return CALL_INIT_FUNCTION(cryptoint_initialize_library);
}

/*
 * Clean up the crypto library state
 */

void cryptoint_cleanup_library (void)
{
    if (!INITIALIZER_RAN(cryptoint_initialize_library))
	return;
    krb5int_prng_cleanup ();
}

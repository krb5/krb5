#include <assert.h>
#include "crypto_libinit.h"
/* get prng_cleanup decl */
#include "k5-int.h"

static	int		initialized = 0;

extern void prng_cleanup (void);

/*
 * Initialize the crypto library.
 */

int cryptoint_initialize_library (void)
{
	
	if (!initialized) {
		initialized = 1;
	}
	
	return 0;
}

/*
 * Clean up the crypto library state
 */

void cryptoint_cleanup_library (void)
{
	assert (initialized);
	
	krb5int_prng_cleanup ();
	
	initialized = 0;
}

#include <assert.h>

static	int		initialized = 0;

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
	
	prng_cleanup ();
	
	initialized = 0;
}

#include <assert.h>

static	int		initialized = false;

/*
 * Initialize the crypto library.
 */

int cryptoint_initialize_library (void)
{
	
	if (!initialized) {
		initialized = true;
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
	
	initialized = false;
}
#include <assert.h>

#include "gssapi_err_generic.h"
#include "gssapi_err_krb5.h"
#include "gssapiP_krb5.h"

#include "gss_libinit.h"
#include "k5-platform.h"

static	int		initialized = 0;

/*
 * Initialize the GSSAPI library.
 */

MAKE_INIT_FUNCTION(gssint_lib_init);
MAKE_FINI_FUNCTION(gssint_lib_fini);

int gssint_lib_init(void)
{
    return k5_mutex_finish_init(&kg_vdb.mutex);
}

void gssint_lib_fini(void)
{
    if (!INITIALIZER_RAN(gssint_lib_init) || PROGRAM_EXITING())
	return;
    k5_mutex_destroy(&kg_vdb.mutex);
}

OM_uint32 gssint_initialize_library (void)
{
	if (!initialized) {
#if !USE_BUNDLE_ERROR_STRINGS
	    add_error_table(&et_k5g_error_table);
	    add_error_table(&et_ggss_error_table);
#endif

	    initialized = 1;
	}

	return CALL_INIT_FUNCTION(gssint_lib_init);
}

/*
 * Clean up the Kerberos v5 lirbary state
 */

void gssint_cleanup_library (void)
{
	assert (initialized);

#if !USE_BUNDLE_ERROR_STRINGS
	remove_error_table(&et_k5g_error_table);
	remove_error_table(&et_ggss_error_table);
#endif

	initialized = 0;
}

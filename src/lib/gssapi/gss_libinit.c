#include <assert.h>

#include "gssapi_err_generic.h"
#include "gssapi_err_krb5.h"

#include "gss_libinit.h"

static	int		initialized = false;

/*
 * Initialize the GSSAPI library.
 */

OM_uint32 gssint_initialize_library (void)
{
	
	if (!initialized) {
	    add_error_table(&et_k5g_error_table);
	    add_error_table(&et_ggss_error_table);

		initialized = true;
	}
	
	return 0;
}

/*
 * Clean up the Kerberos v5 lirbary state
 */

void gssint_cleanup_library (void)
{
	OM_uint32 maj_stat, min_stat;

	assert (initialized);
	
	maj_stat = kg_release_defcred (&min_stat);
	
    remove_error_table(&et_k5g_error_table);
    remove_error_table(&et_ggss_error_table);
	
	initialized = false;
}
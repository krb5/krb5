#include <assert.h>

#include "krb5.h"
#include "krb5_err.h"
#include "kv5m_err.h"
#include "asn1_err.h"
#include "kdb5_err.h"

static	int		initialized = 0;

/*
 * Initialize the Kerberos v5 library.
 */

krb5_error_code krb5int_initialize_library (void)
{
	
	if (!initialized) {
	    add_error_table(&et_krb5_error_table);
	    add_error_table(&et_kv5m_error_table);
	    add_error_table(&et_kdb5_error_table);
	    add_error_table(&et_asn1_error_table);

		initialized = 1;
	}
	
	return 0;
}

/*
 * Clean up the Kerberos v5 lirbary state
 */

void krb5int_cleanup_library (void)
{
	assert (initialized);
	
	krb5_stdcc_shutdown();
	
    remove_error_table(&et_krb5_error_table);
    remove_error_table(&et_kv5m_error_table);
    remove_error_table(&et_kdb5_error_table);
    remove_error_table(&et_asn1_error_table);
	
	initialized = 0;
}

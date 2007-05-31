#include <stdio.h>
#include <limits.h>
#include <Kerberos/Kerberos.h>

#include "test_ccapi_check.h"
#include "test_ccapi_constants.h"
#include "test_ccapi_context.h"
#include "test_ccapi_ccache.h"

int main (int argc, const char * argv[]) {
    
	cc_int32 err = ccNoError;
//	cc_ccache_iterator_t cache_iterator = NULL;
//	cc_credentials_iterator_t cred_iterator = NULL;
	
	fprintf(stdout, "Testing CCAPI against CCAPI v3 rev 8 documentation...\n");
	fprintf(stdout, "Warning: this test suite is woefully incomplete and unpolished.\n");
	
	T_CCAPI_INIT;
	
	err = check_constants();
	
	// *** cc_context ***
	err = check_cc_initialize();
	err = check_cc_context_get_version();
	err = check_cc_context_release();
	err = check_cc_context_get_change_time();
	err = check_cc_context_get_default_ccache_name();
	err = check_cc_context_open_ccache();
	err = check_cc_context_open_default_ccache();
	err = check_cc_context_create_ccache();
	err = check_cc_context_create_default_ccache();
	err = check_cc_context_create_new_ccache();
	err = check_cc_context_new_ccache_iterator();
	// err = check_cc_context_lock();
	// err = check_cc_context_unlock();
	err = check_cc_context_compare();
	
	// *** cc_ccache ***
	err = check_cc_ccache_release();
	err = check_cc_ccache_destroy();
	err = check_cc_ccache_set_default();
	err = check_cc_ccache_get_credentials_version();
	err = check_cc_ccache_get_name();
	err = check_cc_ccache_get_principal();
	err = check_cc_ccache_set_principal();
	err = check_cc_ccache_store_credentials();
	err = check_cc_ccache_remove_credentials();
	err = check_cc_ccache_new_credentials_iterator();
	// err = check_cc_ccache_lock();
	// err = check_cc_ccache_unlock();
	err = check_cc_ccache_get_change_time();
	err = check_cc_ccache_get_last_default_time();
	err = check_cc_ccache_move();
	err = check_cc_ccache_compare();
	err = check_cc_ccache_get_kdc_time_offset();
	err = check_cc_ccache_set_kdc_time_offset();
	err = check_cc_ccache_clear_kdc_time_offset();
	
	// *** cc_ccache_iterator ***
	err = check_cc_ccache_iterator_next();
	
	// *** cc_credentials_iterator ***
	err = check_cc_credentials_iterator_next();
	
	fprintf(stdout, "\nFinished testing CCAPI. %d failure%s in total.\n", total_failure_count, (total_failure_count == 1) ? "" : "s");
	
    return err;
}

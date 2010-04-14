/*
 * plugin_prng.h
 *
 */

#ifndef PLUGIN_PRNG_H_
#define PLUGIN_PRNG_H_

#include <plugin_manager.h>
#include <k5-int.h>

/* PRNG API */
typedef struct {
	int version;
	krb5_error_code (*prng_seed)(krb5_context, unsigned int, const krb5_data*);
	krb5_error_code (*prng_os_seed)(krb5_context, int, int*);
	krb5_error_code (*prng_rand)(krb5_context, krb5_data*);
	krb5_error_code (*prng_init)(void);
	void (*prng_cleanup)(void);
} plugin_prng;

/* Utility functions */
krb5_error_code plugin_prng_seed(plhandle handle, krb5_context context, unsigned int randsource,
                          const krb5_data *data); 
krb5_error_code plugin_prng_os_seed(plhandle handle, krb5_context context, int strong, int *success);
krb5_error_code plugin_prng_rand(plhandle handle, krb5_context context, krb5_data *data);

krb5_error_code plugin_prng_init(plhandle handle);
void plugin_prng_cleanup(plhandle handle);

#endif /* PLUGIN_PRNG_H_ */

/*
 * plugins.c
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "plugin_prng.h"

static krb5_error_code
_plugin_prng_os_seed(krb5_context context, int strong, int *success)
{
    return 0;
}
static krb5_error_code
_plugin_prng_seed(krb5_context context, unsigned int randsource,
                          const krb5_data *data)
{
    long seed = (long)data->data;
	printf("seeding prng...\n");
	srand(seed);
    return 0;
}

static krb5_error_code
_plugin_prng_rand(krb5_context context, krb5_data *data)
{
	int number = rand();
	printf("generating random number...\n");
        memcpy(data->data, &number, data->length);
	return 0;
}

static void
_plugin_prng_cleanup(plugin_prng* api)
{
    return;
/*	if (api != NULL) {
		free(api);
	}
*/
}

static krb5_error_code
_plugin_prng_init(void)
{
     return 0;
}


plhandle 
plugin_simple_prng_create()
{
	plhandle handle;
	plugin_prng* api = malloc(sizeof(plugin_prng));

	memset(api, 0, sizeof(plugin_prng));
	api->version = 0;
	api->prng_rand = _plugin_prng_rand;
	api->prng_seed = _plugin_prng_seed;
        api->prng_os_seed = _plugin_prng_os_seed;
        api->prng_init = _plugin_prng_init;
        api->prng_cleanup = _plugin_prng_cleanup;
	handle.api = api;

	return handle;
}

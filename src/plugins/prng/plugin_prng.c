/*
 * plugin_prng.c
 *
 */
#include <plugin_manager.h>
#include "plugin_prng.h"

krb5_error_code
plugin_prng_seed(plhandle handle, krb5_context context, unsigned int randsource,
                          const krb5_data *data)
{
    plugin_prng* api = (plugin_prng*) handle.api;
    api->prng_seed(context, randsource, data);
    return 0;
}

krb5_error_code
plugin_prng_os_seed(plhandle handle, krb5_context context, int strong, int *success)
{
    plugin_prng* api = (plugin_prng*) handle.api;
    api->prng_os_seed(context, strong, success);
    return 0;
}

krb5_error_code
plugin_prng_rand(plhandle handle, krb5_context context, krb5_data *data)
{
    plugin_prng* api = (plugin_prng*) handle.api;
    api->prng_rand(context, data);
    return 0;
}

krb5_error_code
plugin_prng_init(plhandle handle)
{
    plugin_prng* api = (plugin_prng*) handle.api;
    api->prng_init();
    return 0;
}

void
plugin_prng_cleanup(plhandle handle)
{
    plugin_prng* api = (plugin_prng*) handle.api;
    api->prng_cleanup();
    return 0;
}

/*
 * plugin_loader.c
 *
 */

#include <string.h>
#include "plugin_loader.h"

krb5_error_code
plugin_loader_create_api (loader_handle handle, const char* plugin_name, plhandle *pl_handle)
{
    plugin_loader* loader = (plugin_loader*) handle.api;
    if (loader != NULL) {
        *pl_handle = loader->create_api(plugin_name);
    }
    return 0;
}

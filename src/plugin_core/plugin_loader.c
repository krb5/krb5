/*
 * plugin_loader.c
 *
 */

#include <string.h>
#include "plugin_loader.h"

void
get_loader_content (loader_handle handle, const char* container[])
{
    plugin_loader* loader = (plugin_loader*) handle.api;
    if (loader != NULL) {
        return loader->get_loader_content(container);
    }
    return;
}

plhandle
create_api (loader_handle handle, const char* plugin_name)
{
    plugin_loader* loader = (plugin_loader*) handle.api;
    if (loader != NULL) {
        return loader->create_api(plugin_name);
    }
    return;
}

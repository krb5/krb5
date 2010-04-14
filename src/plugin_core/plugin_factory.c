/*
 * plugin_factory.c
 *
 */

#include <string.h>
#include "plugin_factory.h"

void
get_factory_content (FactoryHandle handle, const char* container[])
{
	plugin_factory* factory = (plugin_factory*) handle.api;
	factory->get_factory_content(container);
}

plhandle
create_api (FactoryHandle handle, const char* plugin_name)
{
	plugin_factory* factory = (plugin_factory*) handle.api;
	return factory->create_api(plugin_name);
}

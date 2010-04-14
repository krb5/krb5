/*
 * plugin_manager.c
 *
 */
#include "plugin_manager.h"
#include "string.h"


static plugin_manager* _instance = NULL;

void
set_plugin_manager_instance(plugin_manager* manager) {
	_instance = manager;
}

void
plugin_manager_configure(const char* path)
{
	if(_instance != NULL) {
		_instance->configure(_instance->data, path);
	}
}

void plugin_manager_start()
{
	if(_instance != NULL) {
		_instance->start(_instance->data);
	}
}

void plugin_manager_stop()
{
	if(_instance != NULL) {
		_instance->stop(_instance->data);
	}
}

plhandle
plugin_manager_get_service(const char* service_name)
{
	plhandle handle;
	if(_instance != NULL) {
		handle = _instance->getService(_instance->data, service_name);
	} else {
		handle.api = NULL;
	}
	return handle;
}




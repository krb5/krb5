/*
 * plugin_manager.c
 *
 */
#include "plugin_manager.h"
#include <k5-int.h>

void
set_plugin_manager_instance(plugin_manager **_instance, plugin_manager* manager)
{
    *_instance = manager;
}

int
plugin_manager_configure(plugin_manager* _instance,const char* path)
{
    if (_instance != NULL) {
        _instance->configure(_instance->data, path);
    }
    return 0;
}

void plugin_manager_start(plugin_manager* _instance)
{
    if (_instance != NULL) {
        _instance->start(_instance->data);
    }
}

void plugin_manager_stop(plugin_manager* _instance)
{
    if (_instance != NULL) {
        _instance->stop(_instance->data);
    }
}

plhandle
plugin_manager_get_service(plugin_manager* _instance, const char* service_name, const int pl_id)
{
    plhandle handle;
    if (_instance != NULL) {
        handle = _instance->getService(_instance->data, service_name, pl_id);
    } else {
        handle.api = NULL;
    }
    return handle;
}

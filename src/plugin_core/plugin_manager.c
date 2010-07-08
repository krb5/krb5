/*
 * plugin_manager.c
 *
 */
#include "plugin_manager.h"
#include <k5-int.h>

krb5_error_code
plugin_manager_configure(plugin_manager* instance,const char* path)
{
    if (instance != NULL) {
        instance->configure(instance->data, path);
    }
    return 0;
}

krb5_error_code
plugin_manager_start(plugin_manager* instance)
{
    if (instance != NULL) {
        instance->start(instance->data);
    }
    return 0;
}

krb5_error_code
plugin_manager_stop(plugin_manager* instance)
{
    if (instance != NULL) {
        instance->stop(instance->data);
    }
    return 0;
}

krb5_error_code
plugin_manager_get_service(plugin_manager* instance, const char* service_name, const char *pl_id, plhandle *pl_handle)
{
    plhandle handle;
    if (instance != NULL) {
        handle = instance->getService(instance->data, service_name, pl_id);
    } else {
        handle.api = NULL;
    }
    *pl_handle = handle;
    return 0;
}

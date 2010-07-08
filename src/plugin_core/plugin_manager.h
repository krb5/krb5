/*
 * plugin_manager.h
 *
 */

#ifndef PLUGIN_MANAGER_H_
#define PLUGIN_MANAGER_H_

#include <k5-int.h>

krb5_error_code plugin_manager_get_service(plugin_manager* instance,const char*, const char*, plhandle* );
krb5_error_code plugin_manager_configure(plugin_manager* instance,const char*);
krb5_error_code plugin_manager_start(plugin_manager* instance);
krb5_error_code plugin_manager_stop(plugin_manager* instance);

#endif /* PLUGIN_MANAGER_H_ */

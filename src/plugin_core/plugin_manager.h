/*
 * plugin_manager.h
 *
 */

#ifndef PLUGIN_MANAGER_H_
#define PLUGIN_MANAGER_H_

#include <k5-int.h>

plhandle plugin_manager_get_service(plugin_manager* instance,const char*, const int);
int plugin_manager_configure(plugin_manager* instance,const char*);
void plugin_manager_start(plugin_manager* instance);
void plugin_manager_stop(plugin_manager* instance);

#endif /* PLUGIN_MANAGER_H_ */

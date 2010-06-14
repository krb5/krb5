/*
 * plugin_manager.h
 *
 */

#ifndef PLUGIN_MANAGER_H_
#define PLUGIN_MANAGER_H_

#include <k5-int.h>

void set_plugin_manager_instance(plugin_manager** _instance,plugin_manager*);

/* Utility functions */
int plugin_manager_configure(plugin_manager* _instance,const char*);
void plugin_manager_start(plugin_manager* _instance);
void plugin_manager_stop(plugin_manager* _instance);
plhandle plugin_manager_get_service(plugin_manager* _instance,const char*, const int);

#endif /* PLUGIN_MANAGER_H_ */

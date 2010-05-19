/*
 * plugin_manager.h
 *
 */

#ifndef PLUGIN_MANAGER_H_
#define PLUGIN_MANAGER_H_

#include <k5-int.h>

void set_plugin_manager_instance(plugin_manager*);

/* Utility functions */
void plugin_manager_configure(const char*);
void plugin_manager_start();
void plugin_manager_stop();
plhandle plugin_manager_get_service(const char*);

#endif /* PLUGIN_MANAGER_H_ */

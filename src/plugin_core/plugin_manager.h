/*
 * plugin_manager.h
 *
 */

#ifndef PLUGIN_MANAGER_H_
#define PLUGIN_MANAGER_H_

#include <k5-int.h>

typedef struct {
    char api_name[512];
    plhandle* first;
    plhandle* last;
    int size;
} reg_entry;

typedef struct {
    reg_entry* table;
    long registry_size;
    long registry_max_size;
} registry_data;

typedef struct {
    registry_data* registry;
} manager_data;

typedef struct {
	manager_data * data;
	void (*configure)(manager_data *  data, const char*);
	void (*start)(manager_data * data);
	void (*stop)(manager_data * data);
	plhandle (*getService)(manager_data * data, const char*);
} plugin_manager;

void set_plugin_manager_instance(plugin_manager*);

/* Utility functions */
void plugin_manager_configure(const char*);
void plugin_manager_start();
void plugin_manager_stop();
plhandle plugin_manager_get_service(const char*);

#endif /* PLUGIN_MANAGER_H_ */

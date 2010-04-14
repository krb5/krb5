/*
 * plugin_factory.h
 *
 */
#ifndef PLUGIN_FACTORY_H_
#define PLUGIN_FACTORY_H_

#include "plugin_manager.h"

/* Plugin factory API */
typedef struct {
	void *api;
} factory_handle;

typedef struct {
	const char* factory_name;
	factory_handle (*factory_creator)();
} plugin_factory_descr;

typedef struct {
	const char* plugin_name;
	plhandle (*plugin_creator)();
} plugin_descr;

typedef struct {
	void (*get_factory_content)(const char* []);
	plhandle (*create_api)(const char*);
} plugin_factory;

/* Utility functions */
void get_factory_content(factory_handle handle, const char* container[]);
plhandle create_api(factory_handle handle, const char* plugin_name);

#endif /* PLUGIN_FACTORY_H_ */

/*
 * plugin_loader.h
 *
 */
#ifndef PLUGIN_LOADER_H_
#define PLUGIN_LOADER_H_

#include "plugin_manager.h"

/* Plugin loader API */
typedef struct {
	void *api;
} loader_handle;

typedef struct {
	const char* loader_name;
	loader_handle (*loader_creator)();
} plugin_loader_descr;

typedef struct {
	const char* plugin_name;
	plhandle (*plugin_creator)();
} plugin_descr;

typedef struct {
	void (*get_loader_content)(const char* []);
	plhandle (*create_api)(const char*);
} plugin_loader;

krb5_error_code plugin_loader_create_api(loader_handle handle, const char* plugin_name, plhandle *);

#endif /* PLUGIN_LOADER_H_ */

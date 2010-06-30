/*
 * plugin_dyn_loader.c
 *
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <plugin_manager.h>
#include <plugin_loader.h>
#include <plugin_dyn_loader.h>

static plugin_loader* _dyn_loader_instance = NULL;

/* dynamic  plugins */
static plugin_descr  plugin_dyn_loader_table[] = {
        {"plugin_pwd_qlty_DYN",   plugin_pwd_qlty_DYN_create},
        {NULL,NULL}
};

static void
_get_loader_content (const char* container[]) {
    plugin_descr *ptr = NULL;
    int i = 0;
    for( ptr = plugin_dyn_loader_table; ptr->plugin_name != NULL; ptr++,i++) {
        container[i] = ptr->plugin_name;
    }
}

static plhandle
_create_api (const char* plugin_name)
{
    plhandle handle;
    plugin_descr *ptr = NULL;

    memset(&handle, 0, sizeof(handle));
    if(plugin_name){
        handle.api = NULL;
        for( ptr = plugin_dyn_loader_table; ptr->plugin_name != NULL; ptr++) {
            if (strcmp(ptr->plugin_name, plugin_name) == 0) {
                handle = ptr->plugin_creator();
                break;
            }
        }
    }
    return handle;
}


loader_handle
plugin_loader_get_instance()
{
    plugin_loader* instance = _dyn_loader_instance;
    loader_handle handle;

    if(_dyn_loader_instance == NULL) {
        instance = (plugin_loader*) malloc(sizeof(plugin_loader));
        memset(instance, 0, sizeof(plugin_loader));
        instance->get_loader_content = _get_loader_content;
        instance->create_api = _create_api;
        _dyn_loader_instance = instance;
    }
    handle.api = instance;
    return (handle);
}


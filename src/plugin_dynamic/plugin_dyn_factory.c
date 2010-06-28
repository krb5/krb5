/*
 * plugin_dyn_factory.c
 *
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <plugin_manager.h>
#include <plugin_factory.h>
#include <plugin_dyn_factory.h>

static plugin_factory* _dyn_factory_instance = NULL;

/* dynamic  plugins */
static plugin_descr  plugin_dyn_factory_table[] = {
        {"plugin_pwd_qlty_DYN",   plugin_pwd_qlty_DYN_create},
        {NULL,NULL}
};

/* Factory API implementation */
static void
_get_factory_content (const char* container[]) {
    plugin_descr *ptr = NULL;
    int i = 0;
    for( ptr = plugin_dyn_factory_table; ptr->plugin_name != NULL; ptr++,i++) {
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
        for( ptr = plugin_dyn_factory_table; ptr->plugin_name != NULL; ptr++) {
            if (strcmp(ptr->plugin_name, plugin_name) == 0) {
                handle = ptr->plugin_creator();
                break;
            }
        }
    }
    return handle;
}


factory_handle
plugin_factory_get_instance()
{
    plugin_factory* instance = _dyn_factory_instance;
    factory_handle handle;

    if(_dyn_factory_instance == NULL) {
        instance = (plugin_factory*) malloc(sizeof(plugin_factory));
        memset(instance, 0, sizeof(plugin_factory));
        instance->get_factory_content = _get_factory_content;
        instance->create_api = _create_api;
        _dyn_factory_instance = instance;
    }
    handle.api = instance;
    return (handle);
}


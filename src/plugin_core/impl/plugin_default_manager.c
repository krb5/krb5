/*
 * plugin_default_manager.c
 *
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <plugin_manager.h>
#include <plugin_factory.h>
#include "plugin_default_manager.h"
#include "plugin_default_factory.h"
#ifdef CONFIG_IN_YAML
#include "yaml_parser.h"
#else
#include "krb5_parser.h"
#endif


static plugin_manager* _instance = NULL;

static plugin_factory_descr _table[] = {
        {"plugin_default_factory", plugin_default_factory_get_instance},
        {NULL, NULL}
};

static factory_handle
_load_factory (const char* factory_name, const char* factory_type)
{
    factory_handle handle;
    plugin_factory_descr *ptr = NULL;

    handle.api = NULL;
    for( ptr = _table; ptr->factory_name != NULL; ptr++) {
        if (strcmp(ptr->factory_name, factory_name) == 0) {
            handle = ptr->factory_creator();
            break;
        }
    }
    return handle;
}

static registry_data*
_create_registry()
{
    registry_data* registry = (registry_data*) malloc(sizeof(registry_data));
    memset(registry, 0, sizeof(registry_data));

    return registry;
}

static void
_extend_registry (registry_data* data, int ext_n)
{
    if(data->registry_max_size == 0) {
        data->table = NULL;
    }
    data->table = (reg_entry*) realloc(data->table, ext_n * sizeof(reg_entry));
    memset(data->table + data->registry_max_size, 0, ext_n * sizeof(reg_entry));
    data->registry_max_size += ext_n;
}

static reg_entry*
_search_registry (registry_data* data, const char* api_name)
{
    int i = 0;
    reg_entry* ptr = data->table;

    for(i = 0; i < data->registry_size; i++,ptr++) {
        if(strcmp(api_name, ptr->api_name) == 0) {
            return ptr;
        }
    }
    return NULL;
}

static plhandle
_create_api(const char* plugin_name, const char* factory_name,
            const char* factory_type/*, config_node* properties*/)
{
    plhandle p_handle;
    factory_handle f_handle = _load_factory(factory_name, factory_type);
    p_handle = create_api(f_handle, plugin_name);

    return(p_handle);
}

static int
_register_api(registry_data* data, const char* api_name,
              const char* plugin_type, plhandle handle)
{
    const int extension_size = 32;
    reg_entry* entry = NULL;
    plhandle* next;
    int ret = 0;

    if(data->registry_size == data->registry_max_size) {
        _extend_registry(data, extension_size);
    }
    entry = _search_registry(data, api_name);
    if(entry == NULL) {
        entry = data->table + data->registry_size;
        data->registry_size++;
    }
    if(entry->size && strcmp(plugin_type, "service") == 0) {
        //printf("%s is already registered, only one plugin is allowed per service\n", api_name);
        ret = 0;
    } else {
        strcpy(entry->api_name, api_name);
        next = (plhandle*) malloc(sizeof(plhandle));
        memset(next, 0, sizeof(plhandle));
        next->api = handle.api;
        if(entry->first == NULL) {
            entry->first = next;
            entry->last = next;
        } else {
            entry->last->next = next;
            entry->last = next;
        }
        entry->size++;
        ret = 1;
    }
    return ret;
}

#ifdef CONFIG_IN_YAML
static void
_configure_plugin_yaml(manager_data* mdata, config_node* plugin_node)
{
    config_node* p = NULL;
    config_node* properties = NULL;
    const char* plugin_api = NULL;
    const char* factory_name = NULL;
    const char* factory_type = NULL;
    const char* plugin_name = NULL;
    const char* plugin_type = NULL;
    plhandle handle;

    for (p = plugin_node->node_value.seq_value.start; p != NULL; p = p->next) {
        if(strcmp(p->node_name, "api") == 0) {
            plugin_api = p->node_value.str_value;
        } else if(strcmp(p->node_name, "type") == 0) {
            plugin_type = p->node_value.str_value;
        } else if(strcmp(p->node_name, "constructor") == 0) {
            config_node* q = NULL;
            for(q = p->node_value.seq_value.start; q != NULL; q = q->next) {
                if(strcmp(q->node_name, "factory_name") == 0) {
                    factory_name = q->node_value.str_value;
                } else if(strcmp(q->node_name, "factory_type") == 0) {
                    factory_type = q->node_value.str_value;
                } else if(strcmp(q->node_name, "plugin_name") == 0) {
                    plugin_name = q->node_value.str_value;
                }
            }
        } else if(strcmp(p->node_name, "properties") == 0) {
            properties = p;
        }
    }
    /*printf("**Start**\n");
    printf("api=%s\n", plugin_api);
    printf("factory=%s\n", factory_name);
    printf("factory_type=%s\n", factory_type);
    printf("plugin_name=%s\n", plugin_name);
    printf("plugin_type=%s\n", plugin_type);
    printf("**End**\n");
*/
    handle = _create_api(plugin_name, factory_name, factory_type/*, properties*/);
    if(handle.api != NULL) {
        if(!(_register_api(mdata->registry,plugin_api, plugin_type, handle))) {
         /*   printf("Failed to register %s for %s(factory=%s,plugin_type=%s)\n",
                    plugin_name, plugin_api, factory_name, plugin_type);
           */
              exit(1);
        }
    } else {
        /*printf("Failed to configure plugin: api=%s, plugin_name=%s,factory=%s\n",
                plugin_api, plugin_name, factory_name);
*/
    }
    return;
}

/* Plugin API implementation */
static void
_configure_yaml(void* data, const char* path)
{
    manager_data* mdata = (manager_data*) data;
    config_node* stream = NULL;
    config_node* p = NULL;
    stream = parse_file(path);

    for(p = stream->node_value.seq_value.start; p != NULL; p = p->next) {
        config_node* q = NULL;
        for(q = p->node_value.seq_value.start; q != NULL; q = q->next) {
            if(strcmp(q->node_tag,"!Plugin") == 0) {
                _configure_plugin_yaml(mdata, q);
            } else {
                printf("Failed to find plugin configuration\n");
            }
        }
    }
}

#else

/* krb5.conf */

static void
_configure_krb5(void* data, const char* path)
{
    manager_data* mdata = (manager_data*) data;
    krb5_error_code retval;
    char *plugin;
    void *iter;
    profile_filespec_t *files = 0;
    profile_t profile;
    const char  *realm_srv_names[4];
    char **factory_name, **factory_type, **plugin_name, **plugin_type;
    plhandle handle;

    retval = os_get_default_config_files(&files, FALSE); // TRUE - goes to /etc/krb5.conf
    retval = profile_init((const_profile_filespec_t *) files, &profile);
/*    if (files)
        free_filespecs(files);

    if (retval)
        ctx->profile = 0;
*/
    if (retval == ENOENT)
        return; // KRB5_CONFIG_CANTOPEN;


    if ((retval = krb5_plugin_iterator_create(profile, &iter))) {
        com_err("krb5_PLUGIN_iterator_create", retval, 0);
        return;
    }
    while (iter) {
        if ((retval = krb5_plugin_iterator(profile, &iter, &plugin))) {
            com_err("krb5_PLUGIN_iterator", retval, 0);
            krb5_plugin_iterator_free(profile, &iter);
            return;
        }
        if (plugin) {
            printf("PLUGIN: '%s'\n", plugin);
            realm_srv_names[0] = "plugins";
            realm_srv_names[1] = plugin;

            /* plugin_name */
            realm_srv_names[2] = "plugin_name";
            realm_srv_names[3] = 0;

            retval = profile_get_values(profile, realm_srv_names, &plugin_name);

            /* plugin_type */
            realm_srv_names[2] = "plugin_type";
            realm_srv_names[3] = 0;

            retval = profile_get_values(profile, realm_srv_names, &plugin_type);

            /* factory_name */
            realm_srv_names[2] = "plugin_factory_name";
            realm_srv_names[3] = 0;

            retval = profile_get_values(profile, realm_srv_names, &factory_name);

            /* factory_type */
            realm_srv_names[2] = "plugin_factory_type";
            realm_srv_names[3] = 0;

            retval = profile_get_values(profile, realm_srv_names, &factory_type);

            handle = _create_api(*plugin_name, *factory_name, *factory_type/*, properties*/);
            if(handle.api != NULL) {
                if(!(_register_api(mdata->registry,plugin, *plugin_type, handle))) {
                   printf("Failed to register %s for %s(factory=%s,plugin_type=%s)\n",
                            *plugin_name, plugin, *factory_name, *plugin_type);
                    exit(1);
                }
            } else {
                printf("Failed to configure plugin: api=%s, plugin_name=%s,factory=%s\n",
                         plugin, *plugin_name, *factory_name);
            }

            krb5_free_plugin_string(profile, plugin);
        }
    }

}

#endif

static void
_start(void* data)
{
    return;
}

static void
_stop(void* data)
{
    return;
}

static plhandle
_getService(void* data, const char* service_name)
{
    plhandle handle;
    manager_data* mdata = (manager_data*) data;
    reg_entry* entry = _search_registry(mdata->registry, service_name);

    memset(&handle, 0, sizeof handle);
    if(entry) {
        handle = *(entry->first);
    } else {
        printf("service %s is not available\n", service_name);
    }

    return handle;
}

static manager_data*
_init_data()
{
    manager_data* data = (manager_data*) malloc(sizeof(manager_data));
    memset(data, 0, sizeof(manager_data));
    data->registry = _create_registry();

    return data;
}

plugin_manager*
plugin_default_manager_get_instance()
{
    plugin_manager* instance = _instance;

    if(_instance == NULL) {
        instance = (plugin_manager*) malloc(sizeof(plugin_manager));
        memset(instance, 0, sizeof(plugin_manager));
        instance->data = _init_data();
#ifdef CONFIG_IN_YAML
        instance->configure = _configure_yaml;
#else
        instance->configure = _configure_krb5;
#endif
        instance->start = _start;
        instance->stop = _stop;
        instance->getService = _getService;
        _instance = instance;
    }
    return (instance);
}


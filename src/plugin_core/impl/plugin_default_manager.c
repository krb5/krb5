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

static plugin_factory_descr _table[] = {
        {"plugin_default_factory", plugin_default_factory_get_instance},
        {NULL, NULL}
};

static factory_handle
_load_factory (const char* factory_name, const char* factory_type)
{
    factory_handle handle;
    plugin_factory_descr *ptr = NULL;
#ifdef DEBUG_PLUGINS
    printf("plugins:  _load_factory\n");
#endif

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
#ifdef DEBUG_PLUGINS
    printf("plugins:  _create_registry\n");
#endif
    memset(registry, 0, sizeof(registry_data));

    return registry;
}

static void
_extend_registry (registry_data* data, int ext_n)
{
#ifdef DEBUG_PLUGINS
    printf("plugins:  _extend_registry\n");
#endif
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

#ifdef DEBUG_PLUGINS
    printf("plugins:  _search_registry\n");
#endif
    for(i = 0; i < data->registry_size; i++,ptr++) {
        if(strcmp(api_name, ptr->api_name) == 0) {
            return ptr;
        }
    }
    return NULL;
}

static plhandle
_create_api(const char* plugin_name, const char* factory_name,
            const char* factory_type, const char* plugin_id /*, config_node* properties*/)
{
    plhandle p_handle;
    factory_handle f_handle = _load_factory(factory_name, factory_type);
#ifdef DEBUG_PLUGINS
    printf("plugins:  _create_api\n");
#endif
    p_handle = create_api(f_handle, plugin_name);
    p_handle.plugin_id = atoi(plugin_id);

    return(p_handle);
}

#define API_REGISTER_OK 	0
#define API_REGISTER_FAILED 	1
#define API_ALREADY_REGISTERED 	2

/* _register_api - returns API_REGISTER_OK on success,
 *                         API_REGISTER_FAILED - on failure,
 *                         API_ALREADY_REGISTERED if api is already registered
 */
static int
_register_api(registry_data* data, const char* api_name,
              const char* plugin_type, plhandle handle)
{
    const int extension_size = 32;
    reg_entry* entry = NULL;
    plhandle* next;
    int ret = API_REGISTER_FAILED;

    if(data->registry_size == data->registry_max_size) {
        _extend_registry(data, extension_size);
    }

#ifdef DEBUG_PLUGINS
    printf ("plugins: _register_api %s\n", api_name);
#endif

    entry = _search_registry(data, api_name);
    if(entry == NULL) {
        /* Do this in case of a new id only */
        entry = data->table + data->registry_size;
        data->registry_size++;
    }
#if 0
    if(entry->size && strcmp(plugin_type, "service") == 0) {
#ifdef DEBUG_PLUGINS
        printf("%s is already registered, only one plugin is allowed per service\n", api_name);
#endif
        ret = API_ALREADY_REGISTERED;
    } else
#endif
    {
        strcpy(entry->api_name, api_name);
        next = (plhandle*) malloc(sizeof(plhandle));
        memset(next, 0, sizeof(plhandle));
        next->api = handle.api;
        next->plugin_id = handle.plugin_id;
        if(entry->first == NULL) {
            entry->first = next;
            entry->last = next;
        } else {
            entry->last->next = next;
            entry->last = next;
        }
        entry->size++;
        ret = API_REGISTER_OK;
    }
    return ret;
}

#ifdef CONFIG_IN_YAML
static int
_configure_plugin_yaml(manager_data* mdata, config_node* plugin_node)
{
    config_node* p = NULL;
    config_node* properties = NULL;
    const char* plugin_api = NULL;
    const char* factory_name = NULL;
    const char* factory_type = NULL;
    const char* plugin_name = NULL;
    const char* plugin_type = NULL;
    const char* plugin_id = NULL;
    plhandle handle;
    int ret = API_REGISTER_FAILED;

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
                } else if(strcmp(q->node_name, "plugin_id") == 0) {
                    plugin_id = q->node_value.str_value;
                }

            }
        } else if(strcmp(p->node_name, "properties") == 0) {
            properties = p;
        }
    }
#ifdef DEBUG_PLUGINS
    printf("**Start**\n");
    printf("api=%s\n", plugin_api);
    printf("factory=%s\n", factory_name);
    printf("factory_type=%s\n", factory_type);
    printf("plugin_name=%s\n", plugin_name);
    printf("plugin_type=%s\n", plugin_type);
    printf("plugin_id=%s\n", plugin_id);
    printf("**End**\n");
#endif

    handle = _create_api(plugin_name, factory_name, factory_type/*, plugin_id*//*, properties*/);
    if(handle.api != NULL) {
        ret = _register_api(mdata->registry,plugin_api, plugin_type, handle);
        if (ret != API_REGISTER_OK) {
#ifdef DEBUG_PLUGINS
            printf("Failed to register %s for %s(factory=%s,plugin_type=%s)\n",
                    plugin_name, plugin_api, factory_name, plugin_type);
#endif
        }
        else
            printf("SUCCESS to register %s for %s(factory=%s,plugin_type=%s)\n",
                    plugin_name, plugin_api, factory_name, plugin_type);
    } else {
#ifdef DEBUG_PLUGINS
        printf("Failed to configure plugin: api=%s, plugin_name=%s,factory=%s\n",
                plugin_api, plugin_name, factory_name);
#endif
    }
    return ret;
}

/* Plugin API implementation */
static int
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
#ifdef DEBUG_PLUGINS
                printf("Failed to find plugin configuration\n");
#endif
            }
        }
    }
}

#else

/* krb5.conf */

static void
_configure_krb5(manager_data* data, const char* path)
{
    manager_data* mdata = (manager_data*) data;
    krb5_error_code retval;
    char *plugin;
    void *iter;
    int i = 0;
    profile_filespec_t *files = NULL;
    profile_t profile;
    const char  *hierarchy[4];
    char **factory_name, **factory_type, **plugin_name, **plugin_type;
    char** plugin_id;
    char** plugin_api;
    plhandle handle;
    char **pl_list, *pl_l;


    retval = krb5_get_default_config_files(&files);
#if 0
    if (files)
        free_filespecs(files);
    if (retval)
        ctx->profile = 0;
#endif

    if (retval == ENOENT)
        return; // KRB5_CONFIG_CANTOPEN;

    retval = profile_init((const_profile_filespec_t *) files, &profile);
    if (retval == ENOENT)
        return;

    if ((retval = krb5_plugin_iterator_create(profile, &iter))) {
        com_err("krb5_PLUGIN_iterator_create", retval, 0);
        return;
    }
    /* Get the list of the plugins that may be used during run time */
    hierarchy[0] = "plugins";
    hierarchy[1] = "plugin_list";
    hierarchy[2] = 0;
    retval = profile_get_values(profile, hierarchy, &pl_list);
    if (retval){
        com_err("krb5_PLUGIN no plugins listed to configure/register", retval, 0);
        return;
    }

#if 0
    while (iter && pl_list[i]) {
        if ((retval = krb5_plugin_iterator(profile, &iter, &plugin))) {
            com_err("krb5_PLUGIN_iterator", retval, 0);
            krb5_plugin_iterator_free(profile, &iter);
            return;
        }
        if (plugin) {
#endif

    i=0;
    while (pl_l = pl_list[i++]){

#ifdef DEBUG_PLUGINS
        printf("plugins: nickname in conf file: '%s'\n", pl_l);
#endif
        hierarchy[0] = "plugins";
        hierarchy[1] = pl_l;
        //hierarchy[1] = plugin;

        /* plugin_name */
        hierarchy[2] = "plugin_api";
        hierarchy[3] = 0;
        retval = profile_get_values(profile, hierarchy, &plugin_api);

        /* plugin_name */
        hierarchy[2] = "plugin_name";
        hierarchy[3] = 0;
        retval = profile_get_values(profile, hierarchy, &plugin_name);

        /* plugin_type */
        hierarchy[2] = "plugin_type";
        hierarchy[3] = 0;
        retval = profile_get_values(profile, hierarchy, &plugin_type);

        /* plugin_id */
        hierarchy[2] = "plugin_id";
        hierarchy[3] = 0;
        retval = profile_get_values(profile, hierarchy, &plugin_id);

        /* factory_name */
        hierarchy[2] = "plugin_factory_name";
        hierarchy[3] = 0;
        retval = profile_get_values(profile, hierarchy, &factory_name);

        /* factory_type */
        hierarchy[2] = "plugin_factory_type";
        hierarchy[3] = 0;
        retval = profile_get_values(profile, hierarchy, &factory_type);

#ifdef DEBUG_PLUGINS
        printf("plugins:  >>>\n");
        printf("api=%s\n", *plugin_api);
        printf("factory=%s\n", *factory_name);
        printf("factory_type=%s\n", *factory_type);
        printf("plugin_name=%s\n", *plugin_name);
        printf("plugin_type=%s\n",*plugin_type);
        printf("plugin_id=%s\n", *plugin_id);
        printf("<<< plugins\n");
#endif

        handle = _create_api(*plugin_name, *factory_name, *factory_type ,*plugin_id/*, properties*/);
        if(handle.api != NULL) {
            retval = _register_api(mdata->registry,*plugin_api, *plugin_type, handle);
            if(retval != API_REGISTER_OK) {
#ifdef DEBUG_PLUGINS
                printf("plugins: Failed to register %s for %s(factory=%s,plugin_type=%s) ret=%i\n",
                       *plugin_name, *plugin_api, *factory_name, *plugin_type, retval);
#endif
            } else {
#ifdef DEBUG_PLUGINS
                   printf("plugins: registered OK\n");
#endif
            }
        } else {
#ifdef DEBUG_PLUGINS
            printf("plugins: Failed to configure plugin: api=%s, plugin_name=%s,factory=%s\n",
                    *plugin_api, *plugin_name, *factory_name);
#endif
        }

        // Need to cleanup ~ krb5_free_plugin_string(profile, plugin);
    }
}

#endif

static void
_start(manager_data* data)
{
    return;
}

static void
_stop(manager_data* data)
{
    return;
}

static plhandle
_getService(manager_data* data, const char* service_name, int plugin_id)
{
    plhandle *handle;
    manager_data* mdata = (manager_data*) data;
    reg_entry* entry = _search_registry(mdata->registry, service_name);

    memset(&handle, 0, sizeof handle);
    if(entry) {
        for(handle = entry->first; handle != NULL; handle = handle->next) {
            if (handle->plugin_id == plugin_id)
                break;
        }
        if (handle == NULL) {
#ifdef DEBUG_PLUGINS
            printf("service %s:%d is not registered \n", service_name, plugin_id);
#endif
        }

    } else {
#ifdef DEBUG_PLUGINS
        printf("service %s is not available\n", service_name);
#endif
    }

    return *handle;
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
plugin_default_manager_get_instance(plugin_manager** plugin_mngr_instance)
{
    plugin_manager* instance = NULL;
#ifdef DEBUG_PLUGINS
    printf("plugins: plugin_default_manager_get_instanc \n");
#endif

    if(*plugin_mngr_instance == NULL) {

        instance = (plugin_manager*) malloc(sizeof(plugin_manager));
        if (!instance)
            return NULL;
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
        *plugin_mngr_instance = instance;
    }
    return (*plugin_mngr_instance);
}

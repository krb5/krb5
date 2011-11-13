/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/krb/plugin.c - Plugin framework functions */
/*
 * Copyright (C) 2010 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "k5-int.h"

const char *interface_names[] = {
    "pwqual",
    "kadm5_hook",
    "clpreauth",
    "kdcpreauth",
    "ccselect"
};

/* Return the context's interface structure for id, or NULL if invalid. */
static inline struct plugin_interface *
get_interface(krb5_context context, int id)
{
    if (context == NULL || id < 0 || id >= PLUGIN_NUM_INTERFACES)
        return NULL;
    return &context->plugins[id];
}

/* Release the memory associated with the linked list entry map. */
static void
free_plugin_mapping(struct plugin_mapping *map)
{
    if (map == NULL)
        return;
    free(map->modname);
    if (map->dyn_handle != NULL)
        krb5int_close_plugin(map->dyn_handle);
    free(map);
}

/*
 * Register a mapping from modname to module.  On success, dyn_handle is
 * remembered in the mapping and will be released when the mapping is
 * overwritten or the context is destroyed.
 */
static krb5_error_code
register_module(krb5_context context, struct plugin_interface *interface,
                const char *modname, krb5_plugin_initvt_fn module,
                struct plugin_file_handle *dyn_handle)
{
    struct plugin_mapping *map, **pmap;

    /* If a mapping already exists for modname, remove it. */
    for (pmap = &interface->modules; *pmap != NULL; pmap = &(*pmap)->next) {
        map = *pmap;
        if (strcmp(map->modname, modname) == 0) {
            *pmap = map->next;
            free_plugin_mapping(map);
            break;
        }
    }

    /* Create a new mapping structure. */
    map = malloc(sizeof(*map));
    if (map == NULL)
        return ENOMEM;
    map->modname = strdup(modname);
    if (map->modname == NULL) {
        free(map);
        return ENOMEM;
    }
    map->module = module;
    map->dyn_handle = dyn_handle;

    /* Chain it into the list. */
    map->next = interface->modules;
    interface->modules = map;
    return 0;
}

/* Parse a profile module string of the form "modname:modpath" into its
 * component parts. */
static krb5_error_code
parse_modstr(krb5_context context, const char *modstr,
             char **modname, char **modpath)
{
    const char *sep;
    char *name = NULL, *path = NULL;

    *modname = NULL;
    *modpath = NULL;

    sep = strchr(modstr, ':');
    if (sep == NULL) {
        krb5_set_error_message(context, KRB5_PLUGIN_BAD_MODULE_SPEC,
                               _("Invalid module specifier %s"), modstr);
        return KRB5_PLUGIN_BAD_MODULE_SPEC;
    }

    /* Copy the module name. */
    name = malloc(sep - modstr + 1);
    if (name == NULL)
        return ENOMEM;
    memcpy(name, modstr, sep - modstr);
    name[sep - modstr] = '\0';

    /* Copy the module path. */
    path = strdup(sep + 1);
    if (path == NULL) {
        free(name);
        return ENOMEM;
    }

    *modname = name;
    *modpath = path;
    return 0;
}

/* Return true if value is found in list. */
static krb5_boolean
find_in_list(char **list, const char *value)
{
    for (; *list != NULL; list++) {
        if (strcmp(*list, value) == 0)
            return TRUE;
    }
    return FALSE;
}

/* Return true if module is not filtered out by enable or disable lists. */
static krb5_boolean
module_enabled(const char *modname, char **enable, char **disable)
{
    return ((enable == NULL || find_in_list(enable, modname)) &&
            (disable == NULL || !find_in_list(disable, modname)));
}

/* Remove any registered modules whose names are filtered out. */
static void
filter_builtins(krb5_context context, struct plugin_interface *interface,
                char **enable, char **disable)
{
    struct plugin_mapping *map, **pmap;

    pmap = &interface->modules;
    while (*pmap != NULL) {
        map = *pmap;
        if (!module_enabled(map->modname, enable, disable)) {
            *pmap = map->next;
            free_plugin_mapping(map);
        } else
            pmap = &map->next;
    }
}

static krb5_error_code
register_dyn_module(krb5_context context, struct plugin_interface *interface,
                    const char *iname, const char *modname, const char *path)
{
    krb5_error_code ret;
    char *symname = NULL;
    struct plugin_file_handle *handle = NULL;
    void (*initvt_fn)();

    /* Construct the initvt symbol name for this interface and module. */
    if (asprintf(&symname, "%s_%s_initvt", iname, modname) < 0) {
        symname = NULL;
        ret = ENOMEM;
        goto cleanup;
    }

    /* Open the plugin and resolve the initvt symbol. */
    ret = krb5int_open_plugin(path, &handle, &context->err);
    if (ret != 0)
        goto cleanup;
    ret = krb5int_get_plugin_func(handle, symname, &initvt_fn, &context->err);
    if (ret != 0)
        goto cleanup;

    /* Create a mapping for the module. */
    ret = register_module(context, interface, modname,
                          (krb5_plugin_initvt_fn)initvt_fn, handle);
    if (ret != 0)
        goto cleanup;
    handle = NULL;              /* Now owned by the module mapping. */

cleanup:
    free(symname);
    if (handle != NULL)
        krb5int_close_plugin(handle);
    return ret;
}

/* Register the plugin module given by the profile string mod, if enabled
 * according to the values of enable and disable. */
static krb5_error_code
register_dyn_mapping(krb5_context context, struct plugin_interface *interface,
                     const char *iname, const char *modstr, char **enable,
                     char **disable)
{
    krb5_error_code ret;
    char *modname = NULL, *modpath = NULL, *fullpath = NULL;

    /* Parse out the module name and path, and make sure it is enabled. */
    ret = parse_modstr(context, modstr, &modname, &modpath);
    if (ret != 0)
        goto cleanup;
    /* Treat non-absolute modpaths as relative to the plugin base directory. */
    ret = k5_path_join(context->plugin_base_dir, modpath, &fullpath);
    if (ret != 0)
        goto cleanup;
    if (!module_enabled(modname, enable, disable))
        goto cleanup;
    ret = register_dyn_module(context, interface, iname, modname, fullpath);

cleanup:
    free(modname);
    free(modpath);
    free(fullpath);
    return ret;
}

/* Ensure that a plugin interface is configured.  id is assumed to be valid. */
static krb5_error_code
configure_interface(krb5_context context, int id)
{
    krb5_error_code ret;
    struct plugin_interface *interface = &context->plugins[id];
    const char *iname = interface_names[id];
    char **modules = NULL, **enable = NULL, **disable = NULL, **mod;
    static const char *path[4];

    if (interface->configured)
        return 0;

    /* Detect consistency errors when plugin interfaces are added. */
    assert(sizeof(interface_names) / sizeof(*interface_names) ==
           PLUGIN_NUM_INTERFACES);

    /* Read the configuration variables for this interface. */
    path[0] = KRB5_CONF_PLUGINS;
    path[1] = iname;
    path[2] = KRB5_CONF_MODULE;
    path[3] = NULL;
    ret = profile_get_values(context->profile, path, &modules);
    if (ret != 0 && ret != PROF_NO_RELATION)
        goto cleanup;
    path[2] = KRB5_CONF_ENABLE_ONLY;
    ret = profile_get_values(context->profile, path, &enable);
    if (ret != 0 && ret != PROF_NO_RELATION)
        goto cleanup;
    path[2] = KRB5_CONF_DISABLE;
    ret = profile_get_values(context->profile, path, &disable);
    if (ret != 0 && ret != PROF_NO_RELATION)
        goto cleanup;

    /* Remove built-in modules which are filtered out by configuration. */
    filter_builtins(context, interface, enable, disable);

    /* Create mappings for dynamic modules which aren't filtered out. */
    for (mod = modules; mod && *mod; mod++) {
        ret = register_dyn_mapping(context, interface, iname, *mod,
                                   enable, disable);
        if (ret != 0)
            return ret;
    }

    ret = 0;
cleanup:
    profile_free_list(modules);
    profile_free_list(enable);
    profile_free_list(disable);
    return ret;
}

krb5_error_code
k5_plugin_load(krb5_context context, int interface_id, const char *modname,
               krb5_plugin_initvt_fn *module)
{
    krb5_error_code ret;
    struct plugin_interface *interface = get_interface(context, interface_id);
    struct plugin_mapping *map;

    if (interface == NULL)
        return EINVAL;
    ret = configure_interface(context, interface_id);
    if (ret != 0)
        return ret;
    for (map = interface->modules; map != NULL; map = map->next) {
        if (strcmp(map->modname, modname) == 0) {
            *module = map->module;
            return 0;
        }
    }
    krb5_set_error_message(context, KRB5_PLUGIN_NAME_NOTFOUND,
                           _("Could not find %s plugin module named '%s'"),
                           interface_names[interface_id], modname);
    return KRB5_PLUGIN_NAME_NOTFOUND;
}

krb5_error_code
k5_plugin_load_all(krb5_context context, int interface_id,
                   krb5_plugin_initvt_fn **modules)
{
    krb5_error_code ret;
    struct plugin_interface *interface = get_interface(context, interface_id);
    struct plugin_mapping *map;
    krb5_plugin_initvt_fn *list;
    size_t count;

    if (interface == NULL)
        return EINVAL;
    ret = configure_interface(context, interface_id);
    if (ret != 0)
        return ret;

    /* Count the modules and allocate a list to hold them. */
    count = 0;
    for (map = interface->modules; map != NULL; map = map->next)
        count++;
    list = malloc((count + 1) * sizeof(*list));
    if (list == NULL)
        return ENOMEM;

    /* Place each module's initvt function into list. */
    count = 0;
    for (map = interface->modules; map != NULL; map = map->next)
        list[count++] = map->module;
    list[count] = NULL;

    *modules = list;
    return 0;
}

void
k5_plugin_free_modules(krb5_context context, krb5_plugin_initvt_fn *modules)
{
    free(modules);
}

krb5_error_code
k5_plugin_register(krb5_context context, int interface_id, const char *modname,
                   krb5_plugin_initvt_fn module)
{
    struct plugin_interface *interface = get_interface(context, interface_id);

    if (interface == NULL)
        return EINVAL;

    /* Disallow registering plugins after load.  We may need to reconsider
     * this, but it simplifies the design. */
    if (interface->configured)
        return EINVAL;

    return register_module(context, interface, modname, module, NULL);
}

krb5_error_code
k5_plugin_register_dyn(krb5_context context, int interface_id,
                       const char *modname, const char *modsubdir)
{
    krb5_error_code ret;
    struct plugin_interface *interface = get_interface(context, interface_id);
    char *path;

    /* Disallow registering plugins after load. */
    if (interface == NULL || interface->configured)
        return EINVAL;
    if (asprintf(&path, "%s/%s/%s%s", context->plugin_base_dir, modsubdir,
                 modname, PLUGIN_EXT) < 0)
        return ENOMEM;

    ret = register_dyn_module(context, interface,
                              interface_names[interface_id], modname, path);
    free(path);
    return ret;
}

void
k5_plugin_free_context(krb5_context context)
{
    int i;
    struct plugin_interface *interface;
    struct plugin_mapping *map, *next;

    for (i = 0; i < PLUGIN_NUM_INTERFACES; i++) {
        interface = &context->plugins[i];
        for (map = interface->modules; map != NULL; map = next) {
            next = map->next;
            free_plugin_mapping(map);
        }
        interface->modules = NULL;
        interface->configured = FALSE;
    }
}

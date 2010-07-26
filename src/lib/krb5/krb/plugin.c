/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/krb5/krb/plugin.c
 *
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
 *
 *
 * Plugin framework functions
 */

#include "k5-int.h"

const char *interface_names[PLUGIN_NUM_INTERFACES] = {
    "pwqual"
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
        krb5_set_error_message(context, EINVAL, "Invalid module string %s",
                               modstr);
        return EINVAL; /* XXX create specific error code */
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

/* Open a dynamic object at modpath, look up symname within it, and register
 * the resulting init function as modname. */
static krb5_error_code
open_and_register(krb5_context context, struct plugin_interface *interface,
                  const char *modname, const char *modpath,
                  const char *symname)
{
    krb5_error_code ret;
    struct plugin_file_handle *handle;
    void (*initvt_fn)();

    ret = krb5int_open_plugin(modpath, &handle, &context->err);
    if (ret != 0)
        return ret;

    ret = krb5int_get_plugin_func(handle, symname, &initvt_fn, &context->err);
    if (ret != 0) {
        krb5int_close_plugin(handle);
        return ret;
    }

    ret = register_module(context, interface, modname,
                          (krb5_plugin_initvt_fn)initvt_fn, handle);
    if (ret != 0)
        krb5int_close_plugin(handle);
    return ret;
}

/* Register the plugins given by the profile strings in modules. */
static krb5_error_code
register_dyn_modules(krb5_context context, struct plugin_interface *interface,
                     const char *iname, char **modules)
{
    krb5_error_code ret;
    char *modname = NULL, *modpath = NULL, *symname = NULL;

    for (; *modules != NULL; modules++) {
        ret = parse_modstr(context, *modules, &modname, &modpath);
        if (ret != 0)
            return ret;
        if (asprintf(&symname, "%s_%s_initvt", iname, modname) < 0) {
            free(modname);
            free(modpath);
            return ENOMEM;
        }
        /* XXX should errors here be fatal, or just ignore the module? */
        ret = open_and_register(context, interface, modname, modpath, symname);
        free(modname);
        free(modpath);
        free(symname);
        if (ret != 0)
            return ret;
    }
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

/* Remove any registered modules whose names are not present in enable. */
static void
filter_enable(krb5_context context, struct plugin_interface *interface,
              char **enable)
{
    struct plugin_mapping *map, **pmap;

    pmap = &interface->modules;
    while (*pmap != NULL) {
        map = *pmap;
        if (!find_in_list(enable, map->modname)) {
            *pmap = map->next;
            free_plugin_mapping(map);
        } else
            pmap = &map->next;
    }
}

/* Remove any registered modules whose names are present in disable. */
static void
filter_disable(krb5_context context, struct plugin_interface *interface,
               char **disable)
{
    struct plugin_mapping *map, **pmap;

    pmap = &interface->modules;
    while (*pmap != NULL) {
        map = *pmap;
        if (find_in_list(disable, map->modname)) {
            *pmap = map->next;
            free_plugin_mapping(map);
        } else
            pmap = &map->next;
    }
}

/* Ensure that a plugin interface is configured.  id is assumed to be valid. */
static krb5_error_code
configure_interface(krb5_context context, int id)
{
    krb5_error_code ret;
    struct plugin_interface *interface = &context->plugins[id];
    const char *iname = interface_names[id];
    char **modules = NULL, **enable = NULL, **disable = NULL;
    static const char *path[4];

    if (interface->configured)
        return 0;

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

    if (modules != NULL) {
        ret = register_dyn_modules(context, interface, iname, modules);
        if (ret != 0)
            return ret;
    }
    if (enable != NULL)
        filter_enable(context, interface, enable);
    if (disable != NULL)
        filter_disable(context, interface, disable);

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
    return ENOENT; /* XXX Create error code? */
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

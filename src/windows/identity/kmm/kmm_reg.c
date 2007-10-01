/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
 * Copyright (c) 2006, 2007 Secure Endpoints Inc.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* $Id$ */

#include<kmminternal.h>

KHMEXP khm_int32   KHMAPI 
kmm_get_module_info(wchar_t * module_name, khm_int32 flags, 
                    kmm_module_info * buffer, khm_size * cb_buffer)
{
    /*TODO:Implement this */
    return KHM_ERROR_NOT_IMPLEMENTED;
}

KHMEXP khm_int32   KHMAPI 
kmm_get_plugin_info(wchar_t * plugin_name, 
                    kmm_plugin_info * buffer, khm_size * cb_buffer)
{
    /*TODO:Implement this */
    return KHM_ERROR_NOT_IMPLEMENTED;
}

KHMEXP khm_int32   KHMAPI 
kmm_get_plugins_config(khm_int32 flags, khm_handle * result) {
    khm_handle csp_root;
    khm_handle csp_plugins;
    khm_int32 rv;

    rv = khc_open_space(KHM_INVALID_HANDLE, KMM_CSNAME_ROOT, flags, &csp_root);

    if(KHM_FAILED(rv))
        return rv;

    rv = khc_open_space(csp_root, KMM_CSNAME_PLUGINS, flags, &csp_plugins);
    khc_close_space(csp_root);

    if(KHM_SUCCEEDED(rv))
        *result = csp_plugins;
    else
        *result = NULL;

    return rv;
}


KHMEXP khm_int32   KHMAPI 
kmm_get_modules_config(khm_int32 flags, khm_handle * result) {
    khm_handle croot;
    khm_handle kmm_all_modules;
    khm_int32 rv;

    rv = khc_open_space(NULL, KMM_CSNAME_ROOT, flags, &croot);

    if(KHM_FAILED(rv))
        return rv;

    rv = khc_open_space(croot, KMM_CSNAME_MODULES, flags, &kmm_all_modules);
    khc_close_space(croot);

    if(KHM_SUCCEEDED(rv))
        *result = kmm_all_modules;
    else
        *result = NULL;

    return rv;
}


KHMEXP khm_int32   KHMAPI 
kmm_get_plugin_config(wchar_t * plugin, khm_int32 flags, khm_handle * result)
{
    khm_handle csplugins;
    khm_handle csplugin;
    khm_int32 rv;

    if(!plugin || wcschr(plugin, L'/') || wcschr(plugin, L'\\'))
        return KHM_ERROR_INVALID_PARAM;

    if(KHM_FAILED(kmm_get_plugins_config(flags, &csplugins)))
        return KHM_ERROR_UNKNOWN;

    rv = khc_open_space(csplugins, plugin, flags, &csplugin);
    *result = csplugin;

    khc_close_space(csplugins);

    return rv;
}


KHMEXP khm_int32   KHMAPI 
kmm_get_module_config(wchar_t * module, khm_int32 flags, khm_handle * result)
{
    khm_handle csmodules;
    khm_handle csmodule;
    khm_int32 rv;

    if(!module || wcschr(module, L'/') || wcschr(module, L'\\'))
        return KHM_ERROR_INVALID_PARAM;

    if(KHM_FAILED(kmm_get_modules_config(flags, &csmodules)))
        return KHM_ERROR_UNKNOWN;

    rv = khc_open_space(csmodules, module, flags, &csmodule);
    *result = csmodule;

    khc_close_space(csmodules);

    return rv;
}

KHMEXP khm_int32   KHMAPI 
kmm_register_plugin(kmm_plugin_reg * plugin, khm_int32 config_flags)
{
    khm_int32 rv = KHM_ERROR_SUCCESS;
    khm_handle csp_plugin = NULL;
    khm_handle csp_module = NULL;
    size_t cch;

    /* avoid accidently creating the module key if it doesn't exist */
    config_flags &= ~KHM_FLAG_CREATE;

    if((plugin == NULL) ||
       (plugin->dependencies && 
        KHM_FAILED(multi_string_length_cch(plugin->dependencies, 
                                           KMM_MAXCCH_DEPS, &cch))) ||
       FAILED(StringCchLength(plugin->module, KMM_MAXCCH_NAME, &cch)) ||
       (plugin->description &&
        FAILED(StringCchLength(plugin->description,
                               KMM_MAXCCH_DESC, &cch))) ||
       FAILED(StringCchLength(plugin->name, KMM_MAXCCH_NAME, &cch)))
    {
        return KHM_ERROR_INVALID_PARAM;
    }

    /* note that we are retaining the length of the plugin name in
       chars in cch */
    cch ++;

#define CKRV if(KHM_FAILED(rv)) goto _exit

    rv = kmm_get_plugin_config(plugin->name, 
                               config_flags | KHM_FLAG_CREATE, &csp_plugin);
    CKRV;

    /* should fail if the module key doesn't exist */
    rv = kmm_get_module_config(plugin->module, config_flags, &csp_module);
    CKRV;

    /*TODO: Make sure that the module registration is in the same
      config store as the one in which the plugin is going to be
      registered */

    rv = khc_write_string(csp_plugin, L"Module", plugin->module);
    CKRV;
    if(plugin->description) {
        rv = khc_write_string(csp_plugin, L"Description", plugin->description);
        CKRV;
    }

    if(plugin->dependencies) {
        rv = khc_write_multi_string(csp_plugin, L"Dependencies", 
                                    plugin->dependencies);
        CKRV;
    }

    rv = khc_write_int32(csp_plugin, L"Type", plugin->type);
    CKRV;
    rv = khc_write_int32(csp_plugin, L"Disabled",
                         !!(plugin->flags & KMM_PLUGIN_FLAG_DISABLED));
    CKRV;

    {
        khm_size cb = 0;
        wchar_t * pl = NULL;
        size_t scb = 0;

        rv = khc_read_multi_string(csp_module, L"PluginList", NULL, &cb);
        if(rv != KHM_ERROR_TOO_LONG) {
            if (rv == KHM_ERROR_NOT_FOUND) {

                scb = cb = (cch + 1) * sizeof(wchar_t);
                pl = PMALLOC(cb);
                multi_string_init(pl, cb);
                rv = KHM_ERROR_SUCCESS;

                goto add_plugin_to_list;

            } else {
                goto _exit;
            }
        }

        cb += cch * sizeof(wchar_t);
        scb = cb;

        pl = PMALLOC(cb);

        rv = khc_read_multi_string(csp_module, L"PluginList", pl, &cb);
        if(KHM_FAILED(rv)) {
            if(pl)
                PFREE(pl);
            goto _exit;
        }

    add_plugin_to_list:

        if(!multi_string_find(pl, plugin->name, 0)) {
            multi_string_append(pl, &scb, plugin->name);
            rv = khc_write_multi_string(csp_module, L"PluginList", pl);
        }

        PFREE(pl);
        CKRV;
    }

#undef CKRV

_exit:
    if(csp_plugin)
        khc_close_space(csp_plugin);
    if(csp_module)
        khc_close_space(csp_module);

    return rv;
}

KHMEXP khm_int32   KHMAPI 
kmm_register_module(kmm_module_reg * module, khm_int32 config_flags)
{
    khm_int32 rv = KHM_ERROR_SUCCESS;
    khm_handle csp_module = NULL;
    size_t cch;
    int i;

    if((module == NULL) ||
        FAILED(StringCchLength(module->name, KMM_MAXCCH_NAME, &cch)) ||
        (module->description && 
            FAILED(StringCchLength(module->description, 
                                   KMM_MAXCCH_DESC, &cch))) ||
        FAILED(StringCchLength(module->path, MAX_PATH, &cch)) ||
        (module->n_plugins > 0 && module->plugin_reg_info == NULL)) {
        return KHM_ERROR_INVALID_PARAM;
    }

#define CKRV if(KHM_FAILED(rv)) goto _exit

    rv = kmm_get_module_config(module->name, config_flags | KHM_FLAG_CREATE, 
                               &csp_module);
    CKRV;

    rv = khc_write_string(csp_module, L"ImagePath", module->path);
    CKRV;

    rv = khc_write_int32(csp_module, L"Disabled", 0);
    CKRV;

    /* FileVersion and ProductVersion will be set when the module
       is loaded for the first time */

    for(i=0; i<module->n_plugins; i++) {
        rv = kmm_register_plugin(&(module->plugin_reg_info[i]), config_flags);
        CKRV;
    }

#undef CKRV
_exit:
    if(csp_module)
        khc_close_space(csp_module);

    return rv;
}

KHMEXP khm_int32   KHMAPI 
kmm_unregister_plugin(wchar_t * plugin, khm_int32 config_flags)
{
    khm_handle csp_plugin = NULL;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    rv = kmm_get_plugin_config(plugin, config_flags, &csp_plugin);

    if (KHM_FAILED(rv))
        goto _cleanup;

    rv = khc_remove_space(csp_plugin);

 _cleanup:

    if (csp_plugin)
        khc_close_space(csp_plugin);

    return rv;
}

KHMEXP khm_int32   KHMAPI 
kmm_unregister_module(wchar_t * module, khm_int32 config_flags)
{
    khm_handle csp_module = NULL;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    rv = kmm_get_module_config(module, config_flags, &csp_module);

    if (KHM_FAILED(rv))
        goto _cleanup;

    rv = khc_remove_space(csp_module);

 _cleanup:
    if (csp_module)
        khc_close_space(csp_module);

    return rv;
}

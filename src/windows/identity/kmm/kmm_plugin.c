/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
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

/* Called with no locks held to get a kmm_plugin_i structure
   that matches the name.  First we look in the hash table, and
   if one isn't found, we create an empty one.
*/

kmm_plugin_i * 
kmmint_get_plugin_i(wchar_t * name)
{
    kmm_plugin_i * p;
    size_t cb;

    if(FAILED(StringCbLength(name, KMM_MAXCB_NAME, &cb)))
        return NULL;
    cb += sizeof(wchar_t);

    EnterCriticalSection(&cs_kmm);
    p = (kmm_plugin_i *) hash_lookup(hash_plugins, (void *) name);

    if(p == NULL) {
        p = PMALLOC(sizeof(kmm_plugin_i));
        ZeroMemory(p, sizeof(kmm_plugin_i));
        p->magic = KMM_PLUGIN_MAGIC;
        p->p.name = PMALLOC(cb);
        StringCbCopy(p->p.name, cb, name);
        p->state = KMM_PLUGIN_STATE_NONE;

        hash_add(hash_plugins, (void *) p->p.name, (void *) p);
        kmmint_list_plugin(p);
    }
    LeaveCriticalSection(&cs_kmm);

    return p;
}

kmm_plugin_i * 
kmmint_find_plugin_i(wchar_t * name)
{
    kmm_plugin_i * p;
    size_t cb;

    if(FAILED(StringCbLength(name, KMM_MAXCB_NAME, &cb)))
        return NULL;

    EnterCriticalSection(&cs_kmm);
    p = (kmm_plugin_i *) hash_lookup(hash_plugins, (void *) name);
    LeaveCriticalSection(&cs_kmm);

    return p;
}

/* the plugin must be delisted before calling this */
void 
kmmint_list_plugin(kmm_plugin_i * p)
{
    EnterCriticalSection(&cs_kmm);
    if((p->flags & KMM_PLUGIN_FLAG_IN_MODLIST) ||
        (p->flags & KMM_PLUGIN_FLAG_IN_LIST)) 
    {
        RaiseException(2, EXCEPTION_NONCONTINUABLE, 0, NULL);
    }
    p->flags |= KMM_PLUGIN_FLAG_IN_LIST;
    LPUSH(&kmm_listed_plugins, p);
    LeaveCriticalSection(&cs_kmm);
}

void 
kmmint_delist_plugin(kmm_plugin_i * p)
{
    EnterCriticalSection(&cs_kmm);
    if(p->flags & KMM_PLUGIN_FLAG_IN_LIST) {
        p->flags &= ~KMM_PLUGIN_FLAG_IN_LIST;
        LDELETE(&kmm_listed_plugins, p);
    }
    if(p->flags & KMM_PLUGIN_FLAG_IN_MODLIST) {
        p->flags &= ~KMM_PLUGIN_FLAG_IN_MODLIST;
        LDELETE(&(p->module->plugins), p);
    }
    LeaveCriticalSection(&cs_kmm);
}

KHMEXP khm_int32   KHMAPI 
kmm_hold_plugin(kmm_plugin p)
{
    kmm_plugin_i * pi;

    if(!kmm_is_plugin(p))
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_kmm);
    pi = kmm_plugin_from_handle(p);
    pi->refcount++;
    LeaveCriticalSection(&cs_kmm);

    return KHM_ERROR_SUCCESS;
}

/* called with cs_kmm held */
void 
kmmint_free_plugin(kmm_plugin_i * pi)
{
    int i;
    pi->magic = 0;

    hash_del(hash_plugins, (void *) pi->p.name);

    kmmint_delist_plugin(pi);

    for(i=0; i<pi->n_dependants; i++) {
        kmm_release_plugin(kmm_handle_from_plugin(pi->dependants[i]));
        pi->dependants[i] = NULL;
    }

    if(pi->module) {
        kmm_release_module(kmm_handle_from_module(pi->module));
    }

    pi->module = NULL;
    pi->p.module = NULL;

    if(pi->p.name)
        PFREE(pi->p.name);
    pi->p.name = NULL;

    if(pi->p.description)
        PFREE(pi->p.description);
    pi->p.description = NULL;

    if(pi->p.dependencies)
        PFREE(pi->p.dependencies);
    pi->p.dependencies = NULL;

    PFREE(pi);
}

KHMEXP khm_int32   KHMAPI
kmm_enable_plugin(kmm_plugin p, khm_boolean enable) {
    kmm_plugin_i * pi;
    khm_int32 rv = KHM_ERROR_NOT_FOUND; /* default to error */
    khm_handle csp_plugin = NULL;

    EnterCriticalSection(&cs_kmm);
    if (!kmm_is_plugin(p)) {
        rv = KHM_ERROR_INVALID_PARAM;
        goto _cleanup;
    }

    pi = kmm_plugin_from_handle(p);

    if (KHM_FAILED(rv = kmm_get_plugin_config(pi->p.name, 0, &csp_plugin))) {
        goto _cleanup;
    }

    if (KHM_FAILED(rv = khc_write_int32(csp_plugin, L"Disabled", !enable))) {
        goto _cleanup;
    }

    rv = KHM_ERROR_SUCCESS;

 _cleanup:
    LeaveCriticalSection(&cs_kmm);

    if (csp_plugin)
        khc_close_space(csp_plugin);

    return rv;
}

KHMEXP khm_int32   KHMAPI
kmm_get_plugin_info_i(kmm_plugin p, kmm_plugin_info * info) {
    khm_int32 rv = KHM_ERROR_SUCCESS;
    kmm_plugin_i * pi;
    khm_handle csp_plugin;

    if (!info)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_kmm);
    if (!kmm_is_plugin(p)) {
        rv = KHM_ERROR_INVALID_PARAM;
        goto _cleanup;
    }

    pi = kmm_plugin_from_handle(p);

    ZeroMemory(info, sizeof(*info));

    info->reg = pi->p;
    info->reg.msg_proc = NULL;

    if (KHM_FAILED(kmm_get_plugin_config(pi->p.name, KHM_PERM_READ,
                                         &csp_plugin))) {
        info->failure_count = 0;
        *((khm_int64 *)&info->failure_time) = 0;
        info->failure_reason = 0;
    } else {
        if (KHM_FAILED(khc_read_int32(csp_plugin, L"FailureCount",
                                      &info->failure_count)))
            info->failure_count = 0;
        if (KHM_FAILED(khc_read_int64(csp_plugin, L"FailureTime",
                                      (khm_int64 *) &info->failure_time)))
            *((khm_int64 *) &info->failure_time) = 0;
        if (KHM_FAILED(khc_read_int32(csp_plugin, L"FailureReason",
                                      &info->failure_reason)))
            info->failure_reason = 0;

        khc_close_space(csp_plugin);
    }

    info->state = pi->state;

    kmm_hold_plugin(p);
    info->h_plugin = p;

    info->flags = (pi->flags & KMM_PLUGIN_FLAG_DISABLED);

 _cleanup:
    LeaveCriticalSection(&cs_kmm);

    return rv;
}

KHMEXP khm_int32   KHMAPI
kmm_release_plugin_info_i(kmm_plugin_info * info) {
    khm_int32 rv;

    if (!info || !info->h_plugin)
        return KHM_ERROR_INVALID_PARAM;

    rv = kmm_release_plugin(info->h_plugin);

    ZeroMemory(info, sizeof(info));

    return rv;
}

KHMEXP khm_int32   KHMAPI
kmm_get_next_plugin(kmm_plugin p, kmm_plugin * p_next) {
    khm_int32 rv = KHM_ERROR_SUCCESS;
    kmm_plugin_i * pi;
    kmm_plugin_i * pi_next = NULL;
    kmm_module_i * m;

    EnterCriticalSection(&cs_kmm);
    if (p == NULL) {
        if (kmm_listed_plugins)
            pi_next = kmm_listed_plugins;
        else {
            for (m = kmm_all_modules; m; m = LNEXT(m)) {
                if (m->plugins) {
                    pi_next = m->plugins;
                    break;
                }
            }
        }
    } else if (kmm_is_plugin(p)) {
        pi = kmm_plugin_from_handle(p);
        pi_next = LNEXT(pi);

        if (!pi_next) {
            /* we have either exhausted the listed plugins or we are
               at the end of the module's plugin list */
            if (pi->module) {
                m = LNEXT(pi->module);
            } else {
                m = kmm_all_modules;
            }

            for(; m; m = LNEXT(m)) {
                if (m->plugins) {
                    pi_next = m->plugins;
                    break;
                }
            }
        }
    }

    if (pi_next) {
        *p_next = kmm_handle_from_plugin(pi_next);
        kmm_hold_plugin(*p_next);
    } else {
        *p_next = NULL;
        rv = KHM_ERROR_NOT_FOUND;
    }

    LeaveCriticalSection(&cs_kmm);
    return rv;
}

KHMEXP khm_int32   KHMAPI 
kmm_release_plugin(kmm_plugin p)
{
    kmm_plugin_i * pi;

    if(!kmm_is_plugin(p))
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_kmm);
    pi = kmm_plugin_from_handle(p);
    pi->refcount--;
    if(pi->refcount == 0) {
        kmmint_free_plugin(pi);
    }
    LeaveCriticalSection(&cs_kmm);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32   KHMAPI 
kmm_provide_plugin(kmm_module module, kmm_plugin_reg * plugin)
{
    kmm_module_i * m;
    kmm_plugin_i * p;
    size_t cb_name = 0;
    size_t cb_desc = 0;
    size_t cb_dep = 0;

    m = kmm_module_from_handle(module);

    /* can only called when handing init_module() */
    if(m->state != KMM_MODULE_STATE_INIT)
        return KHM_ERROR_INVALID_OPERATION;

    if(!plugin || 
       FAILED(StringCbLength(plugin->name, KMM_MAXCB_NAME - sizeof(wchar_t), 
                             &cb_name)) ||
       (plugin->description && 
        FAILED(StringCbLength(plugin->description, 
                              KMM_MAXCB_DESC - sizeof(wchar_t), 
                              &cb_desc))) ||
       (plugin->dependencies && 
        KHM_FAILED(multi_string_length_cb(plugin->dependencies, 
                                          KMM_MAXCB_DEPS, &cb_dep)))) {
        return KHM_ERROR_INVALID_PARAM;
    }

    cb_name += sizeof(wchar_t);
    cb_desc += sizeof(wchar_t);

    p = kmmint_get_plugin_i(plugin->name);

    /* released below or in kmmint_init_module() */
    kmm_hold_plugin(kmm_handle_from_plugin(p));

    if(p->state != KMM_PLUGIN_STATE_NONE &&
        p->state != KMM_PLUGIN_STATE_PLACEHOLDER)
    {
        kmm_release_plugin(kmm_handle_from_plugin(p));
        return KHM_ERROR_DUPLICATE;
    }

    /* released when the plugin quits */
    kmm_hold_module(module);

    p->module = m;
    p->p.flags = plugin->flags;
    p->p.msg_proc = plugin->msg_proc;
    p->p.type = plugin->type;

    if(plugin->description) {
        p->p.description = PMALLOC(cb_desc);
        StringCbCopy(p->p.description, cb_desc, plugin->description);
    } else
        p->p.description = NULL;

    if(plugin->dependencies) {
        p->p.dependencies = PMALLOC(cb_dep);
        multi_string_copy_cb(p->p.dependencies, cb_dep, plugin->dependencies);
    } else
        p->p.dependencies = NULL;

    p->p.module = p->module->name;

    p->p.icon = plugin->icon;

    p->state = KMM_PLUGIN_STATE_REG;

    kmmint_delist_plugin(p);
    EnterCriticalSection(&cs_kmm);
    LPUSH(&(m->plugins), p);
    p->flags |= KMM_PLUGIN_FLAG_IN_MODLIST;
    LeaveCriticalSection(&cs_kmm);

    /* leave the plugin held because it is in the module's plugin list */
    return KHM_ERROR_SUCCESS;
}


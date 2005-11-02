/*
 * Copyright (c) 2004 Massachusetts Institute of Technology
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

static LONG pending_modules = 0;
static LONG pending_plugins = 0;
static LONG startup_signal = 0;
static BOOL load_done = FALSE;

void
kmmint_check_completion(void) {
    if (pending_modules == 0 &&
        pending_plugins == 0 &&
        InterlockedIncrement(&startup_signal) == 1) {

        load_done = TRUE;
        kmq_post_message(KMSG_KMM, KMSG_KMM_I_DONE, 0, 0);
    }
}

void
kmmint_add_to_module_queue(void) {
    InterlockedIncrement(&pending_modules);
}

void
kmmint_remove_from_module_queue(void) {

    InterlockedDecrement(&pending_modules);

    kmmint_check_completion();
}

void
kmmint_add_to_plugin_queue(void) {
    InterlockedIncrement(&pending_plugins);
}

void
kmmint_remove_from_plugin_queue(void) {
    InterlockedDecrement(&pending_plugins);

    kmmint_check_completion();
}

KHMEXP khm_boolean  KHMAPI
kmm_load_pending(void) {
    return !load_done;
}

/*! \internal
  \brief Message handler for the registrar thread. */
khm_boolean KHMAPI kmm_reg_cb(
    khm_int32 msg_type, 
    khm_int32 msg_sub_type, 
    khm_ui_4 uparam,
    void *vparam)
{
    /* we should only be getting <KMSG_KMM,KMSG_KMM_I_REG> anyway */
    if(msg_type != KMSG_KMM || msg_sub_type != KMSG_KMM_I_REG)
        return FALSE;

    switch(uparam) {
        case KMM_REG_INIT_MODULE:
            kmm_init_module((kmm_module_i *) vparam);
            kmm_release_module(kmm_handle_from_module((kmm_module_i *) vparam));
            break;

        case KMM_REG_EXIT_MODULE:
            kmm_exit_module((kmm_module_i *) vparam);
            kmm_release_module(kmm_handle_from_module((kmm_module_i *) vparam));
            break;

        case KMM_REG_INIT_PLUGIN:
            kmm_init_plugin((kmm_plugin_i *) vparam);
            kmm_release_plugin(kmm_handle_from_plugin((kmm_plugin_i *) vparam));
            break;

        case KMM_REG_EXIT_PLUGIN:
            kmm_exit_plugin((kmm_plugin_i *) vparam);
            kmm_release_plugin(kmm_handle_from_plugin((kmm_plugin_i *) vparam));
            break;
    }
    return TRUE;
}

/*! \internal
  \brief The registrar thread.

  The only thing this function does is to dispatch messages to the
  callback routine ( kmm_reg_cb() ) */
DWORD WINAPI kmm_registrar(
  LPVOID lpParameter
)
{
    tid_registrar = GetCurrentThreadId();

    kmq_subscribe(KMSG_KMM, kmm_reg_cb);
    kmq_subscribe(KMSG_SYSTEM, kmm_reg_cb);

    SetEvent(evt_startup);

    while(KHM_SUCCEEDED(kmq_dispatch(INFINITE)));

    ExitThread(0);
    /* not reached */
    return 0;
}

/*! \internal
  \brief Manages a plugin message thread.

  Each plugin gets its own plugin thread which is used to dispatch
  messages to the plugin.  This acts as the thread function for the
  plugin thread.*/
DWORD WINAPI kmm_plugin_broker(LPVOID lpParameter)
{
    DWORD rv = 0;
    kmm_plugin_i * p = (kmm_plugin_i *) lpParameter;

    TlsSetValue(tls_kmm, (LPVOID) p);

    kmm_hold_plugin(kmm_handle_from_plugin(p));

    p->tid_thread = GetCurrentThreadId();

    rv = (p->p.msg_proc(KMSG_SYSTEM, KMSG_SYSTEM_INIT, 0, (void *) &(p->p)));

    /* if it fails to initialize, we exit the plugin */
    if(KHM_FAILED(rv)) {
	kmmint_remove_from_plugin_queue();
        rv = 1;
        goto _exit;
    }

    /* subscribe to default message classes by plugin type */
    if(p->p.type & KHM_PITYPE_CRED) {
        kmq_subscribe(KMSG_SYSTEM, p->p.msg_proc);
        kmq_subscribe(KMSG_KCDB, p->p.msg_proc);
        kmq_subscribe(KMSG_CRED, p->p.msg_proc);
    }

    if(p->p.flags & KHM_PIFLAG_IDENTITY_PROVIDER) {
        khm_handle h = NULL;

        kmq_create_subscription(p->p.msg_proc, &h);
        kcdb_identity_set_provider(h);
        /* kcdb deletes the subscription when it's done with it */
    }

    if(p->p.type == KHM_PITYPE_CONFIG) {
        /*TODO: subscribe to configuration provider messages here */
    }

    p->state = KMM_PLUGIN_STATE_RUNNING;

    /* if there were any plugins that were waiting for this one to
       start, we should start them too */
    EnterCriticalSection(&cs_kmm);
    do {
        kmm_plugin_i * pd;
        int i;

        for(i=0; i < p->n_dependants; i++) {
            pd = p->dependants[i];

            pd->n_unresolved--;

            if(pd->n_unresolved == 0) {
                kmm_hold_plugin(kmm_handle_from_plugin(pd));
                kmq_post_message(KMSG_KMM, KMSG_KMM_I_REG, KMM_REG_INIT_PLUGIN, (void *) pd);
            }
        }
    } while(FALSE);
    LeaveCriticalSection(&cs_kmm);

    kmmint_remove_from_plugin_queue();

    /* main message loop */
    while(KHM_SUCCEEDED(kmq_dispatch(INFINITE)));

    /* unsubscribe from default message classes by plugin type */
    if(p->p.type & KHM_PITYPE_CRED) {
        kmq_unsubscribe(KMSG_SYSTEM, p->p.msg_proc);
        kmq_unsubscribe(KMSG_KCDB, p->p.msg_proc);
        kmq_unsubscribe(KMSG_CRED, p->p.msg_proc);
    }

    if(p->p.flags & KHM_PIFLAG_IDENTITY_PROVIDER) {
        kcdb_identity_set_provider(NULL);
    }

    if(p->p.type == KHM_PITYPE_CONFIG) {
        /*TODO: unsubscribe from configuration provider messages here */
    }

    p->p.msg_proc(KMSG_SYSTEM, KMSG_SYSTEM_EXIT, 0, (void *) &(p->p));

_exit:
    p->state = KMM_PLUGIN_STATE_EXITED;

    /* the following call will automatically release the plugin */
    kmq_post_message(KMSG_KMM, KMSG_KMM_I_REG, KMM_REG_EXIT_PLUGIN, (void *) p);

    TlsSetValue(tls_kmm, (LPVOID) 0);

    ExitThread(rv);

    /* not reached */
    return rv;
}

/*! \internal
  \brief Initialize a plugin

  \note If kmm_init_plugin() is called on a plugin, then kmm_exit_plugin()
      \b must be called for the plugin.

  \note Should only be called from the context of the registrar thread */
void kmm_init_plugin(kmm_plugin_i * p) {
    DWORD dummy;
    khm_handle csp_plugin   = NULL;
    khm_handle csp_plugins  = NULL;
    khm_int32 t;

    /* the following will be undone in kmm_exit_plugin() */
    kmm_hold_plugin(kmm_handle_from_plugin(p));

    EnterCriticalSection(&cs_kmm);
    if(p->state != KMM_PLUGIN_STATE_REG &&
        p->state != KMM_PLUGIN_STATE_HOLD)
    {
        LeaveCriticalSection(&cs_kmm);
        goto _exit;
    }

    _begin_task(0);
    _report_mr1(KHERR_NONE, MSG_IP_TASK_DESC, _cstr(p->p.name));
    _describe();

    if(p->state == KMM_PLUGIN_STATE_HOLD) {
        /* if this plugin was held, then we already had a hold
           from the initial attempt to start the plugin.  Undo
           the hold we did a few lines earlier. */
        kmm_release_plugin(kmm_handle_from_plugin(p));
        /* same for the plugin count for the module. */
        p->module->plugin_count--;
    }

    p->state = KMM_PLUGIN_STATE_PREINIT;
    LeaveCriticalSection(&cs_kmm);

    if(KHM_FAILED(kmm_get_plugins_config(0, &csp_plugins))) {
        _report_mr0(KHERR_ERROR, MSG_IP_GET_CONFIG);

        p->state = KMM_PLUGIN_STATE_FAIL_UNKNOWN;
        goto _exit;
    }

    if(KHM_FAILED(kmm_get_plugin_config(p->p.name, 0, &csp_plugin)) ||
        KHM_FAILED(khc_read_int32(csp_plugin, L"Flags", &t)))
    {
        if(KHM_FAILED(kmm_register_plugin(&(p->p), 0))) {
            _report_mr0(KHERR_ERROR, MSG_IP_NOT_REGISTERED);

            p->state = KMM_PLUGIN_STATE_FAIL_NOT_REGISTERED;
            goto _exit;
        }
        
        if(KHM_FAILED(kmm_get_plugin_config(p->p.name, 0, &csp_plugin))) {
            _report_mr0(KHERR_ERROR, MSG_IP_NOT_REGISTERED);

            p->state = KMM_PLUGIN_STATE_FAIL_NOT_REGISTERED;
            goto _exit;
        }

        if(KHM_FAILED(khc_read_int32(csp_plugin, L"Flags", &t))) {
            _report_mr0(KHERR_ERROR, MSG_IP_NOT_REGISTERED);

            p->state = KMM_PLUGIN_STATE_FAIL_NOT_REGISTERED;
            goto _exit;
        }
    }

    if(t & KMM_PLUGIN_FLAG_DISABLED) {
        _report_mr0(KHERR_ERROR, MSG_IP_DISABLED);

        p->state = KMM_PLUGIN_STATE_FAIL_DISABLED;
        goto _exit;
    }

#if 0
    /*TODO: check the failure count and act accordingly */
    if(KHM_SUCCEEDED(khc_read_int32(csp_plugin, L"FailureCount", &t)) && (t > 0)) {
    }
#endif

    EnterCriticalSection(&cs_kmm);

    p->n_depends = 0;
    p->n_unresolved = 0;
    
    do {
        wchar_t * deps = NULL;
        wchar_t * d;
        khm_size sz = 0;

        if(khc_read_multi_string(csp_plugin, L"Dependencies", NULL, &sz) != KHM_ERROR_TOO_LONG)
            break;

        deps = malloc(sz);
        if(KHM_FAILED(khc_read_multi_string(csp_plugin, L"Dependencies", deps, &sz))) {
            if(deps)
                free(deps);
            break;
        }

        for(d = deps; d && *d; d = multi_string_next(d)) {
            kmm_plugin_i * pd;
            int i;

            pd = kmm_get_plugin_i(d);

            if(pd->state == KMM_PLUGIN_STATE_NONE) {
                /* the dependant was not previously known */
                pd->state = KMM_PLUGIN_STATE_PLACEHOLDER;
            }

            for(i=0; i<pd->n_dependants; i++) {
                if(pd->dependants[i] == p)
                    break;
            }

            if(i >= pd->n_dependants) {
                if( pd->n_dependants >= KMM_MAX_DEPENDANTS ) {
                    /*TODO: handle this gracefully */
                    RaiseException(1, EXCEPTION_NONCONTINUABLE, 0, NULL);
                }

                /* released in kmm_free_plugin() */
                kmm_hold_plugin(kmm_handle_from_plugin(p));
                pd->dependants[pd->n_dependants] = p;
                pd->n_dependants++;
            }

            p->n_depends++;

            if(pd->state != KMM_PLUGIN_STATE_RUNNING) {
                p->n_unresolved++;
            }
        }

        if(p->n_unresolved > 0) {
            p->state = KMM_PLUGIN_STATE_HOLD;
        }

        free(deps);

    } while(FALSE);
    LeaveCriticalSection(&cs_kmm);

    EnterCriticalSection(&cs_kmm);
    p->module->plugin_count++;
    kmm_delist_plugin(p);
    kmm_list_plugin(p);
    LeaveCriticalSection(&cs_kmm);

    if(p->state == KMM_PLUGIN_STATE_HOLD) {
        _report_mr1(KHERR_INFO, MSG_IP_HOLD, _dupstr(p->p.name));

        goto _exit_post;
    }

    kmmint_add_to_plugin_queue();

    p->ht_thread = CreateThread(
        NULL,
        0,
        kmm_plugin_broker,
        (LPVOID) p,
        CREATE_SUSPENDED,
        &dummy);

    p->state = KMM_PLUGIN_STATE_INIT;

    ResumeThread(p->ht_thread);

_exit_post:
    if(csp_plugin != NULL)
        khc_close_space(csp_plugin);

    if(csp_plugins != NULL)
        khc_close_space(csp_plugins);

    _report_mr2(KHERR_INFO, MSG_IP_STATE, 
                _dupstr(p->p.name), _int32(p->state));

    _end_task();
    
    return;

    /* jump here if an error condition happens before the plugin
       broker thread starts and the plugin should be unloaded */

_exit:
    if(csp_plugin != NULL)
        khc_close_space(csp_plugin);
    if(csp_plugins != NULL)
        khc_close_space(csp_plugins);

    _report_mr2(KHERR_WARNING, MSG_IP_EXITING, 
                _dupstr(p->p.name), _int32(p->state));
    _end_task();

    kmm_hold_plugin(kmm_handle_from_plugin(p));

    kmq_post_message(KMSG_KMM, KMSG_KMM_I_REG, KMM_REG_EXIT_PLUGIN, (void *) p);
}

/*! \internal
  \brief Uninitialize a plugin

  In addition to terminating the thread, and removing p from the
  linked list and hashtable, it also frees up p.
   
  \note Should only be called from the context of the registrar thread. */
void kmm_exit_plugin(kmm_plugin_i * p) {
    int np;

    if(p->state == KMM_PLUGIN_STATE_RUNNING ||
        p->state == KMM_PLUGIN_STATE_INIT)
    {
        kmq_post_thread_quit_message(p->tid_thread, 0, NULL);
        /* when we post the quit message to the plugin thread, the plugin
           broker terminates the plugin and posts a EXIT_PLUGIN message,
           which calls this function again.  We just exit here because
           the EXIT_PLUGIN message will end up calling us again momentarily */
        return;
    }

    if(p->ht_thread) {
        /* wait for the thread to terminate */
        WaitForSingleObject(p->ht_thread, INFINITE);
        p->ht_thread = NULL;
    }

    EnterCriticalSection(&cs_kmm);

    /* undo reference count done in kmm_init_plugin() */
    if(p->state == KMM_PLUGIN_STATE_EXITED ||
        p->state == KMM_PLUGIN_STATE_HOLD) 
    {
        np = --(p->module->plugin_count);
    } else {
        /* the plugin was never active.  We can't base a module unload
           decision on np */
        np = TRUE;
    }
    LeaveCriticalSection(&cs_kmm);

    if(!np) {
        /*  if this is the last plugin to exit, then notify the
            registrar that the module should be removed as well */
        kmm_hold_module(kmm_handle_from_module(p->module));
        kmq_post_message(KMSG_KMM, KMSG_KMM_I_REG, KMM_REG_EXIT_MODULE, (void *) p->module);
    }

    /* release the hold obtained in kmm_init_plugin() */
    kmm_release_plugin(kmm_handle_from_plugin(p));
}

/*! \internal
  \brief Initialize a module

  \a m is not in the linked list yet.

  \note Should only be called from the context of the registrar thread. */
void kmm_init_module(kmm_module_i * m) {
    HMODULE hm;
    init_module_t p_init_module;
    kmm_plugin_i * pi;
    khm_int32 rv;
    khm_handle csp_mod = NULL;
    khm_handle csp_mods = NULL;
    khm_size sz;
    khm_int32 i;

    /* error condition handling */
    BOOL exit_module = FALSE;
    BOOL release_module = TRUE;
    BOOL record_failure = FALSE;

    /* failure handling */
    khm_int32 max_fail_count = 0;
    khm_int64 fail_reset_time = 0;

    _begin_task(0);
    _report_mr1(KHERR_NONE, MSG_INIT_MODULE, _cstr(m->name));
    _describe();

    kmm_hold_module(kmm_handle_from_module(m));

    if(KHM_FAILED(kmm_get_modules_config(0, &csp_mods))) {
        _report_mr0(KHERR_ERROR, MSG_IM_GET_CONFIG);
        _location(L"kmm_get_modules_config()");

        m->state = KMM_MODULE_STATE_FAIL_UNKNOWN;
        goto _exit;
    }

    khc_read_int32(csp_mods, L"ModuleMaxFailureCount", &max_fail_count);
    khc_read_int64(csp_mods, L"ModuleFailureCountResetTime", &fail_reset_time);

    /* If the module is not in the pre-init state, we can't
       initialize it. */
    if(m->state != KMM_MODULE_STATE_PREINIT) {
        _report_mr1(KHERR_WARNING, MSG_IM_NOT_PREINIT, _int32(m->state));
        goto _exit;
    }

    if(KHM_FAILED(kmm_get_module_config(m->name, 0, &csp_mod))) {
        _report_mr0(KHERR_ERROR, MSG_IM_NOT_REGISTERED);

        m->state = KMM_MODULE_STATE_FAIL_NOT_REGISTERED;
        goto _exit;
    }

    if(KHM_SUCCEEDED(khc_read_int32(csp_mod, L"Flags", &i))) {
        if(i & KMM_MODULE_FLAG_DISABLED) {
            _report_mr0(KHERR_ERROR, MSG_IM_DISABLED);

            m->state = KMM_MODULE_STATE_FAIL_DISABLED;
            goto _exit;
        }
    }

    if(KHM_SUCCEEDED(khc_read_int32(csp_mod, L"FailureCount", &i))) {
        khm_int64 tm;
        khm_int64 ct;

        /* reset the failure count if the failure count reset time
           period has elapsed */
        tm = 0;
        khc_read_int64(csp_mod, L"FailureTime", &tm);
        GetSystemTimeAsFileTime((LPFILETIME) &ct);
        ct -= tm;

        if(tm > 0 && 
           FtIntervalToSeconds((LPFILETIME) &ct) > fail_reset_time) {

            i = 0;
            khc_write_int32(csp_mod, L"FailureCount", 0);
            khc_write_int64(csp_mod, L"FailureTime", 0);

        }

        if(i > max_fail_count) {
            /* failed too many times */
            _report_mr0(KHERR_ERROR, MSG_IM_MAX_FAIL);

            m->state = KMM_MODULE_STATE_FAIL_MAX_FAILURE;
            goto _exit;
        }
    }

    if(khc_read_string(csp_mod, L"ImagePath", NULL, &sz) == KHM_ERROR_TOO_LONG) {
        if(m->path)
            free(m->path);
        m->path = malloc(sz);
        khc_read_string(csp_mod, L"ImagePath", m->path, &sz);
    } else {
        _report_mr0(KHERR_ERROR, MSG_IM_NOT_REGISTERED);

        m->state = KMM_MODULE_STATE_FAIL_NOT_REGISTERED;
        goto _exit;
    }

    if (khc_read_string(csp_mod, L"Vendor", NULL, &sz) == KHM_ERROR_TOO_LONG) {
        if (m->vendor)
            free(m->vendor);
        m->vendor = malloc(sz);
        khc_read_string(csp_mod, L"Vendor", m->vendor, &sz);
    }

    /* check again */
    if(m->state != KMM_MODULE_STATE_PREINIT) {
        _report_mr0(KHERR_ERROR, MSG_IM_NOT_PREINIT);

        goto _exit;
    }

    hm = LoadLibrary(m->path);
    if(!hm) {
        m->h_module = NULL;
        m->state = KMM_MODULE_STATE_FAIL_NOT_FOUND;
        record_failure = TRUE;

        _report_mr1(KHERR_ERROR, MSG_IM_NOT_FOUND, _dupstr(m->path));

        goto _exit;
    }

    /* from this point on, we need to discard the module through
       exit_module */
    release_module = FALSE;
    exit_module = TRUE;
    record_failure = TRUE;

    m->flags |= KMM_MODULE_FLAG_LOADED;
    m->h_module = hm;

    /*TODO: check signatures */

    p_init_module = (init_module_t) GetProcAddress(hm, EXP_INIT_MODULE);

    if(!p_init_module) {
        _report_mr1(KHERR_ERROR, MSG_IM_NO_ENTRY, _cstr(EXP_INIT_MODULE));

        m->state = KMM_MODULE_STATE_FAIL_INVALID;
        goto _exit;
    }

    m->state = KMM_MODULE_STATE_INIT;


    /* call init_module() */
    rv = (*p_init_module)(kmm_handle_from_module(m));

    m->flags |= KMM_MODULE_FLAG_INITP;

    if(KHM_FAILED(rv)) {
        _report_mr1(KHERR_ERROR, MSG_IM_INIT_FAIL, _int32(rv));

        m->state = KMM_MODULE_STATE_FAIL_LOAD;
        goto _exit;
    }

    if(!m->plugins) {
        _report_mr0(KHERR_ERROR, MSG_IM_NO_PLUGINS);

        m->state = KMM_MODULE_STATE_FAIL_NO_PLUGINS;
        record_failure = FALSE;
        goto _exit;
    }

    m->state = KMM_MODULE_STATE_INITPLUG;

    do {
        LPOP(&(m->plugins), &pi);
        if(pi) {
            pi->flags &= ~KMM_PLUGIN_FLAG_IN_MODLIST;
            kmm_init_plugin(pi);

            /* release the hold obtained in kmm_provide_plugin() */
            kmm_release_plugin(kmm_handle_from_plugin(pi));
        }
    } while(pi);

    if(!m->plugin_count) {
        _report_mr0(KHERR_ERROR, MSG_IM_NO_PLUGINS);

        m->state = KMM_MODULE_STATE_FAIL_NO_PLUGINS;
        record_failure = FALSE;
        goto _exit;
    }

    m->state = KMM_MODULE_STATE_RUNNING;

    exit_module = FALSE;
    record_failure = FALSE;

    ResetEvent(evt_exit);

_exit:
    if(csp_mod) {
        if(record_failure) {
            khm_int64 ct;

            i = 0;
            khc_read_int32(csp_mod, L"FailureCount", &i);
            i++;
            khc_write_int32(csp_mod, L"FailureCount", i);

            if(i==1) { /* first fault */
                GetSystemTimeAsFileTime((LPFILETIME) &ct);
                khc_write_int64(csp_mod, L"FailureTime", ct);
            }
        }
        khc_close_space(csp_mod);
    }
    if(csp_mods)
        khc_close_space(csp_mods);

    _report_mr2(KHERR_INFO, MSG_IM_MOD_STATE, 
                _dupstr(m->name), _int32(m->state));

    if(release_module)
        kmm_release_module(kmm_handle_from_module(m));

    kmmint_remove_from_module_queue();

    /* if something went wrong after init_module was called on the
       module code, we need to call exit_module */
    if(exit_module)
        kmm_exit_module(m);

    _end_task();
}


/*! \internal
  \brief Uninitializes a module

  \note Should only be called from the context of the registrar
  thread */
void kmm_exit_module(kmm_module_i * m) {
    kmm_plugin_i * p;

    /*  exiting a module happens in two stages.  
    
        If the module state is running (there are active plugins) then
        those plugins must be exited.  This has to be done from the
        plugin threads.  The signal for the plugins to exit must be
        issued from the registrar.  Therefore, we post messages to the
        registrar for each plugin we want to remove and exit
        kmm_exit_module().

        When the last plugin is exited, the plugin management code
        automatically signalls the registrar to remove the module.
        kmm_exit_module() gets called again.  This is the second
        stage, where we call exit_module() for the module and start
        unloading everything.
    */

    EnterCriticalSection(&cs_kmm);

    /* get rid of any dangling uninitialized plugins */
    LPOP(&(m->plugins), &p);
    while(p) {
        p->flags &= ~KMM_PLUGIN_FLAG_IN_MODLIST;
        kmm_exit_plugin(p);

        /* release hold from kmm_provide_plugin() */
        kmm_release_plugin(kmm_handle_from_plugin(p));

        LPOP(&(m->plugins), &p);
    }

    if(m->state == KMM_MODULE_STATE_RUNNING) {
        int np = 0;

        m->state = KMM_MODULE_STATE_EXITPLUG;

        p = kmm_listed_plugins;

        while(p) {
            if(p->module == m) {
                kmm_hold_plugin(kmm_handle_from_plugin(p));
                kmq_post_message(KMSG_KMM, KMSG_KMM_I_REG, KMM_REG_EXIT_PLUGIN, (void *) p);
                np++;
            }

            p = LNEXT(p);
        }

        if(np > 0) {
            /*  we have to go back and wait for the plugins to exit.
                when the last plugin exits, it automatically posts
                EXIT_MODULE. We can pick up from there when this
                happens. */
            LeaveCriticalSection(&cs_kmm);
            return;
        }
    }

    if(m->flags & KMM_MODULE_FLAG_INITP)
    {
        exit_module_t p_exit_module;

        if(m->state > 0)
            m->state = KMM_MODULE_STATE_EXIT;

        p_exit_module = 
            (exit_module_t) GetProcAddress(m->h_module, 
                                           EXP_EXIT_MODULE);
        if(p_exit_module) {
            LeaveCriticalSection(&cs_kmm);
            p_exit_module(kmm_handle_from_module(m));
            EnterCriticalSection(&cs_kmm);
        }
    }

    LeaveCriticalSection(&cs_kmm);

    if(m->state > 0)
        m->state = KMM_MODULE_STATE_EXITED;

    if(m->h_module) {
        FreeLibrary(m->h_module);
    }

    if(m->h_resource && (m->h_resource != m->h_module)) {
        FreeLibrary(m->h_resource);
    }

    m->h_module = NULL;
    m->h_resource = NULL;
    m->flags = 0;

    /* release the hold obtained in kmm_init_module() */
    kmm_release_module(kmm_handle_from_module(m));
}

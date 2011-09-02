/*
 * Copyright 2011 Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define _GNU_SOURCE /* For dladdr(), asprintf() */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <stdarg.h>

#include <libgen.h>
#include <sys/types.h>
#include <dirent.h>

#ifdef WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include <verto-module.h>

#ifdef WIN32
#define pdlmsuffix ".dll"
#define pdlmtype HMODULE
#define pdlopenl(filename) LoadLibraryEx(filename, NULL, DONT_RESOLVE_DLL_REFERENCES)
#define pdlclose(module) FreeLibrary((pdlmtype) module)
#define pdlsym(mod, sym) ((void *) GetProcAddress(mod, sym))

static pdlmtype
pdlreopen(const char *filename, pdlmtype module)
{
    pdlclose(module);
    return LoadLibrary(filename);
}

static char *pdlerror() {
    char *amsg;
    LPTSTR msg;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER
                      | FORMAT_MESSAGE_FROM_SYSTEM
                      | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, GetLastError(),
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPTSTR) &msg, 0, NULL);
    amsg = strdup((const char*) msg);
    LocalFree(msg);
    return amsg;
}

static bool
pdlsymlinked(const char *modn, const char *symb) {
    return (GetProcAddress(GetModuleHandle(modn), symb) != NULL ||
            GetProcAddress(GetModuleHandle(NULL), symb) != NULL);
}

static bool
pdladdrmodname(void *addr, char **buf) {
    MEMORY_BASIC_INFORMATION info;
    HMODULE mod;
    char modname[MAX_PATH];

    if (!VirtualQuery(addr, &info, sizeof(info)))
        return false;
    mod = (HMODULE) info.AllocationBase;

    if (!GetModuleFileNameA(mod, modname, MAX_PATH))
        return false;

    if (buf) {
        *buf = strdup(modname);
        if (!buf)
            return false;
    }

    return true;
}
#else
#define pdlmsuffix ".so"
#define pdlmtype void *
#define pdlopenl(filename) dlopen(filename, RTLD_LAZY | RTLD_LOCAL)
#define pdlclose(module) dlclose((pdlmtype) module)
#define pdlreopen(filename, module) module
#define pdlsym(mod, sym) dlsym(mod, sym)
#define pdlerror() strdup(dlerror())

static int
pdlsymlinked(const char* modn, const char* symb)
{
    void* mod = dlopen(NULL, RTLD_LAZY | RTLD_LOCAL);
    if (mod) {
        void* sym = dlsym(mod, symb);
        dlclose(mod);
        return sym != NULL;
    }
    return 0;
}

static int
pdladdrmodname(void *addr, char **buf) {
    Dl_info dlinfo;
    if (!dladdr(addr, &dlinfo))
        return 0;
    if (buf) {
        *buf = strdup(dlinfo.dli_fname);
        if (!*buf)
            return 0;
    }
    return 1;
}
#endif

#ifndef NSIG
#ifdef _NSIG
#define NSIG _NSIG
#else
#define NSIG SIGRTMIN
#endif
#endif

#define  _str(s) # s
#define __str(s) _str(s)
#define vnew(type) ((type*) malloc(sizeof(type)))
#define vnew0(type) ((type*) memset(vnew(type), 0, sizeof(type)))

struct _verto_ctx {
    void *dll;
    void *modpriv;
    verto_ev_type types;
    verto_ctx_funcs funcs;
    verto_ev *events;
};

typedef struct {
    verto_proc proc;
    verto_proc_status status;
} verto_child;

struct _verto_ev {
    verto_ev *next;
    verto_ctx *ctx;
    verto_ev_type type;
    verto_callback *callback;
    verto_callback *onfree;
    void *priv;
    void *modpriv;
    verto_ev_flag flags;
    verto_ev_flag actual;
    size_t depth;
    int deleted;
    union {
        int fd;
        int signal;
        time_t interval;
        verto_child child;
    } option;
};

const verto_module *defmodule;

static int
_vasprintf(char **strp, const char *fmt, va_list ap) {
    va_list apc;
    int size = 0;

    va_copy(apc, ap);
    size = vsnprintf(NULL, 0, fmt, apc);
    va_end(apc);

    *strp = malloc(size + 1);
    if (!size)
        return -1;

    return vsnprintf(*strp, size + 1, fmt, ap);
}

static int
_asprintf(char **strp, const char *fmt, ...) {
    va_list ap;
    int size = 0;

    va_start(ap, fmt);
    size = _vasprintf(strp, fmt, ap);
    va_end(ap);
    return size;
}

static int
do_load_file(const char *filename, int reqsym, verto_ev_type reqtypes,
             pdlmtype *dll, const verto_module **module)
{
    *dll = pdlopenl(filename);
    if (!*dll) {
        /* printf("%s -- %s\n", filename, pdlerror()); */
        return 0;
    }

    *module = (verto_module*) pdlsym(*dll, __str(VERTO_MODULE_TABLE));
    if (!*module || (*module)->vers != VERTO_MODULE_VERSION
            || !(*module)->new_ctx || !(*module)->def_ctx)
        goto error;

    /* Check to make sure that we have our required symbol if reqsym == true */
    if ((*module)->symb && reqsym && !pdlsymlinked(NULL, (*module)->symb))
        goto error;

    /* Check to make sure that this module supports our required features */
    if (reqtypes != VERTO_EV_TYPE_NONE && ((*module)->types & reqtypes) != reqtypes)
        goto error;

    /* Re-open in execution mode */
    *dll = pdlreopen(filename, *dll);
    if (!*dll)
        return 0;

    /* Get the module struct again */
    *module = (verto_module*) pdlsym(*dll, __str(VERTO_MODULE_TABLE));
    if (!*module)
        goto error;

    return 1;

    error:
        pdlclose(*dll);
        return 0;
}

static int
do_load_dir(const char *dirname, const char *prefix, const char *suffix,
            int reqsym, verto_ev_type reqtypes, pdlmtype *dll,
            const verto_module **module)
{
    *module = NULL;
    DIR *dir = opendir(dirname);
    if (!dir)
        return 0;

    struct dirent *ent = NULL;
    while ((ent = readdir(dir))) {
        size_t flen = strlen(ent->d_name);
        size_t slen = strlen(suffix);

        if (!strcmp(".", ent->d_name) || !strcmp("..", ent->d_name))
            continue;
        if (strstr(ent->d_name, prefix) != ent->d_name)
            continue;
        if (flen < slen || strcmp(ent->d_name + flen - slen, suffix))
            continue;

        char *tmp = NULL;
        if (_asprintf(&tmp, "%s/%s", dirname, ent->d_name) < 0)
            continue;

        int success = do_load_file(tmp, reqsym, reqtypes, dll, module);
        free(tmp);
        if (success)
            break;
        *module = NULL;
    }

    closedir(dir);
    return *module != NULL;
}

static int
load_module(const char *impl, verto_ev_type reqtypes, pdlmtype *dll,
            const verto_module **module)
{
    int success = 0;
    char *prefix = NULL;
    char *suffix = NULL;
    char *tmp = NULL;

    if (!pdladdrmodname(verto_convert_funcs, &prefix))
        return 0;

    /* Example output:
     *    prefix == /usr/lib/libverto-
     *    impl == glib
     *    suffix == .so.0
     * Put them all together: /usr/lib/libverto-glib.so.0 */
    suffix = strstr(prefix, pdlmsuffix);
    if (!suffix || strlen(suffix) < 1 || !(suffix = strdup(suffix))) {
        free(prefix);
        return 0;
    }
    strcpy(prefix + strlen(prefix) - strlen(suffix), "-");

    if (impl) {
        /* Try to do a load by the path */
        if (strchr(impl, '/'))
            success = do_load_file(impl, 0, reqtypes, dll, module);
        if (!success) {
            /* Try to do a load by the name */
            tmp = NULL;
            if (_asprintf(&tmp, "%s%s%s", prefix, impl, suffix) > 0) {
                success = do_load_file(tmp, 0, reqtypes, dll, module);
                free(tmp);
            }
        }
    } else {
        /* First, try the default implementation (aka 'the cache')*/
        *dll = NULL;
        *module = NULL;

        if (defmodule != NULL
                && (reqtypes == VERTO_EV_TYPE_NONE
                        || (defmodule->types & reqtypes) == reqtypes))
            *module = defmodule;

        if (!(success = *module != NULL)) {
            /* NULL was passed, so we will use the dirname of
             * the prefix to try and find any possible plugins */
            tmp = strdup(prefix);
            if (tmp) {
                char *dname = strdup(dirname(tmp));
                free(tmp);

                tmp = strdup(basename(prefix));
                free(prefix);
                prefix = tmp;

                if (dname && prefix) {
                    /* Attempt to find a module we are already linked to */
                    success = do_load_dir(dname, prefix, suffix, 1, reqtypes,
                                          dll, module);
                    if (!success) {
#ifdef DEFAULT_LIBRARY
                        /* Attempt to find the default module */
                        success = load_module(DEFAULT_LIBRARY, reqtypes, dll, module);
                        if (!success)
#endif /* DEFAULT_LIBRARY */
                        /* Attempt to load any plugin (we're desperate) */
                        success = do_load_dir(dname, prefix, suffix, 0,
                                              reqtypes, dll, module);
                    }
                }

                free(dname);
            }
        }
    }

    free(suffix);
    free(prefix);
    return success;
}

static verto_ev *
make_ev(verto_ctx *ctx, verto_callback *callback,
        verto_ev_type type, verto_ev_flag flags)
{
    verto_ev *ev = NULL;

    if (!ctx || !callback)
        return NULL;

    ev = malloc(sizeof(verto_ev));
    if (ev) {
        memset(ev, 0, sizeof(verto_ev));
        ev->ctx        = ctx;
        ev->type       = type;
        ev->callback   = callback;
        ev->flags      = flags;
    }

    return ev;
}

static void
push_ev(verto_ctx *ctx, verto_ev *ev)
{
    if (!ctx || !ev)
        return;

    verto_ev *tmp = ctx->events;
    ctx->events = ev;
    ctx->events->next = tmp;
}

static void
remove_ev(verto_ev **origin, verto_ev *item)
{
    if (!origin || !*origin || !item)
        return;

    if (*origin == item)
        *origin = (*origin)->next;
    else
        remove_ev(&((*origin)->next), item);
}

static void
signal_ignore(verto_ctx *ctx, verto_ev *ev)
{
}

verto_ctx *
verto_new(const char *impl, verto_ev_type reqtypes)
{
    pdlmtype dll = NULL;
    const verto_module *module = NULL;
    verto_ctx *ctx = NULL;

    if (!load_module(impl, reqtypes, &dll, &module))
        return NULL;

    ctx = module->new_ctx();
    if (!ctx && dll)
        pdlclose(dll);
    if (ctx && defmodule != module)
        ctx->dll = dll;

    return ctx;
}

verto_ctx *
verto_default(const char *impl, verto_ev_type reqtypes)
{
    pdlmtype dll = NULL;
    const verto_module *module = NULL;
    verto_ctx *ctx = NULL;

    if (!load_module(impl, reqtypes, &dll, &module))
        return NULL;

    ctx = module->def_ctx();
    if (!ctx && dll)
        pdlclose(dll);
    if (ctx && defmodule != module)
        ctx->dll = dll;

    return ctx;
}

int
verto_set_default(const char *impl, verto_ev_type reqtypes)
{
    pdlmtype dll = NULL; /* we will leak the dll */
    return (!defmodule && impl && load_module(impl, reqtypes, &dll, &defmodule));
}

void
verto_free(verto_ctx *ctx)
{
#ifndef WIN32
    int i;
    sigset_t old;
    sigset_t block;
    struct sigaction act;
#endif

    if (!ctx)
        return;

    /* Cancel all pending events */
    while (ctx->events)
        verto_del(ctx->events);

    /* Free the private */
    ctx->funcs.ctx_free(ctx->modpriv);

    /* Unload the module */
    if (ctx->dll) {
        /* If dlclose() unmaps memory that is registered as a signal handler
         * we have to remove that handler otherwise if that signal is fired
         * we jump into unmapped memory. So we loop through and test each
         * handler to see if it is in unmapped memory.  If it is, we set it
         * back to the default handler. Lastly, if a signal were to fire it
         * could be a race condition. So we mask out all signals during this
         * process.
         */
#ifndef WIN32
        sigfillset(&block);
        sigprocmask(SIG_SETMASK, &block, &old);
#endif
        pdlclose(ctx->dll);
#ifndef WIN32
        for (i=1 ; i < NSIG ; i++) {
            if (sigaction(i, NULL, &act) == 0) {
                if (act.sa_flags & SA_SIGINFO) {
                    if (!pdladdrmodname(act.sa_sigaction, NULL))
                        signal(i, SIG_DFL);
                } else if (act.sa_handler != SIG_DFL
                        && act.sa_handler != SIG_IGN) {
                    if (!pdladdrmodname(act.sa_handler, NULL))
                        signal(i, SIG_DFL);
                }
            }
        }
        sigprocmask(SIG_SETMASK, &old, NULL);
#endif
    }

    free(ctx);
}

void
verto_run(verto_ctx *ctx)
{
    if (!ctx)
        return;
    ctx->funcs.ctx_run(ctx->modpriv);
}

void
verto_run_once(verto_ctx *ctx)
{
    if (!ctx)
        return;
    ctx->funcs.ctx_run_once(ctx->modpriv);
}

void
verto_break(verto_ctx *ctx)
{
    if (!ctx)
        return;
    ctx->funcs.ctx_break(ctx->modpriv);
}

#define doadd(set, type) \
    verto_ev *ev = make_ev(ctx, callback, type, flags); \
    if (ev) { \
        set; \
        ev->actual = ev->flags; \
        ev->modpriv = ctx->funcs.ctx_add(ctx->modpriv, ev, &ev->actual); \
        if (!ev->modpriv) { \
            free(ev); \
            return NULL; \
        } \
        push_ev(ctx, ev); \
    } \
    return ev;

verto_ev *
verto_add_io(verto_ctx *ctx, verto_ev_flag flags,
             verto_callback *callback, int fd)
{
    if (fd < 0 || !(flags & (VERTO_EV_FLAG_IO_READ | VERTO_EV_FLAG_IO_WRITE)))
        return NULL;
    doadd(ev->option.fd = fd, VERTO_EV_TYPE_IO);
}

verto_ev *
verto_add_timeout(verto_ctx *ctx, verto_ev_flag flags,
                  verto_callback *callback, time_t interval)
{
    doadd(ev->option.interval = interval, VERTO_EV_TYPE_TIMEOUT);
}

verto_ev *
verto_add_idle(verto_ctx *ctx, verto_ev_flag flags,
               verto_callback *callback)
{
    doadd(, VERTO_EV_TYPE_IDLE);
}

verto_ev *
verto_add_signal(verto_ctx *ctx, verto_ev_flag flags,
                 verto_callback *callback, int signal)
{
    if (signal < 0)
        return NULL;
#ifndef WIN32
    if (signal == SIGCHLD)
        return NULL;
#endif
    if (callback == VERTO_SIG_IGN) {
        callback = signal_ignore;
        if (!(flags & VERTO_EV_FLAG_PERSIST))
            return NULL;
    }
    doadd(ev->option.signal = signal, VERTO_EV_TYPE_SIGNAL);
}

verto_ev *
verto_add_child(verto_ctx *ctx, verto_ev_flag flags,
                verto_callback *callback, verto_proc proc)
{
    if (flags & VERTO_EV_FLAG_PERSIST) /* persist makes no sense */
        return NULL;
#ifdef WIN32
    if (proc == NULL)
#else
    if (proc < 1)
#endif
        return NULL;
    doadd(ev->option.child.proc = proc, VERTO_EV_TYPE_CHILD);
}

int
verto_set_private(verto_ev *ev, void *priv, verto_callback *free)
{
    if (!ev)
        return 0;
    if (ev->onfree && free)
        ev->onfree(ev->ctx, ev);
    ev->priv = priv;
    ev->onfree = free;
    return 1;
}

void *
verto_get_private(const verto_ev *ev)
{
    return ev->priv;
}

verto_ev_type
verto_get_type(const verto_ev *ev)
{
    return ev->type;
}

verto_ev_flag
verto_get_flags(const verto_ev *ev)
{
    return ev->flags;
}

int
verto_get_fd(const verto_ev *ev)
{
    if (ev && (ev->type == VERTO_EV_TYPE_IO))
        return ev->option.fd;
    return -1;
}

time_t
verto_get_interval(const verto_ev *ev)
{
    if (ev && (ev->type == VERTO_EV_TYPE_TIMEOUT))
        return ev->option.interval;
    return 0;
}

int
verto_get_signal(const verto_ev *ev)
{
    if (ev && (ev->type == VERTO_EV_TYPE_SIGNAL))
        return ev->option.signal;
    return -1;
}

verto_proc
verto_get_proc(const verto_ev *ev) {
    if (ev && ev->type == VERTO_EV_TYPE_CHILD)
        return ev->option.child.proc;
    return (verto_proc) 0;
}

verto_proc_status
verto_get_proc_status(const verto_ev *ev)
{
    return ev->option.child.status;
}

void
verto_del(verto_ev *ev)
{
    if (!ev)
        return;

    /* If the event is freed in the callback, we just set a flag so that
     * verto_fire() can actually do the delete when the callback completes.
     *
     * If we don't do this, than verto_fire() will access freed memory. */
    if (ev->depth > 0) {
        ev->deleted = 1;
        return;
    }

    if (ev->onfree)
        ev->onfree(ev->ctx, ev);
    ev->ctx->funcs.ctx_del(ev->ctx->modpriv, ev, ev->modpriv);
    remove_ev(&(ev->ctx->events), ev);
    free(ev);
}

verto_ev_type
verto_get_supported_types(verto_ctx *ctx)
{
    return ctx->types;
}

/*** THE FOLLOWING ARE FOR IMPLEMENTATION MODULES ONLY ***/

verto_ctx *
verto_convert_funcs(const verto_ctx_funcs *funcs,
               const verto_module *module,
               void *ctx_private)
{
    verto_ctx *ctx = NULL;

    if (!funcs || !module || !ctx_private)
        return NULL;

    ctx = vnew0(verto_ctx);
    if (!ctx)
        return NULL;

    ctx->modpriv = ctx_private;
    ctx->funcs = *funcs;
    ctx->types = module->types;

    if (!defmodule)
        defmodule = module;

    return ctx;
}

void
verto_fire(verto_ev *ev)
{
    void *priv;

    ev->depth++;
    ev->callback(ev->ctx, ev);
    ev->depth--;

    if (ev->depth == 0) {
        if (!(ev->flags & VERTO_EV_FLAG_PERSIST) || ev->deleted)
            verto_del(ev);
        else if (!ev->actual & VERTO_EV_FLAG_PERSIST) {
            ev->actual = ev->flags;
            priv = ev->ctx->funcs.ctx_add(ev->ctx->modpriv, ev, &ev->actual);
            assert(priv); /* TODO: create an error callback */
            ev->ctx->funcs.ctx_del(ev->ctx->modpriv, ev, ev->modpriv);
            ev->modpriv = priv;
        }
    }
}

void
verto_set_proc_status(verto_ev *ev, verto_proc_status status)
{
    if (ev && ev->type == VERTO_EV_TYPE_CHILD)
        ev->option.child.status = status;
}

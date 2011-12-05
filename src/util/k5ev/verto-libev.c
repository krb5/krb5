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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <verto-libev.h>
#define VERTO_MODULE_TYPES
typedef struct ev_loop verto_mod_ctx;
typedef ev_watcher verto_mod_ev;
#include <verto-module.h>

static verto_mod_ctx *
libev_ctx_new(void)
{
    return ev_loop_new(EVFLAG_AUTO);
}

static verto_mod_ctx *
libev_ctx_default(void)
{
    return ev_default_loop(EVFLAG_AUTO);
}

static void
libev_ctx_free(verto_mod_ctx *ctx)
{
    if (ctx != EV_DEFAULT)
        ev_loop_destroy(ctx);
}

static void
libev_ctx_run(verto_mod_ctx *ctx)
{
    ev_run(ctx, 0);
}

static void
libev_ctx_run_once(verto_mod_ctx *ctx)
{
    ev_run(ctx, EVRUN_ONCE);
}

static void
libev_ctx_break(verto_mod_ctx *ctx)
{
    ev_break(ctx, EVBREAK_ONE);
}

static void
libev_ctx_reinitialize(verto_mod_ctx *ctx)
{
    ev_loop_fork(ctx);
}

static void
libev_callback(EV_P_ ev_watcher *w, int revents)
{
    if (verto_get_type(w->data) == VERTO_EV_TYPE_CHILD)
        verto_set_proc_status(w->data, ((ev_child*) w)->rstatus);

    verto_fire(w->data);
}

#define setuptype(type, ...) \
    w.type = malloc(sizeof(ev_ ## type)); \
    if (w.type) { \
    	ev_ ## type ## _init(w.type, (EV_CB(type, (*))) __VA_ARGS__); \
    	ev_ ## type ## _start(ctx, w.type); \
    } \
    break

static verto_mod_ev *
libev_ctx_add(verto_mod_ctx *ctx, const verto_ev *ev, verto_ev_flag *flags)
{
    union {
       ev_watcher *watcher;
       ev_io *io;
       ev_timer *timer;
       ev_idle *idle;
       ev_signal *signal;
       ev_child *child;
    } w;
    ev_tstamp interval;
    int events = EV_NONE;

    w.watcher = NULL;
    *flags |= VERTO_EV_FLAG_PERSIST;
    switch (verto_get_type(ev)) {
        case VERTO_EV_TYPE_IO:
            if (verto_get_flags(ev) & VERTO_EV_FLAG_IO_READ)
                events |= EV_READ;
            if (verto_get_flags(ev) & VERTO_EV_FLAG_IO_WRITE)
                events |= EV_WRITE;
            setuptype(io, libev_callback, verto_get_fd(ev), events);
        case VERTO_EV_TYPE_TIMEOUT:
            interval = ((ev_tstamp) verto_get_interval(ev)) / 1000.0;
            setuptype(timer, libev_callback, interval, interval);
        case VERTO_EV_TYPE_IDLE:
            setuptype(idle, libev_callback);
        case VERTO_EV_TYPE_SIGNAL:
            setuptype(signal, libev_callback, verto_get_signal(ev));
        case VERTO_EV_TYPE_CHILD:
            *flags &= ~VERTO_EV_FLAG_PERSIST; /* Child events don't persist */
            setuptype(child, libev_callback, verto_get_proc(ev), 0);
        default:
            break; /* Not supported */
    }

    if (w.watcher)
        w.watcher->data = (void*) ev;
    return w.watcher;
}

static void
libev_ctx_del(verto_mod_ctx *ctx, const verto_ev *ev, verto_mod_ev *evpriv)
{
    switch (verto_get_type(ev)) {
        case VERTO_EV_TYPE_IO:
            ev_io_stop(ctx, (ev_io*) evpriv);
            break;
        case VERTO_EV_TYPE_TIMEOUT:
            ev_timer_stop(ctx, (ev_timer*) evpriv);
            break;
        case VERTO_EV_TYPE_IDLE:
            ev_idle_stop(ctx, (ev_idle*) evpriv);
            break;
        case VERTO_EV_TYPE_SIGNAL:
            ev_signal_stop(ctx, (ev_signal*) evpriv);
            break;
        case VERTO_EV_TYPE_CHILD:
            ev_child_stop(ctx, (ev_child*) evpriv);
            break;
        default:
            break;
    }

    free(evpriv);
}

VERTO_MODULE(libev, ev_loop_new,
             VERTO_EV_TYPE_IO |
             VERTO_EV_TYPE_TIMEOUT |
             VERTO_EV_TYPE_IDLE |
             VERTO_EV_TYPE_SIGNAL |
             VERTO_EV_TYPE_CHILD);

verto_ctx *
verto_convert_libev(struct ev_loop* loop)
{
    return verto_convert(libev, 0, loop);
}

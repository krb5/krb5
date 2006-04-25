/*
 * util/support/plugins.c
 *
 * Copyright 2006 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * Plugin module support, and shims around dlopen/whatever.
 */

#include "k5-plugin.h"
#if USE_DLOPEN
#include <dlfcn.h>
#endif
#if USE_CFBUNDLE
#include <CoreFoundation/CoreFoundation.h>
#endif
#include <stdio.h>
#include <sys/types.h>
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdarg.h>
static void Tprintf (const char *fmt, ...)
{
#ifdef DEBUG
    va_list va;
    va_start (va, fmt);
    vfprintf (stderr, fmt, va);
    va_end (va);
#endif
}

struct plugin_file_handle {
#if USE_DLOPEN
    void *dlhandle;
#endif
#if USE_CFBUNDLE
    CFBundleRef bundle;
#endif
#if !defined (USE_DLOPEN) && !defined (USE_CFBUNDLE)
    char dummy;
#endif
};

long KRB5_CALLCONV
krb5int_open_plugin (const char *filename, struct plugin_file_handle **h,
		     struct errinfo *ep)
{
    long err = 0;
    struct stat statbuf;
    struct plugin_file_handle *htmp = NULL;
    int got_plugin = 0;

    if (!err) {
        if (stat (filename, &statbuf) < 0) {
            Tprintf ("stat(%s): %s\n", filename, strerror (errno));
            err = errno;
        }
    }

    if (!err) {
        htmp = calloc (1, sizeof (*htmp)); /* calloc initializes ptrs to NULL */
        if (htmp == NULL) { err = errno; }
    }

#if USE_DLOPEN
    if (!err && (statbuf.st_mode & S_IFMT) == S_IFREG) {
        void *handle = NULL;

        if (!err) {
            handle = dlopen(filename, RTLD_NOW | RTLD_GLOBAL);
            if (handle == NULL) {
                const char *e = dlerror();
                Tprintf ("dlopen(%s): %s\n", filename, e);
                err = ENOENT; /* XXX */
		krb5int_set_error (ep, err, "%s", e);
            }
        }

        if (!err) {
            got_plugin = 1;
            htmp->dlhandle = handle;
            handle = NULL;
        }

        if (handle != NULL) { dlclose (handle); }
    }
#endif

#if USE_CFBUNDLE
    if (!err && (statbuf.st_mode & S_IFMT) == S_IFDIR) {
        CFStringRef pluginPath = NULL;
        CFURLRef pluginURL = NULL;
        CFBundleRef pluginBundle = NULL;

        if (!err) {
            pluginPath = CFStringCreateWithCString (kCFAllocatorDefault, filename, 
                                                    kCFStringEncodingASCII);
            if (pluginPath == NULL) { err = ENOMEM; }
        }
        
        if (!err) {
            pluginURL = CFURLCreateWithFileSystemPath (kCFAllocatorDefault, pluginPath, 
                                                       kCFURLPOSIXPathStyle, true);
            if (pluginURL == NULL) { err = ENOMEM; }
        }
        
        if (!err) {
            pluginBundle = CFBundleCreate (kCFAllocatorDefault, pluginURL);
            if (pluginBundle == NULL) { err = ENOENT; } /* XXX need better error */
        }
        
        if (!err) {
            if (!CFBundleIsExecutableLoaded (pluginBundle)) {
                int loaded = CFBundleLoadExecutable (pluginBundle);
                if (!loaded) { err = ENOENT; }  /* XXX need better error */
            }
        }
        
        if (!err) {
            got_plugin = 1;
            htmp->bundle = pluginBundle;
            pluginBundle = NULL;  /* htmp->bundle takes ownership */
        }

        if (pluginBundle != NULL) { CFRelease (pluginBundle); }
        if (pluginURL    != NULL) { CFRelease (pluginURL); }
        if (pluginPath   != NULL) { CFRelease (pluginPath); }
    }
#endif
        
    if (!err && !got_plugin) {
        err = ENOENT;  /* no plugin or no way to load plugins */
    }
    
    if (!err) {
        *h = htmp;
        htmp = NULL;  /* h takes ownership */
    }
    
    if (htmp != NULL) { free (htmp); }
    
    return err;
}

static long
krb5int_get_plugin_sym (struct plugin_file_handle *h, 
                        const char *csymname, int isfunc, void **ptr,
			struct errinfo *ep)
{
    long err = 0;
    void *sym = NULL;
    
#if USE_DLOPEN
    if (!err && !sym && (h->dlhandle != NULL)) {
        /* XXX Do we need to add a leading "_" to the symbol name on any
        modern platforms?  */
        sym = dlsym (h->dlhandle, csymname);
        if (sym == NULL) {
            const char *e = dlerror (); /* XXX copy and save away */
            Tprintf ("dlsym(%s): %s\n", csymname, e);
            err = ENOENT; /* XXX */
	    krb5int_set_error(ep, err, "%s", e);
        }
    }
#endif
    
#if USE_CFBUNDLE
    if (!err && !sym && (h->bundle != NULL)) {
        CFStringRef cfsymname = NULL;
        
        if (!err) {
            cfsymname = CFStringCreateWithCString (kCFAllocatorDefault, csymname, 
                                                   kCFStringEncodingASCII);
            if (cfsymname == NULL) { err = ENOMEM; }
        }
        
        if (!err) {
            if (isfunc) {
                sym = CFBundleGetFunctionPointerForName (h->bundle, cfsymname);
            } else {
                sym = CFBundleGetDataPointerForName (h->bundle, cfsymname);
            }
            if (sym == NULL) { err = ENOENT; }  /* XXX */       
        }
        
        if (cfsymname != NULL) { CFRelease (cfsymname); }
    }
#endif
    
    if (!err && (sym == NULL)) {
        err = ENOENT;  /* unimplemented */
    }
    
    if (!err) {
        *ptr = sym;
    }
    
    return err;
}

long KRB5_CALLCONV
krb5int_get_plugin_data (struct plugin_file_handle *h, const char *csymname,
			 void **ptr, struct errinfo *ep)
{
    return krb5int_get_plugin_sym (h, csymname, 0, ptr, ep);
}

long KRB5_CALLCONV
krb5int_get_plugin_func (struct plugin_file_handle *h, const char *csymname,
			 void (**ptr)(), struct errinfo *ep)
{
    void *dptr = NULL;    
    long err = krb5int_get_plugin_sym (h, csymname, 1, &dptr, ep);
    if (!err) {
        /* Cast function pointers to avoid code duplication */
        *ptr = (void (*)()) dptr;
    }
    return err;
}

void KRB5_CALLCONV
krb5int_close_plugin (struct plugin_file_handle *h)
{
#if USE_DLOPEN
    if (h->dlhandle != NULL) { dlclose(h->dlhandle); }
#endif
#if USE_CFBUNDLE
    /* Do not call CFBundleUnloadExecutable because it's not ref counted. 
     * CFRelease will unload the bundle if the internal refcount goes to zero. */
    if (h->bundle != NULL) { CFRelease (h->bundle); }
#endif
    free (h);
}

/* autoconf docs suggest using this preference order */
#if HAVE_DIRENT_H || USE_DIRENT_H
#include <dirent.h>
#define NAMELEN(D) strlen((D)->d_name)
#else
#define dirent direct
#define NAMELEN(D) ((D)->d->namlen)
#if HAVE_SYS_NDIR_H
# include <sys/ndir.h>
#elif HAVE_SYS_DIR_H
# include <sys/dir.h>
#elif HAVE_NDIR_H
# include <ndir.h>
#endif
#endif


#ifdef HAVE_STRERROR_R
#define ERRSTR(ERR, BUF) \
    (strerror_r (ERR, BUF, sizeof(BUF)) == 0 ? BUF : strerror (ERR))
#else
#define ERRSTR(ERR, BUF) \
    (strerror (ERR))
#endif

long KRB5_CALLCONV
krb5int_open_plugin_dir (const char *dirname,
			 struct plugin_dir_handle *dirhandle,
			 struct errinfo *ep)
{
    long err = 0;
    DIR *dir = NULL;
    struct dirent *d = NULL;
    struct plugin_file_handle **h = NULL;
    int count = 0;

    if (!err) {
        h = calloc (1, sizeof (*h)); /* calloc initializes to NULL */
        if (h == NULL) { err = errno; }
    }
    
    if (!err) {
        dir = opendir(dirname);
        if (dir == NULL) {
            err = errno;
            Tprintf ("-> error %d/%s\n", err, strerror (err));
        }
    }
    
    while (!err) {
        size_t len = 0;
        char *path = NULL;
        struct plugin_file_handle *handle = NULL;
        
        d = readdir (dir);
	if (d == NULL) { break; }
        
        if ((strcmp (d->d_name, ".") == 0) || 
            (strcmp (d->d_name, "..") == 0)) {
            continue;
        }
        
        if (!err) {
            len = NAMELEN (d);
            path = malloc (strlen (dirname) + len + 2); /* '/' and NULL */
            if (path == NULL) { 
                err = errno; 
            } else {
                sprintf (path, "%s/%*s", dirname, (int) len, d->d_name);
            }
        }
        
        if (!err) {            
            if (krb5int_open_plugin (path, &handle, ep) == 0) {
                struct plugin_file_handle **newh = NULL;

                count++;
                newh = realloc (h, ((count + 1) + sizeof (*h))); /* +1 for NULL */
                if (newh == NULL) { 
                    err = errno; 
                } else {
                    h = newh;
                    h[count - 1] = handle;
                    h[count] = NULL;
                    handle = NULL;  /* h takes ownership */
                }
            }
        }
        
        if (path   != NULL) { free (path); }
        if (handle != NULL) { krb5int_close_plugin (handle); }
    }
    
    if (err == ENOENT) {
        err = 0;  /* ran out of plugins -- do nothing */
    }
     
    if (!err) {
        dirhandle->files = h;
        h = NULL;  /* dirhandle->files takes ownership */
    }
    
    if (h != NULL) {
        int i;
        for (i = 0; h[i] != NULL; i++) {
            krb5int_close_plugin (h[i]);
        }
        free (h);
    }
    if (dir != NULL) { closedir (dir); }
    
    return err;
}

void KRB5_CALLCONV
krb5int_close_plugin_dir (struct plugin_dir_handle *dirhandle)
{
    if (dirhandle->files != NULL) {
        int i;
        for (i = 0; dirhandle->files[i] != NULL; i++) {
            krb5int_close_plugin (dirhandle->files[i]);
        }
        free (dirhandle->files);
        dirhandle->files = NULL;
    }
}

void KRB5_CALLCONV
krb5int_free_plugin_dir_data (void **ptrs)
{
    /* Nothing special to be done per pointer.  */
    free(ptrs);
}

long KRB5_CALLCONV
krb5int_get_plugin_dir_data (struct plugin_dir_handle *dirhandle,
			     const char *symname,
			     void ***ptrs,
			     struct errinfo *ep)
{
    long err = 0;
    void **p = NULL;
    int count = 0;

    /* XXX Do we need to add a leading "_" to the symbol name on any
       modern platforms?  */
    
    Tprintf("get_plugin_data_sym(%s)\n", symname);

    if (!err) {
        p = calloc (1, sizeof (*p)); /* calloc initializes to NULL */
        if (p == NULL) { err = errno; }
    }
    
    if (!err && (dirhandle != NULL) && (dirhandle->files != NULL)) {
        int i = 0;

        for (i = 0; !err && (dirhandle->files[i] != NULL); i++) {
            void *sym = NULL;

            if (krb5int_get_plugin_data (dirhandle->files[i], symname, &sym, ep) == 0) {
                void **newp = NULL;

                count++;
                newp = realloc (p, ((count + 1) + sizeof (*p))); /* +1 for NULL */
                if (newp == NULL) { 
                    err = errno; 
                } else {
                    p = newp;
                    p[count - 1] = sym;
                    p[count] = NULL;
                }
            }
        }
    }
    
    if (!err) {
        *ptrs = p;
        p = NULL; /* ptrs takes ownership */
    }
    
    if (p != NULL) { free (p); }
    
    return err;
}

void KRB5_CALLCONV
krb5int_free_plugin_dir_func (void (**ptrs)(void))
{
    /* Nothing special to be done per pointer.  */
    free(ptrs);
}

long KRB5_CALLCONV
krb5int_get_plugin_dir_func (struct plugin_dir_handle *dirhandle,
			     const char *symname,
			     void (***ptrs)(void),
			     struct errinfo *ep)
{
    long err = 0;
    void (**p)() = NULL;
    int count = 0;
    
    /* XXX Do we need to add a leading "_" to the symbol name on any
        modern platforms?  */
    
    Tprintf("get_plugin_data_sym(%s)\n", symname);
    
    if (!err) {
        p = calloc (1, sizeof (*p)); /* calloc initializes to NULL */
        if (p == NULL) { err = errno; }
    }
    
    if (!err && (dirhandle != NULL) && (dirhandle->files != NULL)) {
        int i = 0;
        
        for (i = 0; !err && (dirhandle->files[i] != NULL); i++) {
            void (*sym)() = NULL;
            
            if (krb5int_get_plugin_func (dirhandle->files[i], symname, &sym, ep) == 0) {
                void (**newp)() = NULL;

                count++;
                newp = realloc (p, ((count + 1) + sizeof (*p))); /* +1 for NULL */
                if (newp == NULL) { 
                    err = errno; 
                } else {
                    p = newp;
                    p[count - 1] = sym;
                    p[count] = NULL;
                }
            }
        }
    }
    
    if (!err) {
        *ptrs = p;
        p = NULL; /* ptrs takes ownership */
    }
    
    if (p != NULL) { free (p); }
    
    return err;
}

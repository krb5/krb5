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
#define NULL_HANDLE(X) ((X)->dlhandle == NULL)
#define MAKE_NULL_HANDLE(X) ((X)->dlhandle = NULL)
/* #elif _WIN32 ... */
#else
    char dummy;
#define NULL_HANDLE(X) (1)
#define MAKE_NULL_HANDLE(X) (0)
#endif
};

int32_t KRB5_CALLCONV
krb5int_open_plugin (const char *filename, struct plugin_file_handle **h)
{
#if USE_DLOPEN
    struct plugin_file_handle *htmp;
    void *handle;

    handle = dlopen(filename, RTLD_NOW | RTLD_GLOBAL);
    if (handle == NULL) {
	const char *e;
	e = dlerror();
	/* XXX copy and save away */
	return ENOENT;		/* XXX */
    }
    htmp = malloc (sizeof (*htmp));
    if (htmp == NULL) {
	int err = errno;
	dlclose(handle);
	return err;
    }
    *h = htmp;
    htmp->dlhandle = handle;
    return 0;
/* #elif _WIN32 */
#else
    return ENOENT;
#endif
}

int32_t KRB5_CALLCONV
krb5int_get_plugin_data (struct plugin_file_handle *h, const char *csymname,
			 void **ptr)
{
#if USE_DLOPEN
    void *sym;
    /* XXX Do we need to add a leading "_" to the symbol name on any
       modern platforms?  */
    sym = dlsym(h->dlhandle, csymname);
    if (sym == NULL) {
	const char *e;
	e = dlerror();
	return ENOENT;
    }
    *ptr = sym;
    return 0;
/* #elif _WIN32 */
#else
    return ENOENT;
#endif
}

int32_t KRB5_CALLCONV
krb5int_get_plugin_func (struct plugin_file_handle *h, const char *csymname,
			 void (**ptr)())
{
    /* This code should do for any systems where function and data
       symbols are handled the same.  Note that this means there's no
       function version of (say) dlsym, *and* the symbol-prefix
       handling is the same for both data and functions.  (And the
       casting we do here works, etc.)  */
    void *dptr;
    int32_t err;

    err = krb5int_get_plugin_data (h, csymname, &dptr);
    if (err == 0)
	*ptr = (void (*)()) dptr;
    return err;
}

void KRB5_CALLCONV
krb5int_close_plugin (struct plugin_file_handle *h)
{
#if USE_DLOPEN
    dlclose(h->dlhandle);
    h->dlhandle = NULL;
    free (h);
/* #elif _WIN32 */
#endif
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

int32_t KRB5_CALLCONV
krb5int_open_plugin_dir (const char *dirname,
			 struct plugin_dir_handle *dirhandle)
{
    /* Q: Should names be sorted in some way first?  */
    /* XXX This should be a portable directory-scanning routine which
       calls on the above routines; shouldn't be calling dlopen
       directly here.  */
#if USE_DLOPEN
    DIR *dir;
    struct dirent *d;
    struct plugin_file_handle *h, *newh, handle;
    int nh;
    int error = 0;
    char path[MAXPATHLEN];

    h = NULL;
    nh = 0;
    Tprintf("opening plugin directory '%s' to scan...\n", dirname);
    dir = opendir(dirname);
    if (dir == NULL) {
	error = errno;
	Tprintf("-> error %d/%s\n", error, strerror(error));
	if (error == ENOENT)
	    return 0;
	return error;
    }
    do {
	size_t len;
	struct stat statbuf;

	d = readdir (dir);
	if (d == NULL)
	    break;
	len = NAMELEN(d);
	if (strlen(dirname) + len + 2 > sizeof(path))
	    continue;
	sprintf(path, "%s/%*s", dirname, (int) len, d->d_name);
	/* Optimization: Linux includes a file type field in the
	   directory structure.  */
	if (stat(path, &statbuf) < 0) {
	    Tprintf("stat(%s): %s\n", path, strerror(errno));
	    continue;
	}
	if ((statbuf.st_mode & S_IFMT) != S_IFREG) {
	    Tprintf("stat(%s): not a regular file\n", path);
	    continue;
	}
	Tprintf("trying to dlopen '%s'\n", path);
	handle.dlhandle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
	if (handle.dlhandle == NULL) {
	    const char *e = dlerror();
	    Tprintf("dlopen error: %s\n", e);
	    /* dlerror(); */
	    continue;
	} else {
	    Tprintf("dlopen succeeds: %p\n", handle.dlhandle);
	}
	newh = realloc (h, (nh+1) * sizeof(*h));
	if (newh == NULL) {
	    int i;
	close_and_return_errno:
	    error = errno;
	    for (i = 0; i < nh; i++)
		dlclose(h[i].dlhandle);
	    free(h);
	    return error;
	}
	h = newh;
	h[nh] = handle;
	nh++;
    } while (1);
    Tprintf("done scanning plugin directory\n");
    newh = realloc (h, (nh+1) * sizeof(*h));
    if (newh == NULL)
	goto close_and_return_errno;
    h = newh;
    MAKE_NULL_HANDLE (&h[nh]);
    dirhandle->files = h;
    return 0;
/* #elif _WIN32 */
#else
    dirhandle->files = NULL;
    return 0;
#endif
}

void KRB5_CALLCONV
krb5int_close_plugin_dir (struct plugin_dir_handle *dirhandle)
{
#if USE_DLOPEN
    struct plugin_file_handle *h;
    if (dirhandle->files == NULL)
	return;
    for (h = dirhandle->files; !NULL_HANDLE (h); h++) {
	dlclose (h->dlhandle);
    }
    free(dirhandle->files);
    dirhandle->files = NULL;
#endif
}

void KRB5_CALLCONV
krb5int_free_plugin_dir_data (void **ptrs)
{
    /* Nothing special to be done per pointer.  */
    free(ptrs);
}

int32_t KRB5_CALLCONV
krb5int_get_plugin_dir_data (struct plugin_dir_handle *dirhandle,
			     const char *symname,
			     void ***ptrs)
{
    void **p, **newp, *sym;
    int count, i, err;

    /* XXX Do we need to add a leading "_" to the symbol name on any
       modern platforms?  */

    Tprintf("get_plugin_data_sym(%s)\n", symname);
    p = 0;
    count = 0;
    if (dirhandle == NULL || dirhandle->files == NULL)
	goto skip_loop;
    for (i = 0; !NULL_HANDLE (&dirhandle->files[i]); i++) {
	int32_t kerr;
	sym = NULL;
	kerr = krb5int_get_plugin_data(&dirhandle->files[i], symname, &sym);
	if (kerr)
	    continue;
	newp = realloc (p, (count+1) * sizeof(*p));
	if (newp == NULL) {
	realloc_failure:
	    err = errno;
	    free(p);
	    return err;
	}
	p = newp;
	p[count] = sym;
	count++;
    }
skip_loop:
    newp = realloc(p, (count+1) * sizeof(*p));
    if (newp == NULL)
	goto realloc_failure;
    p = newp;
    p[count] = NULL;
    *ptrs = p;
    return 0;
}

void KRB5_CALLCONV
krb5int_free_plugin_dir_func (void (**ptrs)(void))
{
    /* Nothing special to be done per pointer.  */
    free(ptrs);
}

int32_t KRB5_CALLCONV
krb5int_get_plugin_dir_func (struct plugin_dir_handle *dirhandle,
			     const char *symname,
			     void (***ptrs)(void))
{
    void (**p)(), (**newp)(), (*sym)();
    int count, i, err;

    if (dirhandle == NULL) {
	*ptrs = 0;
	return 0;
    }

    /* XXX Do we need to add a leading "_" to the symbol name on any
       modern platforms?  */

    p = 0;
    count = 0;
    for (i = 0; !NULL_HANDLE (&dirhandle->files[i]); i++) {
	int32_t kerr;
	kerr = krb5int_get_plugin_func(&dirhandle->files[i], symname, &sym);
	if (kerr)
	    continue;
	newp = realloc (p, (count+1) * sizeof(*p));
	if (newp == NULL) {
	realloc_failure:
	    err = errno;
	    free(p);
	    return err;
	}
	p = newp;
	p[count] = sym;
	count++;
    }
    newp = realloc(p, (count+1) * sizeof(*p));
    if (newp == NULL)
	goto realloc_failure;
    p[count] = NULL;
    *ptrs = p;
    return 0;
}

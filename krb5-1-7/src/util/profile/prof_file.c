/*
 * prof_file.c ---- routines that manipulate an individual profile file.
 */

#include "prof_int.h"

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <stddef.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#if defined(_WIN32)
#include <io.h>
#define HAVE_STAT	
#define stat _stat
#endif

#include "k5-platform.h"

struct global_shared_profile_data {
	/* This is the head of the global list of shared trees */
	prf_data_t trees;
	/* Lock for above list.  */
	k5_mutex_t mutex;
};
#define g_shared_trees		(krb5int_profile_shared_data.trees)
#define g_shared_trees_mutex	(krb5int_profile_shared_data.mutex)

static struct global_shared_profile_data krb5int_profile_shared_data = {
    0,
    K5_MUTEX_PARTIAL_INITIALIZER
};

MAKE_INIT_FUNCTION(profile_library_initializer);
MAKE_FINI_FUNCTION(profile_library_finalizer);

int profile_library_initializer(void)
{
#ifdef SHOW_INITFINI_FUNCS
    printf("profile_library_initializer\n");
#endif
    add_error_table(&et_prof_error_table);

    return k5_mutex_finish_init(&g_shared_trees_mutex);
}
void profile_library_finalizer(void)
{
    if (! INITIALIZER_RAN(profile_library_initializer) || PROGRAM_EXITING()) {
#ifdef SHOW_INITFINI_FUNCS
	printf("profile_library_finalizer: skipping\n");
#endif
	return;
    }
#ifdef SHOW_INITFINI_FUNCS
    printf("profile_library_finalizer\n");
#endif
    k5_mutex_destroy(&g_shared_trees_mutex);

    remove_error_table(&et_prof_error_table);
}

static void profile_free_file_data(prf_data_t);

#if 0

#define scan_shared_trees_locked()				\
	{							\
	    prf_data_t d;					\
	    k5_mutex_assert_locked(&g_shared_trees_mutex);	\
	    for (d = g_shared_trees; d; d = d->next) {		\
		assert(d->magic == PROF_MAGIC_FILE_DATA);	\
		assert((d->flags & PROFILE_FILE_SHARED) != 0);	\
		assert(d->filespec[0] != 0);			\
		assert(d->fslen <= 1000); /* XXX */		\
		assert(d->filespec[d->fslen] == 0);		\
		assert(d->fslen = strlen(d->filespec));		\
		assert(d->root != NULL);			\
	    }							\
	}

#define scan_shared_trees_unlocked()			\
	{						\
	    int r;					\
	    r = k5_mutex_lock(&g_shared_trees_mutex);	\
	    assert (r == 0);				\
	    scan_shared_trees_locked();			\
	    k5_mutex_unlock(&g_shared_trees_mutex);	\
	}

#else

#define scan_shared_trees_locked()	{ ; }
#define scan_shared_trees_unlocked()	{ ; }

#endif

static int rw_access(const_profile_filespec_t filespec)
{
#ifdef HAVE_ACCESS
	if (access(filespec, W_OK) == 0)
		return 1;
	else
		return 0;
#else
	/*
	 * We're on a substandard OS that doesn't support access.  So
	 * we kludge a test using stdio routines, and hope fopen
	 * checks the r/w permissions.
	 */
	FILE	*f;

	f = fopen(filespec, "r+");
	if (f) {
		fclose(f);
		return 1;
	}
	return 0;
#endif
}

static int r_access(const_profile_filespec_t filespec)
{
#ifdef HAVE_ACCESS
	if (access(filespec, R_OK) == 0)
		return 1;
	else
		return 0;
#else
	/*
	 * We're on a substandard OS that doesn't support access.  So
	 * we kludge a test using stdio routines, and hope fopen
	 * checks the r/w permissions.
	 */
	FILE	*f;

	f = fopen(filespec, "r");
	if (f) {
		fclose(f);
		return 1;
	}
	return 0;
#endif
}

int profile_file_is_writable(prf_file_t profile)
{
    if (profile && profile->data) {
        return rw_access(profile->data->filespec);
    } else {
        return 0;
    }
}

prf_data_t
profile_make_prf_data(const char *filename)
{
    prf_data_t d;
    size_t len, flen, slen;
    char *fcopy;

    flen = strlen(filename);
    slen = offsetof(struct _prf_data_t, filespec);
    len = slen + flen + 1;
    if (len < sizeof(struct _prf_data_t))
	len = sizeof(struct _prf_data_t);
    d = malloc(len);
    if (d == NULL)
	return NULL;
    memset(d, 0, len);
    fcopy = (char *) d + slen;
    assert(fcopy == d->filespec);
    strlcpy(fcopy, filename, flen + 1);
    d->refcount = 1;
    d->comment = NULL;
    d->magic = PROF_MAGIC_FILE_DATA;
    d->root = NULL;
    d->next = NULL;
    d->fslen = flen;
    return d;
}

errcode_t profile_open_file(const_profile_filespec_t filespec,
			    prf_file_t *ret_prof)
{
	prf_file_t	prf;
	errcode_t	retval;
	char		*home_env = 0;
	prf_data_t	data;
	char		*expanded_filename;

	retval = CALL_INIT_FUNCTION(profile_library_initializer);
	if (retval)
		return retval;

	scan_shared_trees_unlocked();

	prf = malloc(sizeof(struct _prf_file_t));
	if (!prf)
		return ENOMEM;
	memset(prf, 0, sizeof(struct _prf_file_t));
	prf->magic = PROF_MAGIC_FILE;

	if (filespec[0] == '~' && filespec[1] == '/') {
		home_env = getenv("HOME");
#ifdef HAVE_PWD_H
		if (home_env == NULL) {
		    uid_t uid;
		    struct passwd *pw, pwx;
		    char pwbuf[BUFSIZ];

		    uid = getuid();
		    if (!k5_getpwuid_r(uid, &pwx, pwbuf, sizeof(pwbuf), &pw)
			&& pw != NULL && pw->pw_dir[0] != 0)
			home_env = pw->pw_dir;
		}
#endif
	}
	if (home_env) {
	    if (asprintf(&expanded_filename, "%s%s", home_env,
			 filespec + 1) < 0)
		expanded_filename = 0;
	} else
	    expanded_filename = strdup(filespec);
	if (expanded_filename == 0) {
	    free(prf);
	    return ENOMEM;
	}

	retval = k5_mutex_lock(&g_shared_trees_mutex);
	if (retval) {
	    free(expanded_filename);
	    free(prf);
	    scan_shared_trees_unlocked();
	    return retval;
	}
	scan_shared_trees_locked();
	for (data = g_shared_trees; data; data = data->next) {
	    if (!strcmp(data->filespec, expanded_filename)
		/* Check that current uid has read access.  */
		&& r_access(data->filespec))
		break;
	}
	if (data) {
	    data->refcount++;
	    (void) k5_mutex_unlock(&g_shared_trees_mutex);
	    retval = profile_update_file_data(data);
	    free(expanded_filename);
	    prf->data = data;
	    *ret_prof = prf;
	    scan_shared_trees_unlocked();
	    return retval;
	}
	(void) k5_mutex_unlock(&g_shared_trees_mutex);
	data = profile_make_prf_data(expanded_filename);
	if (data == NULL) {
	    free(prf);
	    free(expanded_filename);
	    return ENOMEM;
	}
	free(expanded_filename);
	prf->data = data;

	retval = k5_mutex_init(&data->lock);
	if (retval) {
	    free(data);
	    free(prf);
	    return retval;
	}

	retval = profile_update_file(prf);
	if (retval) {
		profile_close_file(prf);
		return retval;
	}

	retval = k5_mutex_lock(&g_shared_trees_mutex);
	if (retval) {
	    profile_close_file(prf);
	    scan_shared_trees_unlocked();
	    return retval;
	}
	scan_shared_trees_locked();
	data->flags |= PROFILE_FILE_SHARED;
	data->next = g_shared_trees;
	g_shared_trees = data;
	scan_shared_trees_locked();
	(void) k5_mutex_unlock(&g_shared_trees_mutex);

	*ret_prof = prf;
	return 0;
}

errcode_t profile_update_file_data_locked(prf_data_t data)
{
	errcode_t retval;
#ifdef HAVE_STAT
	struct stat st;
	unsigned long frac;
	time_t now;
#endif
	FILE *f;

#ifdef HAVE_STAT
	now = time(0);
	if (now == data->last_stat && data->root != NULL) {
	    return 0;
	}
	if (stat(data->filespec, &st)) {
	    return errno;
	}
	data->last_stat = now;
#if defined HAVE_STRUCT_STAT_ST_MTIMENSEC
	frac = st.st_mtimensec;
#elif defined HAVE_STRUCT_STAT_ST_MTIMESPEC_TV_NSEC
	frac = st.st_mtimespec.tv_nsec;
#elif defined HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC
	frac = st.st_mtim.tv_nsec;
#else
	frac = 0;
#endif
	if (st.st_mtime == data->timestamp
	    && frac == data->frac_ts
	    && data->root != NULL) {
	    return 0;
	}
	if (data->root) {
		profile_free_node(data->root);
		data->root = 0;
	}
	if (data->comment) {
		free(data->comment);
		data->comment = 0;
	}
#else
	/*
	 * If we don't have the stat() call, assume that our in-core
	 * memory image is correct.  That is, we won't reread the
	 * profile file if it changes.
	 */
	if (data->root) {
	    return 0;
	}
#endif
	errno = 0;
	f = fopen(data->filespec, "r");
	if (f == NULL) {
		retval = errno;
		if (retval == 0)
			retval = ENOENT;
		return retval;
	}
	set_cloexec_file(f);
	data->upd_serial++;
	data->flags &= PROFILE_FILE_SHARED;  /* FIXME same as '=' operator */
	retval = profile_parse_file(f, &data->root);
	fclose(f);
	if (retval) {
	    return retval;
	}
	assert(data->root != NULL);
#ifdef HAVE_STAT
	data->timestamp = st.st_mtime;
	data->frac_ts = frac;
#endif
	return 0;
}

errcode_t profile_update_file_data(prf_data_t data)
{
    errcode_t retval, retval2;

    retval = k5_mutex_lock(&data->lock);
    if (retval)
	return retval;
    retval = profile_update_file_data_locked(data);
    retval2 = k5_mutex_unlock(&data->lock);
    return retval ? retval : retval2;
}

static int
make_hard_link(const char *oldpath, const char *newpath)
{
#ifdef _WIN32
    return -1;
#else
    return link(oldpath, newpath);
#endif
}

static errcode_t write_data_to_file(prf_data_t data, const char *outfile,
				    int can_create)
{
	FILE		*f;
	profile_filespec_t new_file;
	profile_filespec_t old_file;
	errcode_t	retval = 0;

	retval = ENOMEM;
	
	new_file = old_file = 0;
	if (asprintf(&new_file, "%s.$$$", outfile) < 0) {
	    new_file = NULL;
	    goto errout;
	}
	if (asprintf(&old_file, "%s.bak", outfile) < 0) {
	    old_file = NULL;
	    goto errout;
	}

	errno = 0;

	f = fopen(new_file, "w");
	if (!f) {
		retval = errno;
		if (retval == 0)
			retval = PROF_FAIL_OPEN;
		goto errout;
	}

	set_cloexec_file(f);
	profile_write_tree_file(data->root, f);
	if (fclose(f) != 0) {
		retval = errno;
		goto errout;
	}

	unlink(old_file);
	if (make_hard_link(outfile, old_file) == 0) {
	    /* Okay, got the hard link.  Yay.  Now we've got our
	       backup version, so just put the new version in
	       place.  */
	    if (rename(new_file, outfile)) {
		/* Weird, the rename didn't work.  But the old version
		   should still be in place, so no special cleanup is
		   needed.  */
		retval = errno;
		goto errout;
	    }
	} else if (errno == ENOENT && can_create) {
	    if (rename(new_file, outfile)) {
		retval = errno;
		goto errout;
	    }
	} else {
	    /* Couldn't make the hard link, so there's going to be a
	       small window where data->filespec does not refer to
	       either version.  */
#ifndef _WIN32
	    sync();
#endif
	    if (rename(outfile, old_file)) {
		retval = errno;
		goto errout;
	    }
	    if (rename(new_file, outfile)) {
		retval = errno;
		rename(old_file, outfile); /* back out... */
		goto errout;
	    }
	}

	data->flags = 0;
	retval = 0;

errout:
	if (new_file)
		free(new_file);
	if (old_file)
		free(old_file);
	return retval;
}

errcode_t profile_flush_file_data_to_buffer (prf_data_t data, char **bufp)
{
	errcode_t	retval;
	retval = k5_mutex_lock(&data->lock);
	if (retval)
		return retval;
	retval = profile_write_tree_to_buffer(data->root, bufp);
	k5_mutex_unlock(&data->lock);
	return retval;
}

errcode_t profile_flush_file_data(prf_data_t data)
{
	errcode_t	retval = 0;

	if (!data || data->magic != PROF_MAGIC_FILE_DATA)
		return PROF_MAGIC_FILE_DATA;

	retval = k5_mutex_lock(&data->lock);
	if (retval)
	    return retval;
	
	if ((data->flags & PROFILE_FILE_DIRTY) == 0) {
	    k5_mutex_unlock(&data->lock);
	    return 0;
	}

	retval = write_data_to_file(data, data->filespec, 0);
	k5_mutex_unlock(&data->lock);
	return retval;
}

errcode_t profile_flush_file_data_to_file(prf_data_t data, const char *outfile)
{
    errcode_t retval = 0;

    if (!data || data->magic != PROF_MAGIC_FILE_DATA)
	return PROF_MAGIC_FILE_DATA;

    retval = k5_mutex_lock(&data->lock);
    if (retval)
	return retval;
    retval = write_data_to_file(data, outfile, 1);
    k5_mutex_unlock(&data->lock);
    return retval;
}



void profile_dereference_data(prf_data_t data)
{
    int err;
    err = k5_mutex_lock(&g_shared_trees_mutex);
    if (err)
	return;
    profile_dereference_data_locked(data);
    (void) k5_mutex_unlock(&g_shared_trees_mutex);
}
void profile_dereference_data_locked(prf_data_t data)
{
    scan_shared_trees_locked();
    data->refcount--;
    if (data->refcount == 0)
	profile_free_file_data(data);
    scan_shared_trees_locked();
}

int profile_lock_global()
{
    return k5_mutex_lock(&g_shared_trees_mutex);
}
int profile_unlock_global()
{
    return k5_mutex_unlock(&g_shared_trees_mutex);
}

void profile_free_file(prf_file_t prf)
{
    profile_dereference_data(prf->data);
    free(prf);
}

/* Call with mutex locked!  */
static void profile_free_file_data(prf_data_t data)
{
    scan_shared_trees_locked();
    if (data->flags & PROFILE_FILE_SHARED) {
	/* Remove from linked list.  */
	if (g_shared_trees == data)
	    g_shared_trees = data->next;
	else {
	    prf_data_t prev, next;
	    prev = g_shared_trees;
	    next = prev->next;
	    while (next) {
		if (next == data) {
		    prev->next = next->next;
		    break;
		}
		prev = next;
		next = next->next;
	    }
	}
    }
    if (data->root)
	profile_free_node(data->root);
    if (data->comment)
	free(data->comment);
    data->magic = 0;
    k5_mutex_destroy(&data->lock);
    free(data);
    scan_shared_trees_locked();
}

errcode_t profile_close_file(prf_file_t prf)
{
	errcode_t	retval;
	
	retval = profile_flush_file(prf);
	if (retval)
		return retval;
	profile_free_file(prf);
	return 0;
}

/*
 * prof_file.c ---- routines that manipulate an individual profile file.
 */

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>

#include "prof_int.h"

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

#ifdef SHARE_TREE_DATA
struct global_shared_profile_data krb5int_profile_shared_data = {
    0
};
#endif

static void profile_free_file_data(prf_data_t);

static int rw_access(filespec)
	profile_filespec_t filespec;
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

static int r_access(filespec)
	profile_filespec_t filespec;
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

errcode_t profile_open_file(filespec, ret_prof)
	const_profile_filespec_t filespec;
	prf_file_t *ret_prof;
{
	prf_file_t	prf;
	errcode_t	retval;
	char		*home_env = 0;
	unsigned int	len;
	prf_data_t	data;
	char		*expanded_filename;

	prf = malloc(sizeof(struct _prf_file_t));
	if (!prf)
		return ENOMEM;
	memset(prf, 0, sizeof(struct _prf_file_t));
	prf->magic = PROF_MAGIC_FILE;

	len = strlen(filespec)+1;
	if (filespec[0] == '~' && filespec[1] == '/') {
		home_env = getenv("HOME");
#ifdef HAVE_PWD_H
		if (home_env == NULL) {
		    uid_t uid;
		    struct passwd *pw;

		    uid = getuid();
		    pw = getpwuid(uid);
		    if (pw != NULL && pw->pw_dir[0] != 0)
			home_env = pw->pw_dir;
		}
#endif
		if (home_env)
			len += strlen(home_env);
	}
	expanded_filename = malloc(len);
	if (expanded_filename == 0)
	    return errno;
	if (home_env) {
	    strcpy(expanded_filename, home_env);
	    strcat(expanded_filename, filespec+1);
	} else
	    memcpy(expanded_filename, filespec, len);

#ifdef SHARE_TREE_DATA
	(void) prof_mutex_lock(&g_shared_trees_mutex);
	for (data = g_shared_trees; data; data = data->next) {
	    if (!strcmp(data->filespec, expanded_filename)
		/* Check that current uid has read access.  */
		&& r_access(data->filespec))
		break;
	}
	if (data) {
	    retval = profile_update_file_data(data);
	    data->refcount++;
	    (void) prof_mutex_unlock(&g_shared_trees_mutex);
	    free(expanded_filename);
	    prf->data = data;
	    *ret_prof = prf;
	    return retval;
	}
	(void) prof_mutex_unlock(&g_shared_trees_mutex);
	data = malloc(sizeof(struct _prf_data_t));
	if (data == NULL) {
	    free(prf);
	    return ENOMEM;
	}
	memset(data, 0, sizeof(*data));
	prf->data = data;
#else
	data = prf->data;
#endif

	data->magic = PROF_MAGIC_FILE_DATA;
	data->refcount = 1;
	data->comment = 0;
	data->filespec = expanded_filename;

	retval = profile_update_file(prf);
	if (retval) {
		profile_close_file(prf);
		return retval;
	}

#ifdef SHARE_TREE_DATA
	data->flags |= PROFILE_FILE_SHARED;
	(void) prof_mutex_lock(&g_shared_trees_mutex);
	data->next = g_shared_trees;
	g_shared_trees = data;
	(void) prof_mutex_unlock(&g_shared_trees_mutex);
#endif

	*ret_prof = prf;
	return 0;
}

errcode_t profile_update_file_data(prf_data_t data)
{
	errcode_t retval;
#ifdef HAVE_STAT
	struct stat st;
#endif
	FILE *f;

#ifdef HAVE_STAT
	if (stat(data->filespec, &st))
		return errno;
	if (st.st_mtime == data->timestamp)
		return 0;
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
	if (data->root)
		return 0;
#endif
	errno = 0;
	f = fopen(data->filespec, "r");
	if (f == NULL) {
		retval = errno;
		if (retval == 0)
			retval = ENOENT;
		return retval;
	}
	data->upd_serial++;
	data->flags = 0;
	if (rw_access(data->filespec))
		data->flags |= PROFILE_FILE_RW;
	retval = profile_parse_file(f, &data->root);
	fclose(f);
	if (retval)
		return retval;
#ifdef HAVE_STAT
	data->timestamp = st.st_mtime;
#endif
	return 0;
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

errcode_t profile_flush_file_data(data)
	prf_data_t data;
{
	FILE		*f;
	profile_filespec_t new_file;
	profile_filespec_t old_file;
	errcode_t	retval = 0;
	
	if (!data || data->magic != PROF_MAGIC_FILE_DATA)
		return PROF_MAGIC_FILE_DATA;
	
	if ((data->flags & PROFILE_FILE_DIRTY) == 0)
		return 0;

	retval = ENOMEM;
	
	new_file = old_file = 0;
	new_file = malloc(strlen(data->filespec) + 5);
	if (!new_file)
		goto errout;
	old_file = malloc(strlen(data->filespec) + 5);
	if (!old_file)
		goto errout;

	sprintf(new_file, "%s.$$$", data->filespec);
	sprintf(old_file, "%s.bak", data->filespec);

	errno = 0;

	f = fopen(new_file, "w");
	if (!f) {
		retval = errno;
		if (retval == 0)
			retval = PROF_FAIL_OPEN;
		goto errout;
	}

	profile_write_tree_file(data->root, f);
	if (fclose(f) != 0) {
		retval = errno;
		goto errout;
	}

	unlink(old_file);
	if (make_hard_link(data->filespec, old_file) == 0) {
	    /* Okay, got the hard link.  Yay.  Now we've got our
	       backup version, so just put the new version in
	       place.  */
	    if (rename(new_file, data->filespec)) {
		/* Weird, the rename didn't work.  But the old version
		   should still be in place, so no special cleanup is
		   needed.  */
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
	    if (rename(data->filespec, old_file)) {
		retval = errno;
		goto errout;
	    }
	    if (rename(new_file, data->filespec)) {
		retval = errno;
		rename(old_file, data->filespec); /* back out... */
		goto errout;
	    }
	}

	data->flags = 0;
	if (rw_access(data->filespec))
		data->flags |= PROFILE_FILE_RW;
	retval = 0;
	
errout:
	if (new_file)
		free(new_file);
	if (old_file)
		free(old_file);
	return retval;
}


void profile_dereference_data(prf_data_t data)
{
#ifdef SHARE_TREE_DATA
    (void) prof_mutex_lock(&g_shared_trees_mutex);
    data->refcount--;
    if (data->refcount == 0)
	profile_free_file_data(data);
    (void) prof_mutex_unlock(&g_shared_trees_mutex);
#else
    profile_free_file_data(data);
#endif
}

void profile_free_file(prf)
	prf_file_t prf;
{
    profile_dereference_data(prf->data);
    free(prf);
}

/* Call with mutex locked!  */
static void profile_free_file_data(data)
	prf_data_t data;
{
#ifdef SHARE_TREE_DATA
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
#endif
	if (data->filespec)
		free(data->filespec);
	if (data->root)
		profile_free_node(data->root);
	if (data->comment)
		free(data->comment);
	data->magic = 0;
#ifdef SHARE_TREE_DATA
	free(data);
#endif
}

errcode_t profile_close_file(prf)
	prf_file_t prf;
{
	errcode_t	retval;
	
	retval = profile_flush_file(prf);
	if (retval)
		return retval;
	profile_free_file(prf);
	return 0;
}

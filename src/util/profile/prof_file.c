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

#ifndef NO_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifndef NO_SYS_STAT_H
#include <sys/stat.h>
#endif
#include <errno.h>


#if defined(_MSDOS) || defined(_WIN32)
#include <io.h>
#define HAVE_STAT	
#define stat _stat
#endif

static int rw_access(filename)
	const char *filename;
{
#ifdef HAVE_ACCESS
	if (access(filename, W_OK) == 0)
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

	f = fopen(filename, "r+");
	if (f) {
		fclose(f);
		return 1;
	}
	return 0;
#endif
}

errcode_t profile_open_file(filename, ret_prof)
	const char *filename;
	prf_file_t *ret_prof;
{
	prf_file_t	prf;
	errcode_t	retval;
	char		*home_env = 0;
	int		len;

	prf = malloc(sizeof(struct _prf_file_t));
	if (!prf)
		return ENOMEM;
	memset(prf, 0, sizeof(struct _prf_file_t));
	len = strlen(filename)+1;
	if (filename[0] == '~' && filename[1] == '/') {
		home_env = getenv("HOME");
		if (home_env)
			len += strlen(home_env);
	}
	prf->filename = malloc(len);
	if (!prf->filename) {
		free(prf);
		return ENOMEM;
	}
	if (home_env) {
		strcpy(prf->filename, home_env);
		strcat(prf->filename, filename+1);
	} else
		strcpy(prf->filename, filename);
	prf->magic = PROF_MAGIC_FILE;

	retval = profile_update_file(prf);
	if (retval) {
		profile_close_file(prf);
		return retval;
	}

	*ret_prof = prf;
	return 0;
}

errcode_t profile_update_file(prf)
	prf_file_t prf;
{
	errcode_t retval;
#ifdef HAVE_STAT
	struct stat st;
#endif
	FILE *f;

#ifdef HAVE_STAT
	if (stat(prf->filename, &st))
		return errno;
	if (st.st_mtime == prf->timestamp)
		return 0;
	if (prf->root) {
		profile_free_node(prf->root);
		prf->root = 0;
	}
	if (prf->comment) {
		free(prf->comment);
		prf->comment = 0;
	}
#else
	/*
	 * If we don't have the stat() call, assume that our in-core
	 * memory image is correct.  That is, we won't reread the
	 * profile file if it changes.
	 */
	if (prf->root)
		return 0;
#endif
	errno = 0;
	f = fopen(prf->filename, "r");
	if (f == NULL) {
		retval = errno;
		if (retval == 0)
			retval = PROF_FAIL_OPEN;
		return retval;
	}
	prf->upd_serial++;
	prf->flags = 0;
	if (rw_access(prf->filename))
		prf->flags |= PROFILE_FILE_RW;
	retval = profile_parse_file(f, &prf->root);
	fclose(f);
	if (retval)
		return retval;
#ifdef HAVE_STAT
	prf->timestamp = st.st_mtime;
#endif
	return 0;
}

errcode_t profile_flush_file(prf)
	prf_file_t prf;
{
	FILE		*f;
	char		*new_name = 0, *old_name = 0;
	errcode_t	retval = 0;
	
	if (!prf || prf->magic != PROF_MAGIC_FILE)
		return PROF_MAGIC_FILE;
	
	if ((prf->flags & PROFILE_FILE_DIRTY) == 0)
		return 0;

	retval = ENOMEM;
	new_name = malloc(strlen(prf->filename) + 5);
	if (!new_name)
		goto errout;
	old_name = malloc(strlen(prf->filename) + 5);
	if (!old_name)
		goto errout;

	sprintf(new_name, "%s.$$$", prf->filename);
	sprintf(old_name, "%s.bak", prf->filename);

	errno = 0;
	f = fopen(new_name, "w");
	if (!f) {
		retval = errno;
		if (retval == 0)
			retval = PROF_FAIL_OPEN;
		goto errout;
	}

	profile_write_tree_file(prf->root, f);
	if (fclose(f) != 0) {
		retval = errno;
		goto errout;
	}

	unlink(old_name);
	if (rename(prf->filename, old_name)) {
		retval = errno;
		goto errout;
	}
	if (rename(new_name, prf->filename)) {
		retval = errno;
		rename(old_name, prf->filename); /* back out... */
		goto errout;
	}

	prf->flags = 0;
	if (rw_access(prf->filename))
		prf->flags |= PROFILE_FILE_RW;
	retval = 0;
	
errout:
	if (new_name)
		free(new_name);
	if (old_name)
		free(old_name);
	return retval;
}


void profile_free_file(prf)
	prf_file_t prf;
{
	if (prf->filename)
		free(prf->filename);
	if (prf->root)
		profile_free_node(prf->root);
	if (prf->comment)
		free(prf->comment);
	prf->magic = 0;
	free(prf);

	return;
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


/*
 * util/berk_db/krb5_ndbm.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/*
 * krb5_ndbm.c	- Customize the dbm wrapper for Kerberos.
 */

/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Margo Seltzer.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)ndbm.c	8.4 (Berkeley) 7/21/94";
#endif /* LIBC_SCCS and not lint */

/*
 * This package provides a dbm compatible interface to the new hashing
 * package described in db(3).
 */

#include <sys/param.h>

#include <stdio.h>
#include <string.h>

#include <ndbm.h>
#include "hash.h"

/* If the two size fields are not equal, then casting between structures will 
   result in stack garbage being transfered. Has been observed for DEC Alpha
   OSF, but will handle the general case.
*/

#ifndef SIZEOF_DBT_SIZE
#define SIZEOF_DBT_SIZE 4
#endif
#ifndef SIZEOF_DATUM_DSIZE
#define SIZEOF_DATUM_DSIZE 4
#endif

#if SIZEOF_DBT_SIZE != SIZEOF_DATUM_DSIZE
#define NEED_COPY
#endif

/*
 * For Kerberos, we make some generalizations about kdb records.  We assume
 * that records are on average KRB5_DBENT_ASIZE in length.
 *
 * Increasing KRB5_DB_BUCKETSIZE doesn't get you much of anything.
 */
#define	KRB5_DB_BUCKETSIZE	1024
#define	KRB5_DBENT_ASIZE	512
#define	KRB5_DB_MINBUCKET	512
#define	KRB5_DB_INITSIZE	128

/*
 * Returns:
 * 	*DBM on success
 *	 NULL on failure
 */
extern DBM *
db_dbm_open(file, flags, mode)
	const char *file;
	int flags, mode;
{
	HASHINFO info;
	char path[MAXPATHLEN];

	info.bsize = KRB5_DB_BUCKETSIZE;
	/*
	 * if (info.bsize < KRB5_DB_MINBUCKET) info.bsize = KRB5_DB_MINBUCKET;
	 */
	info.ffactor = info.bsize / KRB5_DBENT_ASIZE; 
	info.nelem = KRB5_DB_INITSIZE;
	info.cachesize = 0;
	info.hash = NULL;
	/* Always store databases in big endian (e.g. network order) */
	info.lorder = BIG_ENDIAN;
	(void)strcpy(path, file);
	(void)strcat(path, DBM_SUFFIX);
	return ((DBM *)__hash_open(path, flags, mode, &info, 0));
}

extern void
db_dbm_close(db)
	DBM *db;
{
	(void)(db->close)(db);
}

/*
 * Returns:
 *	DATUM on success
 *	NULL on failure
 */
extern datum
db_dbm_fetch(db, key)
	DBM *db;
	datum key;
{
	datum retval;
	int status;
#ifdef NEED_COPY
	DBT k, r;

	k.data = key.dptr;
	k.size = key.dsize;
	status = (db->get)(db, &k, &r, 0);
	retval.dptr = r.data;
	retval.dsize = r.size;
#else
	status = (db->get)(db, (DBT *)&key, (DBT *)&retval, 0);
#endif
	if (status) {
		retval.dptr = NULL;
		retval.dsize = 0;
	}
	return (retval);
}

/*
 * Returns:
 *	DATUM on success
 *	NULL on failure
 */
extern datum
db_dbm_firstkey(db)
	DBM *db;
{
	int status;
	datum retdata, retkey;
#ifdef NEED_COPY
	DBT k, r;

	status = (db->seq)(db, &k, &r, R_FIRST);
	retkey.dptr = k.data;
	retkey.dsize = k.size;
#else
	status = (db->seq)(db, (DBT *)&retkey, (DBT *)&retdata, R_FIRST);
#endif
	if (status)
		retkey.dptr = NULL;
	return (retkey);
}

/*
 * Returns:
 *	DATUM on success
 *	NULL on failure
 */
extern datum
db_dbm_nextkey(db)
	DBM *db;
{
	int status;
	datum retdata, retkey;
#ifdef NEED_COPY
	DBT k, r;

	status = (db->seq)(db, &k, &r, R_NEXT);
	retkey.dptr = k.data;
	retkey.dsize = k.size;
#else
	status = (db->seq)(db, (DBT *)&retkey, (DBT *)&retdata, R_NEXT);
#endif
	if (status)
		retkey.dptr = NULL;
	return (retkey);
}
/*
 * Returns:
 *	 0 on success
 *	<0 failure
 */
extern int
db_dbm_delete(db, key)
	DBM *db;
	datum key;
{
	int status;
#ifdef NEED_COPY
	DBT k;

	k.data = key.dptr;
	k.size = key.dsize;
	status = (db->del)(db, &k, 0);
#else

	status = (db->del)(db, (DBT *)&key, 0);
#endif
	if (status)
		return (-1);
	else
		return (0);
}

/*
 * Returns:
 *	 0 on success
 *	<0 failure
 *	 1 if DBM_INSERT and entry exists
 */
extern int
db_dbm_store(db, key, content, flags)
	DBM *db;
	datum key, content;
	int flags;
{
#ifdef NEED_COPY
	DBT k, c;

	k.data = key.dptr;
	k.size = key.dsize;
	c.data = content.dptr;
	c.size = content.dsize;
	return ((db->put)(db, &k, &c,
	    (flags == DBM_INSERT) ? R_NOOVERWRITE : 0));
#else
	return ((db->put)(db, (DBT *)&key, (DBT *)&content,
	    (flags == DBM_INSERT) ? R_NOOVERWRITE : 0));
#endif
}

extern int
db_dbm_error(db)
	DBM *db;
{
	HTAB *hp;

	hp = (HTAB *)db->internal;
	return (hp->errno);
}

extern int
db_dbm_clearerr(db)
	DBM *db;
{
	HTAB *hp;

	hp = (HTAB *)db->internal;
	hp->errno = 0;
	return (0);
}

extern int
db_dbm_dirfno(db)
	DBM *db;
{
	return(((HTAB *)db->internal)->fp);
}

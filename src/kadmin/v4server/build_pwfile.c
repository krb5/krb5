#define NDBM
/*
 * build_pwfile.c  --- build a table of bad passwords, keyed by their
 * 	des equivalents.
 *
 * Written by Theodore Ts'o
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#ifndef	lint
static char rcsid_build_pwfile_c[] =
"$Id$";
#endif	lint

#include <mit-copyright.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/file.h>

#ifdef NDBM
#include <ndbm.h>
#else /*NDBM*/
#include <dbm.h>
#endif /*NDBM*/

#include <kadm.h>
#include <kadm_err.h>
#include <krb_db.h>
#include "kadm_server.h"

/* Macros to convert ndbm names to dbm names.
 * Note that dbm_nextkey() cannot be simply converted using a macro, since
 * it is invoked giving the database, and nextkey() needs the previous key.
 *
 * Instead, all routines call "dbm_next" instead.
 */
#ifndef NDBM
typedef char DBM;
#define dbm_open(file, flags, mode) ((dbminit(file) == 0)?"":((char *)0))
#define dbm_fetch(db, key) fetch(key)
#define dbm_store(db, key, content, flag) store(key, content)
#define dbm_firstkey(db) firstkey()
#define dbm_next(db,key) nextkey(key)
#define dbm_close(db) dbmclose()
#else
#define dbm_next(db,key) dbm_nextkey(db)
#endif

main(argc, argv)
	int	argc;
	char	**argv;
{
	DBM	*pwfile;
	FILE	*f;
	datum	passwd, entry;
	des_cblock	key;
	char		word[1024];
	int		len, filenum, i;
	int		wptr;

	if (argc != 2) {
		fprintf(stderr,"%s: Usage: %s filename\n", argv[0], argv[0]);
		exit(1);
	}
	if (!(f = fopen(argv[1], "r"))) {
		perror(argv[1]);
		exit(1);
	}
	pwfile = dbm_open(PW_CHECK_FILE, O_RDWR|O_CREAT, 0644);
	if (!pwfile) {
		fprintf(stderr, "Couldn't open %s for writing.\n",
			PW_CHECK_FILE);
		perror("dbm_open");
		exit(1);
	}
	filenum = 0;
	do {
		filenum++;
		passwd.dptr = (char *) &filenum;
		passwd.dsize = sizeof(filenum);
		entry.dptr = argv[1];
		entry.dsize = strlen(argv[1])+1;
	} while (dbm_store(pwfile, passwd, entry, DBM_INSERT));
	i = 0;
	while (!feof(f)) {
		i++;
		wptr = (filenum << 24) + i;
		fgets(word, sizeof(word), f);
		len = strlen(word);
		if (len > 0 && word[len-1] == '\n')
			word[--len] = '\0';
#ifdef NOENCRYPTION
		bzero((char *) key, sizeof(des_cblock));
		key[0] = (unsigned char) 1;
#else
		(void) des_string_to_key(word, key);
#endif
		
		passwd.dptr = (char *) key;
		passwd.dsize = 8;
		entry.dptr = (char *) &wptr;
#ifdef notdef
		entry.dsize = sizeof(wptr);
#else
		entry.dsize = 0;
#endif
		dbm_store(pwfile, passwd, entry, DBM_REPLACE);
	}
	dbm_close(pwfile);
	exit(0);
}




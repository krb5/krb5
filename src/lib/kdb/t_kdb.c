/*
 * lib/kdb/t_kdb.c
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/*
 * t_kdb.c	- Test [and optionally obtain timing information about] the
 *		  Kerberos database functions.
 */

#define	KDB5_DISPATCH
#include "k5-int.h"
#include <ctype.h>
#include <sys/time.h>
#include <sys/wait.h>
#include "com_err.h"

#if	HAVE_SRAND48
#define	RAND()		lrand48()
#define	SRAND(a)	srand48(a)
#define	RAND_TYPE	long
#elif	HAVE_SRAND
#define	RAND()		rand()
#define	SRAND(a)	srand(a)
#define	RAND_TYPE	int
#elif	HAVE_SRANDOM
#define	RAND()		random()
#define	SRAND(a)	srandom(a)
#define	RAND_TYPE	long
#else	/* no random */
need a random number generator
#endif	/* no random */

#define	T_KDB_N_PASSES	100
#define	T_KDB_DEF_DB	"test_db"
#define	MAX_PNAME_LEN	1024
#define	MAX_PRINC_COMPS	8
#define	MAX_COMP_SIZE	32

#define	RANDOM(a,b)	(a + (RAND() % (b-a)))

enum dbtype { DB_UFO, DB_DEFAULT, DB_BERKELEY, DB_DBM };

char			*programname = (char *) NULL;
krb5_data		mprinc_data_entries[] = {
    { 0, sizeof("master")-1, "master"},
    { 0, sizeof("key")-1, "key"}
};

krb5_principal_data	master_princ_data = {
    0,						/* Magic number		*/
    { 0, sizeof("test.realm")-1, "test.realm"},	/* Realm		*/
    mprinc_data_entries,			/* Name/instance	*/
    sizeof(mprinc_data_entries)/
	sizeof(mprinc_data_entries[0]),		/* Number		*/
    KRB5_NT_SRV_INST				/* Type			*/
};

struct timeval	tstart_time, tend_time;
struct timezone	dontcare;
krb5_principal	*recorded_principals = (krb5_principal *) NULL;
char		**recorded_names = (char **) NULL;

#ifdef BERK_DB_DBM
extern DBM	*db_dbm_open (char *, int, int);
extern void     db_dbm_close (DBM *);
extern datum    db_dbm_fetch (DBM *, datum);
extern datum    db_dbm_firstkey (DBM *);
extern datum    db_dbm_nextkey (DBM *);
extern int      db_dbm_delete (DBM *, datum);
extern int      db_dbm_store (DBM *, datum, datum, int);
extern int	db_dbm_error (DBM *);
extern int	db_dbm_clearerr (DBM *);
extern int	db_dbm_dirfno (DBM *);

static kdb5_dispatch_table berkeley_dispatch = {
    "Berkeley Hashed Database",
    ".db",			/* Index file name ext	*/
    (char *) NULL,		/* Data file name ext	*/
    ".ok",			/* Lock file name ext	*/
    db_dbm_open,		/* Open Database	*/
    db_dbm_close,		/* Close Database	*/
    db_dbm_fetch,		/* Fetch Key		*/
    db_dbm_firstkey,		/* Fetch First Key	*/
    db_dbm_nextkey,		/* Fetch Next Key	*/
    db_dbm_delete,		/* Delete Key		*/
    db_dbm_store,		/* Store Key		*/
    db_dbm_error,		/* Get Database Error	*/
    db_dbm_clearerr,		/* Clear Database Error	*/
    db_dbm_dirfno,		/* Get Database FD num	*/
    (int (*)()) NULL		/* Get Database FD num	*/
};
#endif

#if defined(NDBM) || defined(ODBM)
/*
 * The following prototypes are necessary in case dbm_error and
 * dbm_clearerr are in the library but not prototyped
 * (e.g. NetBSD-1.0)
 */
#ifdef MISSING_ERROR_PROTO
int dbm_error (DBM *);
#endif
#ifdef MISSING_CLEARERR_PROTO
int dbm_clearerr (DBM *);
#endif

static kdb5_dispatch_table dbm_dispatch = {
    "Stock [N]DBM Database",
    ".dir",			/* Index file name ext	*/
    ".pag",			/* Data file name ext	*/
    ".ok",			/* Lock file name ext	*/
    dbm_open,			/* Open Database	*/
    dbm_close,			/* Close Database	*/
    dbm_fetch,			/* Fetch Key		*/
    dbm_firstkey,		/* Fetch First Key	*/
    dbm_nextkey,		/* Fetch Next Key	*/
    dbm_delete,			/* Delete Key		*/
    dbm_store,			/* Store Key		*/
    /*
     * The following are #ifdef'd because they have the potential to be
     * macros rather than functions.
     */
#ifdef	dbm_error
    (int (*)()) NULL,		/* Get Database Error	*/
#else	/* dbm_error */
#ifdef HAVE_DBM_ERROR
    dbm_error,			/* Get Database Error	*/
#else
    (int (*)()) NULL,		/* Get Database Error	*/
#endif
#endif	/* dbm_error */
#ifdef	dbm_clearerr
    (int (*)()) NULL,		/* Clear Database Error	*/
#else	/* dbm_clearerr */
#ifdef HAVE_DBM_CLEARERR
    dbm_clearerr,		/* Clear Database Error	*/
#else
    (int (*)()) NULL,		/* Clear Database Error	*/
#endif
#endif	/* dbm_clearerr */
#ifdef	dbm_dirfno
    (int (*)()) NULL,		/* Get Database FD num	*/
#else	/* dbm_dirfno */
    dbm_dirfno,			/* Get Database FD num	*/
#endif	/* dbm_dirfno */
#ifdef	dbm_pagfno
    (int (*)()) NULL,		/* Get Database FD num	*/
#else	/* dbm_pagfno */
    dbm_pagfno,			/* Get Database FD num	*/
#endif	/* dbm_pagfno */
};
#endif /* NDBM || ODBM */


/*
 * Timer macros.
 */
#define	swatch_on()	((void) gettimeofday(&tstart_time, &dontcare))
#define	swatch_eltime()	((gettimeofday(&tend_time, &dontcare)) ? -1.0 :	\
			 (((float) (tend_time.tv_sec -			\
				    tstart_time.tv_sec)) +		\
			  (((float) (tend_time.tv_usec -		\
				     tstart_time.tv_usec))/1000000.0)))

/*
 * Free all principals and names in the recorded names list.
 */
static void
free_principals(kcontext, nentries)
    krb5_context	kcontext;
    int 		nentries;
{
    int i;
    if (recorded_principals) {
	for (i=0; i<nentries; i++) {
	    if (recorded_principals[i])
		krb5_free_principal(kcontext, recorded_principals[i]);
	}
	free(recorded_principals);
    }
    recorded_principals = (krb5_principal *) NULL;

    if (recorded_names) {
	for (i=0; i<nentries; i++) {
	    if (recorded_names[i])
		free(recorded_names[i]);
	}
	free(recorded_names);
    }
    recorded_names = (char **) NULL;
}

/*
 * Initialize the recorded names list.
 */
static void
init_princ_recording(kcontext, nentries)
    krb5_context	kcontext;
    int 		nentries;
{
    recorded_principals = (krb5_principal *)
	    malloc(nentries * sizeof(krb5_principal));
    if (!recorded_principals)
	    abort();
    memset((char *) recorded_principals, 0,
	   nentries * sizeof(krb5_principal));
    recorded_names = (char **) malloc(nentries * sizeof(char *));
    if (!recorded_names)
	    abort();
    memset((char *) recorded_names, 0, nentries * sizeof(char *));
}

/*
 * Record a principal and name.
 */
static void
record_principal(slotno, princ, pname)
    int			slotno;
    krb5_principal	princ;
    char		*pname;
{
    recorded_principals[slotno] = princ;
    recorded_names[slotno] = (char *) malloc(strlen(pname)+1);
    if (recorded_names[slotno])
	strcpy(recorded_names[slotno], pname);
}

#define	playback_principal(slotno)	(recorded_principals[slotno])
#define	playback_name(slotno)		(recorded_names[slotno])

/*
 * See if a principal already exists.
 */
static krb5_boolean
principal_found(nvalid, pname)
    int		nvalid;
    char	*pname;
{
    krb5_boolean	found;
    int			i;

    found = 0;
    for (i=0; i<nvalid; i++) {
	if (!strcmp(recorded_names[i], pname)) {
	    found = 1;
	    break;
	}
    }
    return(found);
}

/*
 * Add a principal to the database.
 */
static krb5_error_code
add_principal(kcontext, principal, mkey, key, rseed)
    krb5_context	  kcontext;
    krb5_principal	  principal;
    krb5_keyblock	* mkey;
    krb5_keyblock	* key;
    krb5_pointer	  rseed;
{
    krb5_error_code	  kret;
    krb5_db_entry	  dbent;
    krb5_keyblock	* rkey = NULL, lkey;
    krb5_timestamp	  timenow;
    int			  nentries = 1;

    memset((char *) &dbent, 0, sizeof(dbent));
    dbent.len			= KRB5_KDB_V1_BASE_LENGTH;

    dbent.attributes 		= KRB5_KDB_DEF_FLAGS;
    dbent.max_life 		= KRB5_KDB_MAX_LIFE;
    dbent.expiration 		= KRB5_KDB_EXPIRATION;
    dbent.max_renewable_life 	= KRB5_KDB_MAX_RLIFE;

    if ((kret = krb5_copy_principal(kcontext, principal, &dbent.princ)))
	goto out;

    if ((kret = krb5_timeofday(kcontext, &timenow)))
	goto out;
    if ((kret = krb5_dbe_update_mod_princ_data(kcontext, &dbent,
					       timenow, principal)))
	    goto out;

    if (!key) {
	kret = krb5_c_make_random_key (kcontext, mkey->enctype, &lkey);
	if (kret)
	    goto out;
	rkey = &lkey;
    } else
	rkey = key;

    if ((kret = krb5_dbe_create_key_data(kcontext, &dbent)))
	goto out;
    if ((kret = krb5_dbekd_encrypt_key_data(kcontext, mkey, rkey, NULL, 1,
					    &dbent.key_data[0])))
	goto out;

    if (!key)
	krb5_free_keyblock_contents(kcontext, rkey);

    kret = krb5_db_put_principal(kcontext, &dbent, &nentries);
    if ((!kret) && (nentries != 1))
	kret = KRB5_KDB_UK_SERROR;
 out:
    krb5_dbe_free_contents(kcontext, &dbent);
    return(kret);
}

/*
 * Generate a principal name.
 */
static krb5_error_code
gen_principal(kcontext, realm, do_rand, n, princp, namep)
    krb5_context	kcontext;
    char		*realm;
    int			do_rand;
    int			n;
    krb5_principal	*princp;
    char		**namep;
{
    static char pnamebuf[MAX_PNAME_LEN];
    static char *instnames[] = {
	"instance1", "xxx2", "whereami3", "ABCDEFG4", "foofoo5" };
    static char *princnames[] = {
	"princ1", "user2", "service3" };

    krb5_error_code	kret;
    char		*instname;
    char		*princbase;
    int			ncomps;
    int			i, complen, j;
    char		*cp;

    if (do_rand) {
	ncomps = RANDOM(1,MAX_PRINC_COMPS);
	cp = pnamebuf;
	for (i=0; i<ncomps; i++) {
	    complen = RANDOM(1,MAX_COMP_SIZE);
	    for (j=0; j<complen; j++) {
		*cp = (char) RANDOM(0,256);
		while (!isalnum(*cp & 0xff))
		    *cp = (char) RANDOM(0,256);
		cp++;
	        if(cp + strlen(realm) >= pnamebuf + sizeof(pnamebuf))
		    break;
	    }
	    if(cp + strlen(realm) >= pnamebuf + sizeof(pnamebuf))
		break;
	    *cp = '/';
	    cp++;
	}
	if(cp + strlen(realm) < pnamebuf + sizeof(pnamebuf)) {
	    cp[-1] = '@';
	    strcpy(cp, realm);
	} else {
            strcpy(cp , "");
	}
    }
    else {
	instname = instnames[n % (sizeof(instnames)/sizeof(instnames[0]))];
	princbase = princnames[n % (sizeof(princnames)/sizeof(princnames[0]))];
	sprintf(pnamebuf, "%s%d/%s@%s", princbase, n, instname, realm);
    }
    kret = krb5_parse_name(kcontext, pnamebuf, princp);
    *namep = (!kret) ? pnamebuf : (char *) NULL;
    return(kret);
}

/*
 * Find a principal in the database.
 */
static krb5_error_code
find_principal(kcontext, principal, docompare)
    krb5_context	kcontext;
    krb5_principal	principal;
    krb5_boolean	docompare;
{
    krb5_error_code	kret;
    krb5_db_entry	dbent;
    krb5_principal	mod_princ;
    krb5_timestamp	mod_time;
    int			how_many;
    krb5_boolean	more;

    more = 0;
    how_many = 1;
    if ((kret = krb5_db_get_principal(kcontext, principal, &dbent,
				      &how_many, &more)))
	return(kret);
    if (how_many == 0) 
	return(KRB5_KDB_NOENTRY);

    if ((kret = krb5_dbe_lookup_mod_princ_data(kcontext, &dbent,
					       &mod_time, &mod_princ)))

	return(kret);
    
    if (docompare) {
	if ((dbent.max_life != KRB5_KDB_MAX_LIFE) ||
	    (dbent.max_renewable_life != KRB5_KDB_MAX_RLIFE) ||
	    (dbent.expiration != KRB5_KDB_EXPIRATION) ||
	    (dbent.attributes != KRB5_KDB_DEF_FLAGS) ||
	    !krb5_principal_compare(kcontext, principal, dbent.princ) ||
	    !krb5_principal_compare(kcontext, principal, mod_princ))
	    kret = KRB5_PRINC_NOMATCH;
    }

    krb5_db_free_principal(kcontext, &dbent, how_many);
    krb5_free_principal(kcontext, mod_princ);
    if (!kret) 
        return(((how_many == 1) && (more == 0)) ? 0 : KRB5KRB_ERR_GENERIC);
    else
        return(kret);

}

/*
 * Delete a principal.
 */
static krb5_error_code
delete_principal(kcontext, principal)
    krb5_context	kcontext;
    krb5_principal	principal;
{
    krb5_error_code	kret;
    int			num2delete;

    num2delete = 1;
    if ((kret = krb5_db_delete_principal(kcontext, principal, &num2delete)))
	return(kret);
    return((num2delete == 1) ? 0 : KRB5KRB_ERR_GENERIC);
}

static int
do_testing(db, passes, verbose, timing, rcases, check, save_db, dontclean,
	   ptest, hash)
    char	*db;
    int		passes;
    int		verbose;
    int		timing;
    int		rcases;
    int		check;
    int		save_db;
    int		dontclean;
    int		ptest;
    int		hash;
{
    krb5_error_code	kret;
    krb5_context	kcontext;
    char		*op, *linkage, *oparg;
    krb5_principal	master_princ;
    int                 master_princ_set = 0;
    char		*mkey_name;
    char		*realm;
    char		*mkey_fullname;
    char		*master_passwd;
    krb5_data		salt_data;
    krb5_encrypt_block	master_encblock;
    krb5_keyblock	master_keyblock;
    krb5_data		passwd;
    krb5_pointer	rseed;
    krb5_boolean	db_open, db_created;
    int			passno;
    krb5_principal	principal;
    char		*pname;
    float		elapsed;
    krb5_keyblock	stat_kb;
    krb5_int32		crflags;

    mkey_name = "master/key";
    realm = master_princ_data.realm.data;
    mkey_fullname = (char *) NULL;
    master_princ = (krb5_principal) NULL;
    master_passwd = "master_password";
    db_open = 0;
    db_created = 0;
    linkage = "";
    oparg = "";
    crflags = hash ? KRB5_KDB_CREATE_HASH : KRB5_KDB_CREATE_BTREE;

    memset(&master_keyblock, 0, sizeof(master_keyblock));

    /* Set up some initial context */
    op = "initializing krb5";
    kret = krb5_init_context(&kcontext);
    if (kret)
	    goto goodbye;

    /* 
     * The database had better not exist.
     */
    op = "making sure database doesn't exist";
    if (!(kret = krb5_db_set_name(kcontext, db))) {
	kret = EEXIST;
	goto goodbye;
    }

    /* Set up the master key name */
    op = "setting up master key name";
    if ((kret = krb5_db_setup_mkey_name(kcontext, mkey_name, realm,
					&mkey_fullname, &master_princ)))
	goto goodbye;

    master_princ_set = 1;
    if (verbose)
	fprintf(stdout, "%s: Initializing '%s', master key is '%s'\n",
		programname, db, mkey_fullname);

    free(mkey_fullname);
    mkey_fullname = 0;

    op = "salting master key";
    if ((kret = krb5_principal2salt(kcontext, master_princ, &salt_data)))
	goto goodbye;

    op = "converting master key";
    krb5_use_enctype(kcontext, &master_encblock, DEFAULT_KDC_ENCTYPE);
    master_keyblock.enctype = DEFAULT_KDC_ENCTYPE;
    passwd.length = strlen(master_passwd);
    passwd.data = master_passwd;
    if ((kret = krb5_string_to_key(kcontext, &master_encblock,
				   &master_keyblock, &passwd, &salt_data)))
	goto goodbye;
    /* Clean up */
    free(salt_data.data);

    /* Process master key */
    op = "processing master key";
    if ((kret = krb5_process_key(kcontext, &master_encblock,
				 &master_keyblock)))
	goto goodbye;

    /* Initialize random key generator */
    op = "initializing random key generator";
    if ((kret = krb5_init_random_key(kcontext,
				     &master_encblock,
				     &master_keyblock,
				     &rseed)))
	goto goodbye;

    /* Create database */
    op = "creating database";
    if ((kret = krb5_db_create(kcontext, db, crflags)))
	goto goodbye;

    db_created = 1;

    /* Set this database as active. */
    op = "setting active database";
    if ((kret = krb5_db_set_name(kcontext, db)))
	goto goodbye;

    /* Initialize database */
    op = "initializing database";
    if ((kret = krb5_db_init(kcontext)))
	goto goodbye;

    db_open = 1;
    op = "adding master principal";
    if ((kret = add_principal(kcontext,
			      master_princ,
			      &master_keyblock,
			      &master_keyblock,
			      rseed)))
	goto goodbye;


    stat_kb.enctype = DEFAULT_KDC_ENCTYPE;
    stat_kb.length = 8;
    stat_kb.contents = (krb5_octet *) "helpmeee";

    /* We are now ready to proceed to test. */
    if (verbose)
	fprintf(stdout, "%s: Beginning %stest\n",
		programname, (rcases) ? "random " : "");
    init_princ_recording(kcontext, passes);
    if (rcases) {
	struct tacc {
	    float	t_time;
	    int		t_number;
	} accumulated[3];
	int 		i, nvalid, discrim, highwater, coinflip;
	krb5_keyblock	*kbp;

	/* Generate random cases */
	for (i=0; i<3; i++) {
	    accumulated[i].t_time = 0.0;
	    accumulated[i].t_number = 0;
	}

	/*
	 * Generate principal names.
	 */
	if (verbose > 1)
	    fprintf(stdout, "%s: generating %d names\n",
		    programname, passes);
	for (passno=0; passno<passes; passno++) {
	    op = "generating principal name";
	    do {
		if ((kret = gen_principal(kcontext, realm, rcases,
					  passno, &principal, &pname)))
			goto goodbye;
	    } while (principal_found(passno-1, pname));
	    record_principal(passno, principal, pname);
	}

	/* Prime the database with some number of entries */
	nvalid = passes/4;
	if (nvalid < 10)
	    nvalid = 10;
	if (nvalid > passes)
	    nvalid = passes;

	if (verbose > 1)
	    fprintf(stdout, "%s: priming database with %d principals\n",
		    programname, nvalid);
	highwater = 0;
	for (passno=0; passno<nvalid; passno++) {
	    op = "adding principal";
	    coinflip = RANDOM(0,2);
	    kbp = (coinflip) ? &stat_kb : (krb5_keyblock *) NULL;
	    if (timing) {
		swatch_on();
	    }
	    if ((kret = add_principal(kcontext, playback_principal(passno),
				      &master_keyblock, kbp, rseed))) {
		linkage = "initially ";
		oparg = playback_name(passno);
		goto cya;
	    }
	    if (timing) {
		elapsed = swatch_eltime();
		accumulated[0].t_time += elapsed;
		accumulated[0].t_number++;
	    }
	    if (verbose > 4)
		fprintf(stderr, "*A(%s)\n", playback_name(passno));
	    highwater++;
	}

	if (verbose > 1)
	    fprintf(stderr, "%s: beginning random loop\n", programname);
	/* Loop through some number of times and pick random operations */
	for (i=0; i<3*passes; i++) {
	    discrim = RANDOM(0,100);

	    /* Add a principal 25% of the time, if possible */
	    if ((discrim < 25) && (nvalid < passes)) {
		op = "adding principal";
		coinflip = RANDOM(0,2);
		kbp = (coinflip) ? &stat_kb : (krb5_keyblock *) NULL;
		if (timing) {
		    swatch_on();
		}
		if ((kret = add_principal(kcontext,
					  playback_principal(nvalid),
					  &master_keyblock,
					  kbp, rseed))) {
		    oparg = playback_name(nvalid);
		    goto cya;
		}
		if (timing) {
		    elapsed = swatch_eltime();
		    accumulated[0].t_time += elapsed;
		    accumulated[0].t_number++;
		}
		if (verbose > 4)
		    fprintf(stderr, "*A(%s)\n", playback_name(nvalid));
		nvalid++;
		if (nvalid > highwater)
		    highwater = nvalid;
	    }
	    /* Delete a principal 15% of the time, if possible */
	    else if ((discrim > 85) && (nvalid > 10)) {
		op = "deleting principal";
		if (timing) {
		    swatch_on();
		}
		if ((kret = delete_principal(kcontext,
					     playback_principal(nvalid-1)))) {
		    oparg = playback_name(nvalid-1);
		    goto cya;
		}
		if (timing) {
		    elapsed = swatch_eltime();
		    accumulated[2].t_time += elapsed;
		    accumulated[2].t_number++;
		}
		if (verbose > 4)
		    fprintf(stderr, "XD(%s)\n", playback_name(nvalid-1));
		nvalid--;
	    }
	    /* Otherwise, find a principal */
	    else {
		op = "looking up principal";
		passno = RANDOM(0, nvalid);
		if (timing) {
		    swatch_on();
		}
		if ((kret = find_principal(kcontext,
					   playback_principal(passno),
					   check))) {
		    oparg = playback_name(passno);
		    goto cya;
		}
		if (timing) {
		    elapsed = swatch_eltime();
		    accumulated[1].t_time += elapsed;
		    accumulated[1].t_number++;
		}
		if (verbose > 4)
		    fprintf(stderr, "-S(%s)\n", playback_name(passno));
	    }
	}

	if (!dontclean) {
	    /* Clean up the remaining principals */
	    if (verbose > 1)
		fprintf(stdout, "%s: deleting remaining %d principals\n",
			programname, nvalid);
	    for (passno=0; passno<nvalid; passno++) {
		op = "deleting principal";
		if (timing) {
		    swatch_on();
		}
		if ((kret = delete_principal(kcontext,
					     playback_principal(passno)))) {
		    linkage = "finally ";
		    oparg = playback_name(passno);
		    goto cya;
		}
		if (timing) {
		    elapsed = swatch_eltime();
		    accumulated[2].t_time += elapsed;
		    accumulated[2].t_number++;
		}
		if (verbose > 4)
		    fprintf(stderr, "XD(%s)\n", playback_name(passno));
	    }
	}
    cya:
	if (verbose)
	    fprintf(stdout,
		    "%s: highwater mark was %d principals\n",
		    programname, highwater);
	if (accumulated[0].t_number && timing)
	    fprintf(stdout,
		    "%s: performed %8d additions in %9.4f seconds (%9.4f/add)\n",
		    programname, accumulated[0].t_number,
		    accumulated[0].t_time, 
		    accumulated[0].t_time / (float) accumulated[0].t_number);
	if (accumulated[1].t_number && timing)
	    fprintf(stdout,
		    "%s: performed %8d lookups   in %9.4f seconds (%9.4f/search)\n",
		    programname, accumulated[1].t_number,
		    accumulated[1].t_time, 
		    accumulated[1].t_time / (float) accumulated[1].t_number);
	if (accumulated[2].t_number && timing)
	    fprintf(stdout,
		    "%s: performed %8d deletions in %9.4f seconds (%9.4f/delete)\n",
		    programname, accumulated[2].t_number,
		    accumulated[2].t_time, 
		    accumulated[2].t_time / (float) accumulated[2].t_number);
	if (kret)
	    goto goodbye;
    }
    else {
	/*
	 * Generate principal names.
	 */
	for (passno=0; passno<passes; passno++) {
	    op = "generating principal name";
	    if ((kret = gen_principal(kcontext, realm, rcases,
				     passno, &principal, &pname)))
		goto goodbye;
	    record_principal(passno, principal, pname);
	}
	/*
	 * Add principals.
	 */
	if (timing) {
	    swatch_on();
	}
	for (passno=0; passno<passes; passno++) {
	    op = "adding principal";
	    if ((kret = add_principal(kcontext, playback_principal(passno),
				     &master_keyblock, &stat_kb, rseed)))
		goto goodbye;
	    if (verbose > 4)
		fprintf(stderr, "*A(%s)\n", playback_name(passno));
	}
	if (timing) {
	    elapsed = swatch_eltime();
	    fprintf(stdout,
		    "%s:   added %d principals in %9.4f seconds (%9.4f/add)\n",
		    programname, passes, elapsed, elapsed/((float) passes));
	}

	/*
	 * Lookup principals.
	 */
	if (timing) {
	    swatch_on();
	}
	for (passno=0; passno<passes; passno++) {
	    op = "looking up principal";
	    if ((kret = find_principal(kcontext, playback_principal(passno),
				       check)))
		goto goodbye;
	    if (verbose > 4)
		fprintf(stderr, "-S(%s)\n", playback_name(passno));
	}
	if (timing) {
	    elapsed = swatch_eltime();
	    fprintf(stdout,
		    "%s:   found %d principals in %9.4f seconds (%9.4f/search)\n",
		    programname, passes, elapsed, elapsed/((float) passes));
	}

	/*
	 * Delete principals.
	 */
	if (!dontclean) {
	    if (timing) {
		swatch_on();
	    }
	    for (passno=passes-1; passno>=0; passno--) {
		op = "deleting principal";
		if ((kret = delete_principal(kcontext,
					     playback_principal(passno))))
		    goto goodbye;
		if (verbose > 4)
		    fprintf(stderr, "XD(%s)\n", playback_name(passno));
	    }
	    if (timing) {
		elapsed = swatch_eltime();
		fprintf(stdout,
			"%s: deleted %d principals in %9.4f seconds (%9.4f/delete)\n",
			programname, passes, elapsed,
			elapsed/((float) passes));
	    }
	}

    }

 goodbye:
    if(master_princ_set) {
	krb5_free_principal(kcontext, master_princ);
    }
    if (kret)
	fprintf(stderr, "%s: error while %s %s%s(%s)\n",
		programname, op, linkage, oparg, error_message(kret));

    if (!kret && ptest) {
	int	nper;
	pid_t	children[32], child;
	int	nprocs, existat, i, j, fd;

	nprocs = ptest + 1;
	if (nprocs > 32)
	    nprocs = 32;

	nper = passes / nprocs;
	unlink("./test.lock");
	for (i=0; i<nprocs; i++) {
	    child = fork();
	    if (child == 0) {
		/* Child */
		int base;
		krb5_context	ccontext;
		struct stat stbuf;

		while (stat("./test.lock", &stbuf) == -1)
	        kret = krb5_init_context(&ccontext);
		if (kret) {
		    com_err(programname, kret, "while initializing krb5");
		    exit(1);
		}
		if ((kret = krb5_db_set_name(ccontext, db)) ||
		    (kret = krb5_db_init(ccontext)))
		    exit(1);
		base = i*nper;
		for (j=0; j<nper; j++) {
		    if ((kret = add_principal(ccontext,
					      playback_principal(base+j),
					      &master_keyblock,
					      &stat_kb,
					      rseed))) {
			fprintf(stderr,
				"%ld: (%d,%d) Failed add of %s with %s\n",
				(long) getpid(), i, j, playback_name(base+j),
				error_message(kret));
			break;
		    }
		    if (verbose > 4)
			fprintf(stderr, "*A[%ld](%s)\n", (long) getpid(),
				playback_name(base+j));
		}   
		for (j=0; (j<nper) && (!kret); j++) {
		    if ((kret = find_principal(ccontext,
					       playback_principal(base+j),
					       check))) {
			fprintf(stderr,
				"%ld: (%d,%d) Failed lookup of %s with %s\n",
				(long) getpid(), i, j, playback_name(base+j),
				error_message(kret));
			break;
		    }
		    if (verbose > 4)
			fprintf(stderr, "-S[%ld](%s)\n", (long) getpid(),
				playback_name(base+j));
		}   
		for (j=0; (j<nper) && (!kret); j++) {
		    if ((kret = delete_principal(ccontext,
					       playback_principal(base+j)))) {
			fprintf(stderr,
				"%ld: (%d,%d) Failed delete of %s with %s\n",
				(long) getpid(), i, j, playback_name(base+j),
				error_message(kret));
			break;
		    }
		    if (verbose > 4)
			fprintf(stderr, "XD[%ld](%s)\n", (long) getpid(),
				playback_name(base+j));
		}
		krb5_db_fini(ccontext);
		krb5_free_context(ccontext);
		exit((kret) ? 1 : 0);
	    }
	    else
		children[i] = child;
	}
	fd = open("./test.lock", O_CREAT|O_RDWR|O_EXCL, 0666);
	close(fd);
	sleep(1);
	unlink("./test.lock");
	for (i=0; i<nprocs; i++) {
	    if (waitpid(children[i], &existat, 0) == children[i]) {
		if (verbose) 
		    fprintf(stderr, "%ld finished with %d\n",
			    (long) children[i], existat);
		if (existat)
		    kret = KRB5KRB_ERR_GENERIC;
	    }
	    else
		fprintf(stderr, "Wait for %ld failed\n", (long) children[i]);
	}
    }

    free_principals(kcontext, passes);
    if (db_open)
	(void) krb5_db_fini(kcontext);
    if (db_created) {
	if (!kret && !save_db) {
	    krb5_db_destroy(kcontext, db);
	    krb5_db_fini(kcontext);
	} else {
	    if (kret && verbose)
		fprintf(stderr, "%s: database not deleted because of error\n",
			programname);
	}
    }

    krb5_free_keyblock_contents(kcontext, &master_keyblock);
    krb5_free_context(kcontext);

    return((kret) ? 1 : 0);
}

/*
 * usage:
 *	t_kdb	[-t]		- Get timing information.
 *		[-r]		- Generate random cases.
 *		[-n <num>]	- Use <num> as the number of passes.
 *		[-c]		- Check contents.
 *		[-v]		- Verbose output.
 *		[-d <dbname>]	- Database name.
 *		[-s]		- Save database even on successful completion.
 *		[-D]		- Leave database dirty.
 */
int
main(argc, argv)
    int		argc;
    char	*argv[];
{
    int	option;
    extern char	*optarg;

    int		do_time, do_random, num_passes, check_cont, verbose, error;
    int		save_db, dont_clean, do_ptest, hash;
    char	*db_name;

    programname = argv[0];
    if (strrchr(programname, (int) '/'))
	programname = strrchr(programname, (int) '/') + 1;
    SRAND((RAND_TYPE)time((void *) NULL));

    /* Default values. */
    do_time = 0;
    do_random = 0;
    num_passes = T_KDB_N_PASSES;
    check_cont = 0;
    verbose = 0;
    db_name = T_KDB_DEF_DB;
    save_db = 0;
    dont_clean = 0;
    error = 0;
    do_ptest = 0;
    hash = 0;

    /* Parse argument list */
    while ((option = getopt(argc, argv, "cd:n:prstvDh")) != -1) {
	switch (option) {
	case 'c':
	    check_cont = 1;
	    break;
	case 'd':
	    db_name = optarg;
	    break;
	case 'n':
	    if (sscanf(optarg, "%d", &num_passes) != 1) {
		fprintf(stderr, "%s: %s is not a valid number for %c option\n",
			programname, optarg, option);
		error++;
	    }
	    break;
	case 'p':
	    do_ptest++;
	    break;
	case 'r':
	    do_random = 1;
	    break;
	case 's':
	    save_db = 1;
	    break;
	case 't':
	    do_time = 1;
	    break;
	case 'v':
	    verbose++;
	    break;
	case 'D':
	    dont_clean = 1;
	    break;
	case 'h':
	    hash = 1;
	    break;
	default:
	    error++;
	    break;
	}
    }
    if (error)
	fprintf(stderr, "%s: usage is %s [-cprstv] [-d <dbname>] [-n <num>]\n",
		programname, programname);
    else
	error = do_testing(db_name,
			   num_passes,
			   verbose,
			   do_time,
			   do_random,
			   check_cont,
			   save_db,
			   dont_clean,
			   do_ptest,
			   hash);
    return(error);
}



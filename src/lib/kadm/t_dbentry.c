/*
 * lib/kadm/t_dbentry.c
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
 * t_dbentry.c	- Test function of krb5_adm_{proto_to_dbent,dbent_to_proto}.
 */

#include "k5-int.h"
#include "adm.h"
#include "adm_proto.h"

#if	HAVE_SRAND48
#define	SRAND	srand48
#define	RAND	lrand48
#define	RAND_TYPE	long
#endif	/* HAVE_SRAND48 */

#if	!defined(RAND_TYPE) && defined(HAVE_SRAND)
#define	SRAND	srand
#define	RAND	rand
#define	RAND_TYPE	int
#endif	/* !defined(RAND_TYPE) && defined(HAVE_SRAND) */

#if	!defined(RAND_TYPE) && defined(HAVE_SRANDOM)
#define	SRAND	srandom
#define	RAND	random
#define	RAND_TYPE	long
#endif	/* !defined(RAND_TYPE) && defined(HAVE_SRANDOM) */

#if	!defined(RAND_TYPE)
There is no random number generator.
#endif	/* !defined(RAND_TYPE) */

/*
 * Generate a random event that has an a/b chance of succeeding
 */
#define	RANDOM_EVENT(a,b)	((RAND() % b) < a)
/* Define probabilities of generating each attribute type */
#define	PASSWORD_EVENT		RANDOM_EVENT(3,5)
#define	KVNO_EVENT		RANDOM_EVENT(2,5)
#define	MAXLIFE_EVENT		RANDOM_EVENT(1,4)
#define	MAXRENEWLIFE_EVENT	RANDOM_EVENT(1,4)
#define	EXPIRATION_EVENT	RANDOM_EVENT(1,3)
#define	PWEXPIRATION_EVENT	RANDOM_EVENT(1,3)
#define	RANDOMKEY_EVENT		RANDOM_EVENT(1,8)
#define	FLAGS_EVENT		RANDOM_EVENT(9,10)
#define	SALT_EVENT		RANDOM_EVENT(7,16)
#define	MKVNO_EVENT		RANDOM_EVENT(2,5)
#define	LASTPWCHANGE_EVENT	RANDOM_EVENT(2,5)
#define	LASTSUCCESS_EVENT	RANDOM_EVENT(2,5)
#define	LASTFAILED_EVENT	RANDOM_EVENT(2,5)
#define	FAILCOUNT_EVENT		RANDOM_EVENT(2,5)
#define	MODNAME_EVENT		RANDOM_EVENT(2,5)
#define	MODDATE_EVENT		RANDOM_EVENT(2,5)
#define	SET_EVENT		RANDOM_EVENT(1,4)

/*
 * Convert a time value to a string for output messages.
 */
static char *
time2string(ts)
    krb5_timestamp	ts;
{
    static char buf[1024];

    strcpy(buf, ctime((time_t *) &ts));
    /* Remove trailing \n */
    buf[strlen(buf)-1] = '\0';
    return(buf);
}

/*
 * Generate a database entry, either randomly, or using well known values.
 */
static void
gen_dbent(kcontext, dbentp, isrand, validp, pwdp, expectp)
    krb5_context	kcontext;
    krb5_db_entry	*dbentp;
    krb5_boolean	isrand;
    krb5_ui_4		*validp;
    char		**pwdp;
    krb5_boolean	*expectp;
{
    time_t		now;
    krb5_boolean	is_set;
    size_t		pwlen;
    int			i;
    static char		*defpass = "testpassword";
    static char		*defprinc = "testprinc/instance@realm";

    now = time((time_t *) NULL);
    is_set = ((*validp & KRB5_ADM_M_SET) != 0);

    /* Do password on set */
    if (isrand) {
	if (PASSWORD_EVENT) {
	    pwlen = 9 + (RAND() % 56);
	    *pwdp = (char *) malloc(pwlen);
	    for (i=0; i<pwlen-1; i++) {
		(*pwdp)[i] = RAND() % 128;
		while (!isalnum((int) (*pwdp)[i]))
		    (*pwdp)[i] = RAND() % 128;
	    }
	    (*pwdp)[pwlen-1] = '\0';
	    *validp |= KRB5_ADM_M_PASSWORD;
	}
    }
    else {
	if (is_set) {
	    *pwdp = (char *) malloc(strlen(defpass)+1);
	    strcpy(*pwdp, defpass);
	    *validp |= KRB5_ADM_M_PASSWORD;
	}
    }

    /* Do kvno */
    if (isrand) {
	if (KVNO_EVENT) {
	    dbentp->kvno = RAND();
	    *validp |= KRB5_ADM_M_KVNO;
	}
    }
    else {
	dbentp->kvno = 1;
	*validp |= KRB5_ADM_M_KVNO;
    }

    /* Do maxlife */
    if (isrand) {
	if (MAXLIFE_EVENT) {
	    dbentp->max_life = RAND();
	    *validp |= KRB5_ADM_M_MAXLIFE;
	}
    }
    else {
	dbentp->max_life = KRB5_KDB_MAX_LIFE;
	*validp |= KRB5_ADM_M_MAXLIFE;
    }

    /* Do maxrenewlife */
    if (isrand) {
	if (MAXRENEWLIFE_EVENT) {
	    dbentp->max_renewable_life = RAND();
	    *validp |= KRB5_ADM_M_MAXRENEWLIFE;
	}
    }
    else {
	dbentp->max_renewable_life = KRB5_KDB_MAX_RLIFE;
	*validp |= KRB5_ADM_M_MAXRENEWLIFE;
    }

    /* Do expiration */
    if (isrand) {
	if (EXPIRATION_EVENT) {
	    dbentp->expiration = RAND();
	    *validp |= KRB5_ADM_M_EXPIRATION;
	}
    }
    else {
	dbentp->expiration = KRB5_KDB_EXPIRATION;
	*validp |= KRB5_ADM_M_EXPIRATION;
    }

    /* Do pw_expiration */
    if (isrand) {
	if (PWEXPIRATION_EVENT) {
	    dbentp->pw_expiration = RAND();
	    *validp |= KRB5_ADM_M_PWEXPIRATION;
	}
    }
    else {
	dbentp->pw_expiration = (krb5_timestamp) now + 3600;
	*validp |= KRB5_ADM_M_PWEXPIRATION;
    }

    /* Do randomkey - 1/8 probability of doing randomkey */
    if (isrand && (RANDOMKEY_EVENT)) {
	*validp |= KRB5_ADM_M_RANDOMKEY;
    }

    /* Do flags */
    if (isrand) {
	if (FLAGS_EVENT) {
	    dbentp->attributes = RAND();
	    *validp |= KRB5_ADM_M_FLAGS;
	}
    }
    else {
	dbentp->attributes = KRB5_KDB_DEF_FLAGS;
	*validp |= KRB5_ADM_M_FLAGS;
    }

    /* Do salts */
    if (isrand) {
	if (SALT_EVENT) {
	    dbentp->salt_type = (RAND() % 1);
	    dbentp->alt_salt_type = (RAND() % 1);
	    *validp |= KRB5_ADM_M_SALTTYPE;
	}
    }
    else {
	dbentp->salt_type = dbentp->alt_salt_type = KRB5_KDB_SALTTYPE_NORMAL;
	*validp |= KRB5_ADM_M_SALTTYPE;
    }

    /* Do mkvno */
    if (isrand) {
	if (MKVNO_EVENT) {
	    dbentp->mkvno = RAND();
	    *validp |= KRB5_ADM_M_MKVNO;
	}
    }
    else {
	if (!is_set) {
	    dbentp->mkvno = 1;
	    *validp |= KRB5_ADM_M_MKVNO;
	}
    }

    /* Do lastpwchange */
    if (isrand) {
	if (LASTPWCHANGE_EVENT) {
	    dbentp->last_pwd_change = RAND();
	    *validp |= KRB5_ADM_M_LASTPWCHANGE;
	}
    }
    else {
	if (!is_set) {
	    dbentp->last_pwd_change = (krb5_timestamp) now - 3600;
	    *validp |= KRB5_ADM_M_LASTPWCHANGE;
	}
    }

    /* Do lastsuccess */
    if (isrand) {
	if (LASTSUCCESS_EVENT) {
	    dbentp->last_success = RAND();
	    *validp |= KRB5_ADM_M_LASTSUCCESS;
	}
    }
    else {
	if (!is_set) {
	    dbentp->last_success = (krb5_timestamp) now - 3600;
	    *validp |= KRB5_ADM_M_LASTSUCCESS;
	}
    }

    /* Do lastfailed */
    if (isrand) {
	if (LASTFAILED_EVENT) {
	    dbentp->last_failed = RAND();
	    *validp |= KRB5_ADM_M_LASTFAILED;
	}
    }
    else {
	if (!is_set) {
	    dbentp->last_failed = (krb5_timestamp) now - 3600;
	    *validp |= KRB5_ADM_M_LASTFAILED;
	}
    }

    /* Do failcount */
    if (isrand) {
	if (FAILCOUNT_EVENT) {
	    dbentp->fail_auth_count = RAND();
	    *validp |= KRB5_ADM_M_FAILCOUNT;
	}
    }
    else {
	if (!is_set) {
	    dbentp->fail_auth_count = 0;
	    *validp |= KRB5_ADM_M_FAILCOUNT;
	}
    }

    /* Do modname */
    if (isrand) {
	if (MODNAME_EVENT) {
	    if (!krb5_parse_name(kcontext, defprinc, &dbentp->mod_name)) {
		*validp |= KRB5_ADM_M_MODNAME;
	    }
	}
    }
    else {
	if (!is_set) {
	    if (!krb5_parse_name(kcontext, defprinc, &dbentp->mod_name)) {
		*validp |= KRB5_ADM_M_MODNAME;
	    }
	}
    }

    /* Do mod_date */
    if (isrand) {
	if (MODDATE_EVENT) {
	    dbentp->mod_date = RAND();
	    *validp |= KRB5_ADM_M_MODDATE;
	}
    }
    else {
	if (!is_set) {
	    dbentp->mod_date = (krb5_timestamp) now;
	    *validp |= KRB5_ADM_M_MODDATE;
	}
    }

    if (is_set) {
	/* Only 25% may fail at most */
	if (isrand && ((RAND() % 100) < 75)) {
	    *validp &= KRB5_ADM_M_SET_VALID;
	}
#ifdef	notdef
	if ((*validp & KRB5_ADM_M_PASSWORD) != 0)
	    *validp &= ~KRB5_ADM_M_RANDOMKEY;
#endif	/* notdef */
	*expectp = ((*validp & ~KRB5_ADM_M_SET_VALID) != 0) ? 1 : 0;
    }
    else {
	/* Only 25% may fail at most */
	if (isrand && ((RAND() % 100) < 75))
	    *validp &= KRB5_ADM_M_GET_VALID;
	*expectp = ((*validp & ~KRB5_ADM_M_GET_VALID) != 0) ? 1 : 0;
    }
}

/*
 * Compare two entries.
 */
static krb5_boolean
compare_entries(kcontext, ivalid, ientp, ipwd, ovalid, oentp, opwd)
    krb5_context	kcontext;
    krb5_ui_4		ivalid;
    krb5_db_entry	*ientp;
    char		*ipwd;
    krb5_ui_4		ovalid;
    krb5_db_entry	*oentp;
    char		*opwd;
{
    /* Handle/compare password */
    if (((ivalid & KRB5_ADM_M_PASSWORD) != 0) &&
	(((ovalid & KRB5_ADM_M_PASSWORD) == 0) ||
	 strcmp(ipwd, opwd)))
	    return(0);

    /* Handle/compare kvno */
    if (((ivalid & KRB5_ADM_M_KVNO) != 0) &&
	(((ovalid & KRB5_ADM_M_KVNO) == 0) ||
	 (ientp->kvno != oentp->kvno)))
	return(0);

    /* Handle/compare maxlife */
    if (((ivalid & KRB5_ADM_M_MAXLIFE) != 0) &&
	(((ovalid & KRB5_ADM_M_MAXLIFE) == 0) ||
	 (ientp->max_life != oentp->max_life)))
	return(0);

    /* Handle/compare maxrenewlife */
    if (((ivalid & KRB5_ADM_M_MAXRENEWLIFE) != 0) &&
	(((ovalid & KRB5_ADM_M_MAXRENEWLIFE) == 0) ||
	 (ientp->max_renewable_life != oentp->max_renewable_life)))
	return(0);

    /* Handle/compare expiration */
    if (((ivalid & KRB5_ADM_M_EXPIRATION) != 0) &&
	(((ovalid & KRB5_ADM_M_EXPIRATION) == 0) ||
	 (ientp->expiration != oentp->expiration)))
	return(0);

    /* Handle/compare pwexpiration */
    if (((ivalid & KRB5_ADM_M_PWEXPIRATION) != 0) &&
	(((ovalid & KRB5_ADM_M_PWEXPIRATION) == 0) ||
	 (ientp->pw_expiration != oentp->pw_expiration)))
	return(0);

#ifdef	notdef
    /* Handle/compare random key */
    if (((ivalid & KRB5_ADM_M_RANDOMKEY) != 0) &&
	((ovalid & KRB5_ADM_M_PASSWORD) != 0))
	return(0);
#endif	/* notdef */

    /* Handle/compare flags */
    if (((ivalid & KRB5_ADM_M_FLAGS) != 0) &&
	(((ovalid & KRB5_ADM_M_FLAGS) == 0) ||
	 (ientp->attributes != oentp->attributes)))
	return(0);

    /* Handle/compare salts */
    if (((ivalid & KRB5_ADM_M_SALTTYPE) != 0) &&
	(((ovalid & KRB5_ADM_M_SALTTYPE) == 0) ||
	 (ientp->salt_type != oentp->salt_type) ||
	 (ientp->alt_salt_type != oentp->alt_salt_type)))
	return(0);

    /* Handle/compare mkvno */
    if (((ivalid & KRB5_ADM_M_MKVNO) != 0) &&
	(((ovalid & KRB5_ADM_M_MKVNO) == 0) ||
	 (ientp->mkvno != oentp->mkvno)))
	return(0);

    /* Handle/compare lastpwchange */
    if (((ivalid & KRB5_ADM_M_LASTPWCHANGE) != 0) &&
	(((ovalid & KRB5_ADM_M_LASTPWCHANGE) == 0) ||
	 (ientp->last_pwd_change != oentp->last_pwd_change)))
	return(0);

    /* Handle/compare lastsuccess */
    if (((ivalid & KRB5_ADM_M_LASTSUCCESS) != 0) &&
	(((ovalid & KRB5_ADM_M_LASTSUCCESS) == 0) ||
	 (ientp->last_success != oentp->last_success)))
	return(0);

    /* Handle/compare lastfailed */
    if (((ivalid & KRB5_ADM_M_LASTFAILED) != 0) &&
	(((ovalid & KRB5_ADM_M_LASTFAILED) == 0) ||
	 (ientp->last_failed != oentp->last_failed)))
	return(0);

    /* Handle/compare failcount */
    if (((ivalid & KRB5_ADM_M_FAILCOUNT) != 0) &&
	(((ovalid & KRB5_ADM_M_FAILCOUNT) == 0) ||
	 (ientp->fail_auth_count != oentp->fail_auth_count)))
	return(0);

    /* Handle/compare mod_name */
    if (((ivalid & KRB5_ADM_M_MODNAME) != 0) &&
	(((ovalid & KRB5_ADM_M_MODNAME) == 0) ||
	 !krb5_principal_compare(kcontext, ientp->mod_name, oentp->mod_name)))
	return(0);

    /* Handle/compare mod_date */
    if (((ivalid & KRB5_ADM_M_MODDATE) != 0) &&
	(((ovalid & KRB5_ADM_M_MODDATE) == 0) ||
	 (ientp->mod_date != oentp->mod_date)))
	return(0);
    return(1);
}

/*
 * Print out an entry.
 */
static void
print_dbent(kcontext, ivalid, ientp, ipwd)
    krb5_context	kcontext;
    krb5_ui_4		ivalid;
    krb5_db_entry	*ientp;
    char		*ipwd;
{
    printf("Valid mask:\t%08x\n", ivalid);

    /* Print password */
    if ((ivalid & KRB5_ADM_M_PASSWORD) != 0)
	printf("Password:\t%s\n", ipwd);

    /* Print kvno */
    if ((ivalid & KRB5_ADM_M_KVNO) != 0)
	printf("kvno:\t\t%8d\t%08x\n", ientp->kvno, ientp->kvno);

    /* Print maxlife */
    if ((ivalid & KRB5_ADM_M_MAXLIFE) != 0)
	printf("max_life:\t%8d\t%08x\n", ientp->max_life, ientp->max_life);

    /* Print maxrenewlife */
    if ((ivalid & KRB5_ADM_M_MAXRENEWLIFE) != 0)
	printf("max_rlife:\t%8d\t%08x\n", ientp->max_renewable_life,
	       ientp->max_renewable_life);

    /* Print expiration */
    if ((ivalid & KRB5_ADM_M_EXPIRATION) != 0)
	printf("expires:\t%8d\t%08x\t%s\n", ientp->expiration,
	       ientp->expiration, time2string(ientp->expiration));

    /* Print pwexpiration */
    if ((ivalid & KRB5_ADM_M_PWEXPIRATION) != 0)
	printf("pw expires:\t%8d\t%08x\t%s\n", ientp->pw_expiration,
	       ientp->pw_expiration, time2string(ientp->pw_expiration));

    /* Print random key */
    if ((ivalid & KRB5_ADM_M_RANDOMKEY) != 0)
	printf("random key\n");

    /* Print flags */
    if ((ivalid & KRB5_ADM_M_FLAGS) != 0)
	printf("flags:\t\t%8d\t%08x\n", ientp->attributes, ientp->attributes);

    /* Print salts */
    if ((ivalid & KRB5_ADM_M_SALTTYPE) != 0)
	printf("salts:\t\t%d, %d\n", ientp->salt_type, ientp->alt_salt_type);

    /* Print mkvno */
    if ((ivalid & KRB5_ADM_M_MKVNO) != 0)
	printf("mkvno:\t\t%8d\t%08x\n", ientp->mkvno, ientp->mkvno);

    /* Print lastpwchange */
    if ((ivalid & KRB5_ADM_M_LASTPWCHANGE) != 0)
	printf("lastpwchg:\t%8d\t%08x\t%s\n", ientp->last_pwd_change,
	       ientp->last_pwd_change, time2string(ientp->last_pwd_change));

    /* Print lastsuccess */
    if ((ivalid & KRB5_ADM_M_LASTSUCCESS) != 0)
	printf("lastsucc:\t%8d\t%08x\t%s\n", ientp->last_success,
	       ientp->last_success, time2string(ientp->last_success));

    /* Print lastfailed */
    if ((ivalid & KRB5_ADM_M_LASTFAILED) != 0)
	printf("lastfail:\t%8d\t%08x\t%s\n", ientp->last_failed,
	       ientp->last_failed, time2string(ientp->last_failed));

    /* Print failcount */
    if ((ivalid & KRB5_ADM_M_FAILCOUNT) != 0)
	printf("failcount:\t%8d\t%08x\n", ientp->fail_auth_count,
	       ientp->fail_auth_count);

    /* Print mod_name */
    if ((ivalid & KRB5_ADM_M_MODNAME) != 0) {
	char *mprinc;

	if (!krb5_unparse_name(kcontext, ientp->mod_name, &mprinc)) {
	    printf("modname:\t%s\n", mprinc);
	    krb5_xfree(mprinc);
	}
    }

    /* Print mod_date */
    if ((ivalid & KRB5_ADM_M_MODDATE) != 0)
	printf("moddate:\t%8d\t%08x\t%s\n", ientp->mod_date,
	       ientp->mod_date, time2string(ientp->mod_date));
}

/*
 * Do a test case.
 *
 * Strategy: Generate the desired database entry type, then convert it using
 *	krb5_adm_dbent_to_proto, then convert it back to a database entry
 *	using krb5_adm_proto_to_dbent.  Then verify the match.
 */
static krb5_int32
do_test(pname, verbose, isrand, is_a_set, title, passno)
    char		*pname;
    krb5_boolean	verbose;
    krb5_boolean	isrand;
    krb5_boolean	is_a_set;
    char		*title;
    krb5_int32		passno;
{
    krb5_context	kcontext;
    krb5_db_entry	*in_dbent;
    krb5_db_entry	*out_dbent;
    krb5_error_code	kret;
    krb5_int32		ncomps;
    krb5_data		*complist;
    krb5_ui_4		in_validmask;
    krb5_ui_4		out_validmask;
    char		*in_password;
    char		*out_password;
    krb5_boolean	should_fail;

    if (verbose) {
	printf("* Begin %s", title);
	if (isrand)
	    printf(" pass %d", passno);
	printf("\n");
    }

    kret = 0;
    krb5_init_context(&kcontext);
    krb5_init_ets(kcontext);
    in_dbent = (krb5_db_entry *) malloc(sizeof(krb5_db_entry));
    out_dbent = (krb5_db_entry *) malloc(sizeof(krb5_db_entry));
    if (in_dbent && out_dbent) {
	/* Initialize our data */
	memset((char *) in_dbent, 0, sizeof(krb5_db_entry));
	memset((char *) out_dbent, 0, sizeof(krb5_db_entry));
	in_password = out_password = (char *) NULL;
	out_validmask = 0;
	ncomps = 0;
	complist = (krb5_data *) NULL;
	should_fail = 0;
	if (!isrand) {
	    if (is_a_set)
		in_validmask = KRB5_ADM_M_SET;
	    else
		in_validmask = KRB5_ADM_M_GET;
	}
	else {
	    if (SET_EVENT)
		in_validmask = KRB5_ADM_M_SET;
	    else
		in_validmask = KRB5_ADM_M_GET;
	}

	/* Generate the database entry. */
	gen_dbent(kcontext,
		  in_dbent, isrand, &in_validmask, &in_password, &should_fail);

	/* Convert it to the o-t-w protocol */
	if (!(kret = krb5_adm_dbent_to_proto(kcontext,
					     in_validmask,
					     in_dbent,
					     in_password,
					     &ncomps,
					     &complist))) {
	    /* If this should fail, then we've got a problem here */
	    if (!should_fail) {

		/* Otherwise, convert it back to a database entry */
		if (!(kret = krb5_adm_proto_to_dbent(kcontext,
						     ncomps,
						     complist,
						     &out_validmask,
						     out_dbent,
						     &out_password))) {
		    /* Compare the entries */
		    if (compare_entries(kcontext,
					in_validmask,
					in_dbent,
					in_password,
					out_validmask,
					out_dbent,
					out_password)) {
			/* Success */
			if (verbose) {
			    printf("Successful translation");
			    printf(" during %s", title);
			    if (isrand)
				printf(" pass %d", passno);
			    printf(" of:\n");
			    print_dbent(kcontext,
					in_validmask, in_dbent, in_password);
			}
		    }
		    else {
			/* Failed */
			fprintf(stderr, "%s: comparison mismatch", pname);
			fprintf(stderr, " during %s", title);
			if (isrand)
			    fprintf(stderr, " pass %d", passno);
			fprintf(stderr, "\n");
			if (verbose) {
			    printf("Input entry is as follows:\n");
			    print_dbent(kcontext,
					in_validmask, in_dbent, in_password);
			    printf("Output entry is as follows:\n");
			    print_dbent(kcontext,
					out_validmask,
					out_dbent,
					out_password);
			}
			kret = KRB5KRB_ERR_GENERIC;
		    }
		    if (out_password)
			krb5_xfree(out_password);
		}
		else {
		    /* Conversion to database entry failed */
		    fprintf(stderr, "%s: protocol decode failed with %d",
			pname, kret);
		    fprintf(stderr, " during %s", title);
		    if (isrand)
			fprintf(stderr, " pass %d", passno);
		    fprintf(stderr, "\n");
		}
	    }
	    else {
		/* Should have failed */
		fprintf(stderr, "%s: protocol encode unexpectedly succeeded",
			pname);
		kret = KRB5KRB_ERR_GENERIC;
		fprintf(stderr, " during %s", title);
		if (isrand)
		    fprintf(stderr, " pass %d", passno);
		fprintf(stderr, "\n");
	    }
	    krb5_free_adm_data(kcontext, ncomps, complist);
	}
	else {
	    /* Convert to protocol failed */
	    if (!should_fail) {
		/* Unexpected failure */
		fprintf(stderr, "%s: protocol encode failed with %d",
			pname, kret);
		fprintf(stderr, " during %s", title);
		if (isrand)
		    fprintf(stderr, " pass %d", passno);
		fprintf(stderr, "\n");
	    }
	    else {
		/* Success */
		if (verbose)
		    printf("- Expected failure OK\n");
		kret = 0;
	    }
	}
	/* Cleanup */
	if (in_password)
	    free(in_password);
	if (in_dbent->mod_name)
	    krb5_free_principal(kcontext, in_dbent->mod_name);
	free(in_dbent);
	if (out_dbent->mod_name)
	    krb5_free_principal(kcontext, out_dbent->mod_name);
	free(out_dbent);
    }
    else {
	fprintf(stderr, "%s: no memory\n", pname);
	kret = ENOMEM;
    }

    krb5_free_context(kcontext);
    if (verbose) {
	printf("* End %s ", title);
	if (isrand)
	    printf(" pass %d ", passno);
	printf("%s", (kret) ? "FAILURE" : "SUCCESS");
	if (kret)
	    printf("%d - %s", kret, error_message(kret));
	printf("\n");
    }
    return((kret) ? 1 : 0);
}

/*
 * usage is: t_dbentry [-r <nnn>] [-v]
 */
int
main(argc, argv)
    int		argc;
    char	*argv[];
{
    krb5_boolean	verbose;
    krb5_int32		randompasses;
    krb5_int32		error;
    int		option;
    extern char		*optarg;
    char		*programname;
    int			i;
    time_t		now;

    randompasses = 0;
    verbose = 0;
    error = 0;
    programname = argv[0];

    now = time((time_t *) NULL);
    SRAND((RAND_TYPE) now);
    while ((option = getopt(argc, argv, "r:v")) != EOF) {
	switch (option) {
	case 'r':
	    if (sscanf(optarg, "%d", &randompasses) != 1) {
		fprintf(stderr, "%s: %s is not a number\n", argv[0], optarg);
		error++;
	    }
	    break;
	case 'v':
	    verbose = 1;
	    break;
	default:
	    fprintf(stderr, "%s: usage is %s [-r number] [-v]\n",
		    argv[0], argv[0]);
	    error++;
	    break;
	}
    }
    if (error)
	return(error);

    error += do_test(programname, verbose, 0, 1, "Standard set test", 0);
    error += do_test(programname, verbose, 0, 0, "Standard get test", 0);
    for (i=0; i<randompasses; i++)
	error += do_test(programname, verbose, 1, 0, "Random test", i+1);
    if (verbose) {
	if (error)
	    printf("%s: %d errors in %d tests (%5.2f%%)\n", argv[0], error,
		   randompasses+2,
		   (float) (error*100) / (float) (randompasses+2));
    }
    return(error);
}


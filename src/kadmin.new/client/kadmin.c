/*
 * Copyright 1994 by the Massachusetts Institute of Technology.
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
 * kadmin.c: base functions for a kadmin command line interface using
 * the OVSecure library
 */

#include <krb5/krb5.h>
#include <krb5/los-proto.h>
#include <krb5/ext-proto.h>
#include <stdio.h>
#include <sys/types.h>
#include <math.h>
#include <unistd.h>
#include <pwd.h>

/* special struct to convert flag names for principals
   to actual krb5_flags for a principal */
struct princ_flag {
    char *flagname;		/* name of flag as typed to CLI */
    int flaglen;		/* length of string (not counting -,+) */
    krb5_flags theflag;		/* actual principal flag to set/clear */
    int set;			/* 0 means clear, 1 means set (on '-') */
};

static struct princ_flag the_flags = {
{ "allow_tgs_req", 13, KRB5_KDB_DISALLOW_TGT_BASED, 1 },
{ "allow_tix", 9, KRB5_KDB_DISALLOW_ALL_TIX, 1 },
{ "needchange", 10, KRB5_KDB_REQUIRES_PWCHANGE, 0 },
{ "password_changing_service", 25, KRB5_KDB_PWCHANGE_SERVICE, 0 }
};

char *getenv();
struct passwd *getpwuid();

void usage()
{
    fprintf(stderr,
	    "usage: kadmin [-r realm] [-p principal] [-k keytab] [-q query]\n");
    exit(1);
}

char *kadmin_startup(argc, argv)
    int argc;
    char *argv[];
{
    extern char *optarg;
    char *realmname = NULL, princstr = NULL, *keytab = NULL, *query = NULL;
    char *luser;
    int optchar, freeprinc = 0;
    struct passwd *pw;
    ovsec_kadm_ret_t retval;
    krb5_ccache cc;
    krb5_principal princ;

    while ((optchar = getopt(argc, argv, "r:p:k:q:")) != EOF) {
	switch (optchar) {
	case 'r':
	    realmname = optarg;
	    break;
	case 'p':
	    princstr = optarg;
	    break;
	case 'k':
	    fprintf(stderr, "kadmin: -k not supported yet\n");
	    exit(1);
	    break;
	case 'q':
	    query = optarg;
	    break;
	default:
	    usage();
	}
    }
    if (princstr == NULL) {
	if (!krb5_cc_default(&cc) && !krb5_cc_get_principal(cc, &princ)) {
	    princstr =
		(char *)malloc(krb5_princ_component(princ, 0)->length +
			       7 /* "/admin@" */ +
			       krb5_princ_realm(princ)->length + 1);
	    if (princstr == NULL) {
		fprintf(stderr, "kadmin: out of memory\n");
		exit(1);
	    }
	    /* XXX assuming no nulls in principal */
	    strncpy(princstr, krb5_princ_component(princ, 0)->data,
		    krb5_princ_component(princ, 0)->length);
	    princstr[krb5_princ_component(princ, 0)->length] = '\0';
	    strcat(princstr, "/admin@");
	    strncat(princstr, krb5_princ_realm(princ)->data,
		    krb5_princ_realm(princ)->length);
	    krb5_free_principal(princ);
	    freeprinc++;
	} else if (luser = getenv("USER")) {
	    princstr = malloc(strlen(luser) + 6 /* "/admin" */ + 1);
	    if (princstr == NULL) {
		fprintf(stderr, "kadmin: out of memory\n");
		exit(1);
	    }
	    strcpy(princstr, luser);
	    strcat(princstr, "/admin");
	    freeprinc++;
	} else if (pw = getpwuid(getuid())) {
	    princstr = malloc(strlen(pw->pw_name) + 6 /* "/admin" */ + 1);
	    if (princstr == NULL) {
		fprintf(stderr, "kadmin: out of memory\n");
		exit(1);
	    }
	    strcpy(princstr, pw->pw_name);
	    strcat(princstr, "/admin");
	    freeprinc++;
	} else {
	    fprintf(stderr, "kadmin: unable to figure out a principal name\n");
	    exit(1);
	}
    }
    
    retval = ovsec_kadm_init(princstr, NULL, OVSEC_KADM_ADMIN_SERVICE,
			     realmname);
    if (freeprinc)
	free(princstr);
    if (retval) {		/* assume kadm_init does init_ets() */
	com_err("kadmin", retval, "while initializing kadmin interface");
	exit(1);
    }
    return query;
}

int quit()
{
    ovsec_kadm_destroy();
    /* insert more random cleanup here */
}

void kadmin_delprinc(argc, argv)
    int argc;
    char *argv[];
{
    ovsec_kadm_ret_t retval;
    krb5_principal princ;
    int i;
    char reply[5];

    if (argc > 3) {
	fprintf(stderr, "delete_principal: too many arguments\n");
	return;
    }
    if (argc == 1) {
	printf("Are you sure you want to delete the principal \"%s\"? (yes/no): ", argv[1]);
	fgets(reply, sizeof (reply), stdin);
	if (strcmp("yes\n", reply)) {
	    fprintf(stderr, "Principal \"%s\" not deleted\n", argv[1]);
	    return;
	}
    }
    if ((argc == 2) && ((i = strlen(argv[1])) == 6) &&
	strcmp("-force", argv[1]) || (i != 6) {
	fprintf(stderr, "delete_principal: bad arguments\n");
	return;
    }
    retval = krb5_parse_name(argv[argc - 1], &princ);
    if (retval) {
	com_err("delete_principal", retval, "while parsing principal name");
	return;
    }
    reval = ovsec_kadm_delete_principal(princ);
    krb5_free_principal(princ);
    if (retval) {
	com_err("delete_principal", retval,
		"while deleteing principal \"%s\"", argv[argc - 1]);
	return;
    }
    printf("Principal \"%s\" deleted.\nMake sure that you have removed this principal from all ACLs before reusing.\n", argv[argc - 1]);
    return;
}

void kadmin_renprinc(argc, argv)
    int argc;
    char *argv[];
{
    krb5_principal oldprinc, newprinc;
    int i;
    char reply[5];
    ovsec_kadm_ret_t retval;

    if (argc > 4 || argc < 3) {
	fprintf(stderr, "rename_principal: too many arguments\n");
	return;
    }
    if (argc == 3) {
	printf("Are you sure you want to rename the principal \"%s\" to \"%s\"? (yes/no): ",
	       argv[1], argv[2]);
	fgets(reply, sizeof (reply), stdin);
	if (strcmp("yes\n", reply)) {
	    fprintf(stderr, "rename_principal: \"%s\" NOT renamed to \"%s\".\n",
		    argv[1], argv[2]);
	    return;
	}
    }
    if ((argc == 4) && ((i = strlen(argv[1])) == 6) &&
	!strcmp("-force", argv[1]) || (i != 6)) {
	fprintf(stderr, "rename_principal: wrong arguments\n");
	return;
    }
    retval = krb5_parse_name(argv[argc - 2], &oldprinc);
    if (retval) {
	com_err("rename_principal", retval, "while parsing old principal");
	return;
    }
    retval = krb5_parse_name(argv[argc - 1], &newprinc);
    if (retval) {
	krb5_free_principal(oldprinc);
	com_err("rename_principal", retval, "while parsing new principal");
	return;
    }
    retval = ovsed_kadm_rename_principal(oldprinc, newprinc);
    krb5_free_principal(oldprinc);
    krb5_free_principal(newprinc);
    if (retval) {
	com_err("rename_principal", retval,
		"while renaming \"%s\" to \"%s\".", argv[argc - 2],
		argv[argc - 1]);
	return;
    }
    fprintf("Principal \"%s\" renamed to \"%s\".\nMake sure that you have removed \"%s\" from all ACLs before reusing.\n",
	    argv[argc - 2], argv[argc - 1], argv[argc - 2]);
    return;
}

void kadmin_cpw(argc, argv)
    int argc;
    char *argv[];
{
    ovsec_kadm_ret_t retval;
    static char newpw[1024];
    static char prompt1[1024], prompt2[1024];
    krb5_principal princ;

    if (argc > 4) {
	fprintf(stderr, "change_password: too many arguments\n");
	return;
    }
    retval = krb5_parse_name(argv[argc - 1], &princ);
    if (retval) {
	com_err("change_password", retval, "while parsing principal name");
	return;
    }
    if ((argc == 4) && (strlen(argv[1]) == 3) && !strcmp("-pw", argv[1])) {
	retval = ovsec_kadm_chpass_principal(princ, argv[2]);
	krb5_free_principal(princ);
	if (retval) {
	    com_err("change_password", retval,
		    "while changing password for \"%s\".", argv[3]);
	    return;
	}
	printf("Password for \"%s\" changed.\n", argv[3]);
	return;
    } else if ((argc == 3) && (strlen(argv[1]) == 8) &&
	       !strcmp("-randkey", argv[1])) {
	krb5_keyblock *newkey = NULL;
	retval = ovsec_kadm_randkey_principal(princ, &newkey);
	krb5_free_principal(princ);
	if (retval) {
	    com_err("change_password", retval,
		    "while randomizing key for \"%s\".", argv[2]);
	    return;
	}
	memset(newkey->contents, 0, newkey->length);
	printf("Key for \"%s\" randomized.\n", argv[2]);
	return;
    } else if (argc == 2) {
	int i = sizeof (newpw) - 1;

	sprintf(prompt1, "Enter password for principal \"%.900s\": ",
		argv[1]);
	sprintf(prompt2,
		"Re-enter password for principal \"%.900s\": ",
		argv[1]);
	retval = krb5_read_password(prompt1, prompt2,
				    newpw, &i);
	if (retval) {
	    com_err("change_password", retval,
		    "while reading password for \"%s\".", argv[1]);
	    krb5_free_principal(princ);
	    return;
	}
	retval = ovsec_kadm_chpass_principal(princ, newpw);
	krb5_free_principal(princ);
	memset(newpw, 0, sizeof (newpw));
	if (retval) {
	    com_err("change_password", retval,
		    "while changing password for \"%s\".", argv[1]);
	    return;
	}
	printf("Password for \"%s\" changed.", argv[1]);
	return;
    }
    fprintf(stderr, "change_password: bad args\n");
    krb5_free_principal(princ);
    return;
}

int kadmin_parse_princ_args(argc, argv, oprinc, mask, pass)
    int argc;
    char *argv[];
    ovsec_kadm_principal_ent_t *oprinc;
    u_int32 *mask;
    char *pw;
{
    int i;
    struct timeb now;

    ftime(&now);
    for (i = 1; i < argc - 1; i++) {
	if (strlen(argv[i]) == 7 &&
	    !strcmp("-expire", argv[i])) {
	    if (++i >= argc - 1)
		return -1;
	    else {
		oprinc->princ_expire_time = get_date(argv[i], now);
		*mask |= OVSEC_KADM_PRINC_EXPIRE_TIME;
		continue;
	    }
	}
	if (strlen(argv[i]) == 9 &&
	    !strcmp("-pwexpire", argv[i])) {
	    if (++i >= argc - 1)
		return -1;
	    else {
		oprinc->pw_expiration = get_date(argv[i], now);
		*mask |= OVSEC_KADM_PW_EXPIRATION;
		continue;
	    }
	}
	if (strlen(argv[i]) == 5 &&
	    !strcmp("-kvno", argv[i])) {
	    if (++i >= argc - 1)
		return -1;
	    else {
		oprinc->kvno = atoi(argv[i]);
		*mask |= OVSEC_KADM_KVNO;
		continue;
	    }
	}
	if (strlen(argv[i]) == 8 &&
	    !strcmp("-policy", argv[i])) {
	    if (++i >= argc - 1)
		return -1;
	    else {
		oprinc->policy = argv[i];
		*mask |= OVSEC_KADM_POLICY;
		continue;
	    }
	}
	if (strlen(argv[i]) == 12 &&
	    !strcmp("-clearpolicy", argv[i])) {
	    if (++i >= argc - 1)
		return -1;
	    else {
		oprinc->policy = NULL;
		*mask |= OVSEC_KADM_POLICY_CLR;
		continue;
	    }
	}
    }
}

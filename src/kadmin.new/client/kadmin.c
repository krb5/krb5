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
#include <krb5/kdb.h>
#include <ovsec_admin/admin.h>
#include <stdio.h>
#include <sys/types.h>
#include <math.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/timeb.h>

/* special struct to convert flag names for principals
   to actual krb5_flags for a principal */
struct pflag {
    char *flagname;		/* name of flag as typed to CLI */
    int flaglen;		/* length of string (not counting -,+) */
    krb5_flags theflag;		/* actual principal flag to set/clear */
    int set;			/* 0 means clear, 1 means set (on '-') */
};

static struct pflag flags[] = {
{"allow_postdated",	15,	KRB5_KDB_DISALLOW_POSTDATED,	1},
{"allow_forwardable",	17,	KRB5_KDB_DISALLOW_FORWARDABLE,	1},
{"allow_tgs_req",	13,	KRB5_KDB_DISALLOW_TGT_BASED,	1},
{"allow_renewable",	15,	KRB5_KDB_DISALLOW_RENEWABLE,	1},
{"allow_proxiable",	15,	KRB5_KDB_DISALLOW_PROXIABLE,	1},
{"allow_dup_skey",	14,	KRB5_KDB_DISALLOW_DUP_SKEY,	1},
{"allow_tix",		9,	KRB5_KDB_DISALLOW_ALL_TIX,	1},
{"requires_preauth",	16,	KRB5_KDB_REQUIRES_PRE_AUTH,	0},
{"requres_hwauth",	14,	KRB5_KDB_REQUIRES_HW_AUTH,	0},
{"needchange",		10,	KRB5_KDB_REQUIRES_PWCHANGE,	0},
{"allow_svr",		9,	KRB5_KDB_DISALLOW_SVR,		1},
{"password_changing_service",	25,	KRB5_KDB_PWCHANGE_SERVICE,	0 }
};

static char *prflags[] = {
    "DISALLOW_POSTDATED",	/* 0x00000001 */
    "DISALLOW_FORWARDABLE",	/* 0x00000002 */
    "DISALLOW_TGT_BASED",	/* 0x00000004 */
    "DISALLOW_RENEWABLE",	/* 0x00000008 */
    "DISALLOW_PROXIABLE",	/* 0x00000010 */
    "DISALLOW_DUP_SKEY",	/* 0x00000020 */
    "DISALLOW_ALL_TIX",		/* 0x00000040 */
    "REQUIRES_PRE_AUTH",	/* 0x00000080 */
    "REQUIRES_HW_AUTH",		/* 0x00000100 */
    "REQUIRES_PWCHANGE",	/* 0x00000200 */
    "UNKNOWN_0x00000400",	/* 0x00000400 */
    "UNKNOWN_0x00000800,	/* 0x00000800 */
    "DISALLOW_SVR",		/* 0x00001000 */
    "PWCHANGE_SERVICE"		/* 0x00002000 */
};

char *getenv();
struct passwd *getpwuid();
int exit_status = 0;

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
    char *realmname = NULL, *princstr = NULL, *keytab = NULL, *query = NULL;
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
    char *canon;
    char reply[5];

    if (argc < 2 || argc > 3) {
	fprintf(stderr, "delete_principal: wrong number of arguments\n");
	return;
    }
    if (argc == 3 &&
	(strlen(argv[1]) == 6 ? strcmp("-force", argv[1]) : 1)) {
	fprintf(stderr, "delete_principal: bad arguments\n");
	return;
    }
    retval = krb5_parse_name(argv[argc - 1], &princ);
    if (retval) {
	com_err("delete_principal", retval, "while parsing principal name");
	return;
    }
    retval = krb5_unparse_name(princ, &canon);
    if (retval) {
	com_err("delete_principal", retval,
		"while canonicalizing principal");
	krb5_free_principal(princ);
	return;
    }
    if (argc == 2) {
	printf("Are you sure you want to delete the principal \"%s\"? (yes/no): ", canon);
	fgets(reply, sizeof (reply), stdin);
	if (strcmp("yes\n", reply)) {
	    fprintf(stderr, "Principal \"%s\" not deleted\n", canon);
	    free(canon);
	    krb5_free_principal(princ);
	    return;
	}
    }
    retval = ovsec_kadm_delete_principal(princ);
    krb5_free_principal(princ);
    if (retval) {
	com_err("delete_principal", retval,
		"while deleteing principal \"%s\"", canon);
	free(canon);
	return;
    }
    printf("Principal \"%s\" deleted.\nMake sure that you have removed this principal from all ACLs before reusing.\n", canon);
    free(canon);
    return;
}

void kadmin_renprinc(argc, argv)
    int argc;
    char *argv[];
{
    krb5_principal oldprinc, newprinc;
    char *oldcanon, *newcanon;
    char reply[5];
    ovsec_kadm_ret_t retval;

    if (argc < 3 || argc > 4) {
	fprintf(stderr, "rename_principal: wrong number of arguments\n");
	return;
    }
    if (argc == 4 &&
	(strlen(argv[1]) == 6 ? strcmp("-force", argv[1]) : 1)) {
	fprintf(stderr, "rename_principal: bad arguments\n");
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
    retval = krb5_unparse_name(oldprinc, &oldcanon);
    if (retval) {
	com_err("rename_principal", retval,
		"while canonicalizing old principal");
	krb5_free_principal(newprinc);
	krb5_free_principal(oldprinc);
	return;
    }
    retval = krb5_unparse_name(newprinc, &newcanon);
    if (retval) {
	com_err("rename_principal", retval,
		"while canonicalizing new principal");
	free(oldcanon);
	krb5_free_principal(newprinc);
	krb5_free_principal(oldprinc);
	return;
    }
    if (argc == 3) {
	printf("Are you sure you want to rename the principal \"%s\" to \"%s\"? (yes/no): ",
	       oldcanon, newacnon);
	fgets(reply, sizeof (reply), stdin);
	if (strcmp("yes\n", reply)) {
	    fprintf(stderr,
		    "rename_principal: \"%s\" NOT renamed to \"%s\".\n",
		    oldcanon, newcanon);
	    free(newcanon);
	    free(oldcanon);
	    krb5_free_principal(newprinc);
	    krb5_free_principal(oldprinc);
	    return;
	}
    }
    retval = ovsec_kadm_rename_principal(oldprinc, newprinc);
    krb5_free_principal(oldprinc);
    krb5_free_principal(newprinc);
    if (retval) {
	com_err("rename_principal", retval,
		"while renaming \"%s\" to \"%s\".", oldcanon,
		newcanon);
	free(newcanon);
	free(oldcanon);
	return;
    }
    fprintf("Principal \"%s\" renamed to \"%s\".\nMake sure that you have removed \"%s\" from all ACLs before reusing.\n",
	    oldcanon, newcanon, newcanon);
    return;
}

void kadmin_cpw(argc, argv)
    int argc;
    char *argv[];
{
    ovsec_kadm_ret_t retval;
    static char newpw[1024];
    static char prompt1[1024], prompt2[1024];
    char *canon;
    krb5_principal princ;

    if (argc < 2 || argc > 4) {
	fprintf(stderr, "change_password: too many arguments\n");
	return;
    }
    retval = krb5_parse_name(argv[argc - 1], &princ);
    if (retval) {
	com_err("change_password", retval, "while parsing principal name");
	return;
    }
    retval = krb5_unparse_name(princ, &canon);
    if (retval) {
	com_err("change_password", retval, "while canonicalizing principal");
	krb5_free_principal(princ);
	return;
    }
    if ((argc == 4) && (strlen(argv[1]) == 3) && !strcmp("-pw", argv[1])) {
	retval = ovsec_kadm_chpass_principal(princ, argv[2]);
	krb5_free_principal(princ);
	if (retval) {
	    com_err("change_password", retval,
		    "while changing password for \"%s\".", canon);
	    free(canon);
	    return;
	}
	printf("Password for \"%s\" changed.\n", canon);
	free(canon);
	return;
    } else if ((argc == 3) && (strlen(argv[1]) == 8) &&
	       !strcmp("-randkey", argv[1])) {
	krb5_keyblock *newkey = NULL;
	retval = ovsec_kadm_randkey_principal(princ, &newkey);
	krb5_free_principal(princ);
	if (retval) {
	    com_err("change_password", retval,
		    "while randomizing key for \"%s\".", canon);
	    free(canon);
	    return;
	}
	memset(newkey->contents, 0, newkey->length);
	printf("Key for \"%s\" randomized.\n", canon);
	free(canon);
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
		    "while reading password for \"%s\".", canon);
	    free(canon);
	    krb5_free_principal(princ);
	    return;
	}
	retval = ovsec_kadm_chpass_principal(princ, newpw);
	krb5_free_principal(princ);
	memset(newpw, 0, sizeof (newpw));
	if (retval) {
	    com_err("change_password", retval,
		    "while changing password for \"%s\".", canon);
	    free(canon);
	    return;
	}
	printf("Password for \"%s\" changed.", canon);
	free(canon);
	return;
    }
    fprintf(stderr, "change_password: bad arguments\n");
    free(canon);
    krb5_free_principal(princ);
    return;
}

int kadmin_parse_princ_args(argc, argv, oprinc, mask, pass, caller)
    int argc;
    char *argv[];
    ovsec_kadm_principal_ent_t oprinc;
    u_int32 *mask;
    char **pass, *caller;
{
    int i, j;
    struct timeb now;
    krb5_error_code retval;
    
    *mask = 0;
    *pass = NULL;
    ftime(&now);
    for (i = 1; i < argc - 2; i++) {
	if (strlen(argv[i]) == 7 &&
	    !strcmp("-expire", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		oprinc->princ_expire_time = get_date(argv[i], now);
		*mask |= OVSEC_KADM_PRINC_EXPIRE_TIME;
		continue;
	    }
	}
	if (strlen(argv[i]) == 9 &&
	    !strcmp("-pwexpire", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		oprinc->pw_expiration = get_date(argv[i], now);
		*mask |= OVSEC_KADM_PW_EXPIRATION;
		continue;
	    }
	}
	if (strlen(argv[i]) == 8 &&
	    !strcmp("-maxlife", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		oprinc->max_life = get_date(argv[i], now);
		*mask |= OVSEC_KADM_MAX_LIFE;
		continue;
	    }
	}
	if (strlen(argv[i]) == 5 &&
	    !strcmp("-kvno", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		oprinc->kvno = atoi(argv[i]);
		*mask |= OVSEC_KADM_KVNO;
		continue;
	    }
	}
	if (strlen(argv[i]) == 8 &&
	    !strcmp("-policy", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		oprinc->policy = argv[i];
		*mask |= OVSEC_KADM_POLICY;
		continue;
	    }
	}
	if (strlen(argv[i]) == 12 &&
	    !strcmp("-clearpolicy", argv[i])) {
	    oprinc->policy = NULL;
	    *mask |= OVSEC_KADM_POLICY_CLR;
	    continue;
	}
	if (strlen(argv[i]) == 3 &&
	    !strcmp("-pw", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		pass = argv[i];
		continue;
	    }
	}
	for (j = 0; j < sizeof (flags) / sizeof (struct pflag); j++) {
	    if (strlen(argv[i]) == flags[j].flaglen + 1 &&
		!strcmp(flags[j].flagname,
			&argv[i][1] /* strip off leading + or - */)) {
		if (flags[j].set && argv[i][0] == '-' ||
		    !flags[j].set && argv[i][0] == '+') {
		    oprinc->attributes |= flags[j].theflag;
		    *mask |= OVSEC_KADM_ATTRIBUTES;
		    break;
		} else if (flags[j].set && argv[i][0] == '+' ||
			   !flags[j].set && argv[i][0] == '-') {
		    oprinc->attributes &= ~flags[j].theflag;
		    *mask |= OVSEC_KADM_ATTRIBUTES;
		    break;
		} else {
		    return -1;
		}
	    }
	}
    }
    if (i != argc - 1) {
	fprintf("%s: parser lost count!\n", caller);
	return -1;
    }
    retval = krb5_parse_name(argv[i], &oprinc->principal);
    if (retval) {
	com_err(caller, retval, "while parsing principal");
	return -1;
    }
    *mask |= OVSEC_KADM_PRINCIPAL;
    return 0;
}

void kadmin_addprinc(argc, argv)
    int argc;
    char *argv[];
{
    ovsec_kadm_principal_ent_rec princ;
    u_int32 mask;
    char *pass, *canon;
    krb5_error_code retval;

    if (kadmin_parse_princ_args(argc, argv,
				&princ, &mask, pass, "add_principal")) {
	fprintf(stderr, "add_principal: bad arguments\n");
	return;
    }
    retval = krb5_unparse_name(princ->principal, &canon);
    if (retval) {
	com_err("add_principal",
		retval, "while canonicalizing principal");
	krb5_free_principal(princ->principal);
	return;
    }
    retval = ovsec_kadm_create_principal(&princ, mask, pass);
    krb5_free_principal(princ->principal);
    if (retval) {
	com_err("add_principal", retval, "while creating \"%s\".",
		canon);
	free(canon);
	return;
    }
    printf("Principal \"%s\" created.\n", canon);
    free(canon);
}

void kadmin_modprinc(argc, argv)
    int argc;
    char *argv[];
{
    ovsec_kadm_principal_ent_rec princ;
    u_int32 mask;
    krb5_error_code retval;
    char *pass, *canon;

    if (kadmin_parse_princ_args(argc, argv,
				&princ, &mask, pass, "modify_principal")) {
	fprintf(stderr, "modify_principal: bad arguments\n");
	return;
    }
    retval = krb5_unparse_name(princ->principal, &canon);
    if (retval) {
	com_err("modify_principal", retval,
		"while canonicalizing principal");
	krb5_free_principal(princ->principal);
	return;
    }
    retval = ovsec_kadm_modify_principal(&princ, mask);
    if (retval) {
	com_err("modify_principal", retval, "while modifying \"%s\".",
		argv[argc - 1]);
	return;
    }
}

void kadmin_getprinc(argc, argv)
    int argc;
    char *argv[];
{
    ovsec_kadm_principal_ent_t dprinc;
    krb5_principal princ;
    krb5_error_code retval;
    char *canon, *modcanon;
    int i;

    if (argc < 2 || argc > 3) {
	fprintf(stderr, "get_principal: wrong number of arguments\n");
	return;
    }
    if (argc == 3 &&
	(strlen(argv[1]) == 6 ? !strcmp("-terse", argv[1]) : 1)) {
	fprintf(stderr, "get_principal: bad arguments\n");
	return;
    }
    retval = krb5_parse_name(argv[argc - 1], &princ);
    if (retval) {
	com_err("get_principal", retval, "while parsing principal");
	return;
    }
    retval = krb5_unparse_name(princ, &canon);
    if (retval) {
	com_err("get_principal", retval, "while canonicalizing principal");
	krb5_free_principal(princ);
	return;
    }
    retval = ovsec_kadm_get_principal(princ, &dprinc);
    krb5_free_principal(princ);
    if (retval) {
	com_err("get_principal", retval, "while retrieving \"%s\".", canon);
	free(canon);
	krb5_free_principal(princ);
	return;
    }
    retval = krb5_unparse_name(princ->mod_name, &modcanon);
    if (retval) {
	com_err("get_principal", retval, "while unparsing modname");
	ovsec_kadm_free_principal_ent(dprinc);
	free(canon);
	krb5_free_principal(princ);
	return;
    }
    if (argc == 2) {
	printf("Principal: %s\n", canon);
	printf("Expiration date: %d\n", dprinc->princ_expire_time);
	printf("Last password change: %d\n", dprinc->last_pwd_change);
	printf("Password expiration date: %d\n", dprinc->pw_expiration);
	printf("Maximum life: %d\n", dprinc->max_life);
	printf("Last modified: by %s\n\ton %d\n",
	       modcanon, dprinc->mod_date);
	printf("Attributes: ");
	for (i = 0; i < sizeof (prflags) / sizeof (char *); i++) {
	    if (dprinc->attributes & (krb5_flags) 1 << i)
		printf("%s%s", i ? ", " : "", prflags[i]);
	}
	printf("\n");
	printf("Key version: %d\n", dprinc->kvno);
	printf("Master key version: %d\n", dprinc->mkvno);
	printf("Policy: %s\n", dprinc->policy);
    } else {
	printf("\"%s\"\t%d\t%d\t%d\t%d\t\"%s\"\t%d\t%d\t%d\t%d\t\"%s\"\n",
	       canon, dprinc->princ_expire_time, dprinc->last_pwd_change,
	       dprinc->pw_expiration, dprinc->max_life, modcanon,
	       dprinc->mod_date, dprinc->attributes, dprinc->kvno,
	       dprinc->mkvno, dprinc->policy);
    }
    free(modcanon);
    ovsec_kadm_free_principal_ent(dprinc);
    free(canon);
    krb5_free_principal(princ);
}

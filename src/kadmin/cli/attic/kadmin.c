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
    "UNKNOWN_0x00000800",	/* 0x00000800 */
    "DISALLOW_SVR",		/* 0x00001000 */
    "PWCHANGE_SERVICE"		/* 0x00002000 */
};

char *getenv();
struct passwd *getpwuid();
int exit_status = 0;
char *def_realm = NULL;

void *ovsec_hndl = NULL;

void usage()
{
    fprintf(stderr,
	    "usage: kadmin [-r realm] [-p principal] [-k keytab] [-q query]\n");
    exit(1);
}

/* this is a wrapper to go around krb5_parse_principal so we can set
   the default realm up properly */
krb5_error_code kadmin_parse_name(name, principal)
    char *name;
    krb5_principal *principal;
{
    char *cp, *fullname;
    krb5_error_code retval;
    
    /* assumes def_realm is initialized! */
    fullname = (char *)malloc(strlen(name) + 1 + strlen(def_realm) + 1);
    if (fullname == NULL)
	return ENOMEM;
    strcpy(fullname, name);
    cp = strchr(fullname, '@');
    while (cp) {
	if (cp - fullname && *(cp - 1) != '\\')
	    break;
	else
	    cp = strchr(cp, '@');
    }
    if (cp == NULL) {
	strcat(fullname, "@");
	strcat(fullname, def_realm);
    }
    retval = krb5_parse_name(fullname, principal);
    free(fullname);
    return retval;
}

char *kadmin_startup(argc, argv)
    int argc;
    char *argv[];
{
    extern char *optarg;
    char *princstr = NULL, *keytab = NULL, *query = NULL;
    char *luser, *canon, *cp;
    int optchar, freeprinc = 0;
    struct passwd *pw;
    ovsec_kadm_ret_t retval;
    krb5_ccache cc;
    krb5_principal princ;
    
    while ((optchar = getopt(argc, argv, "r:p:k:q:")) != EOF) {
	switch (optchar) {
	case 'r':
	    def_realm = optarg;
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
    if (def_realm == NULL && krb5_get_default_realm(&def_realm)) {
	if (freeprinc)
	    free(princstr);
	fprintf(stderr, "kadmin: unable to get default realm\n");
	exit(1);
    }
    if (princstr == NULL) {
	if (!krb5_cc_default(&cc) && !krb5_cc_get_principal(cc, &princ)) {
	    char *realm = NULL;
	    if (krb5_unparse_name(princ, &canon)) {
		fprintf(stderr,
			"kadmin: unable to canonicalize principal\n");
		krb5_free_principal(princ);
		exit(1);
	    }
	    /* strip out realm of principal if it's there */
	    realm = strchr(canon, '@');
	    while (realm) {
		if (realm - canon && *(realm - 1) != '\\')
		    break;
		else
		    realm = strchr(realm, '@');
	    }
	    if (realm)
		*realm++ = '\0';
	    cp = strchr(canon, '/');
	    while (cp) {
		if (cp - canon && *(cp - 1) != '\\')
		    break;
		else
		    cp = strchr(cp, '/');
	    }
	    if (cp != NULL)
		*cp = '\0';
	    princstr = (char*)malloc(strlen(canon) + 6 /* "/admin" */ +
				     (realm ? 1 + strlen(realm) : 0) + 1);
	    if (princstr == NULL) {
		fprintf(stderr, "kadmin: out of memory\n");
		exit(1);
	    }
	    strcpy(princstr, canon);
	    strcat(princstr, "/admin");
	    if (realm) {
		strcat(princstr, "@");
		strcat(princstr, realm);
	    }
	    free(canon);
	    krb5_free_principal(princ);
	    freeprinc++;
	} else if (luser = getenv("USER")) {
	    princstr = malloc(strlen(luser) + 7 /* "/admin@" */
			      + strlen(def_realm) + 1);
	    if (princstr == NULL) {
		fprintf(stderr, "kadmin: out of memory\n");
		exit(1);
	    }
	    strcpy(princstr, luser);
	    strcat(princstr, "/admin");
	    strcat(princstr, "@");
	    strcat(princstr, def_realm);
	    freeprinc++;
	} else if (pw = getpwuid(getuid())) {
	    princstr = malloc(strlen(pw->pw_name) + 7 /* "/admin@" */
			      + strlen(def_realm) + 1);
	    if (princstr == NULL) {
		fprintf(stderr, "kadmin: out of memory\n");
		exit(1);
	    }
	    strcpy(princstr, pw->pw_name);
	    strcat(princstr, "/admin@");
	    strcat(princstr, def_realm);
	    freeprinc++;
	} else {
	    fprintf(stderr, "kadmin: unable to figure out a principal name\n");
	    exit(1);
	}
    }
    retval = ovsec_kadm_init_with_password(princstr, NULL,
					   OVSEC_KADM_ADMIN_SERVICE, 
					   def_realm,
					   OVSEC_KADM_STRUCT_VERSION,
					   OVSEC_KADM_API_VERSION_1,
					   &ovsec_hndl);
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
    ovsec_kadm_destroy(ovsec_hndl);
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
    retval = kadmin_parse_name(argv[argc - 1], &princ);
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
    retval = ovsec_kadm_delete_principal(ovsec_hndl, princ);
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
    retval = kadmin_parse_name(argv[argc - 2], &oldprinc);
    if (retval) {
	com_err("rename_principal", retval, "while parsing old principal");
	return;
    }
    retval = kadmin_parse_name(argv[argc - 1], &newprinc);
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
	       oldcanon, newcanon);
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
    retval = ovsec_kadm_rename_principal(ovsec_hndl, oldprinc, newprinc);
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
    printf("Principal \"%s\" renamed to \"%s\".\nMake sure that you have removed \"%s\" from all ACLs before reusing.\n",
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
    retval = kadmin_parse_name(argv[argc - 1], &princ);
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
	retval = ovsec_kadm_chpass_principal(ovsec_hndl, princ, argv[2]);
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
	retval = ovsec_kadm_randkey_principal(ovsec_hndl, princ, &newkey);
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
	retval = ovsec_kadm_chpass_principal(ovsec_hndl, princ, newpw);
	krb5_free_principal(princ);
	memset(newpw, 0, sizeof (newpw));
	if (retval) {
	    com_err("change_password", retval,
		    "while changing password for \"%s\".", canon);
	    free(canon);
	    return;
	}
	printf("Password for \"%s\" changed.\n", canon);
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
    for (i = 1; i < argc - 1; i++) {
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
		oprinc->max_life = get_date(argv[i], now) - now.time;
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
		*pass = argv[i];
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
	return -1;
    }
    if (i != argc - 1) {
	fprintf(stderr, "%s: parser lost count!\n", caller);
	return -1;
    }
    retval = kadmin_parse_name(argv[i], &oprinc->principal);
    if (retval) {
	com_err(caller, retval, "while parsing principal");
	return -1;
    }
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
    static char newpw[1024];
    static char prompt1[1024], prompt2[1024];
    
    princ.attributes = 0;
    if (kadmin_parse_princ_args(argc, argv,
				&princ, &mask, &pass, "add_principal")) {
	fprintf(stderr, "add_principal: bad arguments\n");
	return;
    }
    retval = krb5_unparse_name(princ.principal, &canon);
    if (retval) {
	com_err("add_principal",
		retval, "while canonicalizing principal");
	krb5_free_principal(princ.principal);
	return;
    }
    if (pass == NULL) {
	int i = sizeof (newpw) - 1;
	
	sprintf(prompt1, "Enter password for principal \"%.900s\": ",
		argv[1]);
	sprintf(prompt2,
		"Re-enter password for principal \"%.900s\": ",
		argv[1]);
	retval = krb5_read_password(prompt1, prompt2,
				    newpw, &i);
	if (retval) {
	    com_err("add_principal", retval,
		    "while reading password for \"%s\".", canon);
	    free(canon);
	    krb5_free_principal(princ.principal);
	    return;
	}
	pass = newpw;
    }
    mask |= OVSEC_KADM_PRINCIPAL;
    retval = ovsec_kadm_create_principal(ovsec_hndl, &princ, mask, pass);
    krb5_free_principal(princ.principal);
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
    
    princ.attributes = 0;
    if (kadmin_parse_princ_args(argc, argv,
				&princ, &mask, &pass, "modify_principal")) {
	fprintf(stderr, "modify_principal: bad arguments\n");
	return;
    }
    retval = krb5_unparse_name(princ.principal, &canon);
    if (retval) {
	com_err("modify_principal", retval,
		"while canonicalizing principal");
	krb5_free_principal(princ.principal);
	return;
    }
    retval = ovsec_kadm_modify_principal(ovsec_hndl, &princ, mask);
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
	(strlen(argv[1]) == 6 ? strcmp("-terse", argv[1]) : 1)) {
	fprintf(stderr, "get_principal: bad arguments\n");
	return;
    }
    retval = kadmin_parse_name(argv[argc - 1], &princ);
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
    retval = ovsec_kadm_get_principal(ovsec_hndl, princ, &dprinc);
    krb5_free_principal(princ);
    if (retval) {
	com_err("get_principal", retval, "while retrieving \"%s\".", canon);
	free(canon);
	return;
    }
    retval = krb5_unparse_name(dprinc->mod_name, &modcanon);
    if (retval) {
	com_err("get_principal", retval, "while unparsing modname");
	ovsec_kadm_free_principal_ent(ovsec_hndl, dprinc);
	free(canon);
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
		printf(" %s", prflags[i]);
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
    ovsec_kadm_free_principal_ent(ovsec_hndl, dprinc);
    free(canon);
}

int kadmin_parse_policy_args(argc, argv, policy, mask, caller)
    int argc;
    char *argv[];
    ovsec_kadm_policy_ent_t policy;
    u_int32 *mask;
    char *caller;
{
    int i;
    struct timeb now;
    krb5_error_code retval;

    ftime(&now);
    *mask = 0;
    for (i = 1; i < argc - 1; i++) {
	if (strlen(argv[i]) == 8 &&
	    !strcmp(argv[i], "-maxlife")) {
	    if (++i > argc -2)
		return -1;
	    else {
		policy->pw_max_life = get_date(argv[i], now) - now.time;
		*mask |= OVSEC_KADM_PW_MAX_LIFE;
		continue;
	    }
	} else if (strlen(argv[i]) == 8 &&
		   !strcmp(argv[i], "-minlife")) {
	    if (++i > argc - 2)
		return -1;
	    else {
		policy->pw_min_life = get_date(argv[i], now) - now.time;
		*mask |= OVSEC_KADM_PW_MIN_LIFE;
		continue;
	    }
	} else if (strlen(argv[i]) == 10 &&
	    !strcmp(argv[i], "-minlength")) {
	    if (++i > argc - 2)
		return -1;
	    else {
		policy->pw_min_length = atoi(argv[i]);
		*mask |= OVSEC_KADM_PW_MIN_LENGTH;
		continue;
	    }
	} else if (strlen(argv[i]) == 11 &&
		   !strcmp(argv[i], "-minclasses")) {
	    if (++i > argc - 2)
		return -1;
	    else {
		policy->pw_min_classes = atoi(argv[i]);
		*mask |= OVSEC_KADM_PW_MIN_CLASSES;
		continue;
	    }
	} else if (strlen(argv[i]) == 8 &&
		   !strcmp(argv[i], "-history")) {
	    if (++i > argc - 2)
		return -1;
	    else {
		policy->pw_history_num = atoi(argv[i]);
		*mask |= OVSEC_KADM_PW_HISTORY_NUM;
		continue;
	    }
	} else
	    return -1;
    }
    if (i != argc -1) {
	fprintf(stderr, "%s: parser lost count!\n", caller);
	return -1;
    } else
	return 0;
}

void kadmin_addpol(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code retval;
    u_int32 mask;
    ovsec_kadm_policy_ent_rec policy;
    
    if (kadmin_parse_policy_args(argc, argv, &policy, &mask, "add_policy")) {
	fprintf(stderr, "add_policy: bad arguments\n");
	return;
    } else {
	policy.policy = argv[argc - 1];
	mask |= OVSEC_KADM_POLICY;
	retval = ovsec_kadm_create_policy(ovsec_hndl, &policy, mask);
	if (retval) {
	    com_err("add_policy", retval, "while creating policy \"%s\".",
		    policy.policy);
	    return;
	}
    }
    return;
}

void kadmin_modpol(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code retval;
    u_int32 mask;
    ovsec_kadm_policy_ent_rec policy;
    
    if (kadmin_parse_policy_args(argc, argv, &policy, &mask,
				 "modify_policy")) {
	fprintf(stderr, "modify_policy: bad arguments\n");
	return;
    } else {
	policy.policy = argv[argc - 1];
	retval = ovsec_kadm_modify_policy(ovsec_hndl, &policy, mask);
	if (retval) {
	    com_err("modify_policy", retval, "while modifying policy \"%s\".",
		    policy.policy);
	    return;
	}
    }
    return;
}

void kadmin_delpol(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code retval;
    char reply[5];
    
    if (argc < 2 || argc > 3) {
	fprintf(stderr, "delete_policy: wrong number of arguments\n");
	return;
    }
    if (argc == 3 &&
	(strlen(argv[1]) == 6 ? strcmp("-force", argv[1]) : 1)) {
	fprintf(stderr, "delete_policy: bad arguments\n");
	return;
    }
    if (argc == 2) {
	printf("Are you sure you want to delete the policy \"%s\"? (yes/no): ", argv[1]);
	fgets(reply, sizeof (reply), stdin);
	if (strcmp("yes\n", reply)) {
	    fprintf(stderr, "Policy \"%s\" not deleted.\n", argv[1]);
	    return;
	}
    }
    retval = ovsec_kadm_delete_policy(ovsec_hndl, argv[argc - 1]);
    if (retval) {
	com_err("delete_policy:", retval, "while deleting policy \"%s\"",
		argv[argc - 1]);
	return;
    }
    return;
}

void kadmin_getpol(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code retval;
    ovsec_kadm_policy_ent_t policy;
    
    if (argc < 2 || argc > 3) {
	fprintf(stderr, "get_policy: wrong number of arguments\n");
	return;
    }
    if (argc == 3 &&
	(strlen(argv[1]) == 6 ? strcmp("-terse", argv[1]) : 1)) {
	fprintf(stderr, "get_policy: bad arguments\n");
	return;
    }
    retval = ovsec_kadm_get_policy(ovsec_hndl, argv[argc - 1], &policy);
    if (retval) {
	com_err("get_policy", retval, "while retrieving policy \"%s\".",
		argv[argc - 1]);
	return;
    }
    if (argc == 2) {
	printf("Policy: %s\n", policy->policy);
	printf("Maximum password life: %d\n", policy->pw_max_life);
	printf("Minimum password life: %d\n", policy->pw_min_life);
	printf("Minimum password length: %d\n", policy->pw_min_length);
	printf("Minimum number of password character classes: %d\n",
	       policy->pw_min_classes);
	printf("Number of old keys kept: %d\n", policy->pw_history_num);
	printf("Reference count: %d\n", policy->policy_refcnt);
    } else {
	printf("\"%s\"\t%d\t%d\t%d\t%d\t%d\t%d\n",
	       policy->policy, policy->pw_max_life, policy->pw_min_life,
	       policy->pw_min_length, policy->pw_min_classes,
	       policy->pw_history_num, policy->policy_refcnt);
    }
    ovsec_kadm_free_policy_ent(ovsec_hndl, policy);
    return;
}

kadmin_getprivs(argc, argv)
    int argc;
    char *argv[];
{
    static char *privs[] = {"GET", "ADD", "MODIFY", "DELETE"};
    krb5_error_code retval;
    int i;
    u_int32 plist;

    if (argc != 1) {
	fprintf(stderr, "get_privs: bad arguments\n");
	return;
    }
    retval = ovsec_kadm_get_privs(ovsec_hndl, &plist);
    if (retval) {
	com_err("get_privs", retval, "while retrieving privileges");
	return;
    }
    printf("current privileges:");
    for (i = 0; i < sizeof (privs) / sizeof (char *); i++) {
	if (plist & 1 << i)
	    printf(" %s", privs[i]);
    }
    printf("\n");
    return;
}

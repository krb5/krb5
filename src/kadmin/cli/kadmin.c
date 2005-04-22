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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * kadmin.c: base functions for a kadmin command line interface using
 * the OVSecure library
 */

#include <krb5.h>
#include <kadm5/admin.h>
#include <krb5/adm_proto.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <math.h>
#include <unistd.h>
#include <pwd.h>
/* #include <sys/timeb.h> */
#include <time.h>
#include "kadmin.h"

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
{"requires_hwauth",	15,	KRB5_KDB_REQUIRES_HW_AUTH,	0},
{"needchange",		10,	KRB5_KDB_REQUIRES_PWCHANGE,	0},
{"allow_svr",		9,	KRB5_KDB_DISALLOW_SVR,		1},
{"password_changing_service",	25,	KRB5_KDB_PWCHANGE_SERVICE,	0 },
{"support_desmd5",	14,	KRB5_KDB_SUPPORT_DESMD5,	0 }
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
    "PWCHANGE_SERVICE",		/* 0x00002000 */
    "SUPPORT_DESMD5",		/* 0x00004000 */
    "NEW_PRINC",		/* 0x00008000 */
};

char *getenv();
int exit_status = 0;
char *def_realm = NULL;
char *whoami = NULL;

void *handle = NULL;
krb5_context context;
char *ccache_name = NULL;

int locked = 0;

static void usage()
{
    fprintf(stderr,
	 "Usage: %s [-r realm] [-p principal] [-q query] [clnt|local args]\n"
    "\tclnt args: [-s admin_server[:port]] [[-c ccache]|[-k [-t keytab]]]\n"
	 "\tlocal args: [-d dbname] [-e \"enc:salt ...\"] [-m]\n", whoami);
    exit(1);
}

static char *strdur(duration)
    time_t duration;
{
    static char out[50];
    int neg, days, hours, minutes, seconds;

    if (duration < 0) {
	duration *= -1;
	neg = 1;
    } else
	neg = 0;
    days = duration / (24 * 3600);
    duration %= 24 * 3600;
    hours = duration / 3600;
    duration %= 3600;
    minutes = duration / 60;
    duration %= 60;
    seconds = duration;
    sprintf(out, "%s%d %s %02d:%02d:%02d", neg ? "-" : "",
	    days, days == 1 ? "day" : "days",
	    hours, minutes, seconds);
    return out;
}

static char *strdate(when)
    krb5_timestamp when;
{
    struct tm *tm;
    static char out[40];
    
    time_t lcltim = when;
    tm = localtime(&lcltim);
    strftime(out, sizeof(out), "%a %b %d %H:%M:%S %Z %Y", tm);
    return out;
}

/* this is a wrapper to go around krb5_parse_principal so we can set
   the default realm up properly */
static krb5_error_code 
kadmin_parse_name(name, principal)
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
	    cp = strchr(cp + 1, '@');
    }
    if (cp == NULL) {
	strcat(fullname, "@");
	strcat(fullname, def_realm);
    }
    retval = krb5_parse_name(context, fullname, principal);
    free(fullname);
    return retval;
}

char *kadmin_startup(argc, argv)
    int argc;
    char *argv[];
{
    extern char *optarg;
    char *princstr = NULL, *keytab_name = NULL, *query = NULL;
    char *password = NULL;
    char *luser, *canon, *cp;
    int optchar, freeprinc = 0, use_keytab = 0;
    struct passwd *pw;
    kadm5_ret_t retval;
    krb5_ccache cc;
    krb5_principal princ;
    kadm5_config_params params;
    char *svcname;

    memset((char *) &params, 0, sizeof(params));
    
    retval = krb5_init_context(&context);
    if (retval) {
	 com_err(whoami, retval, "while initializing krb5 library");
	 exit(1);
    }
		     
    while ((optchar = getopt(argc, argv, "r:p:kq:w:d:s:mc:t:e:ON")) != EOF) {
	switch (optchar) {
	case 'r':
	    def_realm = optarg;
	    break;
	case 'p':
	    princstr = optarg;
	    break;
        case 'c':
	    ccache_name = optarg;
	    break;
        case 'k':
	    use_keytab++;
	    break;
       case 't':
	    keytab_name = optarg;
	    break;
        case 'w':
	    password = optarg;
	    break;
	case 'q':
	    query = optarg;
	    break;
        case 'd':
	    params.dbname = optarg;
	    params.mask |= KADM5_CONFIG_DBNAME;
	    break;
        case 's':
	    params.admin_server = optarg;
	    params.mask |= KADM5_CONFIG_ADMIN_SERVER;
	    break;
        case 'm':
	    params.mkey_from_kbd = 1;
	    params.mask |= KADM5_CONFIG_MKEY_FROM_KBD;
	    break;
        case 'e':
	    retval = krb5_string_to_keysalts(optarg,
					     ", \t",
					     ":.-",
					     0,
					     &params.keysalts,
					     &params.num_keysalts);
	    if (retval) {
		 com_err(whoami, retval, "while parsing keysalts %s", optarg);
		 exit(1);
	    }
	    params.mask |= KADM5_CONFIG_ENCTYPES;
	    break;
	case 'O':
	    params.mask |= KADM5_CONFIG_OLD_AUTH_GSSAPI;
	    break;
	case 'N':
	    params.mask |= KADM5_CONFIG_AUTH_NOFALLBACK;
	    break;
	default:
	    usage();
	}
    }
    if ((ccache_name && use_keytab) ||
	(keytab_name && !use_keytab))
	 usage();

    if (def_realm == NULL && krb5_get_default_realm(context, &def_realm)) {
	if (freeprinc)
	    free(princstr);
	fprintf(stderr, "%s: unable to get default realm\n", whoami);
	exit(1);
    }

    params.mask |= KADM5_CONFIG_REALM;
    params.realm = def_realm;

    if (params.mask & KADM5_CONFIG_OLD_AUTH_GSSAPI)
	svcname = KADM5_ADMIN_SERVICE;
    else
	svcname = NULL;

    /*
     * Set cc to an open credentials cache, either specified by the -c
     * argument or the default.
     */
    if (ccache_name == NULL) {
	 if ((retval = krb5_cc_default(context, &cc))) {
	      com_err(whoami, retval,
		      "while opening default credentials cache");
	      exit(1);
	 }
    } else {
	 if ((retval = krb5_cc_resolve(context, ccache_name, &cc))) {
	      com_err(whoami, retval,
		      "while opening credentials cache %s", ccache_name);
	      exit(1);
	 }
    }

    /*
     * If no principal name is specified: If a ccache was specified
     * and its primary principal name can be read, it is used, else if
     * a keytab was specified, the principal name is host/hostname,
     * otherwise append "/admin" to the primary name of the default
     * ccache, $USER, or pw_name.
     *
     * Gee, 100+ lines to figure out the client principal name.  This
     * should be compressed...
     */
    
    if (princstr == NULL) {
	if (ccache_name != NULL &&
	    !krb5_cc_get_principal(context, cc, &princ)) {
	     if ((retval = krb5_unparse_name(context, princ, &princstr))) {
		  com_err(whoami, retval,
			  "while canonicalizing principal name");
		  krb5_free_principal(context, princ);
		  exit(1);
	     }
	     krb5_free_principal(context, princ);
	     freeprinc++;
	} else if (use_keytab != 0) {
	     if ((retval = krb5_sname_to_principal(context, NULL,
						   "host",
						   KRB5_NT_SRV_HST,
						   &princ))) {
		  com_err(whoami, retval,
			  "creating host service principal");
		  exit(1);
	     }
	     if ((retval = krb5_unparse_name(context, princ, &princstr))) {
	          com_err(whoami, retval,
			  "while canonicalizing principal name");
		  krb5_free_principal(context, princ);
		  exit(1);
	     }
	     krb5_free_principal(context, princ);
	     freeprinc++;
	} else if (!krb5_cc_get_principal(context, cc, &princ)) {
	    char *realm = NULL;
	    if (krb5_unparse_name(context, princ, &canon)) {
		fprintf(stderr,
			"%s: unable to canonicalize principal\n", whoami);
		krb5_free_principal(context, princ);
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
		fprintf(stderr, "%s: out of memory\n", whoami);
		exit(1);
	    }
	    strcpy(princstr, canon);
	    strcat(princstr, "/admin");
	    if (realm) {
		strcat(princstr, "@");
		strcat(princstr, realm);
	    }
	    free(canon);
	    krb5_free_principal(context, princ);
	    freeprinc++;
	} else if ((luser = getenv("USER"))) {
	    princstr = (char *) malloc(strlen(luser) + 7 /* "/admin@" */
			      + strlen(def_realm) + 1);
	    if (princstr == NULL) {
		fprintf(stderr, "%s: out of memory\n", whoami);
		exit(1);
	    }
	    strcpy(princstr, luser);
	    strcat(princstr, "/admin");
	    strcat(princstr, "@");
	    strcat(princstr, def_realm);
	    freeprinc++;
	} else if ((pw = getpwuid(getuid()))) {
	    princstr = (char *) malloc(strlen(pw->pw_name) + 7 /* "/admin@" */
			      + strlen(def_realm) + 1);
	    if (princstr == NULL) {
		fprintf(stderr, "%s: out of memory\n", whoami);
		exit(1);
	    }
	    strcpy(princstr, pw->pw_name);
	    strcat(princstr, "/admin@");
	    strcat(princstr, def_realm);
	    freeprinc++;
	} else {
	    fprintf(stderr, "%s: unable to figure out a principal name\n",
		    whoami);
	    exit(1);
	}
    }

    retval = krb5_klog_init(context, "admin_server", whoami, 0);
    if (retval) {
	com_err(whoami, retval, "while setting up logging");
	exit(1);
    }

    /*
     * Initialize the kadm5 connection.  If we were given a ccache,
     * use it.  Otherwise, use/prompt for the password.
     */
    if (ccache_name) {
	 printf("Authenticating as principal %s with existing credentials.\n",
		princstr);
	 retval = kadm5_init_with_creds(princstr, cc,
					svcname, 
					&params,
					KADM5_STRUCT_VERSION,
					KADM5_API_VERSION_2,
					&handle);
    } else if (use_keytab) {
	 if (keytab_name)
	     printf("Authenticating as principal %s with keytab %s.\n",
		    princstr, keytab_name);
	 else
	     printf("Authenticating as principal %s with default keytab.\n",
		    princstr);
	 retval = kadm5_init_with_skey(princstr, keytab_name,
				       svcname, 
				       &params,
				       KADM5_STRUCT_VERSION,
				       KADM5_API_VERSION_2,
				       &handle);
    } else {
	 printf("Authenticating as principal %s with password.\n",
		princstr);
	 retval = kadm5_init_with_password(princstr, password,
					   svcname, 
					   &params,
					   KADM5_STRUCT_VERSION,
					   KADM5_API_VERSION_2,
					   &handle);
    }
    if (retval) {
	com_err(whoami, retval, "while initializing %s interface", whoami);
	if (retval == KADM5_BAD_CLIENT_PARAMS ||
	    retval == KADM5_BAD_SERVER_PARAMS)
	     usage();
	exit(1);
    }
    if (freeprinc)
	free(princstr);

    if ((retval = krb5_cc_close(context, cc))) {
	 com_err(whoami, retval, "while closing ccache %s",
		 ccache_name);
	 exit(1);
    }

    /* register the WRFILE keytab type and set it as the default */
    {
#define DEFAULT_KEYTAB "WRFILE:/etc/krb5.keytab"
	 /* XXX krb5_defkeyname is an internal library global and
            should go away */
	 extern char *krb5_defkeyname;
	 krb5_defkeyname = DEFAULT_KEYTAB;
    }
    
    return query;
}

int quit()
{
    kadm5_ret_t retval;

    if (locked) {
	retval = kadm5_unlock(handle);
	if (retval) {
	    com_err("quit", retval, "while unlocking locked database");
	    return 1;
	}
	locked = 0;
    }

     kadm5_destroy(handle);
     if (ccache_name != NULL) {
	  fprintf(stderr,
		  "\n\a\a\aAdministration credentials NOT DESTROYED.\n");
     }

     /* insert more random cleanup here */
     krb5_klog_close(context);
     krb5_free_context(context);
     return 0;
}

void kadmin_lock(argc, argv)
    int argc;
    char *argv[];
{
    kadm5_ret_t retval;

    if (locked)
	return;
    retval = kadm5_lock(handle);
    if (retval) {
	com_err("lock", retval, "");
	return;
    }
    locked = 1;
}

void kadmin_unlock(argc, argv)
    int argc;
    char *argv[];
{
    kadm5_ret_t retval;

    if (!locked)
	return;
    retval = kadm5_lock(handle);
    if (retval) {
	com_err("unlock", retval, "");
	return;
    }
    locked = 0;
}

void kadmin_delprinc(argc, argv)
    int argc;
    char *argv[];
{
    kadm5_ret_t retval;
    krb5_principal princ;
    char *canon;
    char reply[5];
    
    if (! (argc == 2 ||
	   (argc == 3 && !strcmp("-force", argv[1])))) {
	fprintf(stderr, "usage: delete_principal [-force] principal\n");
	return;
    }
    retval = kadmin_parse_name(argv[argc - 1], &princ);
    if (retval) {
	com_err("delete_principal", retval, "while parsing principal name");
	return;
    }
    retval = krb5_unparse_name(context, princ, &canon);
    if (retval) {
	com_err("delete_principal", retval,
		"while canonicalizing principal");
	krb5_free_principal(context, princ);
	return;
    }
    if (argc == 2) {
	printf("Are you sure you want to delete the principal \"%s\"? (yes/no): ", canon);
	fgets(reply, sizeof (reply), stdin);
	if (strcmp("yes\n", reply)) {
	    fprintf(stderr, "Principal \"%s\" not deleted\n", canon);
	    free(canon);
	    krb5_free_principal(context, princ);
	    return;
	}
    }
    retval = kadm5_delete_principal(handle, princ);
    krb5_free_principal(context, princ);
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

void kadmin_cpw(argc, argv)
    int argc;
    char *argv[];
{
    kadm5_ret_t retval;
    static char newpw[1024];
    static char prompt1[1024], prompt2[1024];
    char *canon;
    char *pwarg = NULL;
    int n_ks_tuple = 0, randkey = 0;
    krb5_boolean keepold = FALSE;
    krb5_key_salt_tuple *ks_tuple = NULL;
    krb5_principal princ;
    
    if (argc < 2) {
	 goto usage;
    }
    for (argv++, argc--; argc > 1; argc--, argv++) {
	if (!strcmp("-pw", *argv)) {
	    argc--;
	    if (argc < 1) {
		fprintf(stderr, "change_password: missing password arg\n");
		goto usage;
	    }
	    pwarg = *++argv;
	    continue;
	}
	if (!strcmp("-randkey", *argv)) {
	    randkey++;
	    continue;
	}
	if (!strcmp("-keepold", *argv)) {
	    keepold = TRUE;
	    continue;
	}
	if (!strcmp("-e", *argv)) {
	    argc--;
	    if (argc < 1) {
		fprintf(stderr,
			"change_password: missing keysaltlist arg\n");
		goto usage;
	    }
	    retval = krb5_string_to_keysalts(*++argv, ", \t", ":.-", 0,
					     &ks_tuple, &n_ks_tuple);
	    if (retval) {
		com_err("change_password", retval,
			"while parsing keysalts %s", *argv);
		return;
	    }
	    continue;
	}
	goto usage;
    }
    retval = kadmin_parse_name(*argv, &princ);
    if (retval) {
	com_err("change_password", retval, "while parsing principal name");
	if (ks_tuple != NULL)
	    free(ks_tuple);
	return;
    }
    retval = krb5_unparse_name(context, princ, &canon);
    if (retval) {
	com_err("change_password", retval, "while canonicalizing principal");
	krb5_free_principal(context, princ);
	if (ks_tuple != NULL)
	    free(ks_tuple);
	return;
    }
    if (pwarg != NULL) {
	if (keepold || ks_tuple != NULL) {
	    retval = kadm5_chpass_principal_3(handle, princ, keepold,
					      n_ks_tuple, ks_tuple, pwarg);
	    if (ks_tuple != NULL)
		free(ks_tuple);
	} else {
	    retval = kadm5_chpass_principal(handle, princ, pwarg);
	}
	krb5_free_principal(context, princ);
	if (retval) {
	    com_err("change_password", retval,
		    "while changing password for \"%s\".", canon);
	    free(canon);
	    return;
	}
	printf("Password for \"%s\" changed.\n", canon);
	free(canon);
	return;
    } else if (randkey) {
	if (keepold || ks_tuple != NULL) {
	    retval = kadm5_randkey_principal_3(handle, princ, keepold,
					       n_ks_tuple, ks_tuple,
					       NULL, NULL);
	    if (ks_tuple != NULL)
		free(ks_tuple);
	} else {
	    retval = kadm5_randkey_principal(handle, princ, NULL, NULL);
	}
	krb5_free_principal(context, princ);
	if (retval) {
	    com_err("change_password", retval,
		    "while randomizing key for \"%s\".", canon);
	    free(canon);
	    return;
	}
	printf("Key for \"%s\" randomized.\n", canon);
	free(canon);
	return;
    } else if (argc == 1) {
	unsigned int i = sizeof (newpw) - 1;
	
	sprintf(prompt1, "Enter password for principal \"%.900s\"",
		*argv);
	sprintf(prompt2,
		"Re-enter password for principal \"%.900s\"",
		*argv);
	retval = krb5_read_password(context, prompt1, prompt2,
				    newpw, &i);
	if (retval) {
	    com_err("change_password", retval,
		    "while reading password for \"%s\".", canon);
	    free(canon);
	    if (ks_tuple != NULL)
		free(ks_tuple);
	    krb5_free_principal(context, princ);
	    return;
	}
	if (keepold || ks_tuple != NULL) {
	    retval = kadm5_chpass_principal_3(handle, princ, keepold,
					      n_ks_tuple, ks_tuple,
					      newpw);
	    if (ks_tuple != NULL)
		free(ks_tuple);
	} else {
	    retval = kadm5_chpass_principal(handle, princ, newpw);
	}
	krb5_free_principal(context, princ);
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
   } else {
	free(canon);
	krb5_free_principal(context, princ);
   usage:
	if (ks_tuple != NULL)
	    free(ks_tuple);
	fprintf(stderr,
		"usage: change_password [-randkey] [-keepold] "
		"[-e keysaltlist] [-pw password] "
		"principal\n");
	return;
   }
}

static int 
kadmin_parse_princ_args(argc, argv, oprinc, mask, pass, randkey,
			ks_tuple, n_ks_tuple, caller)
    int argc;
    char *argv[];
    kadm5_principal_ent_t oprinc;
    long *mask;
    char **pass;
    int *randkey;
    krb5_key_salt_tuple **ks_tuple;
    int *n_ks_tuple;
    char *caller;
{
    int i, j, attrib_set;
    time_t date;
    time_t now;
    krb5_error_code retval;
    
    *mask = 0;
    *pass = NULL;
    *n_ks_tuple = 0;
    *ks_tuple = NULL;
    time(&now);
    *randkey = 0;
    for (i = 1; i < argc - 1; i++) {
	attrib_set = 0;
	if (strlen(argv[i]) == 7 &&
	    !strcmp("-expire", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		date = get_date(argv[i]);
 		if (date == (time_t)-1) {
		     fprintf(stderr, "Invalid date specification \"%s\".\n",
			     argv[i]);
		     return -1;
 		}
		oprinc->princ_expire_time = date;
		*mask |= KADM5_PRINC_EXPIRE_TIME;
		continue;
	    }
	}
	if (strlen(argv[i]) == 9 &&
	    !strcmp("-pwexpire", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		date = get_date(argv[i]);
 		if (date == (time_t)-1) {
		     fprintf(stderr, "Invalid date specification \"%s\".\n",
			     argv[i]);
		     return -1;
 		}
		oprinc->pw_expiration = date;
		*mask |= KADM5_PW_EXPIRATION;
		continue;
	    }
	}
	if (strlen(argv[i]) == 8 &&
	    !strcmp("-maxlife", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		date = get_date(argv[i]);
 		if (date == (time_t)-1) {
		     fprintf(stderr, "Invalid date specification \"%s\".\n",
			     argv[i]);
		     return -1;
 		}
		oprinc->max_life = date - now;
		*mask |= KADM5_MAX_LIFE;
		continue;
	    }
	}
	if (strlen(argv[i]) == 13 &&
	    !strcmp("-maxrenewlife", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		date = get_date(argv[i]);
 		if (date == (time_t)-1) {
		     fprintf(stderr, "Invalid date specification \"%s\".\n",
			     argv[i]);
		     return -1;
 		}
		oprinc->max_renewable_life = date - now;
		*mask |= KADM5_MAX_RLIFE;
		continue;
	    }
	}
	if (strlen(argv[i]) == 5 &&
	    !strcmp("-kvno", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		oprinc->kvno = atoi(argv[i]);
		*mask |= KADM5_KVNO;
		continue;
	    }
	}
	if (strlen(argv[i]) == 7 &&
	    !strcmp("-policy", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		oprinc->policy = argv[i];
		*mask |= KADM5_POLICY;
		continue;
	    }
	}
	if (strlen(argv[i]) == 12 &&
	    !strcmp("-clearpolicy", argv[i])) {
	    oprinc->policy = NULL;
	    *mask |= KADM5_POLICY_CLR;
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
	if (strlen(argv[i]) == 8 &&
	    !strcmp("-randkey", argv[i])) {
	    ++*randkey;
	    continue;
	}
	if (!strcmp("-e", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		retval = krb5_string_to_keysalts(argv[i], ", \t", ":.-", 0,
						 ks_tuple, n_ks_tuple);
		if (retval) {
		    com_err(caller, retval,
			    "while parsing keysalts %s", argv[i]);
		    return -1;
		}
	    }
	    continue;
	}
	for (j = 0; j < sizeof (flags) / sizeof (struct pflag); j++) {
	    if (strlen(argv[i]) == flags[j].flaglen + 1 &&
		!strcmp(flags[j].flagname,
			&argv[i][1] /* strip off leading + or - */)) {
		if ((flags[j].set && argv[i][0] == '-') ||
		    (!flags[j].set && argv[i][0] == '+')) {
		    oprinc->attributes |= flags[j].theflag;
		    *mask |= KADM5_ATTRIBUTES;
		    attrib_set++;
		    break;
		} else if ((flags[j].set && argv[i][0] == '+') ||
			   (!flags[j].set && argv[i][0] == '-')) {
		    oprinc->attributes &= ~flags[j].theflag;
		    *mask |= KADM5_ATTRIBUTES;
		    attrib_set++;
		    break;
		} else {
		    return -1;
		}
	    }
	}
	if (!attrib_set)
	    return -1;		/* nothing was parsed */
    }
    if (i != argc - 1) {
	return -1;
    }
    retval = kadmin_parse_name(argv[i], &oprinc->principal);
    if (retval) {
	com_err(caller, retval, "while parsing principal");
	return -1;
    }
    return 0;
}

static void 
kadmin_addprinc_usage(func)
   char *func;
{
     fprintf(stderr, "usage: %s [options] principal\n", func);
     fprintf(stderr, "\toptions are:\n");
     fprintf(stderr, "\t\t[-expire expdate] [-pwexpire pwexpdate] [-maxlife maxtixlife]\n\t\t[-kvno kvno] [-policy policy] [-randkey] [-pw password]\n\t\t[-maxrenewlife maxrenewlife]\n\t\t[-e keysaltlist]\n\t\t[{+|-}attribute]\n");
     fprintf(stderr, "\tattributes are:\n");
     fprintf(stderr, "%s%s%s",
	     "\t\tallow_postdated allow_forwardable allow_tgs_req allow_renewable\n",
	     "\t\tallow_proxiable allow_dup_skey allow_tix requires_preauth\n",
	     "\t\trequires_hwauth needchange allow_svr password_changing_service\n");
}

static void 
kadmin_modprinc_usage(func)
   char *func;
{
     fprintf(stderr, "usage: %s [options] principal\n", func);
     fprintf(stderr, "\toptions are:\n");
     fprintf(stderr, "\t\t[-expire expdate] [-pwexpire pwexpdate] [-maxlife maxtixlife]\n\t\t[-kvno kvno] [-policy policy] [-clearpolicy]\n\t\t[-maxrenewlife maxrenewlife] [{+|-}attribute]\n");
     fprintf(stderr, "\tattributes are:\n");
     fprintf(stderr, "%s%s%s",
	     "\t\tallow_postdated allow_forwardable allow_tgs_req allow_renewable\n",
	     "\t\tallow_proxiable allow_dup_skey allow_tix requires_preauth\n",
	     "\t\trequires_hwauth needchange allow_svr password_changing_service\n");
}

void kadmin_addprinc(argc, argv)
    int argc;
    char *argv[];
{
    kadm5_principal_ent_rec princ;
    kadm5_policy_ent_rec defpol;
    long mask;
    int randkey = 0, i;
    int n_ks_tuple;
    krb5_key_salt_tuple *ks_tuple;
    char *pass, *canon;
    krb5_error_code retval;
    static char newpw[1024], dummybuf[256];
    static char prompt1[1024], prompt2[1024];

    if (dummybuf[0] == 0) {
	 for (i = 0; i < 256; i++)
	      dummybuf[i] = (i+1) % 256;
    }
    
    /* Zero all fields in request structure */
    memset(&princ, 0, sizeof(princ));

    princ.attributes = 0;
    if (kadmin_parse_princ_args(argc, argv,
				&princ, &mask, &pass, &randkey,
				&ks_tuple, &n_ks_tuple,
				"add_principal")) {
	 kadmin_addprinc_usage("add_principal");
	 return;
    }

    retval = krb5_unparse_name(context, princ.principal, &canon);
    if (retval) {
	com_err("add_principal",
		retval, "while canonicalizing principal");
	krb5_free_principal(context, princ.principal);
	if (ks_tuple != NULL)
	    free(ks_tuple);
	return;
    }

    /*
     * If -policy was not specified, and -clearpolicy was not
     * specified, and the policy "default" exists, assign it.  If
     * -clearpolicy was specified, then KADM5_POLICY_CLR should be
     * unset, since it is never valid for kadm5_create_principal.
     */
    if ((! (mask & KADM5_POLICY)) &&
	(! (mask & KADM5_POLICY_CLR))) {
	 if (! kadm5_get_policy(handle, "default", &defpol)) {
	      fprintf(stderr,
		"NOTICE: no policy specified for %s; assigning \"default\"\n",
		      canon);
	      princ.policy = "default";
	      mask |= KADM5_POLICY;
	      (void) kadm5_free_policy_ent(handle, &defpol);
	 } else
	      fprintf(stderr,
	     "WARNING: no policy specified for %s; defaulting to no policy\n",
		      canon);
    }
    mask &= ~KADM5_POLICY_CLR;
    
    if (randkey) {		/* do special stuff if -randkey specified */
	princ.attributes |= KRB5_KDB_DISALLOW_ALL_TIX; /* set notix */
	mask |= KADM5_ATTRIBUTES;
	pass = dummybuf;
    } else if (pass == NULL) {
	unsigned int sz = sizeof (newpw) - 1;
	
	sprintf(prompt1, "Enter password for principal \"%.900s\"",
		canon);
	sprintf(prompt2,
		"Re-enter password for principal \"%.900s\"",
		canon);
	retval = krb5_read_password(context, prompt1, prompt2,
				    newpw, &sz);
	if (retval) {
	    com_err("add_principal", retval,
		    "while reading password for \"%s\".", canon);
	    free(canon);
	    krb5_free_principal(context, princ.principal);
	    return;
	}
	pass = newpw;
    }
    mask |= KADM5_PRINCIPAL;
    if (ks_tuple != NULL) {
	retval = kadm5_create_principal_3(handle, &princ, mask,
					  n_ks_tuple, ks_tuple, pass);
    } else {
	retval = kadm5_create_principal(handle, &princ, mask, pass);
    }
    if (retval) {
	com_err("add_principal", retval, "while creating \"%s\".",
		canon);
	krb5_free_principal(context, princ.principal);
	free(canon);
	if (ks_tuple != NULL)
	    free(ks_tuple);
	return;
    }
    if (randkey) {		/* more special stuff for -randkey */
	if (ks_tuple != NULL) {
	    retval = kadm5_randkey_principal_3(handle, princ.principal,
					       FALSE,
					       n_ks_tuple, ks_tuple,
					       NULL, NULL);
	} else {
	    retval = kadm5_randkey_principal(handle, princ.principal,
					     NULL, NULL);
	}
	if (retval) {
	    com_err("add_principal", retval,
		    "while randomizing key for \"%s\".", canon);
	    krb5_free_principal(context, princ.principal);
	    free(canon);
	    if (ks_tuple != NULL)
		free(ks_tuple);
	    return;
	}
	princ.attributes &= ~KRB5_KDB_DISALLOW_ALL_TIX;	/* clear notix */
	mask = KADM5_ATTRIBUTES;
	retval = kadm5_modify_principal(handle, &princ, mask);
	if (retval) {
	    com_err("add_principal", retval,
		    "while clearing DISALLOW_ALL_TIX for \"%s\".", canon);
	    krb5_free_principal(context, princ.principal);
	    free(canon);
	    if (ks_tuple != NULL)
		free(ks_tuple);
	    return;
	}
    }
    krb5_free_principal(context, princ.principal);
    printf("Principal \"%s\" created.\n", canon);
    if (ks_tuple != NULL)
	free(ks_tuple);
    free(canon);
}

void kadmin_modprinc(argc, argv)
    int argc;
    char *argv[];
{
    kadm5_principal_ent_rec princ, oldprinc;
    krb5_principal kprinc;
    long mask;
    krb5_error_code retval;
    char *pass, *canon;
    int randkey = 0;
    int n_ks_tuple = 0;
    krb5_key_salt_tuple *ks_tuple;

    if (argc < 2) {
	 kadmin_modprinc_usage("modify_principal");
	 return;
    }

    memset(&oldprinc, 0, sizeof(oldprinc));
    memset(&princ, 0, sizeof(princ));

    retval = kadmin_parse_name(argv[argc - 1], &kprinc);
    if (retval) {
	com_err("modify_principal", retval, "while parsing principal");
	return;
    }
    retval = krb5_unparse_name(context, kprinc, &canon);
    if (retval) {
	com_err("modify_principal", retval,
		"while canonicalizing principal");
	krb5_free_principal(context, kprinc);
	return;
    }
    retval = kadm5_get_principal(handle, kprinc, &oldprinc,
				 KADM5_PRINCIPAL_NORMAL_MASK);
    krb5_free_principal(context, kprinc);
    if (retval) {
	com_err("modify_principal", retval, "while getting \"%s\".",
		canon);
	free(canon);
	return;
    }
    princ.attributes = oldprinc.attributes;
    kadm5_free_principal_ent(handle, &oldprinc);
    retval = kadmin_parse_princ_args(argc, argv,
				     &princ, &mask,
				     &pass, &randkey,
				     &ks_tuple, &n_ks_tuple,
				     "modify_principal");
    if (ks_tuple != NULL) {
	free(ks_tuple);
	kadmin_modprinc_usage("modify_principal");
	free(canon);
	return;
    }
    if (retval) {
	kadmin_modprinc_usage("modify_principal");
	free(canon);
	return;
    }
    if (randkey) {
	fprintf(stderr, "modify_principal: -randkey not allowed\n");
	krb5_free_principal(context, princ.principal);
	free(canon);
	return;
    }
    if (pass) {
	fprintf(stderr,
		"modify_principal: -pw not allowed; use change_password\n");
	krb5_free_principal(context, princ.principal);
	free(canon);
	return;
    }
    retval = kadm5_modify_principal(handle, &princ, mask);
    krb5_free_principal(context, princ.principal);
    if (retval) {
	com_err("modify_principal", retval,
		"while modifying \"%s\".", canon);
	free(canon);
	return;
    }
    printf("Principal \"%s\" modified.\n", canon);
    free(canon);
}

void kadmin_getprinc(argc, argv)
    int argc;
    char *argv[];
{
    kadm5_principal_ent_rec dprinc;
    krb5_principal princ;
    krb5_error_code retval;
    char *canon, *modcanon;
    int i;
    
    if (! (argc == 2 ||
	   (argc == 3 && !strcmp("-terse", argv[1])))) {
	fprintf(stderr, "usage: get_principal [-terse] principal\n");
	return;
    }


    memset(&dprinc, 0, sizeof(dprinc));
    memset(&princ, 0, sizeof(princ));

    retval = kadmin_parse_name(argv[argc - 1], &princ);
    if (retval) {
	com_err("get_principal", retval, "while parsing principal");
	return;
    }
    retval = krb5_unparse_name(context, princ, &canon);
    if (retval) {
	com_err("get_principal", retval, "while canonicalizing principal");
	krb5_free_principal(context, princ);
	return;
    }
    retval = kadm5_get_principal(handle, princ, &dprinc,
				 KADM5_PRINCIPAL_NORMAL_MASK | KADM5_KEY_DATA);
    krb5_free_principal(context, princ);
    if (retval) {
	com_err("get_principal", retval, "while retrieving \"%s\".", canon);
	free(canon);
	return;
    }
    retval = krb5_unparse_name(context, dprinc.mod_name, &modcanon);
    if (retval) {
	com_err("get_principal", retval, "while unparsing modname");
	kadm5_free_principal_ent(handle, &dprinc);
	free(canon);
	return;
    }
    if (argc == 2) {
	printf("Principal: %s\n", canon);
	printf("Expiration date: %s\n", dprinc.princ_expire_time ?
	       strdate(dprinc.princ_expire_time) : "[never]");
	printf("Last password change: %s\n", dprinc.last_pwd_change ? 
	       strdate(dprinc.last_pwd_change) : "[never]");
	printf("Password expiration date: %s\n",
	       dprinc.pw_expiration ?
	       strdate(dprinc.pw_expiration) : "[none]");
	printf("Maximum ticket life: %s\n", strdur(dprinc.max_life));
	printf("Maximum renewable life: %s\n", strdur(dprinc.max_renewable_life));
	printf("Last modified: %s (%s)\n", strdate(dprinc.mod_date), modcanon);
	printf("Last successful authentication: %s\n",
	       dprinc.last_success ? strdate(dprinc.last_success) :
	       "[never]"); 
	printf("Last failed authentication: %s\n",
	       dprinc.last_failed ? strdate(dprinc.last_failed) :
	       "[never]");
	printf("Failed password attempts: %d\n",
	       dprinc.fail_auth_count);
	printf("Number of keys: %d\n", dprinc.n_key_data);
	for (i = 0; i < dprinc.n_key_data; i++) {
	     krb5_key_data *key_data = &dprinc.key_data[i];
	     char enctype[BUFSIZ], salttype[BUFSIZ];
	     
	     if (krb5_enctype_to_string(key_data->key_data_type[0],
					enctype, sizeof(enctype)))
		  sprintf(enctype, "<Encryption type 0x%x>",
			  key_data->key_data_type[0]);
	     printf("Key: vno %d, %s, ", key_data->key_data_kvno, enctype);
	     if (key_data->key_data_ver > 1) {
		  if (krb5_salttype_to_string(key_data->key_data_type[1],
					      salttype, sizeof(salttype)))
		       sprintf(salttype, "<Salt type 0x%x>",
			       key_data->key_data_type[1]);
		  printf("%s\n", salttype);
	     } else
		  printf("no salt\n");
	}
	
	printf("Attributes:");
	for (i = 0; i < sizeof (prflags) / sizeof (char *); i++) {
	    if (dprinc.attributes & (krb5_flags) 1 << i)
		printf(" %s", prflags[i]);
	}
	printf("\n");
	printf("Policy: %s\n", dprinc.policy ? dprinc.policy : "[none]");
    } else {
	printf("\"%s\"\t%d\t%d\t%d\t%d\t\"%s\"\t%d\t%d\t%d\t%d\t\"%s\""
	       "\t%d\t%d\t%d\t%d\t%d",
	       canon, dprinc.princ_expire_time, dprinc.last_pwd_change,
	       dprinc.pw_expiration, dprinc.max_life, modcanon,
	       dprinc.mod_date, dprinc.attributes, dprinc.kvno,
	       dprinc.mkvno, dprinc.policy ? dprinc.policy : "[none]",
	       dprinc.max_renewable_life, dprinc.last_success,
	       dprinc.last_failed, dprinc.fail_auth_count,
	       dprinc.n_key_data);
	for (i = 0; i < dprinc.n_key_data; i++)
	     printf("\t%d\t%d\t%d\t%d",
		    dprinc.key_data[i].key_data_ver,
		    dprinc.key_data[i].key_data_kvno,
		    dprinc.key_data[i].key_data_type[0],
		    dprinc.key_data[i].key_data_type[1]);
	printf("\n");
   }
    free(modcanon);
    kadm5_free_principal_ent(handle, &dprinc);
    free(canon);
}

void kadmin_getprincs(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code retval;
    char *expr, **names;
    int i, count;

    expr = NULL;
    if (! (argc == 1 || (argc == 2 && (expr = argv[1])))) {
	fprintf(stderr, "usage: get_principals [expression]\n");
	return;
    }
    retval = kadm5_get_principals(handle, expr, &names, &count);
    if (retval) {
	com_err("get_principals", retval, "while retrieving list.");
	return;
    }
    for (i = 0; i < count; i++)
	 printf("%s\n", names[i]);
    kadm5_free_name_list(handle, names, count);
}

static int 
kadmin_parse_policy_args(argc, argv, policy, mask, caller)
    int argc;
    char *argv[];
    kadm5_policy_ent_t policy;
    long *mask;
    char *caller;
{
    int i;
    time_t now;
    time_t date;

    time(&now);
    *mask = 0;
    for (i = 1; i < argc - 1; i++) {
	if (strlen(argv[i]) == 8 &&
	    !strcmp(argv[i], "-maxlife")) {
	    if (++i > argc -2)
		return -1;
	    else {
		date = get_date(argv[i]);
 		if (date == (time_t)-1) {
		     fprintf(stderr, "Invalid date specification \"%s\".\n",
			     argv[i]);
		     return -1;
 		}
		policy->pw_max_life = date - now;
		*mask |= KADM5_PW_MAX_LIFE;
		continue;
	    }
	} else if (strlen(argv[i]) == 8 &&
		   !strcmp(argv[i], "-minlife")) {
	    if (++i > argc - 2)
		return -1;
	    else {
		date = get_date(argv[i]);
 		if (date == (time_t)-1) {
		     fprintf(stderr, "Invalid date specification \"%s\".\n",
			     argv[i]);
		     return -1;
 		}
		policy->pw_min_life = date - now;
		*mask |= KADM5_PW_MIN_LIFE;
		continue;
	    }
	} else if (strlen(argv[i]) == 10 &&
	    !strcmp(argv[i], "-minlength")) {
	    if (++i > argc - 2)
		return -1;
	    else {
		policy->pw_min_length = atoi(argv[i]);
		*mask |= KADM5_PW_MIN_LENGTH;
		continue;
	    }
	} else if (strlen(argv[i]) == 11 &&
		   !strcmp(argv[i], "-minclasses")) {
	    if (++i > argc - 2)
		return -1;
	    else {
		policy->pw_min_classes = atoi(argv[i]);
		*mask |= KADM5_PW_MIN_CLASSES;
		continue;
	    }
	} else if (strlen(argv[i]) == 8 &&
		   !strcmp(argv[i], "-history")) {
	    if (++i > argc - 2)
		return -1;
	    else {
		policy->pw_history_num = atoi(argv[i]);
		*mask |= KADM5_PW_HISTORY_NUM;
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

static void 
kadmin_addmodpol_usage(func)
   char *func;
{
     fprintf(stderr, "usage; %s [options] policy\n", func);
     fprintf(stderr, "\toptions are:\n");
     fprintf(stderr, "\t\t[-maxlife time] [-minlife time] [-minlength length]\n\t\t[-minclasses number] [-history number]\n");
}

void kadmin_addpol(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code retval;
    long mask;
    kadm5_policy_ent_rec policy;

    memset(&policy, 0, sizeof(policy));
    if (kadmin_parse_policy_args(argc, argv, &policy, &mask, "add_policy")) {
	 kadmin_addmodpol_usage("add_policy");
	 return;
    } else {
	policy.policy = argv[argc - 1];
	mask |= KADM5_POLICY;
	retval = kadm5_create_policy(handle, &policy, mask);
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
    long mask;
    kadm5_policy_ent_rec policy;

    memset(&policy, 0, sizeof(policy));
    if (kadmin_parse_policy_args(argc, argv, &policy, &mask,
				 "modify_policy")) {
	kadmin_addmodpol_usage("modify_policy");
	return;
    } else {
	policy.policy = argv[argc - 1];
	retval = kadm5_modify_policy(handle, &policy, mask);
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
    
    if (! (argc == 2 ||
	   (argc == 3 && !strcmp("-force", argv[1])))) {
	fprintf(stderr, "usage: delete_policy [-force] policy\n");
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
    retval = kadm5_delete_policy(handle, argv[argc - 1]);
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
    kadm5_policy_ent_rec policy;
    
    if (! (argc == 2 ||
	   (argc == 3 && !strcmp("-terse", argv[1])))) {
	fprintf(stderr, "usage: get_policy [-terse] policy\n");
	return;
    }
    retval = kadm5_get_policy(handle, argv[argc - 1], &policy);
    if (retval) {
	com_err("get_policy", retval, "while retrieving policy \"%s\".",
		argv[argc - 1]);
	return;
    }
    if (argc == 2) {
	printf("Policy: %s\n", policy.policy);
	printf("Maximum password life: %ld\n", policy.pw_max_life);
	printf("Minimum password life: %ld\n", policy.pw_min_life);
	printf("Minimum password length: %ld\n", policy.pw_min_length);
	printf("Minimum number of password character classes: %ld\n",
	       policy.pw_min_classes);
	printf("Number of old keys kept: %ld\n", policy.pw_history_num);
	printf("Reference count: %ld\n", policy.policy_refcnt);
    } else {
	printf("\"%s\"\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\n",
	       policy.policy, policy.pw_max_life, policy.pw_min_life,
	       policy.pw_min_length, policy.pw_min_classes,
	       policy.pw_history_num, policy.policy_refcnt);
    }
    kadm5_free_policy_ent(handle, &policy);
    return;
}

void kadmin_getpols(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code retval;
    char *expr, **names;
    int i, count;

    expr = NULL;
    if (! (argc == 1 || (argc == 2 && (expr = argv[1])))) {
	fprintf(stderr, "usage: get_policies [expression]\n");
	return;
    }
    retval = kadm5_get_policies(handle, expr, &names, &count);
    if (retval) {
	com_err("get_policies", retval, "while retrieving list.");
	return;
    }
    for (i = 0; i < count; i++)
	 printf("%s\n", names[i]);
    kadm5_free_name_list(handle, names, count);
}

void kadmin_getprivs(argc, argv)
    int argc;
    char *argv[];
{
    static char *privs[] = {"GET", "ADD", "MODIFY", "DELETE"};
    krb5_error_code retval;
    int i;
    long plist;

    if (argc != 1) {
	fprintf(stderr, "usage: get_privs\n");
	return;
    }
    retval = kadm5_get_privs(handle, &plist);
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

/*
 * clients/kinit/kinit.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 *
 * Initialize a credentials cache.
 */

#include <krb5.h>
#ifdef KRB5_KRB4_COMPAT
#include <kerberosIV/krb.h>
#define HAVE_KRB524
#else
#undef HAVE_KRB524
#endif
#include <string.h>
#include <stdio.h>
#include <time.h>

#ifdef GETOPT_LONG
#include <getopt.h>
#else
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#ifdef sun
/* SunOS4 unistd didn't declare these; okay to make unconditional?  */
extern int optind;
extern char *optarg;
#endif /* sun */
#else
extern int optind;
extern char *optarg;
extern int getopt();
#endif /* HAVE_UNISTD_H */
#endif /* GETOPT_LONG */

#ifndef _WIN32
#define GET_PROGNAME(x) (strrchr((x), '/') ? strrchr((x), '/')+1 : (x))
#else
#define GET_PROGNAME(x) (max(strrchr((x), '/'), strrchr((x), '\\')) + 1, (x))
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
char * get_name_from_os()
{
    struct passwd *pw;
    if (pw = getpwuid((int) getuid()))
	return pw->pw_name;
    return 0;
}
#else /* HAVE_PWD_H */
#ifdef _WIN32
char * get_name_from_os()
{
    static char name[1024];
    DWORD name_size = sizeof(name);
    if (GetUserName(name, &name_size)) {
	name[sizeof(name)-1] = 0; /* Just to be extra safe */
	return name;
    } else {
	return 0;
    }
}
#else /* _WIN32 */
char * get_name_from_os()
{
    return 0;
}
#endif /* _WIN32 */
#endif /* HAVE_PWD_H */

static char *progname;

static char* progname_v5 = 0;
static char* progname_v4 = 0;
static char* progname_v524 = 0;

static int got_k4 = 0;
static int got_k5 = 0;

static int authed_k5 = 0;
static int authed_k4 = 0;

#define KRB4_BACKUP_DEFAULT_LIFE_SECS 10*60*60 /* 10 hours */

typedef enum { INIT_PW, INIT_KT, RENEW, VALIDATE } action_type;

struct k_opts
{
    /* in seconds */
    krb5_deltat starttime;
    krb5_deltat lifetime;
    krb5_deltat rlife;

    int forwardable;
    int proxiable;
    int addresses;

    int not_forwardable;
    int not_proxiable;
    int no_addresses;

    int verbose;

    char* principal_name;
    char* service_name;
    char* keytab_name;
    char* cache_name;

    action_type action;
};

struct k5_data
{
    krb5_context ctx;
    krb5_ccache cc;
    krb5_principal me;
    char* name;
};

struct k4_data
{
    krb5_deltat lifetime;
#ifdef KRB5_KRB4_COMPAT
    char aname[ANAME_SZ + 1];
    char inst[INST_SZ + 1];
    char realm[REALM_SZ + 1];
    char name[ANAME_SZ + 1 + INST_SZ + 1 + REALM_SZ + 1];
#endif
};

#ifdef GETOPT_LONG
/* if struct[2] == NULL, then long_getopt acts as if the short flag
   struct[3] was specified.  If struct[2] != NULL, then struct[3] is
   stored in *(struct[2]), the array index which was specified is
   stored in *index, and long_getopt() returns 0. */

struct option long_options[] = {
    { "noforwardable", 0, NULL, 'F' },
    { "noproxiable", 0, NULL, 'P' },
    { "addresses", 0, NULL, 'a'},
    { "forwardable", 0, NULL, 'f' },
    { "proxiable", 0, NULL, 'p' },
    { "noaddresses", 0, NULL, 'A' },
    { NULL, 0, NULL, 0 }
};

#define GETOPT(argc, argv, str) getopt_long(argc, argv, str, long_options, 0)
#define USAGE_LONG_FORWARDABLE " | --forwardable | --noforwardable"
#define USAGE_LONG_PROXIABLE   " | --proxiable | --noproxiable"
#define USAGE_LONG_ADDRESSES   " | --addresses | --noaddresses"
#else
#define GETOPT(argc, argv, str) getopt(argc, argv, str)
#define USAGE_LONG_FORWARDABLE ""
#define USAGE_LONG_PROXIABLE   ""
#define USAGE_LONG_ADDRESSES   ""
#endif

void
usage()
{
#ifdef KRB5_KRB4_COMPAT
#define USAGE_K54_OPT       "[-4] [-5] "
#define USAGE_K54_SRVTAB    "/srvtab"
#else
#define USAGE_K54_OPT       ""
#define USAGE_K54_SRVTAB    ""
#endif

    fprintf(stderr, "Usage: %s [-V] " USAGE_K54_OPT
	    "[-l lifetime] [-r renewable_life] "
	    "[-f | -F" USAGE_LONG_FORWARDABLE "] "
	    "[-p | -P" USAGE_LONG_PROXIABLE "] "
	    "[-A" USAGE_LONG_ADDRESSES "] "
	    "[-s start_time] [-S target_service] "
	    "[-k [-t keytab_file]] [-R] [-v] [-c cachename] [principal]\n", 
	    progname);
    fprintf(stderr,
#ifdef KRB5_KRB4_COMPAT
            "\t-4 Kerberos 4 only, -5 Kerberos 5 only, default is both\n"
            "\toptions applicable to Kerberos 5 only:\n"
#endif
            "\t\t-v validate\n"
            "\t\t-c cache name\n"
            "\t\t-f forwardable\n"
            "\t\t-F not forwardable\n"
            "\t\t-p proxiable\n"
            "\t\t-P not proxiable\n"
	    "\t\t-A do not include addresses\n"
            "\t\t-r renewable lifetime\n"
            "\t\t-s start time\n"
#ifdef KRB5_KRB4_COMPAT
            "\toptions potentially applicable to both:\n"
#endif
            "\t\t-R renew\n"
            "\t\t-l lifetime\n"
            "\t\t-S service\n"
            "\t\t-k use keytab" USAGE_K54_SRVTAB "\n"
            "\t\t-t filename of keytab" USAGE_K54_SRVTAB " to use\n"
            "\t\t-V verbose\n"
        );
    exit(2);
}

char *
parse_options(argc, argv, opts)
    int argc;
    char **argv;
    struct k_opts* opts;
{
    krb5_error_code code;
    int errflg = 0;
    int use_k4_only = 0;
    int use_k5_only = 0;
    int i;

#ifdef KRB5_KRB4_COMPAT
#define GETOPT_K54 "45"
#else
#define GETOPT_K54 ""
#endif

    while ((i = GETOPT(argc, argv, "r:fpFP" GETOPT_K54 "AVl:s:c:kt:RS:v"))
	   != -1) {
	switch (i) {
        case 'V':
            opts->verbose = 1;
            break;
        case 'l':
            /* Lifetime */
            code = krb5_string_to_deltat(optarg, &opts->lifetime);
            if (code != 0 || opts->lifetime == 0) {
                fprintf(stderr, "Bad lifetime value %s\n", optarg);
                errflg++;
            }
            break;
	case 'r':
            /* Renewable Time */
            code = krb5_string_to_deltat(optarg, &opts->rlife);
            if (code != 0 || opts->rlife == 0) {
                fprintf(stderr, "Bad lifetime value %s\n", optarg);
                errflg++;
            }
            break;
	case 'f':
            opts->forwardable = 1;
            break;
        case 'F':
            opts->not_forwardable = 1;
            break;
	case 'p':
            opts->proxiable = 1;
            break;
	case 'P':
            opts->not_proxiable = 1;
            break;
	case 'a':
	    /* Note: This is supported only with GETOPT_LONG */
	    opts->addresses = 1;
	    break;
	case 'A':
	    opts->no_addresses = 1;
	    break;
       	case 's':
	    code = krb5_string_to_deltat(optarg, &opts->starttime);
	    if (code != 0 || opts->starttime == 0) {
		krb5_timestamp abs_starttime;

		code = krb5_string_to_timestamp(optarg, &abs_starttime);
		if (code != 0 || abs_starttime == 0) {
		    fprintf(stderr, "Bad start time value %s\n", optarg);
		    errflg++;
		} else {
		    opts->starttime = abs_starttime - time(0);
		}
	    }
	    break;
        case 'S':
            opts->service_name = optarg;
	    break;
        case 'k':
            opts->action = INIT_KT;
	    break;
        case 't':
            if (opts->keytab_name)
            {
                fprintf(stderr, "Only one -t option allowed.\n");
                errflg++;
            } else {
                opts->keytab_name = optarg;
            }
            break;
	case 'R':
	    opts->action = RENEW;
	    break;
	case 'v':
	    opts->action = VALIDATE;
	    break;
       	case 'c':
            if (opts->cache_name)
            {
                fprintf(stderr, "Only one -c option allowed\n");
                errflg++;
            } else {
                opts->cache_name = optarg;
            }
	    break;
#ifdef KRB5_KRB4_COMPAT
        case '4':
            if (!got_k4)
            {
                fprintf(stderr, "Kerberos 4 support could not be loaded\n");
                exit(3);
            }
            use_k4_only = 1;
            break;
        case '5':
            if (!got_k5)
            {
                fprintf(stderr, "Kerberos 5 support could not be loaded\n");
                exit(3);
            }
            use_k5_only = 1;
            break;
#endif
	default:
	    errflg++;
	    break;
	}
    }

    if (use_k5_only && use_k4_only)
    {
        fprintf(stderr, "Only one of -4 and -5 allowed\n");
        errflg++;
    }
    if (opts->forwardable && opts->not_forwardable)
    {
        fprintf(stderr, "Only one of -f and -F allowed\n");
        errflg++;
    }
    if (opts->proxiable && opts->not_proxiable)
    {
        fprintf(stderr, "Only one of -p and -P allowed\n");
        errflg++;
    }
    if (opts->addresses && opts->no_addresses)
    {
        fprintf(stderr, "Only one of -a and -A allowed\n");
        errflg++;
    }

    if (argc - optind > 1) {
	fprintf(stderr, "Extra arguments (starting with \"%s\").\n",
		argv[optind+1]);
	errflg++;
    }

    if (errflg) {
        usage();
    }

    /* At this point, we know we only have one option selection */
    if (use_k4_only)
        got_k5 = 0;
    if (use_k5_only)
        got_k4 = 0;

    opts->principal_name = (optind == argc-1) ? argv[optind] : 0;
    return opts->principal_name;
}

int
k5_begin(opts, k5, k4)
    struct k_opts* opts;
    struct k5_data* k5;
    struct k4_data* k4;
{
    char* progname = progname_v5;
    krb5_error_code code = 0;

    if (!got_k5)
        return 0;

    if (code = krb5_init_context(&k5->ctx)) {
        com_err(progname, code, "while initializing Kerberos 5 library");
        return 0;
    }
    if (opts->cache_name)
    {
        code = krb5_cc_resolve(k5->ctx, opts->cache_name, &k5->cc);
        if (code != 0) {
            com_err(progname, code, "resolving ccache %s",
                     opts->cache_name);
            return 0;
        }
    } 
    else
    {
        if ((code = krb5_cc_default(k5->ctx, &k5->cc))) {
            com_err(progname, code, "while getting default ccache");
            return 0;
        }
    }

    if (opts->principal_name)
    {
        /* Use specified name */
        if ((code = krb5_parse_name(k5->ctx, opts->principal_name, 
                                     &k5->me))) {
            com_err(progname, code, "when parsing name %s", 
                     opts->principal_name);
            return 0;
        }
    }
    else
    {
        /* No principal name specified */
        if (opts->action == INIT_KT) {
            /* Use the default host/service name */
            if (code = krb5_sname_to_principal(k5->ctx, NULL, NULL,
					       KRB5_NT_SRV_HST, &k5->me)) {
                com_err(progname, code,
			"when creating default server principal name");
                return 0;
            }
        } else {
            /* Get default principal from cache if one exists */
            if (code = krb5_cc_get_principal(k5->ctx, k5->cc, 
                                             &k5->me))
            {
                char *name = get_name_from_os();
                if (!name)
                {
                    fprintf(stderr, "Unable to identify user\n");
                    return 0;
                }
                if ((code = krb5_parse_name(k5->ctx, name, 
                                             &k5->me)))
                {
                    com_err(progname, code, "when parsing name %s", 
			    name);
                    return 0;
                }
            }
        }
    }
    if (code = krb5_unparse_name(k5->ctx, k5->me, 
				 &k5->name)) {
        com_err(progname, code, "when unparsing name");
        return 0;
    }
    opts->principal_name = k5->name;

#ifdef KRB5_KRB4_COMPAT
    if (got_k4)
    {
	/* Translate to a Kerberos 4 principal */
	code = krb5_524_conv_principal(k5->ctx, k5->me,
				       k4->aname, k4->inst, k4->realm);
	if (code) {
	    k4->aname[0] = 0;
	    k4->inst[0] = 0;
	    k4->realm[0] = 0;
	}
    }
#endif
    return 1;
}

void
k5_end(k5)
    struct k5_data* k5;
{
    if (k5->name)
        krb5_free_unparsed_name(k5->ctx, k5->name);
    if (k5->me)
        krb5_free_principal(k5->ctx, k5->me);
    if (k5->cc)
        krb5_cc_close(k5->ctx, k5->cc);
    if (k5->ctx)
        krb5_free_context(k5->ctx);
    memset(k5, 0, sizeof(*k5));
}

int
k4_begin(opts, k4)
    struct k_opts* opts;
    struct k4_data* k4;
{
    char* progname = progname_v4;
    int k_errno = 0;

    if (!got_k4)
        return 0;

#ifdef KRB5_KRB4_COMPAT
    if (k4->aname[0])
        goto skip;

    if (opts->principal_name)
    {
        /* Use specified name */
        if (k_errno = kname_parse(k4->aname, k4->inst, k4->realm, 
                                  opts->principal_name))
        {
            fprintf(stderr, "%s: %s\n", progname, 
                    krb_get_err_text(k_errno));
            return 0;
        }
    } else {
        /* No principal name specified */
        if (opts->action == INIT_KT) {
            /* Use the default host/service name */
            /* XXX - need to add this functionality */
            fprintf(stderr, "%s: Kerberos 4 srvtab support is not "
                    "implemented\n", progname);
            return 0;
        } else {
            /* Get default principal from cache if one exists */
            if (k_errno = krb_get_tf_fullname(tkt_string(), k4->aname, 
                                              k4->inst, k4->realm))
            {
                char *name = get_name_from_os();
                if (!name)
                {
                    fprintf(stderr, "Unable to identify user\n");
                    return 0;
                }
                if (k_errno = kname_parse(k4->aname, k4->inst, k4->realm,
                                          name))
                {
                    fprintf(stderr, "%s: %s\n", progname, 
                            krb_get_err_text(k_errno));
                    return 0;
                }
            }
        }
    }

    if (!k4->realm[0])
        krb_get_lrealm(k4->realm, 1);

    if (k4->inst[0])
        sprintf(k4->name, "%s.%s@%s", k4->aname, k4->inst, k4->realm);
    else
        sprintf(k4->name, "%s@%s", k4->aname, k4->realm);
    opts->principal_name = k4->name;

 skip:
    if (k4->aname[0] && !k_isname(k4->aname))
    {
	fprintf(stderr, "%s: bad Kerberos 4 name format\n", progname);
        return 0;
    }

    if (k4->inst[0] && !k_isinst(k4->inst))
    {
        fprintf(stderr, "%s: bad Kerberos 4 instance format\n", progname);
        return 0;
    }

    if (k4->realm[0] && !k_isrealm(k4->realm))
    {
        fprintf(stderr, "%s: bad Kerberos 4 realm format\n", progname);
        return 0;
    }
#endif /* KRB5_KRB4_COMPAT */
    return 1;
}

void
k4_end(k4)
    struct k4_data* k4;
{
    memset(k4, 0, sizeof(*k4));
}

int
k5_kinit(opts, k5, password)
    struct k_opts* opts;
    struct k5_data* k5;
    char* password;
{
    char* progname = progname_v5;
    int notix = 1;
    krb5_keytab keytab = 0;
    krb5_creds my_creds;
    krb5_error_code code = 0;
    krb5_get_init_creds_opt options;

    if (!got_k5)
        return 0;

    krb5_get_init_creds_opt_init(&options);
    memset(&my_creds, 0, sizeof(my_creds));

    /*
      From this point on, we can goto cleanup because my_creds is
      initialized.
    */

    if (opts->lifetime)
	krb5_get_init_creds_opt_set_tkt_life(&options, opts->lifetime);
    if (opts->rlife)
	krb5_get_init_creds_opt_set_renew_life(&options, opts->rlife);
    if (opts->forwardable)
	krb5_get_init_creds_opt_set_forwardable(&options, 1);
    if (opts->not_forwardable)
	krb5_get_init_creds_opt_set_forwardable(&options, 0);
    if (opts->proxiable)
	krb5_get_init_creds_opt_set_proxiable(&options, 1);
    if (opts->not_proxiable)
	krb5_get_init_creds_opt_set_proxiable(&options, 0);
    if (opts->addresses)
    {
	krb5_address **addresses = NULL;
	code = krb5_os_localaddr(k5->ctx, &addresses);
	if (code != 0) {
            com_err(progname, code, "getting local addresses");
            goto cleanup;
	}
	krb5_get_init_creds_opt_set_address_list(&options, addresses);
	krb5_free_addresses(k5->ctx, addresses);
    }
    if (opts->no_addresses)
	krb5_get_init_creds_opt_set_address_list(&options, NULL);

    if ((opts->action == INIT_KT) && opts->keytab_name)
    {
        code = krb5_kt_resolve(k5->ctx, opts->keytab_name, &keytab);
        if (code != 0) {
            com_err(progname, code, "resolving keytab %s", 
                     opts->keytab_name);
            goto cleanup;
        }
    }

    switch (opts->action) {
    case INIT_PW:
	code = krb5_get_init_creds_password(k5->ctx, &my_creds, k5->me,
					    password, krb5_prompter_posix, 0,
					    opts->starttime, 
					    opts->service_name,
					    &options);
	break;
    case INIT_KT:
	code = krb5_get_init_creds_keytab(k5->ctx, &my_creds, k5->me,
					  keytab,
					  opts->starttime, 
					  opts->service_name,
					  &options);
	break;
    case VALIDATE:
	code = krb5_get_validated_creds(k5->ctx, &my_creds, k5->me, k5->cc,
					opts->service_name);
	break;
    case RENEW:
	code = krb5_get_renewed_creds(k5->ctx, &my_creds, k5->me, k5->cc,
				      opts->service_name);
	break;
    }

    if (code) {
        char *doing = 0;
        switch (opts->action) {
        case INIT_PW:
        case INIT_KT:
            doing = "getting initial credentials";
            break;
        case VALIDATE:
            doing = "validating credentials";
            break;
        case RENEW:
            doing = "renewing credentials";
            break;
        }

	/* If got code == KRB5_AP_ERR_V4_REPLY && got_k4, we should
	   let the user know that maybe he/she wants -4. */
        if (code == KRB5KRB_AP_ERR_V4_REPLY && got_k4)
            com_err(progname, code, "while %s\n"
                     "The KDC doesn't support v5.  "
                     "You may want the -4 option in the future",
                     doing);
        else if (code == KRB5KRB_AP_ERR_BAD_INTEGRITY)
            fprintf(stderr, "%s: Password incorrect while %s\n", progname,
                    doing);
	else
            com_err(progname, code, "while %s", doing);
        goto cleanup;
    }

    if (!opts->lifetime) {
	/* We need to figure out what lifetime to use for Kerberos 4. */
        opts->lifetime = my_creds.times.endtime - my_creds.times.authtime;
    }

    if (code = krb5_cc_initialize(k5->ctx, k5->cc, k5->me)) {
        com_err(progname, code, "when initializing cache %s",
                 opts->cache_name?opts->cache_name:"");
        goto cleanup;
    }

    if (code = krb5_cc_store_cred(k5->ctx, k5->cc, &my_creds)) {
        com_err(progname, code, "while storing credentials");
        goto cleanup;
    }

    notix = 0;

 cleanup:
    if (my_creds.client == k5->me) {
        my_creds.client = 0;
    }
    krb5_free_cred_contents(k5->ctx, &my_creds);
    if (keytab)
	krb5_kt_close(k5->ctx, keytab);
    return notix?0:1;
}

int
k4_kinit(opts, k4, password)
    struct k_opts* opts;
    struct k4_data* k4;
    char* password;
{
    char* progname = progname_v4;
    int k_errno = 0;

    if (!got_k4)
        return 0;

    if (opts->starttime)
        return 0;

#ifdef KRB5_KRB4_COMPAT
    if (!k4->lifetime)
	k4->lifetime = opts->lifetime;
    if (!k4->lifetime)
	k4->lifetime = KRB4_BACKUP_DEFAULT_LIFE_SECS;

    k4->lifetime /= (5 * 60);
    if (k4->lifetime < 1)
        k4->lifetime = 1;
    if (k4->lifetime > 255)
        k4->lifetime = 255;

    switch (opts->action)
    {
    case INIT_PW:
        k_errno = krb_get_pw_in_tkt(k4->aname, k4->inst, k4->realm, "krbtgt", 
                                     k4->realm, k4->lifetime, password);

        if (k_errno) {
            fprintf(stderr, "%s: %s\n", progname, 
                    krb_get_err_text(k_errno));
            if (authed_k5)
                fprintf(stderr, "Maybe your KDC does not support v4.  "
                        "Try the -5 option next time.\n");
            return 0;
        }
        return 1;
#ifndef HAVE_KRB524
    case INIT_KT:
        fprintf(stderr, "%s: srvtabs are not supported\n", progname);
        return 0;
    case RENEW:
        fprintf(stderr, "%s: renewal of krb4 tickets is not supported\n",
                progname);
        return 0;
#endif
    }
#endif
    return 0;
}

char*
getvprogname(v)
    char *v;
{
    int len = strlen(progname) + 2 + strlen(v) + 2;
    char *ret = malloc(len);
    if (ret)
        sprintf(ret, "%s(v%s)", progname, v);
    else
        ret = progname;
    return ret;
}

#ifdef HAVE_KRB524
/* Convert krb5 tickets to krb4. */
int try_convert524(k5)
    struct k5_data* k5;
{
    char * progname = progname_v524;
    krb5_error_code code = 0;
    int icode = 0;
    krb5_principal kpcserver = 0;
    krb5_creds *v5creds = 0;
    krb5_creds increds;
    CREDENTIALS v4creds;

    if (!got_k4 || !got_k5)
	return 0;

    increds.client = 0;

    /* or do this directly with krb524_convert_creds_kdc */
    krb524_init_ets(k5->ctx);

    if ((code = krb5_build_principal(k5->ctx,
				     &kpcserver, 
				     krb5_princ_realm(k5->ctx, k5->me)->length,
				     krb5_princ_realm(k5->ctx, k5->me)->data,
				     "krbtgt",
				     krb5_princ_realm(k5->ctx, k5->me)->data,
				     NULL))) {
	com_err(progname, code,
		"while creating service principal name");
	goto cleanup;
    }

    memset((char *) &increds, 0, sizeof(increds));
    increds.client = k5->me;
    increds.server = kpcserver;
    increds.times.endtime = 0;
    increds.keyblock.enctype = ENCTYPE_DES_CBC_CRC;
    if ((code = krb5_get_credentials(k5->ctx, 0, 
				     k5->cc,
				     &increds, 
				     &v5creds))) {
	com_err(progname, code,
		"getting V5 credentials");
	goto cleanup;
    }
    if ((icode = krb524_convert_creds_kdc(k5->ctx,
					  v5creds,
					  &v4creds))) {
	com_err(progname, icode, 
		"converting to V4 credentials");
	goto cleanup;
    }
    /* this is stolen from the v4 kinit */
    /* initialize ticket cache */
    if ((icode = in_tkt(v4creds.pname, v4creds.pinst)
	 != KSUCCESS)) {
	com_err(progname, icode,
		"trying to create the V4 ticket file");
	goto cleanup;
    }
    /* stash ticket, session key, etc. for future use */
    if ((icode = krb_save_credentials(v4creds.service,
				       v4creds.instance,
				       v4creds.realm, 
				       v4creds.session,
				       v4creds.lifetime,
				       v4creds.kvno,
				       &(v4creds.ticket_st), 
				       v4creds.issue_date))) {
	com_err(progname, icode,
		"trying to save the V4 ticket");
	goto cleanup;
    }

 cleanup:
    memset(&v4creds, 0, sizeof(v4creds));
    krb5_free_creds(k5->ctx, v5creds);
    increds.client = 0;
    krb5_free_cred_contents(k5->ctx, &increds);
    krb5_free_principal(k5->ctx, kpcserver);
    return !(code || icode);
}
#endif /* HAVE_KRB524 */

int
main(argc, argv)
    int argc;
    char **argv;
{
    struct k_opts opts;
    struct k5_data k5;
    struct k4_data k4;
    char password[255];

    progname = GET_PROGNAME(argv[0]);
    progname_v5 = getvprogname("5");
    progname_v4 = getvprogname("4");
    progname_v524 = getvprogname("524");

    /* Ensure we can be driven from a pipe */
    if(!isatty(fileno(stdin)))
        setvbuf(stdin, 0, _IONBF, 0);
    if(!isatty(fileno(stdout)))
        setvbuf(stdout, 0, _IONBF, 0);
    if(!isatty(fileno(stderr)))
        setvbuf(stderr, 0, _IONBF, 0);

    got_k5 = 1;
#ifdef KRB5_KRB4_COMPAT
    got_k4 = 1;
#endif

    memset(&opts, 0, sizeof(opts));
    opts.action = INIT_PW;

    memset(&k5, 0, sizeof(k5));
    memset(&k4, 0, sizeof(k4));

    parse_options(argc, argv, &opts);

    got_k5 = k5_begin(&opts, &k5, &k4);
    got_k4 = k4_begin(&opts, &k4);

    if (opts.action == INIT_PW)
    {
        char prompt[255];
        int pwsize = sizeof(password);
        krb5_error_code code;

        sprintf(prompt, "Password for %s: ", opts.principal_name);
        password[0] = 0;
        /*
          Note: krb5_read_password does not actually look at the
          context, so we're ok even if we don't have a context.  If
          we cannot dynamically load krb5, we can substitute any
          decent read password function instead of the krb5 one.
        */
        code = krb5_read_password(k5.ctx, prompt, 0, password, &pwsize);
        if (code || pwsize == 0)
        {
            fprintf(stderr, "Error while reading password for '%s'\n",
                    opts.principal_name);
            memset(password, 0, sizeof(password));
            exit(1);
        }
    }

    authed_k5 = k5_kinit(&opts, &k5, password);
    authed_k4 = k4_kinit(&opts, &k4, password);
    memset(password, 0, sizeof(password));

#ifdef HAVE_KRB524
    if (!authed_k4 && authed_k5)
	authed_k4 = try_convert524(&k5);
#endif

    if (authed_k5 && opts.verbose)
        fprintf(stderr, "Authenticated to Kerberos v5\n");
    if (authed_k4 && opts.verbose)
        fprintf(stderr, "Authenticated to Kerberos v4\n");

    k5_end(&k5);
    k4_end(&k4);

    if ((got_k5 && !authed_k5) || (got_k4 && !authed_k4))
        exit(1);
    return 0;
}

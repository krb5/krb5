/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * clients/kinit/kinit.c
 *
 * Copyright 1990, 2008 by the Massachusetts Institute of Technology.
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

#include "autoconf.h"
#include "k5-platform.h"        /* for asprintf */
#include <krb5.h>
#include "extern.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <com_err.h>

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
#define GET_PROGNAME(x) max(max(strrchr((x), '/'), strrchr((x), '\\')) + 1,(x))
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
static
char * get_name_from_os()
{
    struct passwd *pw;
    if ((pw = getpwuid((int) getuid())))
        return pw->pw_name;
    return 0;
}
#else /* HAVE_PWD_H */
#ifdef _WIN32
static
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
static
char * get_name_from_os()
{
    return 0;
}
#endif /* _WIN32 */
#endif /* HAVE_PWD_H */

static char *progname;

typedef enum { INIT_PW, INIT_KT, RENEW, VALIDATE } action_type;

struct k_opts
{
    /* in seconds */
    krb5_deltat starttime;
    krb5_deltat lifetime;
    krb5_deltat rlife;

    int forwardable;
    int proxiable;
    int anonymous;
    int addresses;

    int not_forwardable;
    int not_proxiable;
    int no_addresses;

    int verbose;

    char* principal_name;
    char* service_name;
    char* keytab_name;
    char* k5_cache_name;
    char *armor_ccache;

    action_type action;

    int num_pa_opts;
    krb5_gic_opt_pa_data *pa_opts;

    int canonicalize;
    int enterprise;
};

struct k5_data
{
    krb5_context ctx;
    krb5_ccache cc;
    krb5_principal me;
    char* name;
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
    { "canonicalize", 0, NULL, 'C' },
    { "enterprise", 0, NULL, 'E' },
    { NULL, 0, NULL, 0 }
};

#define GETOPT(argc, argv, str) getopt_long(argc, argv, str, long_options, 0)
#else
#define GETOPT(argc, argv, str) getopt(argc, argv, str)
#endif

static void
usage()
{
#define USAGE_BREAK "\n\t"

#ifdef GETOPT_LONG
#define USAGE_LONG_FORWARDABLE  " | --forwardable | --noforwardable"
#define USAGE_LONG_PROXIABLE    " | --proxiable | --noproxiable"
#define USAGE_LONG_ADDRESSES    " | --addresses | --noaddresses"
#define USAGE_LONG_CANONICALIZE " | --canonicalize"
#define USAGE_LONG_ENTERPRISE   " | --enterprise"
#define USAGE_BREAK_LONG       USAGE_BREAK
#else
#define USAGE_LONG_FORWARDABLE  ""
#define USAGE_LONG_PROXIABLE    ""
#define USAGE_LONG_ADDRESSES    ""
#define USAGE_LONG_CANONICALIZE ""
#define USAGE_LONG_ENTERPRISE   ""
#define USAGE_BREAK_LONG        ""
#endif

    fprintf(stderr, "Usage: %s [-V] "
            "[-l lifetime] [-s start_time] "
            USAGE_BREAK
            "[-r renewable_life] "
            "[-f | -F" USAGE_LONG_FORWARDABLE "] "
            USAGE_BREAK_LONG
            "[-p | -P" USAGE_LONG_PROXIABLE "] "
            USAGE_BREAK_LONG
            "-n "
            "[-a | -A" USAGE_LONG_ADDRESSES "] "
            USAGE_BREAK_LONG
            "[-C" USAGE_LONG_CANONICALIZE "] "
            USAGE_BREAK
            "[-E" USAGE_LONG_ENTERPRISE "] "
            USAGE_BREAK
            "[-v] [-R] "
            "[-k [-t keytab_file]] "
            "[-c cachename] "
            USAGE_BREAK
            "[-S service_name] [-T ticket_armor_cache]"
            USAGE_BREAK
            "[-X <attribute>[=<value>]] [principal]"
            "\n\n",
            progname);

    fprintf(stderr, "    options:");
    fprintf(stderr, "\t-V verbose\n");
    fprintf(stderr, "\t-l lifetime\n");
    fprintf(stderr, "\t-s start time\n");
    fprintf(stderr, "\t-r renewable lifetime\n");
    fprintf(stderr, "\t-f forwardable\n");
    fprintf(stderr, "\t-F not forwardable\n");
    fprintf(stderr, "\t-p proxiable\n");
    fprintf(stderr, "\t-P not proxiable\n");
    fprintf(stderr, "\t-n anonymous\n");
    fprintf(stderr, "\t-a include addresses\n");
    fprintf(stderr, "\t-A do not include addresses\n");
    fprintf(stderr, "\t-v validate\n");
    fprintf(stderr, "\t-R renew\n");
    fprintf(stderr, "\t-C canonicalize\n");
    fprintf(stderr, "\t-E client is enterprise principal name\n");
    fprintf(stderr, "\t-k use keytab\n");
    fprintf(stderr, "\t-t filename of keytab to use\n");
    fprintf(stderr, "\t-c Kerberos 5 cache name\n");
    fprintf(stderr, "\t-S service\n");
    fprintf(stderr, "\t-T armor credential cache\n");
    fprintf(stderr, "\t-X <attribute>[=<value>]\n");
    exit(2);
}

static krb5_context errctx;
static void extended_com_err_fn (const char *myprog, errcode_t code,
                                 const char *fmt, va_list args)
{
    const char *emsg;
    emsg = krb5_get_error_message (errctx, code);
    fprintf (stderr, "%s: %s ", myprog, emsg);
    krb5_free_error_message (errctx, emsg);
    vfprintf (stderr, fmt, args);
    fprintf (stderr, "\n");
}

static int
add_preauth_opt(struct k_opts *opts, char *av)
{
    char *sep, *v;
    krb5_gic_opt_pa_data *p, *x;

    if (opts->num_pa_opts == 0) {
        opts->pa_opts = malloc(sizeof(krb5_gic_opt_pa_data));
        if (opts->pa_opts == NULL)
            return ENOMEM;
    } else {
        size_t newsize = (opts->num_pa_opts + 1) * sizeof(krb5_gic_opt_pa_data);
        x = realloc(opts->pa_opts, newsize);
        if (x == NULL)
            return ENOMEM;
        opts->pa_opts = x;
    }
    p = &opts->pa_opts[opts->num_pa_opts];
    sep = strchr(av, '=');
    if (sep) {
        *sep = '\0';
        v = ++sep;
        p->value = v;
    } else {
        p->value = "yes";
    }
    p->attr = av;
    opts->num_pa_opts++;
    return 0;
}

static char *
parse_options(argc, argv, opts)
    int argc;
    char **argv;
    struct k_opts* opts;
{
    krb5_error_code code;
    int errflg = 0;
    int i;

    while ((i = GETOPT(argc, argv, "r:fpFPn54aAVl:s:c:kt:T:RS:vX:CE"))
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
        case 'n':
            opts->anonymous = 1;
            break;
        case 'a':
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
        case 'T':
            if (opts->armor_ccache) {
                fprintf(stderr, "Only one armor_ccache\n");
                errflg++;
            } else opts->armor_ccache = optarg;
            break;
        case 'R':
            opts->action = RENEW;
            break;
        case 'v':
            opts->action = VALIDATE;
            break;
        case 'c':
            if (opts->k5_cache_name)
            {
                fprintf(stderr, "Only one -c option allowed\n");
                errflg++;
            } else {
                opts->k5_cache_name = optarg;
            }
            break;
        case 'X':
            code = add_preauth_opt(opts, optarg);
            if (code)
            {
                com_err(progname, code, "while adding preauth option");
                errflg++;
            }
            break;
        case 'C':
            opts->canonicalize = 1;
            break;
        case 'E':
            opts->enterprise = 1;
            break;
        case '4':
            fprintf(stderr, "Kerberos 4 is no longer supported\n");
            exit(3);
            break;
        case '5':
            break;
        default:
            errflg++;
            break;
        }
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

    opts->principal_name = (optind == argc-1) ? argv[optind] : 0;
    return opts->principal_name;
}

static int
k5_begin(opts, k5)
    struct k_opts* opts;
    struct k5_data* k5;
{
    krb5_error_code code = 0;
    int flags = opts->enterprise ? KRB5_PRINCIPAL_PARSE_ENTERPRISE : 0;

    code = krb5_init_context(&k5->ctx);
    if (code) {
        com_err(progname, code, "while initializing Kerberos 5 library");
        return 0;
    }
    errctx = k5->ctx;
    if (opts->k5_cache_name)
    {
        code = krb5_cc_resolve(k5->ctx, opts->k5_cache_name, &k5->cc);
        if (code != 0) {
            com_err(progname, code, "resolving ccache %s",
                    opts->k5_cache_name);
            return 0;
        }
        if (opts->verbose) {
            fprintf(stderr, "Using specified cache: %s\n",
                    opts->k5_cache_name);
        }
    }
    else
    {
        if ((code = krb5_cc_default(k5->ctx, &k5->cc))) {
            com_err(progname, code, "while getting default ccache");
            return 0;
        }
        if (opts->verbose) {
            fprintf(stderr, "Using default cache: %s\n",
                    krb5_cc_get_name(k5->ctx, k5->cc));
        }
    }

    if (opts->principal_name)
    {
        /* Use specified name */
        if ((code = krb5_parse_name_flags(k5->ctx, opts->principal_name,
                                          flags, &k5->me))) {
            com_err(progname, code, "when parsing name %s",
                    opts->principal_name);
            return 0;
        }
    }
    else
    {
        /* No principal name specified */
        if (opts->anonymous) {
            char *defrealm;
            code = krb5_get_default_realm(k5->ctx, &defrealm);
            if (code) {
                com_err(progname, code, "while getting default realm");
                return 0;
            }
            code = krb5_build_principal_ext(k5->ctx, &k5->me,
                                            strlen(defrealm), defrealm,
                                            strlen(KRB5_WELLKNOWN_NAMESTR),
                                            KRB5_WELLKNOWN_NAMESTR,
                                            strlen(KRB5_ANONYMOUS_PRINCSTR),
                                            KRB5_ANONYMOUS_PRINCSTR,
                                            0);
            krb5_free_default_realm(k5->ctx, defrealm);
            if (code) {
                com_err(progname, code, "while building principal");
                return 0;
            }
        } else {
            if (opts->action == INIT_KT) {
                /* Use the default host/service name */
                code = krb5_sname_to_principal(k5->ctx, NULL, NULL,
                                               KRB5_NT_SRV_HST, &k5->me);
                if (code) {
                    com_err(progname, code,
                            "when creating default server principal name");
                    return 0;
                }
                if (k5->me->realm.data[0] == 0) {
                    code = krb5_unparse_name(k5->ctx, k5->me, &k5->name);
                    if (code == 0) {
                        com_err(progname, KRB5_ERR_HOST_REALM_UNKNOWN,
                                "(principal %s)", k5->name);
                    } else {
                        com_err(progname, KRB5_ERR_HOST_REALM_UNKNOWN,
                                "for local services");
                    }
                    return 0;
                }
            } else {
                /* Get default principal from cache if one exists */
                code = krb5_cc_get_principal(k5->ctx, k5->cc,
                                             &k5->me);
                if (code) {
                    char *name = get_name_from_os();
                    if (!name) {
                        fprintf(stderr, "Unable to identify user\n");
                        return 0;
                    }
                    if ((code = krb5_parse_name_flags(k5->ctx, name,
                                                      flags, &k5->me))) {
                        com_err(progname, code, "when parsing name %s",
                                name);
                        return 0;
                    }
                }
            }
        }
    }

    code = krb5_unparse_name(k5->ctx, k5->me, &k5->name);
    if (code) {
        com_err(progname, code, "when unparsing name");
        return 0;
    }
    if (opts->verbose)
        fprintf(stderr, "Using principal: %s\n", k5->name);

    opts->principal_name = k5->name;

    return 1;
}

static void
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
    errctx = NULL;
    memset(k5, 0, sizeof(*k5));
}

static krb5_error_code
KRB5_CALLCONV
kinit_prompter(
    krb5_context ctx,
    void *data,
    const char *name,
    const char *banner,
    int num_prompts,
    krb5_prompt prompts[]
)
{
    krb5_error_code rc =
        krb5_prompter_posix(ctx, data, name, banner, num_prompts, prompts);
    return rc;
}

static int
k5_kinit(opts, k5)
    struct k_opts* opts;
    struct k5_data* k5;
{
    int notix = 1;
    krb5_keytab keytab = 0;
    krb5_creds my_creds;
    krb5_error_code code = 0;
    krb5_get_init_creds_opt *options = NULL;
    int i;

    memset(&my_creds, 0, sizeof(my_creds));

    code = krb5_get_init_creds_opt_alloc(k5->ctx, &options);
    if (code)
        goto cleanup;

    /*
      From this point on, we can goto cleanup because my_creds is
      initialized.
    */

    if (opts->lifetime)
        krb5_get_init_creds_opt_set_tkt_life(options, opts->lifetime);
    if (opts->rlife)
        krb5_get_init_creds_opt_set_renew_life(options, opts->rlife);
    if (opts->forwardable)
        krb5_get_init_creds_opt_set_forwardable(options, 1);
    if (opts->not_forwardable)
        krb5_get_init_creds_opt_set_forwardable(options, 0);
    if (opts->proxiable)
        krb5_get_init_creds_opt_set_proxiable(options, 1);
    if (opts->not_proxiable)
        krb5_get_init_creds_opt_set_proxiable(options, 0);
    if (opts->canonicalize)
        krb5_get_init_creds_opt_set_canonicalize(options, 1);
    if (opts->anonymous)
        krb5_get_init_creds_opt_set_anonymous(options, 1);
    if (opts->addresses)
    {
        krb5_address **addresses = NULL;
        code = krb5_os_localaddr(k5->ctx, &addresses);
        if (code != 0) {
            com_err(progname, code, "getting local addresses");
            goto cleanup;
        }
        krb5_get_init_creds_opt_set_address_list(options, addresses);
    }
    if (opts->no_addresses)
        krb5_get_init_creds_opt_set_address_list(options, NULL);
    if (opts->armor_ccache)
        krb5_get_init_creds_opt_set_fast_ccache_name(k5->ctx, options, opts->armor_ccache);


    if ((opts->action == INIT_KT) && opts->keytab_name)
    {
#ifndef _WIN32
        if (strncmp(opts->keytab_name, "KDB:", 3) == 0) {
            code = kinit_kdb_init(&k5->ctx,
                                  krb5_princ_realm(k5->ctx, k5->me)->data);
            if (code != 0) {
                com_err(progname, code,
                        "while setting up KDB keytab for realm %s",
                        krb5_princ_realm(k5->ctx, k5->me)->data);
                goto cleanup;
            }
        }
#endif

        code = krb5_kt_resolve(k5->ctx, opts->keytab_name, &keytab);
        if (code != 0) {
            com_err(progname, code, "resolving keytab %s",
                    opts->keytab_name);
            goto cleanup;
        }
        if (opts->verbose)
            fprintf(stderr, "Using keytab: %s\n", opts->keytab_name);
    }

    for (i = 0; i < opts->num_pa_opts; i++) {
        code = krb5_get_init_creds_opt_set_pa(k5->ctx, options,
                                              opts->pa_opts[i].attr,
                                              opts->pa_opts[i].value);
        if (code != 0) {
            com_err(progname, code, "while setting '%s'='%s'",
                    opts->pa_opts[i].attr, opts->pa_opts[i].value);
            goto cleanup;
        }
        if (opts->verbose) {
            fprintf(stderr, "PA Option %s = %s\n", opts->pa_opts[i].attr,
                    opts->pa_opts[i].value);
        }
    }
    code = krb5_get_init_creds_opt_set_out_ccache(k5->ctx, options, k5->cc);
    if (code)
        goto cleanup;

    switch (opts->action) {
    case INIT_PW:
        code = krb5_get_init_creds_password(k5->ctx, &my_creds, k5->me,
                                            0, kinit_prompter, 0,
                                            opts->starttime,
                                            opts->service_name,
                                            options);
        break;
    case INIT_KT:
        code = krb5_get_init_creds_keytab(k5->ctx, &my_creds, k5->me,
                                          keytab,
                                          opts->starttime,
                                          opts->service_name,
                                          options);
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

        if (code == KRB5KRB_AP_ERR_BAD_INTEGRITY)
            fprintf(stderr, "%s: Password incorrect while %s\n", progname,
                    doing);
        else
            com_err(progname, code, "while %s", doing);
        goto cleanup;
    }

    if ((opts->action != INIT_PW) && (opts->action != INIT_KT)) {
        code = krb5_cc_initialize(k5->ctx, k5->cc, opts->canonicalize ?
                                  my_creds.client : k5->me);
        if (code) {
            com_err(progname, code, "when initializing cache %s",
                    opts->k5_cache_name?opts->k5_cache_name:"");
            goto cleanup;
        }
        if (opts->verbose)
            fprintf(stderr, "Initialized cache\n");

        code = krb5_cc_store_cred(k5->ctx, k5->cc, &my_creds);
        if (code) {
            com_err(progname, code, "while storing credentials");
            goto cleanup;
        }
        if (opts->verbose)
            fprintf(stderr, "Stored credentials\n");
    }
    notix = 0;

cleanup:
    if (options)
        krb5_get_init_creds_opt_free(k5->ctx, options);
    if (my_creds.client == k5->me) {
        my_creds.client = 0;
    }
    if (opts->pa_opts) {
        free(opts->pa_opts);
        opts->pa_opts = NULL;
        opts->num_pa_opts = 0;
    }
    krb5_free_cred_contents(k5->ctx, &my_creds);
    if (keytab)
        krb5_kt_close(k5->ctx, keytab);
    return notix?0:1;
}

int
main(argc, argv)
    int argc;
    char **argv;
{
    struct k_opts opts;
    struct k5_data k5;
    int authed_k5 = 0;

    progname = GET_PROGNAME(argv[0]);

    /* Ensure we can be driven from a pipe */
    if(!isatty(fileno(stdin)))
        setvbuf(stdin, 0, _IONBF, 0);
    if(!isatty(fileno(stdout)))
        setvbuf(stdout, 0, _IONBF, 0);
    if(!isatty(fileno(stderr)))
        setvbuf(stderr, 0, _IONBF, 0);

    memset(&opts, 0, sizeof(opts));
    opts.action = INIT_PW;

    memset(&k5, 0, sizeof(k5));

    set_com_err_hook (extended_com_err_fn);

    parse_options(argc, argv, &opts);

    if (k5_begin(&opts, &k5))
        authed_k5 = k5_kinit(&opts, &k5);

    if (authed_k5 && opts.verbose)
        fprintf(stderr, "Authenticated to Kerberos v5\n");

    k5_end(&k5);

    if (!authed_k5)
        exit(1);
    return 0;
}

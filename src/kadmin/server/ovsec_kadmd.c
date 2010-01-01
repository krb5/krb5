/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include    <errno.h>
#include    <stdio.h>
#include    <signal.h>
#include    <syslog.h>
#include    <sys/types.h>
#ifdef _AIX
#include    <sys/select.h>
#endif
#include    <sys/time.h>
#include    <sys/socket.h>
#include    <unistd.h>
#include    <netinet/in.h>
#include    <arpa/inet.h>  /* inet_ntoa */
#include    <netdb.h>
#include    <gssrpc/rpc.h>
#include    <gssapi/gssapi.h>
#include    "gssapiP_krb5.h" /* for kg_get_context */
#include    <gssrpc/auth_gssapi.h>
#include    <kadm5/admin.h>
#include    <kadm5/kadm_rpc.h>
#include    <kadm5/server_acl.h>
#include    <adm_proto.h>
#include    "kdb_kt.h"  /* for krb5_ktkdb_set_context */
#include    <string.h>
#include    "kadm5/server_internal.h" /* XXX for kadm5_server_handle_t */
#include    <kdb_log.h>

#include    "misc.h"

#ifdef PURIFY
#include    "purify.h"

int     signal_pure_report = 0;
int     signal_pure_clear = 0;
void    request_pure_report(int);
void    request_pure_clear(int);
#endif /* PURIFY */

#if defined(NEED_DAEMON_PROTO)
extern int daemon(int, int);
#endif

volatile int    signal_request_exit = 0;
volatile int    signal_request_hup = 0;
void    setup_signal_handlers(iprop_role iproprole);
void    request_exit(int);
void    request_hup(int);
void    reset_db(void);
void    sig_pipe(int);

#ifdef POSIX_SIGNALS
static struct sigaction s_action;
#endif /* POSIX_SIGNALS */


#define TIMEOUT 15

gss_name_t gss_changepw_name = NULL, gss_oldchangepw_name = NULL;
gss_name_t gss_kadmin_name = NULL;
void *global_server_handle;

extern krb5_keyblock master_keyblock;
extern krb5_keylist_node  *master_keylist;

char *build_princ_name(char *name, char *realm);
void log_badauth(OM_uint32 major, OM_uint32 minor,
                 struct sockaddr_in *addr, char *data);
void log_badverf(gss_name_t client_name, gss_name_t server_name,
                 struct svc_req *rqst, struct rpc_msg *msg,
                 char *data);
void log_miscerr(struct svc_req *rqst, struct rpc_msg *msg, char
                 *error, char *data);
void log_badauth_display_status(char *msg, OM_uint32 major, OM_uint32 minor);
void log_badauth_display_status_1(char *m, OM_uint32 code, int type,
                                  int rec);

int schpw;
void do_schpw(int s, kadm5_config_params *params);

#ifndef DISABLE_IPROP
int ipropfd;
#endif

#ifdef USE_PASSWORD_SERVER
void kadm5_set_use_password_server (void);
#endif

/*
 * Function: usage
 *
 * Purpose: print out the server usage message
 *
 * Arguments:
 * Requires:
 * Effects:
 * Modifies:
 */

static void usage()
{
    fprintf(stderr, "Usage: kadmind [-x db_args]* [-r realm] [-m] [-nofork] "
#ifdef USE_PASSWORD_SERVER
            "[-passwordserver] "
#endif
            "[-port port-number]\n"
            "\t\t[-P pid_file]\n"
            "\nwhere,\n\t[-x db_args]* - any number of database specific arguments.\n"
            "\t\t\tLook at each database documentation for supported arguments\n"
    );
    exit(1);
}

/*
 * Function: display_status
 *
 * Purpose: displays GSS-API messages
 *
 * Arguments:
 *
 *      msg             a string to be displayed with the message
 *      maj_stat        the GSS-API major status code
 *      min_stat        the GSS-API minor status code
 *
 * Effects:
 *
 * The GSS-API messages associated with maj_stat and min_stat are
 * displayed on stderr, each preceeded by "GSS-API error <msg>: " and
 * followed by a newline.
 */
static void display_status_1(char *, OM_uint32, int);

static void display_status(msg, maj_stat, min_stat)
    char *msg;
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
{
    display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
    display_status_1(msg, min_stat, GSS_C_MECH_CODE);
}

static void display_status_1(m, code, type)
    char *m;
    OM_uint32 code;
    int type;
{
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc msg;
    OM_uint32 msg_ctx;

    msg_ctx = 0;
    while (1) {
        maj_stat = gss_display_status(&min_stat, code,
                                      type, GSS_C_NULL_OID,
                                      &msg_ctx, &msg);
        fprintf(stderr, "GSS-API error %s: %s\n", m,
                (char *)msg.value);
        (void) gss_release_buffer(&min_stat, &msg);

        if (!msg_ctx)
            break;
    }
}

/*
 * Function: write_pid_file
 *
 * Purpose: writes the current process PID to a file
 *
 * Arguments:
 *
 *      pid_file        path to output file
 *      <return value>  0 on success, error code on failure
 *
 * Effects:
 *
 * The current process PID, obtained from getpid(), is written to the path
 * given in pid_file, overwriting the existing contents if the file already
 * exists.  The PID will be followed by a newline.
 */
static int
write_pid_file(const char *pid_file)
{
    FILE *file;
    unsigned long pid;

    file = fopen(pid_file, "w");
    if (file == NULL)
        return errno;
    pid = (unsigned long) getpid();
    if (fprintf(file, "%ld\n", pid) < 0 || fclose(file) == EOF)
        return errno;
    return 0;
}

/* XXX yuck.  the signal handlers need this */
static krb5_context context;

static krb5_context hctx;

int nofork = 0;

int main(int argc, char *argv[])
{
    extern     char *optarg;
    extern     int optind, opterr;
    int ret;
    OM_uint32 OMret, major_status, minor_status;
    char *whoami;
    gss_buffer_desc in_buf;
    auth_gssapi_name names[4];
    gss_buffer_desc gssbuf;
    gss_OID nt_krb5_name_oid;
    kadm5_config_params params;
    char **db_args      = NULL;
    int    db_args_size = 0;
    char *errmsg;
    int i;
    int strong_random = 1;
    const char *pid_file = NULL;

    kdb_log_context *log_ctx;

    setvbuf(stderr, NULL, _IONBF, 0);

    /* This is OID value the Krb5_Name NameType */
    gssbuf.value = "{1 2 840 113554 1 2 2 1}";
    gssbuf.length = strlen(gssbuf.value);
    major_status = gss_str_to_oid(&minor_status, &gssbuf, &nt_krb5_name_oid);
    if (major_status != GSS_S_COMPLETE) {
        fprintf(stderr, "Couldn't create KRB5 Name NameType OID\n");
        display_status("str_to_oid", major_status, minor_status);
        exit(1);
    }

    names[0].name = names[1].name = names[2].name = names[3].name = NULL;
    names[0].type = names[1].type = names[2].type = names[3].type =
        nt_krb5_name_oid;

#ifdef PURIFY
    purify_start_batch();
#endif /* PURIFY */
    whoami = (strrchr(argv[0], '/') ? strrchr(argv[0], '/')+1 : argv[0]);

    nofork = 0;

    memset(&params, 0, sizeof(params));

    argc--; argv++;
    while (argc) {
        if (strcmp(*argv, "-x") == 0) {
            argc--; argv++;
            if (!argc)
                usage();
            db_args_size++;
            {
                char **temp = realloc( db_args, sizeof(char*) * (db_args_size+1)); /* one for NULL */
                if( temp == NULL )
                {
                    fprintf(stderr,"%s: cannot initialize. Not enough memory\n",
                            whoami);
                    exit(1);
                }
                db_args = temp;
            }
            db_args[db_args_size-1] = *argv;
            db_args[db_args_size]   = NULL;
        }else if (strcmp(*argv, "-r") == 0) {
            argc--; argv++;
            if (!argc)
                usage();
            params.realm = *argv;
            params.mask |= KADM5_CONFIG_REALM;
            argc--; argv++;
            continue;
        } else if (strcmp(*argv, "-m") == 0) {
            params.mkey_from_kbd = 1;
            params.mask |= KADM5_CONFIG_MKEY_FROM_KBD;
        } else if (strcmp(*argv, "-nofork") == 0) {
            nofork = 1;
#ifdef USE_PASSWORD_SERVER
        } else if (strcmp(*argv, "-passwordserver") == 0) {
            kadm5_set_use_password_server ();
#endif
        } else if(strcmp(*argv, "-port") == 0) {
            argc--; argv++;
            if(!argc)
                usage();
            params.kadmind_port = atoi(*argv);
            params.mask |= KADM5_CONFIG_KADMIND_PORT;
        } else if (strcmp(*argv, "-P") == 0) {
            argc--; argv++;
            if (!argc)
                usage();
            pid_file = *argv;
        } else if (strcmp(*argv, "-W") == 0) {
            strong_random = 0;
        } else
            break;
        argc--; argv++;
    }

    if (argc != 0)
        usage();

    if ((ret = kadm5_init_krb5_context(&context))) {
        fprintf(stderr, "%s: %s while initializing context, aborting\n",
                whoami, error_message(ret));
        exit(1);
    }

    krb5_klog_init(context, "admin_server", whoami, 1);

    if((ret = kadm5_init(context, "kadmind", NULL,
                         NULL, &params,
                         KADM5_STRUCT_VERSION,
                         KADM5_API_VERSION_3,
                         db_args,
                         &global_server_handle)) != KADM5_OK) {
        const char *e_txt = krb5_get_error_message (context, ret);
        krb5_klog_syslog(LOG_ERR, "%s while initializing, aborting",
                         e_txt);
        fprintf(stderr, "%s: %s while initializing, aborting\n",
                whoami, e_txt);
        krb5_klog_close(context);
        exit(1);
    }

    if ((ret = kadm5_get_config_params(context, 1, &params,
                                       &params))) {
        const char *e_txt = krb5_get_error_message (context, ret);
        krb5_klog_syslog(LOG_ERR, "%s: %s while initializing, aborting",
                         whoami, e_txt);
        fprintf(stderr, "%s: %s while initializing, aborting\n",
                whoami, e_txt);
        kadm5_destroy(global_server_handle);
        krb5_klog_close(context);
        exit(1);
    }

#define REQUIRED_PARAMS (KADM5_CONFIG_REALM | KADM5_CONFIG_ACL_FILE)

    if ((params.mask & REQUIRED_PARAMS) != REQUIRED_PARAMS) {
        krb5_klog_syslog(LOG_ERR, "%s: Missing required configuration values "
                         "(%lx) while initializing, aborting", whoami,
                         (params.mask & REQUIRED_PARAMS) ^ REQUIRED_PARAMS);
        fprintf(stderr, "%s: Missing required configuration values "
                "(%lx) while initializing, aborting\n", whoami,
                (params.mask & REQUIRED_PARAMS) ^ REQUIRED_PARAMS);
        krb5_klog_close(context);
        kadm5_destroy(global_server_handle);
        exit(1);
    }

    if ((ret = setup_network(global_server_handle, whoami))) {
        const char *e_txt = krb5_get_error_message (context, ret);
        krb5_klog_syslog(LOG_ERR, "%s: %s while initializing network, aborting",
                         whoami, e_txt);
        fprintf(stderr, "%s: %s while initializing network, aborting\n",
                whoami, e_txt);
        kadm5_destroy(global_server_handle);
        krb5_klog_close(context);
        exit(1);
    }

    names[0].name = build_princ_name(KADM5_ADMIN_SERVICE, params.realm);
    names[1].name = build_princ_name(KADM5_CHANGEPW_SERVICE, params.realm);
    if (names[0].name == NULL || names[1].name == NULL) {
        krb5_klog_syslog(LOG_ERR,
                         "Cannot build GSS-API authentication names, "
                         "failing.");
        fprintf(stderr, "%s: Cannot build GSS-API authentication names.\n",
                whoami);
        kadm5_destroy(global_server_handle);
        krb5_klog_close(context);
        exit(1);
    }

    /*
     * Go through some contortions to point gssapi at a kdb keytab.
     * This prevents kadmind from needing to use an actual file-based
     * keytab.
     */
    /* XXX extract kadm5's krb5_context */
    hctx = ((kadm5_server_handle_t)global_server_handle)->context;
    /* Set ktkdb's internal krb5_context. */
    ret = krb5_ktkdb_set_context(hctx);
    if (ret) {
        krb5_klog_syslog(LOG_ERR, "Can't set kdb keytab's internal context.");
        goto kterr;
    }
    /* XXX master_keyblock is in guts of lib/kadm5/server_kdb.c */
    ret = krb5_db_set_mkey(hctx, &master_keyblock);
    if (ret) {
        krb5_klog_syslog(LOG_ERR, "Can't set master key for kdb keytab.");
        goto kterr;
    }
    ret = krb5_db_set_mkey_list(hctx, master_keylist);
    if (ret) {
        krb5_klog_syslog(LOG_ERR, "Can't set master key list for kdb keytab.");
        goto kterr;
    }
    ret = krb5_kt_register(context, &krb5_kt_kdb_ops);
    if (ret) {
        krb5_klog_syslog(LOG_ERR, "Can't register kdb keytab.");
        goto kterr;
    }
    /* Tell gssapi about the kdb keytab. */
    ret = krb5_gss_register_acceptor_identity("KDB:");
    if (ret) {
        krb5_klog_syslog(LOG_ERR, "Can't register acceptor keytab.");
        goto kterr;
    }
kterr:
    if (ret) {
        krb5_klog_syslog(LOG_ERR, "%s", krb5_get_error_message (context, ret));
        fprintf(stderr, "%s: Can't set up keytab for RPC.\n", whoami);
        kadm5_destroy(global_server_handle);
        krb5_klog_close(context);
        exit(1);
    }

    if (svcauth_gssapi_set_names(names, 2) == FALSE) {
        krb5_klog_syslog(LOG_ERR,
                         "Cannot set GSS-API authentication names (keytab not present?), "
                         "failing.");
        fprintf(stderr, "%s: Cannot set GSS-API authentication names.\n",
                whoami);
        svcauth_gssapi_unset_names();
        kadm5_destroy(global_server_handle);
        krb5_klog_close(context);
        exit(1);
    }

    /* if set_names succeeded, this will too */
    in_buf.value = names[1].name;
    in_buf.length = strlen(names[1].name) + 1;
    (void) gss_import_name(&OMret, &in_buf, nt_krb5_name_oid,
                           &gss_changepw_name);

    svcauth_gssapi_set_log_badauth_func(log_badauth, NULL);
    svcauth_gssapi_set_log_badverf_func(log_badverf, NULL);
    svcauth_gssapi_set_log_miscerr_func(log_miscerr, NULL);

    svcauth_gss_set_log_badauth_func(log_badauth, NULL);
    svcauth_gss_set_log_badverf_func(log_badverf, NULL);
    svcauth_gss_set_log_miscerr_func(log_miscerr, NULL);

    if (svcauth_gss_set_svc_name(GSS_C_NO_NAME) != TRUE) {
        fprintf(stderr, "%s: Cannot initialize RPCSEC_GSS service name.\n",
                whoami);
        exit(1);
    }

    if ((ret = kadm5int_acl_init(context, 0, params.acl_file))) {
        errmsg = krb5_get_error_message (context, ret);
        krb5_klog_syslog(LOG_ERR, "Cannot initialize acl file: %s",
                         errmsg);
        fprintf(stderr, "%s: Cannot initialize acl file: %s\n",
                whoami, errmsg);
        svcauth_gssapi_unset_names();
        kadm5_destroy(global_server_handle);
        krb5_klog_close(context);
        exit(1);
    }

    if (!nofork && (ret = daemon(0, 0))) {
        ret = errno;
        errmsg = krb5_get_error_message (context, ret);
        krb5_klog_syslog(LOG_ERR, "Cannot detach from tty: %s", errmsg);
        fprintf(stderr, "%s: Cannot detach from tty: %s\n",
                whoami, errmsg);
        svcauth_gssapi_unset_names();
        kadm5_destroy(global_server_handle);
        krb5_klog_close(context);
        exit(1);
    }
    if (pid_file != NULL) {
        ret = write_pid_file(pid_file);
        if (ret) {
            errmsg = krb5_get_error_message(context, ret);
            krb5_klog_syslog(LOG_ERR, "Cannot create PID file %s: %s",
                             pid_file, errmsg);
            svcauth_gssapi_unset_names();
            kadm5_destroy(global_server_handle);
            krb5_klog_close(context);
            exit(1);
        }
    }

    krb5_klog_syslog(LOG_INFO, "Seeding random number generator");
    ret = krb5_c_random_os_entropy(context, strong_random, NULL);
    if (ret) {
        krb5_klog_syslog(LOG_ERR, "Error getting random seed: %s, aborting",
                         krb5_get_error_message(context, ret));
        svcauth_gssapi_unset_names();
        kadm5_destroy(global_server_handle);
        krb5_klog_close(context);
        exit(1);
    }

    if (params.iprop_enabled == TRUE)
        ulog_set_role(hctx, IPROP_MASTER);
    else
        ulog_set_role(hctx, IPROP_NULL);

    log_ctx = hctx->kdblog_context;

    if (log_ctx && (log_ctx->iproprole == IPROP_MASTER)) {
        /*
         * IProp is enabled, so let's map in the update log
         * and setup the service.
         */
        if ((ret = ulog_map(hctx, params.iprop_logfile,
                            params.iprop_ulogsize, FKADMIND, db_args)) != 0) {
            fprintf(stderr,
                    _("%s: %s while mapping update log (`%s.ulog')\n"),
                    whoami, error_message(ret), params.dbname);
            krb5_klog_syslog(LOG_ERR,
                             _("%s while mapping update log (`%s.ulog')"),
                             error_message(ret), params.dbname);
            krb5_klog_close(context);
            exit(1);
        }


        if (nofork)
            fprintf(stderr,
                    "%s: create IPROP svc (PROG=%d, VERS=%d)\n",
                    whoami, KRB5_IPROP_PROG, KRB5_IPROP_VERS);

#if 0
        if (!svc_create(krb5_iprop_prog_1,
                        KRB5_IPROP_PROG, KRB5_IPROP_VERS,
                        "circuit_v")) {
            fprintf(stderr,
                    _("%s: Cannot create IProp RPC service (PROG=%d, VERS=%d)\n"),
                    whoami,
                    KRB5_IPROP_PROG, KRB5_IPROP_VERS);
            krb5_klog_syslog(LOG_ERR,
                             _("Cannot create IProp RPC service (PROG=%d, VERS=%d), failing."),
                             KRB5_IPROP_PROG, KRB5_IPROP_VERS);
            krb5_klog_close(context);
            exit(1);
        }
#endif

#if 0 /* authgss only? */
        if ((ret = kiprop_get_adm_host_srv_name(context,
                                                params.realm,
                                                &kiprop_name)) != 0) {
            krb5_klog_syslog(LOG_ERR,
                             _("%s while getting IProp svc name, failing"),
                             error_message(ret));
            fprintf(stderr,
                    _("%s: %s while getting IProp svc name, failing\n"),
                    whoami, error_message(ret));
            krb5_klog_close(context);
            exit(1);
        }

        auth_gssapi_name iprop_name;
        iprop_name.name = build_princ_name(foo, bar);
        if (iprop_name.name == NULL) {
            foo error;
        }
        iprop_name.type = nt_krb5_name_oid;
        if (svcauth_gssapi_set_names(&iprop_name, 1) == FALSE) {
            foo error;
        }
        if (!rpc_gss_set_svc_name(kiprop_name, "kerberos_v5", 0,
                                  KRB5_IPROP_PROG, KRB5_IPROP_VERS)) {
            rpc_gss_error_t err;
            (void) rpc_gss_get_error(&err);

            krb5_klog_syslog(LOG_ERR,
                             _("Unable to set RPCSEC_GSS service name (`%s'), failing."),
                             kiprop_name ? kiprop_name : "<null>");

            fprintf(stderr,
                    _("%s: Unable to set RPCSEC_GSS service name (`%s'), failing.\n"),
                    whoami,
                    kiprop_name ? kiprop_name : "<null>");

            if (nofork) {
                fprintf(stderr,
                        "%s: set svc name (rpcsec err=%d, sys err=%d)\n",
                        whoami,
                        err.rpc_gss_error,
                        err.system_error);
            }

            exit(1);
        }
        free(kiprop_name);
#endif
    }

    setup_signal_handlers(log_ctx->iproprole);
    krb5_klog_syslog(LOG_INFO, _("starting"));
    if (nofork)
        fprintf(stderr, "%s: starting...\n", whoami);

    listen_and_process(global_server_handle, whoami);
    krb5_klog_syslog(LOG_INFO, "finished, exiting");

    /* Clean up memory, etc */
    svcauth_gssapi_unset_names();
    kadm5_destroy(global_server_handle);
    closedown_network(global_server_handle, whoami);
    kadm5int_acl_finish(context, 0);
    if(gss_changepw_name) {
        (void) gss_release_name(&OMret, &gss_changepw_name);
    }
    if(gss_oldchangepw_name) {
        (void) gss_release_name(&OMret, &gss_oldchangepw_name);
    }
    for(i = 0 ; i < 4; i++) {
        if (names[i].name) {
            free(names[i].name);
        }
    }

    krb5_klog_close(context);
    krb5_free_context(context);
    exit(2);
}

/*
 * Function: setup_signal_handlers
 *
 * Purpose: Setup signal handling functions using POSIX's sigaction()
 * if possible, otherwise with System V's signal().
 */

void setup_signal_handlers(iprop_role iproprole) {
#ifdef POSIX_SIGNALS
    (void) sigemptyset(&s_action.sa_mask);
    s_action.sa_handler = request_exit;
    (void) sigaction(SIGINT, &s_action, (struct sigaction *) NULL);
    (void) sigaction(SIGTERM, &s_action, (struct sigaction *) NULL);
    (void) sigaction(SIGQUIT, &s_action, (struct sigaction *) NULL);
    s_action.sa_handler = request_hup;
    (void) sigaction(SIGHUP, &s_action, (struct sigaction *) NULL);
    s_action.sa_handler = sig_pipe;
    (void) sigaction(SIGPIPE, &s_action, (struct sigaction *) NULL);
#ifdef PURIFY
    s_action.sa_handler = request_pure_report;
    (void) sigaction(SIGUSR1, &s_action, (struct sigaction *) NULL);
    s_action.sa_handler = request_pure_clear;
    (void) sigaction(SIGUSR2, &s_action, (struct sigaction *) NULL);
#endif /* PURIFY */

    /*
     * IProp will fork for a full-resync, we don't want to
     * wait on it and we don't want the living dead procs either.
     */
    if (iproprole == IPROP_MASTER) {
        s_action.sa_handler = SIG_IGN;
        (void) sigaction(SIGCHLD, &s_action, (struct sigaction *) NULL);
    }
#else /* POSIX_SIGNALS */
    signal(SIGINT, request_exit);
    signal(SIGTERM, request_exit);
    signal(SIGQUIT, request_exit);
    signal(SIGHUP, request_hup);
    signal(SIGPIPE, sig_pipe);
#ifdef PURIFY
    signal(SIGUSR1, request_pure_report);
    signal(SIGUSR2, request_pure_clear);
#endif /* PURIFY */

    /*
     * IProp will fork for a full-resync, we don't want to
     * wait on it and we don't want the living dead procs either.
     */
    if (iproprole == IPROP_MASTER)
        (void) signal(SIGCHLD, SIG_IGN);
#endif /* POSIX_SIGNALS */
}

#ifdef PURIFY
/*
 * Function: request_pure_report
 *
 * Purpose: sets flag saying the server got a signal and that it should
 *              dump a purify report when convenient.
 *
 * Arguments:
 * Requires:
 * Effects:
 * Modifies:
 *      sets signal_pure_report to one
 */

void request_pure_report(int signum)
{
    krb5_klog_syslog(LOG_DEBUG, "Got signal to request a Purify report");
    signal_pure_report = 1;
    return;
}

/*
 * Function: request_pure_clear
 *
 * Purpose: sets flag saying the server got a signal and that it should
 *              dump a purify report when convenient, then clear the
 *              purify tables.
 *
 * Arguments:
 * Requires:
 * Effects:
 * Modifies:
 *      sets signal_pure_report to one
 *      sets signal_pure_clear to one
 */

void request_pure_clear(int signum)
{
    krb5_klog_syslog(LOG_DEBUG, "Got signal to request a Purify report and clear the old Purify info");
    signal_pure_report = 1;
    signal_pure_clear = 1;
    return;
}
#endif /* PURIFY */

/*
 * Function: request_hup
 *
 * Purpose: sets flag saying the server got a signal and that it should
 *              reset the database files when convenient.
 *
 * Arguments:
 * Requires:
 * Effects:
 * Modifies:
 *      sets signal_request_hup to one
 */

void request_hup(int signum)
{
    signal_request_hup = 1;
    return;
}

/*
 * Function: reset_db
 *
 * Purpose: flushes the currently opened database files to disk.
 *
 * Arguments:
 * Requires:
 * Effects:
 *
 * Currently, just sets signal_request_reset to 0.  The kdb and adb
 * libraries used to be sufficiently broken that it was prudent to
 * close and reopen the databases periodically.  They are no longer
 * that broken, so this function is not necessary.
 */
void reset_db(void)
{
#ifdef notdef
    kadm5_ret_t ret;
    char *errmsg;

    if (ret = kadm5_flush(global_server_handle)) {
        krb5_klog_syslog(LOG_ERR, "FATAL ERROR!  %s while flushing databases.  "
                         "Databases may be corrupt!  Aborting.",
                         krb5_get_error_message (context, ret));
        krb5_klog_close(context);
        exit(3);
    }
#endif

    return;
}

/*
 * Function: request_exit
 *
 * Purpose: sets flags saying the server got a signal and that it
 *          should exit when convient.
 *
 * Arguments:
 * Requires:
 * Effects:
 *      modifies signal_request_exit which ideally makes the server exit
 *      at some point.
 *
 * Modifies:
 *      signal_request_exit
 */

void request_exit(int signum)
{
    krb5_klog_syslog(LOG_DEBUG, "Got signal to request exit");
    signal_request_exit = 1;
    return;
}

/*
 * Function: sig_pipe
 *
 * Purpose: SIGPIPE handler
 *
 * Effects: krb5_klog_syslogs a message that a SIGPIPE occurred and returns,
 * thus causing the read() or write() to fail and, presumable, the RPC
 * to recover.  Otherwise, the process aborts.
 */
void sig_pipe(int unused)
{
    krb5_klog_syslog(LOG_NOTICE, "Warning: Received a SIGPIPE; probably a "
                     "client aborted.  Continuing.");
    return;
}

/*
 * Function: build_princ_name
 *
 * Purpose: takes a name and a realm and builds a string that can be
 *          consumed by krb5_parse_name.
 *
 * Arguments:
 *      name                (input) name to be part of principal
 *      realm               (input) realm part of principal
 *      <return value>      char * pointing to "name@realm"
 *
 * Requires:
 *      name be non-null.
 *
 * Effects:
 * Modifies:
 */

char *build_princ_name(char *name, char *realm)
{
    char *fullname;

    if (realm) {
        if (asprintf(&fullname, "%s@%s", name, realm) < 0)
            fullname = NULL;
    } else
        fullname = strdup(name);

    return fullname;
}

/*
 * Function: log_badverf
 *
 * Purpose: Call from GSS-API Sun RPC for garbled/forged/replayed/etc
 * messages.
 *
 * Argiments:
 *      client_name     (r) GSS-API client name
 *      server_name     (r) GSS-API server name
 *      rqst            (r) RPC service request
 *      msg             (r) RPC message
 *      data            (r) arbitrary data (NULL), not used
 *
 * Effects:
 *
 * Logs the invalid request via krb5_klog_syslog(); see functional spec for
 * format.
 */
void log_badverf(gss_name_t client_name, gss_name_t server_name,
                 struct svc_req *rqst, struct rpc_msg *msg, char
                 *data)
{
    struct procnames {
        rpcproc_t proc;
        const char *proc_name;
    };
    static const struct procnames proc_names[] = {
        {1, "CREATE_PRINCIPAL"},
        {2, "DELETE_PRINCIPAL"},
        {3, "MODIFY_PRINCIPAL"},
        {4, "RENAME_PRINCIPAL"},
        {5, "GET_PRINCIPAL"},
        {6, "CHPASS_PRINCIPAL"},
        {7, "CHRAND_PRINCIPAL"},
        {8, "CREATE_POLICY"},
        {9, "DELETE_POLICY"},
        {10, "MODIFY_POLICY"},
        {11, "GET_POLICY"},
        {12, "GET_PRIVS"},
        {13, "INIT"},
        {14, "GET_PRINCS"},
        {15, "GET_POLS"},
        {16, "SETKEY_PRINCIPAL"},
        {17, "SETV4KEY_PRINCIPAL"},
        {18, "CREATE_PRINCIPAL3"},
        {19, "CHPASS_PRINCIPAL3"},
        {20, "CHRAND_PRINCIPAL3"},
        {21, "SETKEY_PRINCIPAL3"}
    };
#define NPROCNAMES (sizeof (proc_names) / sizeof (struct procnames))
    OM_uint32 minor;
    gss_buffer_desc client, server;
    gss_OID gss_type;
    char *a;
    rpcproc_t proc;
    unsigned int i;
    const char *procname;
    size_t clen, slen;
    char *cdots, *sdots;

    client.length = 0;
    client.value = NULL;
    server.length = 0;
    server.value = NULL;

    (void) gss_display_name(&minor, client_name, &client, &gss_type);
    (void) gss_display_name(&minor, server_name, &server, &gss_type);
    if (client.value == NULL) {
        client.value = "(null)";
        clen = sizeof("(null)") -1;
    } else {
        clen = client.length;
    }
    trunc_name(&clen, &cdots);
    if (server.value == NULL) {
        server.value = "(null)";
        slen = sizeof("(null)") - 1;
    } else {
        slen = server.length;
    }
    trunc_name(&slen, &sdots);
    a = inet_ntoa(rqst->rq_xprt->xp_raddr.sin_addr);

    proc = msg->rm_call.cb_proc;
    procname = NULL;
    for (i = 0; i < NPROCNAMES; i++) {
        if (proc_names[i].proc == proc) {
            procname = proc_names[i].proc_name;
            break;
        }
    }
    if (procname != NULL)
        krb5_klog_syslog(LOG_NOTICE, "WARNING! Forged/garbled request: %s, "
                         "claimed client = %.*s%s, server = %.*s%s, addr = %s",
                         procname, (int) clen, (char *) client.value, cdots,
                         (int) slen, (char *) server.value, sdots, a);
    else
        krb5_klog_syslog(LOG_NOTICE, "WARNING! Forged/garbled request: %d, "
                         "claimed client = %.*s%s, server = %.*s%s, addr = %s",
                         proc, (int) clen, (char *) client.value, cdots,
                         (int) slen, (char *) server.value, sdots, a);

    (void) gss_release_buffer(&minor, &client);
    (void) gss_release_buffer(&minor, &server);
}

/*
 * Function: log_miscerr
 *
 * Purpose: Callback from GSS-API Sun RPC for miscellaneous errors
 *
 * Arguments:
 *      rqst            (r) RPC service request
 *      msg             (r) RPC message
 *      error           (r) error message from RPC
 *      data            (r) arbitrary data (NULL), not used
 *
 * Effects:
 *
 * Logs the error via krb5_klog_syslog(); see functional spec for
 * format.
 */
void log_miscerr(struct svc_req *rqst, struct rpc_msg *msg,
                 char *error, char *data)
{
    char *a;

    a = inet_ntoa(rqst->rq_xprt->xp_raddr.sin_addr);
    krb5_klog_syslog(LOG_NOTICE, "Miscellaneous RPC error: %s, %s", a, error);
}



/*
 * Function: log_badauth
 *
 * Purpose: Callback from GSS-API Sun RPC for authentication
 * failures/errors.
 *
 * Arguments:
 *      major           (r) GSS-API major status
 *      minor           (r) GSS-API minor status
 *      addr            (r) originating address
 *      data            (r) arbitrary data (NULL), not used
 *
 * Effects:
 *
 * Logs the GSS-API error via krb5_klog_syslog(); see functional spec for
 * format.
 */
void log_badauth(OM_uint32 major, OM_uint32 minor,
                 struct sockaddr_in *addr, char *data)
{
    char *a;

    /* Authentication attempt failed: <IP address>, <GSS-API error */
    /* strings> */

    a = inet_ntoa(addr->sin_addr);

    krb5_klog_syslog(LOG_NOTICE, "Authentication attempt failed: %s, GSS-API "
                     "error strings are:", a);
    log_badauth_display_status("   ", major, minor);
    krb5_klog_syslog(LOG_NOTICE, "   GSS-API error strings complete.");
}

void log_badauth_display_status(char *msg, OM_uint32 major, OM_uint32 minor)
{
    log_badauth_display_status_1(msg, major, GSS_C_GSS_CODE, 0);
    log_badauth_display_status_1(msg, minor, GSS_C_MECH_CODE, 0);
}

void log_badauth_display_status_1(char *m, OM_uint32 code, int type,
                                  int rec)
{
    OM_uint32 gssstat, minor_stat;
    gss_buffer_desc msg;
    OM_uint32 msg_ctx;

    msg_ctx = 0;
    while (1) {
        gssstat = gss_display_status(&minor_stat, code,
                                     type, GSS_C_NULL_OID,
                                     &msg_ctx, &msg);
        if (gssstat != GSS_S_COMPLETE) {
            if (!rec) {
                log_badauth_display_status_1(m,gssstat,GSS_C_GSS_CODE,1);
                log_badauth_display_status_1(m, minor_stat,
                                             GSS_C_MECH_CODE, 1);
            } else
                krb5_klog_syslog(LOG_ERR, "GSS-API authentication error %.*s: "
                                 "recursive failure!", (int) msg.length,
                                 (char *) msg.value);
            return;
        }

        krb5_klog_syslog(LOG_NOTICE, "%s %.*s", m, (int)msg.length,
                         (char *)msg.value);
        (void) gss_release_buffer(&minor_stat, &msg);

        if (!msg_ctx)
            break;
    }
}

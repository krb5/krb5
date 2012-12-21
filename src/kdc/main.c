/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* kdc/main.c - Main procedure body for the KDC server process */
/*
 * Copyright 1990,2001,2008,2009 by the Massachusetts Institute of Technology.
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
 */
/*
 * Copyright (c) 2006-2008, Novell, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *   * The copyright holder's name is not used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/wait.h>

#include "k5-int.h"
#include "com_err.h"
#include "adm.h"
#include "adm_proto.h"
#include "kdc_util.h"
#include "extern.h"
#include "kdc5_err.h"
#include "kdb_kt.h"
#include "net-server.h"
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#if defined(NEED_DAEMON_PROTO)
extern int daemon(int, int);
#endif

static void usage (char *);

static krb5_error_code setup_sam (void);

static void initialize_realms (krb5_context, int, char **);

static void finish_realms (void);

static int nofork = 0;
static int workers = 0;
static const char *pid_file = NULL;
static int rkey_init_done = 0;
static volatile int signal_received = 0;
static volatile int sighup_received = 0;

#define KRB5_KDC_MAX_REALMS     32

static krb5_context kdc_err_context;
static const char *kdc_progname;

/*
 * We use krb5_klog_init to set up a com_err callback to log error
 * messages.  The callback also pulls the error message out of the
 * context we pass to krb5_klog_init; however, we use realm-specific
 * contexts for most of our krb5 library calls, so the error message
 * isn't present in the global context.  This wrapper ensures that the
 * error message state from the call context is copied into the
 * context known by krb5_klog.  call_context can be NULL if the error
 * code did not come from a krb5 library function.
 */
void
kdc_err(krb5_context call_context, errcode_t code, const char *fmt, ...)
{
    va_list ap;

    if (call_context)
        krb5_copy_error_message(kdc_err_context, call_context);
    va_start(ap, fmt);
    com_err_va(kdc_progname, code, fmt, ap);
    va_end(ap);
}

/*
 * Find the realm entry for a given realm.
 */
kdc_realm_t *
find_realm_data(char *rname, krb5_ui_4 rsize)
{
    int i;
    for (i=0; i<kdc_numrealms; i++) {
        if ((rsize == strlen(kdc_realmlist[i]->realm_name)) &&
            !strncmp(rname, kdc_realmlist[i]->realm_name, rsize))
            return(kdc_realmlist[i]);
    }
    return((kdc_realm_t *) NULL);
}

krb5_error_code
setup_server_realm(krb5_principal sprinc)
{
    krb5_error_code     kret;
    kdc_realm_t         *newrealm;

    kret = 0;
    if (kdc_numrealms > 1) {
        if (!(newrealm = find_realm_data(sprinc->realm.data,
                                         (krb5_ui_4) sprinc->realm.length)))
            kret = ENOENT;
        else
            kdc_active_realm = newrealm;
    }
    else
        kdc_active_realm = kdc_realmlist[0];
    return(kret);
}

static void
finish_realm(kdc_realm_t *rdp)
{
    if (rdp->realm_name)
        free(rdp->realm_name);
    if (rdp->realm_mpname)
        free(rdp->realm_mpname);
    if (rdp->realm_stash)
        free(rdp->realm_stash);
    if (rdp->realm_ports)
        free(rdp->realm_ports);
    if (rdp->realm_tcp_ports)
        free(rdp->realm_tcp_ports);
    if (rdp->realm_keytab)
        krb5_kt_close(rdp->realm_context, rdp->realm_keytab);
    if (rdp->realm_host_based_services)
        free(rdp->realm_host_based_services);
    if (rdp->realm_no_host_referral)
        free(rdp->realm_no_host_referral);
    if (rdp->realm_context) {
        if (rdp->realm_mprinc)
            krb5_free_principal(rdp->realm_context, rdp->realm_mprinc);
        if (rdp->realm_mkey.length && rdp->realm_mkey.contents) {
            /* XXX shouldn't memset be zap for safety? */
            memset(rdp->realm_mkey.contents, 0, rdp->realm_mkey.length);
            free(rdp->realm_mkey.contents);
        }
        if (rdp->mkey_list)
            krb5_dbe_free_key_list(rdp->realm_context, rdp->mkey_list);
        krb5_db_fini(rdp->realm_context);
        if (rdp->realm_tgsprinc)
            krb5_free_principal(rdp->realm_context, rdp->realm_tgsprinc);
        krb5_free_context(rdp->realm_context);
    }
    memset(rdp, 0, sizeof(*rdp));
    free(rdp);
}

static krb5_error_code
handle_referral_params(krb5_realm_params *rparams,
                       char *no_refrls, char *host_based_srvcs,
                       kdc_realm_t *rdp )
{
    krb5_error_code retval = 0;
    if (no_refrls && krb5_match_config_pattern(no_refrls, KRB5_CONF_ASTERISK) == TRUE) {
        rdp->realm_no_host_referral = strdup(KRB5_CONF_ASTERISK);
        if (!rdp->realm_no_host_referral)
            retval = ENOMEM;
    } else {
        if (rparams && rparams->realm_no_host_referral) {
            if (krb5_match_config_pattern(rparams->realm_no_host_referral,
                                          KRB5_CONF_ASTERISK) == TRUE) {
                rdp->realm_no_host_referral = strdup(KRB5_CONF_ASTERISK);
                if (!rdp->realm_no_host_referral)
                    retval = ENOMEM;
            } else if  (no_refrls && (asprintf(&(rdp->realm_no_host_referral),
                                               "%s%s%s%s%s", " ", no_refrls," ",
                                               rparams->realm_no_host_referral, " ") < 0))
                retval = ENOMEM;
            else if (asprintf(&(rdp->realm_no_host_referral),"%s%s%s", " ",
                              rparams->realm_no_host_referral, " ") < 0)
                retval = ENOMEM;
        } else if( no_refrls != NULL) {
            if ( asprintf(&(rdp->realm_no_host_referral),
                          "%s%s%s", " ", no_refrls, " ") < 0)
                retval = ENOMEM;
        } else
            rdp->realm_no_host_referral = NULL;
    }

    if (rdp->realm_no_host_referral &&
        krb5_match_config_pattern(rdp->realm_no_host_referral,
                                  KRB5_CONF_ASTERISK) == TRUE) {
        rdp->realm_host_based_services = NULL;
        return 0;
    }

    /* default_referral_realm (default none) */
    if (rparams && rparams->realm_default_referral_realm_valid)
        rdp->realm_default_referral_realm = strdup(rparams->realm_default_referral_realm);
    else
        rdp->realm_default_referral_realm = NULL;

    /* cross_realm_default_referral (default no) */
    if (rparams && rparams->realm_cross_realm_default_referral_valid)
        rdp->realm_cross_realm_default_referral = rparams->realm_cross_realm_default_referral;
    else
        rdp->realm_cross_realm_default_referral = 0;

    if (host_based_srvcs &&
        (krb5_match_config_pattern(host_based_srvcs, KRB5_CONF_ASTERISK) == TRUE)) {
        rdp->realm_host_based_services = strdup(KRB5_CONF_ASTERISK);
        if (!rdp->realm_host_based_services)
            retval = ENOMEM;
    } else {
        if (rparams && rparams->realm_host_based_services) {
            if (krb5_match_config_pattern(rparams->realm_host_based_services,
                                          KRB5_CONF_ASTERISK) == TRUE) {
                rdp->realm_host_based_services = strdup(KRB5_CONF_ASTERISK);
                if (!rdp->realm_host_based_services)
                    retval = ENOMEM;
            } else if (host_based_srvcs) {
                if (asprintf(&(rdp->realm_host_based_services), "%s%s%s%s%s",
                             " ", host_based_srvcs," ",
                             rparams->realm_host_based_services, " ") < 0)
                    retval = ENOMEM;
            } else if (asprintf(&(rdp->realm_host_based_services),"%s%s%s", " ",
                                rparams->realm_host_based_services, " ") < 0)
                retval = ENOMEM;
        } else if (host_based_srvcs) {
            if (asprintf(&(rdp->realm_host_based_services),"%s%s%s", " ",
                         host_based_srvcs, " ") < 0)
                retval = ENOMEM;
        } else
            rdp->realm_host_based_services = NULL;
    }

    return retval;
}

/*
 * Initialize a realm control structure from the alternate profile or from
 * the specified defaults.
 *
 * After we're complete here, the essence of the realm is embodied in the
 * realm data and we should be all set to begin operation for that realm.
 */
static krb5_error_code
init_realm(kdc_realm_t *rdp, char *realm, char *def_mpname,
           krb5_enctype def_enctype, char *def_udp_ports, char *def_tcp_ports,
           krb5_boolean def_manual, krb5_boolean def_restrict_anon,
           char **db_args, char *no_refrls, char *host_based_srvcs)
{
    krb5_error_code     kret;
    krb5_boolean        manual;
    krb5_realm_params   *rparams;
    int                 kdb_open_flags;
    krb5_kvno       mkvno = IGNORE_VNO;

    memset(rdp, 0, sizeof(kdc_realm_t));
    if (!realm) {
        kret = EINVAL;
        goto whoops;
    }

    rdp->realm_name = strdup(realm);
    if (rdp->realm_name == NULL) {
        kret = ENOMEM;
        goto whoops;
    }
    kret = krb5int_init_context_kdc(&rdp->realm_context);
    if (kret) {
        kdc_err(NULL, kret, _("while getting context for realm %s"), realm);
        goto whoops;
    }

    kret = krb5_read_realm_params(rdp->realm_context, rdp->realm_name,
                                  &rparams);
    if (kret) {
        kdc_err(rdp->realm_context, kret, _("while reading realm parameters"));
        goto whoops;
    }

    /* Handle profile file name */
    if (rparams && rparams->realm_profile) {
        rdp->realm_profile = strdup(rparams->realm_profile);
        if (!rdp->realm_profile) {
            kret = ENOMEM;
            goto whoops;
        }
    }

    /* Handle master key name */
    if (rparams && rparams->realm_mkey_name)
        rdp->realm_mpname = strdup(rparams->realm_mkey_name);
    else
        rdp->realm_mpname = (def_mpname) ? strdup(def_mpname) :
            strdup(KRB5_KDB_M_NAME);
    if (!rdp->realm_mpname) {
        kret = ENOMEM;
        goto whoops;
    }

    /* Handle KDC ports */
    if (rparams && rparams->realm_kdc_ports)
        rdp->realm_ports = strdup(rparams->realm_kdc_ports);
    else
        rdp->realm_ports = strdup(def_udp_ports);
    if (!rdp->realm_ports) {
        kret = ENOMEM;
        goto whoops;
    }
    if (rparams && rparams->realm_kdc_tcp_ports)
        rdp->realm_tcp_ports = strdup(rparams->realm_kdc_tcp_ports);
    else
        rdp->realm_tcp_ports = strdup(def_tcp_ports);
    if (!rdp->realm_tcp_ports) {
        kret = ENOMEM;
        goto whoops;
    }
    /* Handle stash file */
    if (rparams && rparams->realm_stash_file) {
        rdp->realm_stash = strdup(rparams->realm_stash_file);
        if (!rdp->realm_stash) {
            kret = ENOMEM;
            goto whoops;
        }
        manual = FALSE;
    } else
        manual = def_manual;

    if (rparams && rparams->realm_restrict_anon_valid)
        rdp->realm_restrict_anon = rparams->realm_restrict_anon;
    else
        rdp->realm_restrict_anon = def_restrict_anon;

    /* Handle master key type */
    if (rparams && rparams->realm_enctype_valid)
        rdp->realm_mkey.enctype = (krb5_enctype) rparams->realm_enctype;
    else
        rdp->realm_mkey.enctype = manual ? def_enctype : ENCTYPE_UNKNOWN;

    /* Handle reject-bad-transit flag */
    if (rparams && rparams->realm_reject_bad_transit_valid)
        rdp->realm_reject_bad_transit = rparams->realm_reject_bad_transit;
    else
        rdp->realm_reject_bad_transit = 1;

    /* Handle ticket maximum life */
    rdp->realm_maxlife = (rparams && rparams->realm_max_life_valid) ?
        rparams->realm_max_life : KRB5_KDB_MAX_LIFE;

    /* Handle ticket renewable maximum life */
    rdp->realm_maxrlife = (rparams && rparams->realm_max_rlife_valid) ?
        rparams->realm_max_rlife : KRB5_KDB_MAX_RLIFE;

    /* Handle KDC referrals */
    kret = handle_referral_params(rparams, no_refrls, host_based_srvcs, rdp);
    if (kret == ENOMEM)
        goto whoops;

    if (rparams)
        krb5_free_realm_params(rdp->realm_context, rparams);

    /*
     * We've got our parameters, now go and setup our realm context.
     */

    /* Set the default realm of this context */
    if ((kret = krb5_set_default_realm(rdp->realm_context, realm))) {
        kdc_err(rdp->realm_context, kret,
                _("while setting default realm to %s"), realm);
        goto whoops;
    }

    /* first open the database  before doing anything */
    kdb_open_flags = KRB5_KDB_OPEN_RW | KRB5_KDB_SRV_TYPE_KDC;
    if ((kret = krb5_db_open(rdp->realm_context, db_args, kdb_open_flags))) {
        kdc_err(rdp->realm_context, kret,
                _("while initializing database for realm %s"), realm);
        goto whoops;
    }

    /* Assemble and parse the master key name */
    if ((kret = krb5_db_setup_mkey_name(rdp->realm_context, rdp->realm_mpname,
                                        rdp->realm_name, (char **) NULL,
                                        &rdp->realm_mprinc))) {
        kdc_err(rdp->realm_context, kret,
                _("while setting up master key name %s for realm %s"),
                rdp->realm_mpname, realm);
        goto whoops;
    }

    /*
     * Get the master key (note, may not be the most current mkey).
     */
    if ((kret = krb5_db_fetch_mkey(rdp->realm_context, rdp->realm_mprinc,
                                   rdp->realm_mkey.enctype, manual,
                                   FALSE, rdp->realm_stash,
                                   &mkvno, NULL, &rdp->realm_mkey))) {
        kdc_err(rdp->realm_context, kret,
                _("while fetching master key %s for realm %s"),
                rdp->realm_mpname, realm);
        goto whoops;
    }

    if ((kret = krb5_db_fetch_mkey_list(rdp->realm_context, rdp->realm_mprinc,
                                        &rdp->realm_mkey, mkvno, &rdp->mkey_list))) {
        kdc_err(rdp->realm_context, kret,
                _("while fetching master keys list for realm %s"), realm);
        goto whoops;
    }


    /* Set up the keytab */
    if ((kret = krb5_ktkdb_resolve(rdp->realm_context, NULL,
                                   &rdp->realm_keytab))) {
        kdc_err(rdp->realm_context, kret,
                _("while resolving kdb keytab for realm %s"), realm);
        goto whoops;
    }

    /* Preformat the TGS name */
    if ((kret = krb5_build_principal(rdp->realm_context, &rdp->realm_tgsprinc,
                                     strlen(realm), realm, KRB5_TGS_NAME,
                                     realm, (char *) NULL))) {
        kdc_err(rdp->realm_context, kret,
                _("while building TGS name for realm %s"), realm);
        goto whoops;
    }

    if (!rkey_init_done) {
        krb5_data seed;
        /*
         * If all that worked, then initialize the random key
         * generators.
         */

        seed.length = rdp->realm_mkey.length;
        seed.data = (char *)rdp->realm_mkey.contents;

        if ((kret = krb5_c_random_add_entropy(rdp->realm_context,
                                              KRB5_C_RANDSOURCE_TRUSTEDPARTY, &seed)))
            goto whoops;

        rkey_init_done = 1;
    }
whoops:
    /*
     * If we choked, then clean up any dirt we may have dropped on the floor.
     */
    if (kret) {

        finish_realm(rdp);
    }
    return(kret);
}

static krb5_sigtype
on_monitor_signal(int signo)
{
    signal_received = signo;

#ifdef POSIX_SIGTYPE
    return;
#else
    return(0);
#endif
}

static krb5_sigtype
on_monitor_sighup(int signo)
{
    sighup_received = 1;

#ifdef POSIX_SIGTYPE
    return;
#else
    return(0);
#endif
}

/*
 * Kill the worker subprocesses given by pids[0..bound-1], skipping any which
 * are set to -1, and wait for them to exit (so that we know the ports are no
 * longer in use).
 */
static void
terminate_workers(pid_t *pids, int bound)
{
    int i, status, num_active = 0;
    pid_t pid;

    /* Kill the active worker pids. */
    for (i = 0; i < bound; i++) {
        if (pids[i] == -1)
            continue;
        kill(pids[i], SIGTERM);
        num_active++;
    }

    /* Wait for them to exit. */
    while (num_active > 0) {
        pid = wait(&status);
        if (pid >= 0)
            num_active--;
    }
}

/*
 * Create num worker processes and return successfully in each child.  The
 * parent process will act as a supervisor and will only return from this
 * function in error cases.
 */
static krb5_error_code
create_workers(verto_ctx *ctx, int num)
{
    krb5_error_code retval;
    int i, status;
    pid_t pid, *pids;
#ifdef POSIX_SIGNALS
    struct sigaction s_action;
#endif /* POSIX_SIGNALS */

    /*
     * Setup our signal handlers which will forward to the children.
     * These handlers will be overriden in the child processes.
     */
#ifdef POSIX_SIGNALS
    (void) sigemptyset(&s_action.sa_mask);
    s_action.sa_flags = 0;
    s_action.sa_handler = on_monitor_signal;
    (void) sigaction(SIGINT, &s_action, (struct sigaction *) NULL);
    (void) sigaction(SIGTERM, &s_action, (struct sigaction *) NULL);
    (void) sigaction(SIGQUIT, &s_action, (struct sigaction *) NULL);
    s_action.sa_handler = on_monitor_sighup;
    (void) sigaction(SIGHUP, &s_action, (struct sigaction *) NULL);
#else  /* POSIX_SIGNALS */
    signal(SIGINT, on_monitor_signal);
    signal(SIGTERM, on_monitor_signal);
    signal(SIGQUIT, on_monitor_signal);
    signal(SIGHUP, on_monitor_sighup);
#endif /* POSIX_SIGNALS */

    /* Create child worker processes; return in each child. */
    krb5_klog_syslog(LOG_INFO, _("creating %d worker processes"), num);
    pids = calloc(num, sizeof(pid_t));
    if (pids == NULL)
        return ENOMEM;
    for (i = 0; i < num; i++) {
        pid = fork();
        if (pid == 0) {
            if (!verto_reinitialize(ctx)) {
                krb5_klog_syslog(LOG_ERR,
                                 _("Unable to reinitialize main loop"));
                return ENOMEM;
            }
            retval = loop_setup_signals(ctx, NULL, reset_for_hangup);
            if (retval) {
                krb5_klog_syslog(LOG_ERR, _("Unable to initialize signal "
                                            "handlers in pid %d"), pid);
                return retval;
            }

            /* Avoid race condition */
            if (signal_received)
                exit(0);

            /* Return control to main() in the new worker process. */
            free(pids);
            return 0;
        }
        if (pid == -1) {
            /* Couldn't fork enough times. */
            status = errno;
            terminate_workers(pids, i);
            free(pids);
            return status;
        }
        pids[i] = pid;
    }

    /* We're going to use our own main loop here. */
    loop_free(ctx);

    /* Supervise the worker processes. */
    while (!signal_received) {
        /* Wait until a worker process exits or we get a signal. */
        pid = wait(&status);
        if (pid >= 0) {
            krb5_klog_syslog(LOG_ERR, _("worker %ld exited with status %d"),
                             (long) pid, status);

            /* Remove the pid from the table. */
            for (i = 0; i < num; i++) {
                if (pids[i] == pid)
                    pids[i] = -1;
            }

            /* When one worker process exits, terminate them all, so that KDC
             * crashes behave similarly with or without worker processes. */
            break;
        }

        /* Propagate HUP signal to worker processes if we received one. */
        if (sighup_received) {
            sighup_received = 0;
            for (i = 0; i < num; i++) {
                if (pids[i] != -1)
                    kill(pids[i], SIGHUP);
            }
        }
    }
    if (signal_received)
        krb5_klog_syslog(LOG_INFO, _("signal %d received in supervisor"),
                         signal_received);

    terminate_workers(pids, num);
    free(pids);
    exit(0);
}

static krb5_error_code
setup_sam(void)
{
    return krb5_c_make_random_key(kdc_context, ENCTYPE_DES_CBC_MD5, &psr_key);
}

static void
usage(char *name)
{
    fprintf(stderr,
            _("usage: %s [-x db_args]* [-d dbpathname] [-r dbrealmname]\n"
              "\t\t[-R replaycachename] [-m] [-k masterenctype]\n"
              "\t\t[-M masterkeyname] [-p port] [-P pid_file]\n"
              "\t\t[-n] [-w numworkers] [/]\n\n"
              "where,\n"
              "\t[-x db_args]* - Any number of database specific arguments.\n"
              "\t\t\tLook at each database module documentation for "
              "\t\t\tsupported arguments\n"),
            name);
    exit(1);
}


static void
initialize_realms(krb5_context kcontext, int argc, char **argv)
{
    int                 c;
    char                *db_name = (char *) NULL;
    char                *lrealm = (char *) NULL;
    char                *mkey_name = (char *) NULL;
    krb5_error_code     retval;
    krb5_enctype        menctype = ENCTYPE_UNKNOWN;
    kdc_realm_t         *rdatap = NULL;
    krb5_boolean        manual = FALSE;
    krb5_boolean        def_restrict_anon;
    char                *default_udp_ports = 0;
    char                *default_tcp_ports = 0;
    krb5_pointer        aprof;
    const char          *hierarchy[3];
    char                *no_refrls = NULL;
    char                *host_based_srvcs = NULL;
    int                  db_args_size = 0;
    char                **db_args = NULL;

    extern char *optarg;

    if (!krb5_aprof_init(DEFAULT_KDC_PROFILE, KDC_PROFILE_ENV, &aprof)) {
        hierarchy[0] = KRB5_CONF_KDCDEFAULTS;
        hierarchy[1] = KRB5_CONF_KDC_PORTS;
        hierarchy[2] = (char *) NULL;
        if (krb5_aprof_get_string(aprof, hierarchy, TRUE, &default_udp_ports))
            default_udp_ports = 0;
        hierarchy[1] = KRB5_CONF_KDC_TCP_PORTS;
        if (krb5_aprof_get_string(aprof, hierarchy, TRUE, &default_tcp_ports))
            default_tcp_ports = 0;
        hierarchy[1] = KRB5_CONF_MAX_DGRAM_REPLY_SIZE;
        if (krb5_aprof_get_int32(aprof, hierarchy, TRUE, &max_dgram_reply_size))
            max_dgram_reply_size = MAX_DGRAM_SIZE;
        hierarchy[1] = KRB5_CONF_RESTRICT_ANONYMOUS_TO_TGT;
        if (krb5_aprof_get_boolean(aprof, hierarchy, TRUE, &def_restrict_anon))
            def_restrict_anon = FALSE;
        hierarchy[1] = KRB5_CONF_NO_HOST_REFERRAL;
        if (krb5_aprof_get_string_all(aprof, hierarchy, &no_refrls))
            no_refrls = 0;
        if (!no_refrls ||
            krb5_match_config_pattern(no_refrls, KRB5_CONF_ASTERISK) == FALSE) {
            hierarchy[1] = KRB5_CONF_HOST_BASED_SERVICES;
            if (krb5_aprof_get_string_all(aprof, hierarchy, &host_based_srvcs))
                host_based_srvcs = 0;
        }

        krb5_aprof_finish(aprof);
    }

    if (default_udp_ports == 0) {
        default_udp_ports = strdup(DEFAULT_KDC_UDP_PORTLIST);
        if (default_udp_ports == 0) {
            fprintf(stderr, _(" KDC cannot initialize. Not enough memory\n"));
            exit(1);
        }
    }
    if (default_tcp_ports == 0) {
        default_tcp_ports = strdup(DEFAULT_KDC_TCP_PORTLIST);
        if (default_tcp_ports == 0) {
            fprintf(stderr, _(" KDC cannot initialize. Not enough memory\n"));
            exit(1);
        }
    }

    /*
     * Loop through the option list.  Each time we encounter a realm name,
     * use the previously scanned options to fill in for defaults.
     */
    while ((c = getopt(argc, argv, "x:r:d:mM:k:R:e:P:p:s:nw:4:X3")) != -1) {
        switch(c) {
        case 'x':
            db_args_size++;
            {
                char **temp = realloc( db_args, sizeof(char*) * (db_args_size+1)); /* one for NULL */
                if( temp == NULL )
                {
                    fprintf(stderr, _("%s: KDC cannot initialize. Not enough "
                                      "memory\n"), argv[0]);
                    exit(1);
                }

                db_args = temp;
            }
            db_args[db_args_size-1] = optarg;
            db_args[db_args_size]   = NULL;
            break;

        case 'r':                       /* realm name for db */
            if (!find_realm_data(optarg, (krb5_ui_4) strlen(optarg))) {
                if ((rdatap = (kdc_realm_t *) malloc(sizeof(kdc_realm_t)))) {
                    if ((retval = init_realm(rdatap, optarg, mkey_name,
                                             menctype, default_udp_ports,
                                             default_tcp_ports, manual,
                                             def_restrict_anon, db_args,
                                             no_refrls, host_based_srvcs))) {
                        fprintf(stderr, _("%s: cannot initialize realm %s - "
                                          "see log file for details\n"),
                                argv[0], optarg);
                        exit(1);
                    }
                    kdc_realmlist[kdc_numrealms] = rdatap;
                    kdc_numrealms++;
                    free(db_args), db_args=NULL, db_args_size = 0;
                }
                else
                {
                    fprintf(stderr, _("%s: cannot initialize realm %s. Not "
                                      "enough memory\n"), argv[0], optarg);
                    exit(1);
                }
            }
            break;
        case 'd':                       /* pathname for db */
            /* now db_name is not a seperate argument.
             * It has to be passed as part of the db_args
             */
            if( db_name == NULL ) {
                if (asprintf(&db_name, "dbname=%s", optarg) < 0) {
                    fprintf(stderr, _("%s: KDC cannot initialize. Not enough "
                                      "memory\n"), argv[0]);
                    exit(1);
                }
            }

            db_args_size++;
            {
                char **temp = realloc( db_args, sizeof(char*) * (db_args_size+1)); /* one for NULL */
                if( temp == NULL )
                {
                    fprintf(stderr, _("%s: KDC cannot initialize. Not enough "
                                      "memory\n"), argv[0]);
                    exit(1);
                }

                db_args = temp;
            }
            db_args[db_args_size-1] = db_name;
            db_args[db_args_size]   = NULL;
            break;
        case 'm':                       /* manual type-in of master key */
            manual = TRUE;
            if (menctype == ENCTYPE_UNKNOWN)
                menctype = ENCTYPE_DES_CBC_CRC;
            break;
        case 'M':                       /* master key name in DB */
            mkey_name = optarg;
            break;
        case 'n':
            nofork++;                   /* don't detach from terminal */
            break;
        case 'w':                       /* create multiple worker processes */
            workers = atoi(optarg);
            if (workers <= 0)
                usage(argv[0]);
            break;
        case 'k':                       /* enctype for master key */
            if (krb5_string_to_enctype(optarg, &menctype))
                com_err(argv[0], 0, _("invalid enctype %s"), optarg);
            break;
        case 'R':
            /* Replay cache name; defunct since we don't use a replay cache. */
            break;
        case 'P':
            pid_file = optarg;
            break;
        case 'p':
            if (default_udp_ports)
                free(default_udp_ports);
            default_udp_ports = strdup(optarg);
            if (!default_udp_ports) {
                fprintf(stderr, _(" KDC cannot initialize. Not enough "
                                  "memory\n"));
                exit(1);
            }
#if 0 /* not yet */
            if (default_tcp_ports)
                free(default_tcp_ports);
            default_tcp_ports = strdup(optarg);
#endif
            break;
        case '4':
            break;
        case 'X':
            break;
        case '?':
        default:
            usage(argv[0]);
        }
    }

    /*
     * Check to see if we processed any realms.
     */
    if (kdc_numrealms == 0) {
        /* no realm specified, use default realm */
        if ((retval = krb5_get_default_realm(kcontext, &lrealm))) {
            com_err(argv[0], retval,
                    _("while attempting to retrieve default realm"));
            fprintf (stderr,
                     _("%s: %s, attempting to retrieve default realm\n"),
                     argv[0], krb5_get_error_message(kcontext, retval));
            exit(1);
        }
        if ((rdatap = (kdc_realm_t *) malloc(sizeof(kdc_realm_t)))) {
            if ((retval = init_realm(rdatap, lrealm, mkey_name, menctype,
                                     default_udp_ports, default_tcp_ports,
                                     manual, def_restrict_anon, db_args,
                                     no_refrls, host_based_srvcs))) {
                fprintf(stderr, _("%s: cannot initialize realm %s - see log "
                                  "file for details\n"), argv[0], lrealm);
                exit(1);
            }
            kdc_realmlist[0] = rdatap;
            kdc_numrealms++;
        }
        krb5_free_default_realm(kcontext, lrealm);
    }

    /* Ensure that this is set for our first request. */
    kdc_active_realm = kdc_realmlist[0];
    if (default_udp_ports)
        free(default_udp_ports);
    if (default_tcp_ports)
        free(default_tcp_ports);
    if (db_args)
        free(db_args);
    if (db_name)
        free(db_name);
    if (host_based_srvcs)
        free(host_based_srvcs);
    if (no_refrls)
        free(no_refrls);

    return;
}

static krb5_error_code
write_pid_file(const char *path)
{
    FILE *file;
    unsigned long pid;

    file = fopen(path, "w");
    if (file == NULL)
        return errno;
    pid = (unsigned long) getpid();
    if (fprintf(file, "%ld\n", pid) < 0 || fclose(file) == EOF)
        return errno;
    return 0;
}

static void
finish_realms()
{
    int i;

    for (i = 0; i < kdc_numrealms; i++) {
        finish_realm(kdc_realmlist[i]);
        kdc_realmlist[i] = 0;
    }
    kdc_numrealms = 0;
}

/*
  outline:

  process args & setup

  initialize database access (fetch master key, open DB)

  initialize network

  loop:
  listen for packet

  determine packet type, dispatch to handling routine
  (AS or TGS (or V4?))

  reflect response

  exit on signal

  clean up secrets, close db

  shut down network

  exit
*/

int main(int argc, char **argv)
{
    krb5_error_code     retval;
    krb5_context        kcontext;
    verto_ctx *ctx;
    int errout = 0;
    int i;

    setlocale(LC_MESSAGES, "");
    if (strrchr(argv[0], '/'))
        argv[0] = strrchr(argv[0], '/')+1;

    if (!(kdc_realmlist = (kdc_realm_t **) malloc(sizeof(kdc_realm_t *) *
                                                  KRB5_KDC_MAX_REALMS))) {
        fprintf(stderr, _("%s: cannot get memory for realm list\n"), argv[0]);
        exit(1);
    }
    memset(kdc_realmlist, 0,
           (size_t) (sizeof(kdc_realm_t *) * KRB5_KDC_MAX_REALMS));

    /*
     * A note about Kerberos contexts: This context, "kcontext", is used
     * for the KDC operations, i.e. setup, network connection and error
     * reporting.  The per-realm operations use the "realm_context"
     * associated with each realm.
     */
    retval = krb5int_init_context_kdc(&kcontext);
    if (retval) {
        com_err(argv[0], retval, _("while initializing krb5"));
        exit(1);
    }
    krb5_klog_init(kcontext, "kdc", argv[0], 1);
    kdc_err_context = kcontext;
    kdc_progname = argv[0];
    /* N.B.: After this point, com_err sends output to the KDC log
       file, and not to stderr.  We use the kdc_err wrapper around
       com_err to ensure that the error state exists in the context
       known to the krb5_klog callback. */

    initialize_kdc5_error_table();

    /*
     * Scan through the argument list
     */
    initialize_realms(kcontext, argc, argv);

    ctx = loop_init(VERTO_EV_TYPE_NONE);
    if (!ctx) {
        kdc_err(kcontext, ENOMEM, _("while creating main loop"));
        finish_realms();
        return 1;
    }

    load_preauth_plugins(kcontext);
    load_authdata_plugins(kcontext);

    retval = setup_sam();
    if (retval) {
        kdc_err(kcontext, retval, _("while initializing SAM"));
        finish_realms();
        return 1;
    }

    /* Handle each realm's ports */
    for (i=0; i<kdc_numrealms; i++) {
        char *cp = kdc_realmlist[i]->realm_ports;
        int port;
        while (cp && *cp) {
            if (*cp == ',' || isspace((int) *cp)) {
                cp++;
                continue;
            }
            port = strtol(cp, &cp, 10);
            if (cp == 0)
                break;
            retval = loop_add_udp_port(port);
            if (retval)
                goto net_init_error;
        }

        cp = kdc_realmlist[i]->realm_tcp_ports;
        while (cp && *cp) {
            if (*cp == ',' || isspace((int) *cp)) {
                cp++;
                continue;
            }
            port = strtol(cp, &cp, 10);
            if (cp == 0)
                break;
            retval = loop_add_tcp_port(port);
            if (retval)
                goto net_init_error;
        }
    }

    /*
     * Setup network listeners.  Disallow network reconfig in response to
     * routing socket messages if we're using worker processes, since the
     * children won't be able to re-open the listener sockets.  Hopefully our
     * platform has pktinfo support and doesn't need reconfigs.
     */
    if (workers == 0) {
        retval = loop_setup_routing_socket(ctx, NULL, kdc_progname);
        if (retval) {
            kdc_err(kcontext, retval, _("while initializing routing socket"));
            finish_realms();
            return 1;
        }
        retval = loop_setup_signals(ctx, NULL, reset_for_hangup);
        if (retval) {
            kdc_err(kcontext, retval, _("while initializing signal handlers"));
            finish_realms();
            return 1;
        }
    }
    if ((retval = loop_setup_network(ctx, NULL, kdc_progname))) {
    net_init_error:
        kdc_err(kcontext, retval, _("while initializing network"));
        finish_realms();
        return 1;
    }
    if (!nofork && daemon(0, 0)) {
        kdc_err(kcontext, errno, _("while detaching from tty"));
        finish_realms();
        return 1;
    }
    if (pid_file != NULL) {
        retval = write_pid_file(pid_file);
        if (retval) {
            kdc_err(kcontext, retval, _("while creating PID file"));
            finish_realms();
            return 1;
        }
    }
    if (workers > 0) {
        finish_realms();
        retval = create_workers(ctx, workers);
        if (retval) {
            kdc_err(kcontext, errno, _("creating worker processes"));
            return 1;
        }
        /* We get here only in a worker child process; re-initialize realms. */
        initialize_realms(kcontext, argc, argv);
    }
    krb5_klog_syslog(LOG_INFO, _("commencing operation"));
    if (nofork)
        fprintf(stderr, _("%s: starting...\n"), kdc_progname);

    verto_run(ctx);
    loop_free(ctx);
    krb5_klog_syslog(LOG_INFO, _("shutting down"));
    unload_preauth_plugins(kcontext);
    unload_authdata_plugins(kcontext);
    krb5_klog_close(kdc_context);
    finish_realms();
    if (kdc_realmlist)
        free(kdc_realmlist);
#ifndef NOCACHE
    kdc_free_lookaside(kcontext);
#endif
    krb5_free_context(kcontext);
    return errout;
}

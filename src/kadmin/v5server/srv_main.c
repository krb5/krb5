/*
 * kadmin/v5server/srv_main.c
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
 * srv_main.c
 * Main function of administrative server which speaks new Kerberos V5
 * administrative protocol.
 */

#include <stdio.h>
#include <sys/signal.h>
#include <setjmp.h>
#include "k5-int.h"
#if defined(HAVE_STDARG_H) || defined(_WINDOWS) || defined (_MACINTOSH)
#include <stdarg.h>
#else
#include <varargs.h>
#define VARARGS
#endif
#include "com_err.h"
#include "adm.h"
#include "adm_proto.h"
#include "kadm5_defs.h"

#ifdef	LANGUAGES_SUPPORTED
static const char *usage_format =	"%s: usage is %s [-a aclfile] [-d database] [-m]\n\t[-k menctype] [-l langlist] [-p portnum] [-r realm] [-s stash] [-t timeout] [-n]\n\t[-D dbg] [-M mkeyname] [-T ktabname].\n";
static const char *getopt_string =	"a:d:e:k:l:mnp:r:t:D:M:T:";
#else	/* LANGUAGES_SUPPORTED */
static const char *usage_format =	"%s: usage is %s [-a aclfile] [-d database] [-m]\n\t[-k menctype] [-p portnum] [-r realm] [-s stash] [-t timeout] [-n]\n\t[-D dbg] [-M mkeyname] [-T ktabname].\n";
static const char *getopt_string =	"a:d:e:k:mnp:r:t:D:M:T:";
#endif	/* LANGUAGES_SUPPORTED */
static const char *fval_not_number =	"%s: value (%s) specified for -%c is not numeric.\n";
static const char *extra_params =	"%s extra paramters beginning with %s... \n";
static const char *daemon_err =		"%s: cannot spawn and detach.\n";
static const char *grealm_err =		"%s: cannot get default realm.\n";
static const char *pinit_err = 		"%s: cannot open configuration file %s.\n";
static const char *no_memory_fmt =	"%s: cannot allocate %d bytes for %s.\n";
static const char *begin_op_msg =	"\007%s starting.";
static const char *disp_err_fmt =	"\004dispatch error.";
static const char *happy_exit_fmt =	"\007terminating normally.";
static const char *init_error_fmt =	"%s: cannot initialize %s.\n";
static const char *unh_signal_fmt =	"\007exiting on signal %d.";

static const char *proto_msg =		"protocol module";
static const char *net_msg =		"network";
static const char *output_msg =		"output";
static const char *acl_msg =		"ACLs";
static const char *key_msg =		"key and database";
static const char *server_name_msg =	"Kerberos V5 administrative server";

char *programname = (char *) NULL;
#if	POSIX_SETJMP
static sigjmp_buf	terminal_jmp;
#else	/* POSIX_SETJMP */
static jmp_buf		terminal_jmp;
#endif	/* POSIX_SETJMP */

static void
usage(prog)
    char *prog;
{
    fprintf(stderr, usage_format, prog, prog);
}

/*
 * An unhandled signal just proceeds from the setjmp() in main.
 */
static krb5_sigtype
unhandled_signal(signo)
    int signo;
{
#if	POSIX_SETJMP
    siglongjmp(terminal_jmp, signo);
#else	/* POSIX_SETJMP */
    longjmp(terminal_jmp, signo);
#endif	/* POSIX_SETJMP */
    /* NOTREACHED */
}

#ifdef DEBUG
#ifndef VARARGS
void xprintf(const char *str, ...)
{
#else
void xprintf(va_alist)
  va_dcl
{
  const char *str;
#endif
  va_list pvar;
  FILE* xfd;
  static opened = 0;
  time_t t = time(0);

#ifdef VARARGS
  va_start (pvar);
  str = va_arg (pvar, const char *);
#else
  va_start(pvar, str);
#endif
  xfd = fopen("kadmind5-xprintf.log","a");
  if (!xfd) perror("xfd");
  else {
    if (!opened) {
      opened = 1;
      fprintf(xfd, "starting log pid %d time %s\n", getpid(), ctime(&t));
    }
    vfprintf(xfd,str,pvar);
    fflush(xfd);
    fclose(xfd);
  }
  va_end(pvar);
}
#endif /* DEBUG */

int
main(argc, argv)
    int argc;
    char *argv[];
{
    extern int		optind;
    extern char		*optarg;
    int			option;
    krb5_error_code	error;

    int			key_type = -1;
    int			manual_entry = 0;
    krb5_boolean	mime_enabled = 0;
    int			debug_level = 0;
    int			nofork = 0;
    int			timeout = -1;
    krb5_int32		service_port = -1;
    char		*acl_file = (char *) NULL;
    char		*db_file = (char *) NULL;
    char		*language_list = (char *) NULL;
    char		*db_realm = (char *) NULL;
    char		*master_key_name = (char *) NULL;
    char		*keytab_name = (char *) NULL;
    char		*stash_name = (char *) NULL;
    krb5_deltat		maxlife = -1;
    krb5_deltat		maxrlife = -1;
    krb5_timestamp	def_expiration = 0;
    krb5_flags		def_flags = 0;
    krb5_boolean	exp_valid, flags_valid;
    krb5_realm_params	*rparams;
    krb5_int32		realm_num_keysalts;
    krb5_key_salt_tuple	*realm_keysalts;

    /* Kerberatic contexts */
    krb5_context	kcontext;

    const char		*errmsg;
    int			signal_number;

    /*
     * usage is:
     *	kadmind5	[-a aclfile]		<acl file>
     *			[-d database]		<database file>
     *			[-e enctype]		<encryption type>
     *			[-k masterenctype]	<master key type>
     *			[-l languagelist]	<language list>
     *			[-m]			<manual master key entry>
     *			[-n]			<do not fork/disassociate>
     *			[-p portnumber]		<listen on port>
     *			[-r realmname]		<realm>
     *			[-s stashfile]		<stashfile>
     *			[-t timeout]		<inactivity timeout>
     *			[-D debugmask]		<debug mask>
     *			[-M masterkeyname]	<name of master key>
     *			[-T keytabname]		<key table file>
     */
    error = 0;
    exp_valid = flags_valid = FALSE;
    realm_keysalts = (krb5_key_salt_tuple *) NULL;
    realm_num_keysalts = 0;
    while ((option = getopt(argc, argv, getopt_string)) != EOF) {
	switch (option) {
	case 'a':
	    acl_file = optarg;
	    break;
	case 'd':
	    db_file = optarg;
	    break;
	case 'm':
	    manual_entry++;
	    break;
	case 'k':
	    if (sscanf(optarg, "%d", &key_type) != 1) {
		fprintf(stderr, fval_not_number, argv[0], optarg, 'k');
		error++;
	    }
	    break;
#ifdef	LANGUAGES_SUPPORTED
	case 'l':
	    language_list = optarg;
	    mime_enabled = 1;
	    break;
#endif	/* LANGUAGES_SUPPORTED */
	case 'n':
	    nofork++;
	    break;
	case 'p':
	    if (sscanf(optarg, "%d", &service_port) != 1) {
		fprintf(stderr, fval_not_number, argv[0], optarg, 'p');
		error++;
	    }
	    break;
	case 'r':
	    db_realm = optarg;
	    break;
	case 's':
	    stash_name = optarg;
	    break;
	case 't':
	    if (sscanf(optarg, "%d", &timeout) != 1) {
		fprintf(stderr, fval_not_number, argv[0], optarg, 't');
		error++;
	    }
	    break;
	case 'D':
	    if (sscanf(optarg, "%d", &debug_level) != 1) {
		fprintf(stderr, fval_not_number, argv[0], optarg, 'D');
		error++;
	    }
	    break;
	case 'M':
	    master_key_name = optarg;
	    break;
	case 'T':
	    keytab_name = optarg;
	    break;
	default:
	    error++;
	    break;
	}
    }
    if (optind - argc > 0) {
	fprintf(stderr, extra_params, argv[0], argv[optind+1]);
	error++;
    }
    if (error) {
	usage(argv[0]);
	return(1);
    }

#ifndef	DEBUG
    /*
     * If we're not debugging and we didn't specify -n, then detach from our
     * controlling terminal and exit.
     */
    if (!nofork && daemon(0, (manual_entry != 0))) {
	fprintf(stderr, daemon_err, argv[0]);
	perror(argv[0]);
	return(2);
    }
#endif	/* DEBUG */

    /*
     * We've come this far.  Our arguments are good.
     */
#ifndef	DEBUG
    programname = (char *) strrchr(argv[0], '/');
    if (programname)
	programname++;
    else
	programname = argv[0];
#else	/* DEBUG */
    programname = argv[0];
#endif	/* DEBUG */
    krb5_init_context(&kcontext);
    krb5_init_ets(kcontext);
    krb5_klog_init(kcontext, "admin_server", programname, 1);
    if (db_realm) {
	if ((error = krb5_set_default_realm(kcontext, db_realm))) {
	    com_err(programname, error, "while setting default realm name");
	    return(1);
        }
    }
    
    /*
     * Attempt to read the KDC profile.  If we do, then read appropriate values
     * from it and supercede values supplied on the command line.
     */
    if (!(error = krb5_read_realm_params(kcontext,
					 db_realm,
					 (char *) NULL,
					 (char *) NULL,
					 &rparams))) {
	/* Get the value for the database */
	if (rparams->realm_dbname)
	    db_file = strdup(rparams->realm_dbname);

	/* Get the value for the master key name */
	if (rparams->realm_mkey_name)
	    master_key_name = strdup(rparams->realm_mkey_name);

	/* Get the value for the master key type */
	if (rparams->realm_enctype_valid)
	    key_type = rparams->realm_enctype;

	/* Get the value for the port */
	if (rparams->realm_kadmind_port_valid)
	    service_port = rparams->realm_kadmind_port;

	/* Get the value for the stashfile */
	if (rparams->realm_stash_file)
	    stash_name = strdup(rparams->realm_stash_file);

	/* Get the value for maximum ticket lifetime. */
	if (rparams->realm_max_life_valid)
	    maxlife = rparams->realm_max_life;

	/* Get the value for maximum renewable ticket lifetime. */
	if (rparams->realm_max_rlife_valid)
	    maxrlife = rparams->realm_max_rlife;

	/* Get the value for the default principal expiration */
	if (rparams->realm_expiration_valid) {
	    def_expiration = rparams->realm_expiration;
	    exp_valid = TRUE;
	}

	/* Get the value for the default principal flags */
	if (rparams->realm_flags_valid) {
	    def_flags = rparams->realm_flags;
	    flags_valid = TRUE;
	}

	/* Clone the value of the keysalt array */
	if (realm_num_keysalts = rparams->realm_num_keysalts) {
	    if (realm_keysalts =
		(krb5_key_salt_tuple *) malloc(realm_num_keysalts *
					       sizeof(krb5_key_salt_tuple))) {
		memcpy(realm_keysalts, rparams->realm_keysalts,
		       (realm_num_keysalts * sizeof(krb5_key_salt_tuple)));
	    }
	    else
		realm_num_keysalts = 0;
	}

	krb5_free_realm_params(kcontext, rparams);
    }

    if ((signal_number =
#if	POSIX_SETJMP
	 sigsetjmp(terminal_jmp, 1)
#else	/* POSIX_SETJMP */
	 setjmp(terminal_jmp)
#endif	/* POSIX_SETJMP */
	 ) == 0) {
#if	POSIX_SIGNALS
	struct sigaction s_action;
#endif	/* POSIX_SIGNALS */

	/*
	 * Initialize signal handling.
	 */
#if	POSIX_SIGNALS
	(void) sigemptyset(&s_action.sa_mask);
	s_action.sa_flags = 0;
	s_action.sa_handler = unhandled_signal;
	(void) sigaction(SIGINT, &s_action, (struct sigaction *) NULL);
	(void) sigaction(SIGTERM, &s_action, (struct sigaction *) NULL);
	(void) sigaction(SIGHUP, &s_action, (struct sigaction *) NULL);
	(void) sigaction(SIGQUIT, &s_action, (struct sigaction *) NULL);
	(void) sigaction(SIGPIPE, &s_action, (struct sigaction *) NULL);
	(void) sigaction(SIGALRM, &s_action, (struct sigaction *) NULL);
	(void) sigaction(SIGCHLD, &s_action, (struct sigaction *) NULL);
#else	/* POSIX_SIGNALS */
	signal(SIGINT, unhandled_signal);
	signal(SIGTERM, unhandled_signal);
	signal(SIGHUP, unhandled_signal);
	signal(SIGQUIT, unhandled_signal);
	signal(SIGPIPE, unhandled_signal);
	signal(SIGALRM, unhandled_signal);
	signal(SIGCHLD, unhandled_signal);
#endif	/* POSIX_SIGNALS */

	/*
	 * Initialize our modules.
	 */
	error = key_init(kcontext,
			 debug_level,
			 key_type,
			 master_key_name,
			 manual_entry,
			 db_file,
			 db_realm,
			 keytab_name,
			 stash_name, 
			 realm_num_keysalts,
			 realm_keysalts);
	if (!error) {
	    error = acl_init(kcontext, debug_level, acl_file);
	    if (!error) {
		error = output_init(kcontext, debug_level,
				    language_list, mime_enabled);
		if (!error) {
		    error = net_init(kcontext, debug_level, service_port);
		    if (!error) {
			error = proto_init(kcontext, debug_level, timeout);
			admin_init(maxlife,
				   maxrlife,
				   exp_valid,
				   def_expiration,
				   flags_valid,
				   def_flags);
			if (error)
			    errmsg = proto_msg;
		    }
		    else
			errmsg = net_msg;
		}
		else
		    errmsg = output_msg;
	    }
	    else
		errmsg = acl_msg;
	}
	else
	    errmsg = key_msg;

	if (!error) {
	    /*
	     * We've successfully initialized here.
	     */
	    com_err(programname, 0, begin_op_msg, server_name_msg);

	    /*
	     * net_dispatch() only returns when we're done for some reason.
	     */
	    error = net_dispatch(kcontext, !nofork);

	    com_err(programname, error,
		    ((error) ? disp_err_fmt : happy_exit_fmt));
	}
	else {
	    /* Initialization error */
	    fprintf(stderr, init_error_fmt, programname, errmsg);
	}
    }
    else {
	/* Received an unhandled signal */
#ifndef DEBUG
	com_err(programname, 0, unh_signal_fmt, signal_number);
#endif
    }

    /* Now clean up after ourselves */
    proto_finish(kcontext, debug_level);
    net_finish(kcontext, debug_level);
    output_finish(kcontext, debug_level);
    acl_finish(kcontext, debug_level);
    key_finish(kcontext, debug_level);
    krb5_klog_close(kcontext);
    krb5_xfree(kcontext);
    exit(error);
}

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
#include <syslog.h>
#include <setjmp.h>
#include "k5-int.h"
#include "com_err.h"
#if	HAVE_STDARG_H
#include <stdarg.h>
#else	/* HAVE_STDARG_H */
#include <varargs.h>
#endif	/* HAVE_STDARG_H */

#define	KADM_MAX_ERRMSG_SIZE	1024
#ifndef	LOG_AUTH
#define	LOG_AUTH	0
#endif	/* LOG_AUTH */

#ifdef	LANGUAGES_SUPPORTED
static const char *usage_format =	"%s: usage is %s [-a aclfile] [-d database] [-e enctype] [-i]\n\t[-k mkeytype] [-l langlist] [-r realm] [-t timeout]\n\t[-D dbg] [-M mkeyname].\n";
static const char *getopt_string =	"a:d:e:ik:l:r:t:D:M:";
#else	/* LANGUAGES_SUPPORTED */
static const char *usage_format =	"%s: usage is %s [-a aclfile] [-d database] [-e enctype] [-i]\n\t[-k mkeytype] [-r realm] [-t timeout]\n\t[-D dbg] [-M mkeyname].\n";
static const char *getopt_string =	"a:d:e:ik:r:t:D:M:";
#endif	/* LANGUAGES_SUPPORTED */
static const char *fval_not_number =	"%s: value (%s) specified for -%c is not numeric.\n";
static const char *extra_params =	"%s extra paramters beginning with %s... \n";
static const char *no_memory_fmt =	"%s: cannot allocate %d bytes for %s.\n";
static const char *begin_op_msg =	"%s starting.";
static const char *disp_err_fmt =	"dispatch error.";
static const char *happy_exit_fmt =	"terminating normally.";
static const char *init_error_fmt =	"%s: cannot initialize %s.\n";
static const char *unh_signal_fmt =	"exiting on signal %d.";

static const char *messages_msg =	"messages";
static const char *proto_msg =		"protocol module";
static const char *net_msg =		"network";
static const char *output_msg =		"output";
static const char *acl_msg =		"ACLs";
static const char *key_msg =		"key and database";
static const char *server_name_msg =	"Kerberos V5 administrative server";

char *programname = (char *) NULL;
static jmp_buf	terminal_jmp;

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
    longjmp(terminal_jmp, signo);
    /* NOTREACHED */
}

static void
kadm_com_err_proc(whoami, code, format, ap)
    const char	*whoami;
    long	code;
    const char	*format;
    va_list	ap;
{
    char *outbuf;

    outbuf = (char *) malloc(KADM_MAX_ERRMSG_SIZE);
    if (outbuf) {
	char *cp;
	sprintf(outbuf, "%s: ", whoami);
	if (code) {
	    strcat(outbuf, error_message(code));
	    strcat(outbuf, " - ");
	}
	cp = &outbuf[strlen(outbuf)];
#if	HAVE_VSPRINTF
	vsprintf(cp, format, ap);
#else	/* HAVE_VSPRINTF */
	sprintf(cp, format, ((int *) ap)[0], ((int *) ap)[1],
		((int *) ap)[2], ((int *) ap)[3],
		((int *) ap)[4], ((int *) ap)[5]);
#endif	/* HAVE_VSPRINTF */
#ifndef	DEBUG
	syslog(LOG_AUTH|LOG_ERR, outbuf);
#endif	/* DEBUG */
	strcat(outbuf, "\n");
	fprintf(stderr, outbuf);
	free(outbuf);
    }
    else {
	fprintf(stderr, no_memory_fmt, programname,
		KADM_MAX_ERRMSG_SIZE, messages_msg);
    }
}

int
main(argc, argv)
    int argc;
    char *argv[];
{
    extern int		optind;
    extern char		*optarg;
    int			option;
    krb5_error_code	error;

    int			enc_type = -1;
    int			key_type = -1;
    int			manual_entry = 0;
    krb5_boolean	mime_enabled = 0;
    int			debug_level = 0;
    int			timeout = -1;
    char		*acl_file = (char *) NULL;
    char		*db_file = (char *) NULL;
    char		*language_list = (char *) NULL;
    char		*db_realm = (char *) NULL;
    char		*master_key_name = (char *) NULL;

    /* Kerberatic contexts */
    krb5_context	kcontext;

    const char		*errmsg;
    int			signal_number;

    /*
     * usage is:
     *	kadmind5	[-a aclfile]
     *			[-d database]
     *			[-e enctype]
     *			[-i]
     *			[-k masterkeytype]
     *			[-l languagelist]
     *			[-m yesno]
     *			[-r realmname]
     *			[-t timeout]
     *			[-D debuglevel]
     *			[-M masterkeyname]
     */
    error = 0;
    while ((option = getopt(argc, argv, getopt_string)) != EOF) {
	switch (option) {
	case 'a':
	    acl_file = optarg;
	    break;
	case 'd':
	    db_file = optarg;
	    break;
	case 'e':
	    if (sscanf(optarg, "%d", &enc_type) != 1) {
		fprintf(stderr, fval_not_number, argv[0], optarg, 'e');
		error++;
	    }
	    break;
	case 'i':
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
	case 'r':
	    db_realm = optarg;
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
    openlog(programname, LOG_AUTH|LOG_CONS|LOG_NDELAY|LOG_PID, LOG_LOCAL6);
    (void) set_com_err_hook(kadm_com_err_proc);

    if ((signal_number = setjmp(terminal_jmp)) == 0) {
	/*
	 * Initialize signal handling.
	 */
	signal(SIGINT, unhandled_signal);
	signal(SIGTERM, unhandled_signal);
	signal(SIGHUP, unhandled_signal);
	signal(SIGQUIT, unhandled_signal);
	signal(SIGPIPE, unhandled_signal);
	signal(SIGALRM, unhandled_signal);
	signal(SIGCHLD, unhandled_signal);

	/*
	 * Initialize our modules.
	 */
	error = key_init(kcontext, debug_level, enc_type, key_type,
			 master_key_name, manual_entry, db_file, db_realm);
	if (!error) {
	    error = acl_init(kcontext, debug_level, acl_file);
	    if (!error) {
		error = output_init(kcontext, debug_level,
				    language_list, mime_enabled);
		if (!error) {
		    error = net_init(kcontext,
				     debug_level);
		    if (!error) {
			error = proto_init(kcontext, debug_level, timeout);

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
#ifndef	DEBUG
	    syslog(LOG_AUTH|LOG_INFO, begin_op_msg, server_name_msg);
#endif	/* DEBUG */

	    /*
	     * net_dispatch() only returns when we're done for some reason.
	     */
	    error = net_dispatch(kcontext);

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
	com_err(programname, 0, unh_signal_fmt, signal_number);
    }

    /* Now clean up after ourselves */
    proto_finish(kcontext, debug_level);
    net_finish(kcontext, debug_level);
    output_finish(kcontext, debug_level);
    acl_finish(kcontext, debug_level);
    key_finish(kcontext, debug_level);
    krb5_xfree(kcontext);
    return(error);
}

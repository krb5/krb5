/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Main procedure body for the KDC server process.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_main_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <stdio.h>
#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include <sys/syslog.h>
#include <signal.h>
#include <errno.h>

#include <com_err.h>

#include <krb5/krb5.h>
#include <krb5/osconf.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>
#include <krb5/krb5_err.h>
#include <krb5/isode_err.h>
#include <krb5/kdb5_err.h>
#include <krb5/libos-proto.h>
#include <krb5/ext-proto.h>

#include <krb5/config.h>
#ifdef PROVIDE_DES_CBC_CRC
#include <krb5/des.h>
#endif

#include "kdc_util.h"
#include "extern.h"
#include "kdc5_err.h"

static void
kdc_com_err_proc(whoami, code, format, pvar)
	const char *whoami;
	long code;
	const char *format;
	va_list pvar;
{
    /* XXX need some way to do this better... */

    extern int vfprintf PROTOTYPE((FILE *, const char *, va_list));

    if (whoami) {
        fputs(whoami, stderr);
        fputs(": ", stderr);
    }
    if (code) {
        fputs(error_message(code), stderr);
        fputs(" ", stderr);
    }
    if (format) {
        vfprintf (stderr, format, pvar);
    }
    putc('\n', stderr);
    /* should do this only on a tty in raw mode */
    putc('\r', stderr);
    fflush(stderr);
    if (format) {
	/* now need to frob the format a bit... */
	if (code) {
	    char *nfmt;
	    nfmt = malloc(strlen(format)+strlen(error_message(code))+2);
	    strcpy(nfmt, error_message(code));
	    strcat(nfmt, " ");
	    strcat(nfmt, format);
	    vsyslog(LOG_ERR, nfmt, pvar);
	} else
	    vsyslog(LOG_ERR, format, pvar);
    } else {
	if (code)
	    syslog(LOG_ERR, "%s", error_message(code));
    }

    return;
}

void
setup_com_err()
{
    initialize_krb5_error_table();
    initialize_kdb5_error_table();
    initialize_kdc5_error_table();
    initialize_isod_error_table();

    (void) set_com_err_hook(kdc_com_err_proc);
    return;
}

sigtype
request_exit()
{
    signal_requests_exit = 1;

    return;
}

void
setup_signal_handlers()
{
    signal(SIGINT, request_exit);
    signal(SIGHUP, request_exit);
    signal(SIGTERM, request_exit);

    return;
}

void
usage(name)
char *name;
{
    fprintf(stderr, "usage: %s [-d dbpathname] [-r dbrealmname] [-R replaycachename ]\n\t[-m] [-k masterkeytype] [-M masterkeyname]\n", name);
    return;
}

void
process_args(argc, argv)
int argc;
char **argv;
{
    int c;
    krb5_boolean manual = FALSE;
    int keytypedone = 0;
    char *db_realm = 0;
    char *mkey_name = 0;
    char *rcname = 0;
    char lrealm[BUFSIZ];
    krb5_error_code retval;
    krb5_enctype etype;

    extern char *optarg;
    extern krb5_deltat krb5_clockskew;

    while ((c = getopt(argc, argv, "r:d:mM:k:R:")) != EOF) {
	switch(c) {
	case 'r':			/* realm name for db */
	    db_realm = optarg;
	    break;
	case 'd':			/* pathname for db */
	    dbm_db_name = optarg;
	    break;
	case 'm':			/* manual type-in of master key */
	    manual = TRUE;
	    break;
	case 'M':			/* master key name in DB */
	    mkey_name = optarg;
	    break;
	case 'k':			/* keytype for master key */
	    master_keyblock.keytype = atoi(optarg);
	    keytypedone++;
	    break;
	case 'R':
	    rcname = optarg;
	    break;
	case '?':
	default:
	    usage(argv[0]);
	    exit(1);
	}
    }
    if (!db_realm) {
	/* no realm specified, use default realm */
	if (retval = krb5_get_default_realm(sizeof(lrealm), lrealm)) {
	    com_err(argv[0], retval,
		    "while attempting to retrieve default realm");
	    exit(1);
	}
	db_realm = lrealm;
    }

    if (!mkey_name)
	mkey_name = KRB5_KDB_M_NAME;

    if (!keytypedone)
	master_keyblock.keytype = KEYTYPE_DES;

    if (!rcname)
	rcname = KDCRCACHE;
    if (retval = krb5_rc_resolve_full(&kdc_rcache, rcname)) {
	com_err(argv[0], retval, "while resolving replay cache '%s'", rcname);
	exit(1);
    }
    if ((retval = krb5_rc_recover(kdc_rcache)) &&
	(retval = krb5_rc_initialize(kdc_rcache, krb5_clockskew))) {
	com_err(argv[0], retval, "while initializing replay cache '%s:%s'",
		kdc_rcache->ops->type,
		krb5_rc_get_name(kdc_rcache));
	exit(1);
    }
    if ((retval = krb5_rc_expunge(kdc_rcache))) {
	com_err(argv[0], retval, "while expunging replay cache '%s:%s'",
		kdc_rcache->ops->type,
		krb5_rc_get_name(kdc_rcache));
	exit(1);
    }
    /* assemble & parse the master key name */

    if (retval = krb5_db_setup_mkey_name(mkey_name, db_realm, (char **) 0,
					 &master_princ)) {
	com_err(argv[0], retval, "while setting up master key name");
	(void) krb5_rc_close(kdc_rcache);
	exit(1);
    }

#ifdef PROVIDE_DES_CBC_CRC
    master_encblock.crypto_entry = &mit_des_cryptosystem_entry;
#else
error(You gotta figure out what cryptosystem to use in the KDC);
#endif

    if (retval = krb5_db_fetch_mkey(master_princ, &master_encblock, manual,
				    FALSE, /* only read it once, if at all */
				    &master_keyblock)) {
	com_err(argv[0], retval, "while fetching master key");
	(void) krb5_rc_close(kdc_rcache);
	exit(1);
    }
    /* initialize random key generators */
    for (etype = 0; etype <= krb5_max_cryptosystem; etype++) {
	if (krb5_csarray[etype]) {
	    if (retval = (*krb5_csarray[etype]->system->
			  init_random_key)(&master_keyblock,
					   &krb5_csarray[etype]->random_sequence)) {
		com_err(argv[0], retval, "while setting up random key generator for etype %d--etype disabled", etype);
		krb5_csarray[etype] = 0;
	    }
	}
    }

    return;
}

void
finish_args(prog)
char *prog;
{
    krb5_error_code retval;
    if (retval = krb5_rc_close(kdc_rcache)) {
	com_err(prog, retval, "while closing replay cache '%s:%s'",
		kdc_rcache->ops->type,
		krb5_rc_get_name(kdc_rcache));
    }
    return;
}


krb5_error_code
init_db(dbname, masterkeyname, masterkeyblock)
char *dbname;
krb5_principal masterkeyname;
krb5_keyblock *masterkeyblock;
{
    krb5_error_code retval;

    /* set db name if appropriate */
    if (dbname && (retval = krb5_db_set_name(dbname)))
	return(retval);

    /* initialize database */
    if (retval = krb5_db_init())
	return(retval);

    if (retval = krb5_db_verify_master_key(masterkeyname, masterkeyblock,
					   &master_encblock)) {
	master_encblock.crypto_entry = 0;
	return(retval);
    }

    /* do any necessary key pre-processing */
    if (retval = (*master_encblock.crypto_entry->
		  process_key)(&master_encblock, masterkeyblock)) {
	master_encblock.crypto_entry = 0;
	(void) krb5_db_fini();
	return(retval);
    }

    return 0;
}

krb5_error_code
closedown_db()
{
    krb5_error_code retval;

    /* clean up master key stuff */
    retval = (*master_encblock.crypto_entry->finish_key)(&master_encblock);

    bzero((char *)&master_encblock, sizeof(master_encblock));

    /* close database */
    if (retval) {
	(void) krb5_db_fini();
	return retval;
    } else
	return (krb5_db_fini());
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

/* This void is a bit bogus, but it's necessary to prevent some compilers from
   complaining about a no-value return path from a non-void function. */
void
main(argc, argv)
int argc;
char *argv[];
{
    krb5_error_code retval;
    int errout = 0;

    if (rindex(argv[0], '/'))
	argv[0] = rindex(argv[0], '/')+1;

    setup_com_err();

    openlog(argv[0], LOG_CONS|LOG_NDELAY|LOG_PID, LOG_LOCAL6); /* XXX */

    process_args(argc, argv);		/* includes reading master key */

    setup_signal_handlers();

    if (retval = init_db(dbm_db_name, master_princ, &master_keyblock)) {
	com_err(argv[0], retval, "while initializing database");
	finish_args(argv[0]);
	exit(1);
    }
    if (retval = setup_network(argv[0])) {
	com_err(argv[0], retval, "while initializing network");
	finish_args(argv[0]);
	exit(1);
    }
    syslog(LOG_INFO, "commencing operation");
    if (retval = listen_and_process(argv[0])){
	com_err(argv[0], retval, "while processing network requests");
	errout++;
    }
    if (retval = closedown_network(argv[0])) {
	com_err(argv[0], retval, "while shutting down network");
	errout++;
    }
    if (retval = closedown_db()) {
	com_err(argv[0], retval, "while closing database");
	errout++;
    }
    syslog(LOG_INFO, "shutting down");
    finish_args(argv[0]);
    exit(errout);
}


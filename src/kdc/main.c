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
#include <syslog.h>
#ifdef notdef
#include <varargs.h>			/* XXX ansi? */
#endif
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
#include "../admin/common.h"

#ifdef notdef
/* need to sort out varargs stuff */
static void
kdc_com_err_proc(whoami, code, format, va_alist)
char *whoami;
long code;
char *format;
va_dcl
{
    /* XXX need some way to do this better... */

    if (whoami) {
        fputs(whoami, stderr);
        fputs(": ", stderr);
    }
    if (code) {
        fputs(error_message(code), stderr);
        fputs(" ", stderr);
    }
    if (format) {
        fprintf (stderr, format, va_alist);
    }
    putc('\n', stderr);
    /* should do this only on a tty in raw mode */
    putc('\r', stderr);
    fflush(stderr);

    syslog(LOG_ERR, format, va_alist);

    return;
}
#endif

void
setup_com_err()
{
    initialize_krb5_error_table();
    initialize_kdb5_error_table();
    initialize_isod_error_table();

#ifdef notdef
    (void) set_com_err_hook(kdc_com_err_proc);
#endif
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
    fprintf(stderr, "usage: %s [-d dbpathname] [-r dbrealmname] [-m] [-k masterkeytype] [-M masterkeyname]\n", name);
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
    char lrealm[BUFSIZ];
    krb5_error_code retval;

    extern char *optarg;

    while ((c = getopt(argc, argv, "r:d:mM:k:")) != EOF) {
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

    /* assemble & parse the master key name */

    if (retval = krb5_db_setup_mkey_name(mkey_name, db_realm, &master_princ)) {
	com_err(argv[0], retval, "while setting up master key name");
	exit(1);
    }

#ifdef PROVIDE_DES_CBC_CRC
    master_encblock.crypto_entry = &mit_des_cryptosystem_entry;
#else
#error You gotta figure out what cryptosystem to use in the KDC.
#endif

    if (retval = krb5_db_fetch_mkey(master_princ, &master_encblock, manual,
				    &master_keyblock)) {
	com_err(argv[0], retval, "while fetching master key");
	exit(1);
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

    if (rindex(argv[0], '/'))
	argv[0] = rindex(argv[0], '/')+1;

    setup_com_err();

    process_args(argc, argv);		/* includes reading master key */

    setup_signal_handlers();

    openlog(argv[0], LOG_CONS|LOG_NDELAY, LOG_LOCAL0); /* XXX */
    syslog(LOG_INFO, "commencing operation");

    if (retval = init_db(dbm_db_name, master_princ, &master_keyblock)) {
	com_err(argv[0], retval, "cannot initialize database");
	exit(1);
    }
    setup_network();			/* XXX */
    listen_and_process();		/* XXX */
    closedown_network();		/* XXX */

    closedown_db();
    exit(0);
}


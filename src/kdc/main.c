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
#include <varargs.h>			/* XXX ansi? */
#include <com_err.h>

#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>
#include <krb5/krb5_err.h>
#include <krb5/isode_err.h>
#include <krb5/kdb5_err.h>
#include "kdc_util.h"
#include "extern.h"

char *dbm_db_name = DEFAULT_DBM_FILE;

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

void
setup_com_err()
{
    initialize_krb5_error_table();
    initialize_kdb5_error_table();
    initialize_isod_error_table();

    (void) set_com_err_hook(kdc_com_err_proc);
    return;
}

void
setup_signal_handlers()
{

    return;
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

main(argc, argv)
int argc;
char **argv;
{
    krb5_error_code retval;

    process_args(argc, argv);		/* includes reading master key */

    setup_com_err();

    setup_signal_handlers();

    openlog(argv[0], LOG_CONS|LOG_NDELAY, LOG_LOCAL0); /* XXX */
    syslog(LOG_INFO, "commencing operation");

    if (retval = init_db(dbm_db_name, master_princ, master_keyblock)) {
	com_err(argv[0], retval, "cannot initialize database");
	exit(1);
    }
    setup_network();			/* XXX */
    listen_and_process();		/* XXX */
    closedown_network();		/* XXX */

    closedown_db();
    exit(0);
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

    master_encblock.crypto_entry = &krb5_des_cs_entry; /* XXX */

    if (retval = krb5_db_verify_master_key(masterkeyname, masterkeyblock,
					   &master_encblock)) {
	master_encblock.crypto_entry = 0;
	return(retval);
    }

    /* do any necessary key pre-processing */
    if (retval = (*master_encblock.crypto_entry->
		  process_key)(&master_encblock, masterkeyblock)) {
	master_encblock.crypto_entry = 0;
	return(retval);
    }

    return 0;
}

krb5_error_code
closedown_db()
{
    krb5_error_code retval;

    /* clean up master key stuff */
    if (retval = (*master_encblock.crypto_entry->finish_key)(&master_encblock))
	return retval;
    bzero(&master_encblock, sizeof(master_encblock));

    /* close database */
    if (retval = krb5_db_fini())
	return(retval);

    return 0;
}

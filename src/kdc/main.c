/*
 * kdc/main.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 *
 * Main procedure body for the KDC server process.
 */


#include <stdio.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include <com_err.h>
/* for STDC, com_err gets varargs/stdarg */
#ifndef __STDC__
#include <varargs.h>
#endif

#include <krb5/krb5.h>
#include <krb5/osconf.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>
#include <krb5/los-proto.h>
#include <krb5/ext-proto.h>

#include <krb5/config.h>
#ifdef PROVIDE_DES_CBC_CRC
#include <krb5/mit-des.h>
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

#ifndef __STDC__
    extern int vfprintf();
#endif

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
    krb5_init_ets();
    initialize_kdb5_error_table();
    (void) set_com_err_hook(kdc_com_err_proc);
    return;
}

krb5_sigtype
request_exit()
{
    signal_requests_exit = 1;

#ifdef POSIX_SIGTYPE
    return;
#else
    return(0);
#endif
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
    char *lrealm;
    krb5_error_code retval, retval2;
    krb5_enctype kdc_etype = DEFAULT_KDC_ETYPE;
    krb5_enctype etype;
    extern krb5_deltat krb5_clockskew;

    extern char *optarg;

    while ((c = getopt(argc, argv, "r:d:mM:k:R:e:")) != EOF) {
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
	case 'e':
	    kdc_etype = atoi(optarg);
	    break;
	case '?':
	default:
	    usage(argv[0]);
	    exit(1);
	}
    }
    if (!db_realm) {
	/* no realm specified, use default realm */
	if (retval = krb5_get_default_realm(&lrealm)) {
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
	(retval2 = krb5_rc_initialize(kdc_rcache, krb5_clockskew))) {
	com_err(argv[0], retval, "while recovering replay cache '%s:%s'",
		kdc_rcache->ops->type,
		krb5_rc_get_name(kdc_rcache));
	com_err(argv[0], retval2, "while initializing replay cache '%s:%s'",
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

    if (!valid_etype(kdc_etype)) {
	com_err(argv[0], KRB5_PROG_ETYPE_NOSUPP,
		"while setting up etype %d", kdc_etype);
	exit(1);
    }
    krb5_use_cstype(&master_encblock, kdc_etype);

    if (retval = krb5_db_fetch_mkey(master_princ, &master_encblock, manual,
				    FALSE, /* only read it once, if at all */
				    0, &master_keyblock)) {
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
    char	*rtype, *rname;
    krb5_error_code retval;
    
    if (kdc_rcache) {
	    if (kdc_rcache->ops && kdc_rcache->ops->type)
		    rtype = strdup(kdc_rcache->ops->type);
	    else
		    rtype = strdup("Unknown_rcache_type");
	    rname = strdup(krb5_rc_get_name(kdc_rcache));
	    if (retval = krb5_rc_close(kdc_rcache)) {
		    com_err(prog, retval, "while closing replay cache '%s:%s'",
			    rtype, rname);
	    }
	    free(rtype);
	    free(rname);
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
    int nprincs;
    krb5_boolean more;
    krb5_db_entry server;
#ifdef KRB4
    extern unsigned char master_key_version;
#endif

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

#ifdef KRB4    
    /* get the master key, to extract the master key version number */
    nprincs = 1;
    if (retval = krb5_db_get_principal(masterkeyname,
				       &server, &nprincs,
				       &more)) {
	return(retval);
    }
    if (nprincs != 1) {
	if (nprincs)
	    krb5_db_free_principal(&server, nprincs);
	return(KRB5_KDB_NOMASTERKEY);
    } else if (more) {
	krb5_db_free_principal(&server, nprincs);
	return(KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE);
    }
    master_key_version = server.kvno;
    krb5_db_free_principal(&server, nprincs);
#endif
    
    /* do any necessary key pre-processing */
    if (retval = krb5_process_key(&master_encblock, masterkeyblock)) {
	master_encblock.crypto_entry = 0;
	(void) krb5_db_fini();
	return(retval);
    }

    /* fetch the TGS key, and hold onto it; this is an efficiency hack */

    /* the master key name here is from the master_princ global,
       so we can safely share its substructure */

    krb5_princ_set_realm(tgs_server, krb5_princ_realm(masterkeyname));
    /* tgs_server[0] is init data */
    *krb5_princ_component(tgs_server, 1) = *krb5_princ_realm(masterkeyname);

    nprincs = 1;
    if (retval = krb5_db_get_principal(tgs_server,
				       &server, &nprincs,
				       &more)) {
	return(retval);
    }
    if (more) {
	krb5_db_free_principal(&server, nprincs);
	(void) krb5_finish_key(&master_encblock);
	memset((char *)&master_encblock, 0, sizeof(master_encblock));
	(void) krb5_db_fini();
	return(KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE);
    } else if (nprincs != 1) {
	krb5_db_free_principal(&server, nprincs);
	(void) krb5_finish_key(&master_encblock);
	memset((char *)&master_encblock, 0, sizeof(master_encblock));
	(void) krb5_db_fini();
	return(KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }
    /* convert server.key into a real key (it may be encrypted
       in the database) */
    if (retval = KDB_CONVERT_KEY_OUTOF_DB(&server.key, &tgs_key)) {
	krb5_db_free_principal(&server, nprincs);
	(void) krb5_finish_key(&master_encblock);
	memset((char *)&master_encblock, 0, sizeof(master_encblock));
	(void) krb5_db_fini();
	return retval;
    }
    tgs_kvno = server.kvno;
    krb5_db_free_principal(&server, nprincs);
    return 0;
}

krb5_error_code
closedown_db()
{
    krb5_error_code retval;

    /* clean up master key stuff */
    retval = krb5_finish_key(&master_encblock);

    memset((char *)&master_encblock, 0, sizeof(master_encblock));

    memset((char *)tgs_key.contents, 0, tgs_key.length);

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

main(argc, argv)
int argc;
char *argv[];
{
    krb5_error_code retval;
    int errout = 0;

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    setup_com_err();

    openlog(argv[0], LOG_CONS|LOG_NDELAY|LOG_PID, LOG_LOCAL6); /* XXX */

    process_args(argc, argv);		/* includes reading master key */

    setup_signal_handlers();

    if (retval = init_db(dbm_db_name, master_princ, &master_keyblock)) {
	com_err(argv[0], retval, "while initializing database");
	finish_args(argv[0]);
	return 1;
    }
    if (retval = setup_network(argv[0])) {
	com_err(argv[0], retval, "while initializing network");
	finish_args(argv[0]);
	return 1;
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
    return errout;
}


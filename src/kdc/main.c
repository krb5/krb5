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

#include "com_err.h"
#include "k5-int.h"
#include "kdc_util.h"
#include "extern.h"
#include "kdc5_err.h"
#include "adm_proto.h"

kdc_realm_t *find_realm_data PROTOTYPE((char *, krb5_ui_4));

krb5_error_code setup_server_realm PROTOTYPE((krb5_principal));

void usage PROTOTYPE((char *));

krb5_sigtype request_exit PROTOTYPE((int));

void setup_signal_handlers PROTOTYPE((void));

void initialize_realms PROTOTYPE((krb5_context, krb5_pointer, int, char **));

void finish_realms PROTOTYPE((char *));

static int nofork = 0;
static char *kdc_current_rcname = (char *) NULL;
static int rkey_init_done = 0;

#define	KRB5_KDC_MAX_REALMS	32

/*
 * initialize the replay cache.
 */
krb5_error_code
kdc_initialize_rcache(kcontext, rcache_name)
    krb5_context	kcontext;
    char 		*rcache_name;
{
    krb5_error_code	retval;
    extern krb5_deltat krb5_clockskew;
    char		*rcname;
    char		*sname;

    rcname = (rcache_name) ? rcache_name : kdc_current_rcname;
    if (!rcname)
	rcname = KDCRCACHE;
    if (!(retval = krb5_rc_resolve_full(kcontext, &kdc_rcache, rcname))) {
	/* Recover or initialize the replay cache */
	if (!(retval = krb5_rc_recover(kcontext, kdc_rcache)) ||
	    !(retval = krb5_rc_initialize(kcontext,
					  kdc_rcache,
					  krb5_clockskew))
	    ) {
	    /* Expunge the replay cache */
	    if (!(retval = krb5_rc_expunge(kcontext, kdc_rcache))) {
		sname = kdc_current_rcname;
		kdc_current_rcname = strdup(rcname);
		if (sname)
		    free(sname);
	    }
	}
	if (retval)
	    krb5_rc_close(kcontext, kdc_rcache);
    }
    return(retval);
}

/*
 * Find the realm entry for a given realm.
 */
kdc_realm_t *
find_realm_data(rname, rsize)
    char 	*rname;
    krb5_ui_4	rsize;
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
setup_server_realm(sprinc)
    krb5_principal	sprinc;
{
    krb5_error_code	kret;
    kdc_realm_t		*newrealm;

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
finish_realm(rdp)
    kdc_realm_t *rdp;
{
    if (rdp->realm_dbname)
	free(rdp->realm_dbname);
    if (rdp->realm_mpname)
	free(rdp->realm_mpname);
    if (rdp->realm_stash)
	free(rdp->realm_stash);
    if (rdp->realm_context) {
	if (rdp->realm_mprinc)
	    krb5_free_principal(rdp->realm_context, rdp->realm_mprinc);
	if (rdp->realm_mkey.length && rdp->realm_mkey.contents)
	    krb5_free_keyblock(rdp->realm_context, &rdp->realm_mkey);
	krb5_db_fini(rdp->realm_context);
	if (rdp->realm_tgsprinc)
	    krb5_free_principal(rdp->realm_context, rdp->realm_tgsprinc);
	krb5_free_context(rdp->realm_context);
    }
    memset((char *) rdp, 0, sizeof(*rdp));
}

/*
 * Initialize a realm control structure from the alternate profile or from
 * the specified defaults.
 *
 * After we're complete here, the essence of the realm is embodied in the
 * realm data and we should be all set to begin operation for that realm.
 */
static krb5_error_code
init_realm(progname, rdp, altp, realm, def_dbname, def_mpname,
		 def_keytype, def_port, def_enctype, def_manual)
    char		*progname;
    kdc_realm_t		*rdp;
    krb5_pointer	altp;
    char		*realm;
    char		*def_dbname;
    char		*def_mpname;
    krb5_keytype	def_keytype;
    krb5_int32		def_port;
    krb5_enctype	def_enctype;
    krb5_boolean	def_manual;
{
    krb5_error_code	kret;
    const char		*hierarchy[4];
    krb5_boolean	manual;
    krb5_db_entry	db_entry;
    int			num2get;
    krb5_boolean	more;
    krb5_boolean	db_inited;
    krb5_int32		ibuf;
    krb5_enctype	etype;

    kret = EINVAL;
    db_inited = 0;
    memset((char *) rdp, 0, sizeof(kdc_realm_t));
    if (realm) {
	rdp->realm_name = realm;
	if (!(kret = krb5_init_context(&rdp->realm_context))) {
	    hierarchy[0] = realm;
	    hierarchy[1] = "database_name";
	    hierarchy[2] = (char *) NULL;
	    /*
	     * Attempt to get the real value for the database file.
	     */
	    if (!altp || (kret = krb5_aprof_get_string(altp,
						       hierarchy,
						       TRUE,
						       &rdp->realm_dbname)))
		rdp->realm_dbname = (def_dbname) ? strdup(def_dbname) :
		    strdup(DEFAULT_KDB_FILE);

	    /*
	     * Attempt to get the real value for the master key name.
	     */
	    hierarchy[1] = "master_key_name";
	    if (!altp || (kret = krb5_aprof_get_string(altp,
						       hierarchy,
						       TRUE,
						       &rdp->realm_mpname)))
		rdp->realm_mpname = (def_mpname) ? strdup(def_mpname) :
		    KRB5_KDB_M_NAME;

	    /*
	     * Attempt to get the real value for the master key type.
	     */
	    hierarchy[1] = "master_key_type";
	    if (!altp || (kret = krb5_aprof_get_int32(altp,
						      hierarchy,
						      TRUE,
						      &ibuf)))
		rdp->realm_mkey.keytype = (def_keytype) ? def_keytype :
		    KEYTYPE_DES;
	    else
		rdp->realm_mkey.keytype = (krb5_keytype) ibuf;

	    /*
	     * Attempt to get the real value for the primary port.
	     */
	    hierarchy[1] = "port";
	    if (!altp || (kret = krb5_aprof_get_int32(altp,
						      hierarchy,
						      TRUE,
						      &rdp->realm_pport)))
		rdp->realm_pport = (def_port) ? def_port : KRB5_DEFAULT_PORT;

	    /*
	     * Attempt to get the real value for the encryption type.
	     */
	    hierarchy[1] = "encryption_type";
	    if (!altp || (kret = krb5_aprof_get_int32(altp,
						      hierarchy,
						      TRUE,
						      &ibuf)))
		etype = (def_enctype) ? def_enctype : DEFAULT_KDC_ETYPE;
	    else
		etype = (krb5_enctype) ibuf;

	    if (!valid_etype(etype)) {
		com_err(progname, KRB5_PROG_ETYPE_NOSUPP,
			"while setting up etype %d", etype);
		exit(1);
	    }
	    /*
	     * Attempt to get the real value for the stash file.
	     */
	    hierarchy[1] = "key_stash_file";
	    if (!altp || (kret = krb5_aprof_get_string(altp,
						       hierarchy,
						       TRUE,
						       &rdp->realm_stash)))
		manual = def_manual;
	    else
		manual = FALSE;

	    /*
	     * Attempt to get the real value for the maximum ticket life.
	     */
	    hierarchy[1] = "max_life";
	    if (!altp || (kret = krb5_aprof_get_deltat(altp,
						       hierarchy,
						       TRUE,
						       &rdp->realm_maxlife)))
		rdp->realm_maxlife = KRB5_KDB_MAX_LIFE;

	    /*
	     * Attempt to get the real value for the maximum renewable ticket
	     * life.
	     */
	    hierarchy[1] = "max_renewable_life";
	    if (!altp || (kret = krb5_aprof_get_deltat(altp,
						       hierarchy,
						       TRUE,
						       &rdp->realm_maxrlife)))
		rdp->realm_maxrlife = KRB5_KDB_MAX_RLIFE;

	    /*
	     * We've got our parameters, now go and setup our realm context.
	     */

	    /* Set the default realm of this context */
	    if (kret = krb5_set_default_realm(rdp->realm_context, realm)) {
		com_err(progname, kret, "while setting default realm to %s",
			realm);
		goto whoops;
	    }

	    /* Assemble and parse the master key name */
	    if (kret = krb5_db_setup_mkey_name(rdp->realm_context,
					       rdp->realm_mpname,
					       rdp->realm_name,
					       (char **) NULL,
					       &rdp->realm_mprinc)) {
		com_err(progname, kret,
			"while setting up master key name %s for realm %s",
			rdp->realm_mpname, realm);
		goto whoops;
	    }

	    /* Select the specified encryption type */
	    krb5_use_cstype(rdp->realm_context, &rdp->realm_encblock, etype);

	    /*
	     * If there's a stash file, then we have to go get the key
	     * manually because krb5_db_fetch_mkey() doesn't let us supply
	     * where we've stashed the master key.
	     */
	    if (rdp->realm_stash) {
		FILE *sfile;
		krb5_ui_2 keytype;

		if (sfile = fopen(rdp->realm_stash, "r")) {
		    if ((fread((krb5_pointer) &keytype, 2, 1, sfile) != 1) ||
			(fread((krb5_pointer) &rdp->realm_mkey.length,
			       sizeof(rdp->realm_mkey.length),
			       1,
			       sfile) != 1) ||
			(!(rdp->realm_mkey.contents = (krb5_octet *)
			   malloc(rdp->realm_mkey.length))) ||
			(fread((krb5_pointer) rdp->realm_mkey.contents,
			       sizeof(krb5_octet),
			       rdp->realm_mkey.length, sfile) !=
			 rdp->realm_mkey.length)) {
			com_err(progname, KRB5_KDB_CANTREAD_STORED,
				"while reading stash file %s for realm %s",
				rdp->realm_stash, realm);
			fclose(sfile);
			goto whoops;
		    }
		    rdp->realm_mkey.keytype = keytype;
		    fclose(sfile);
		}
		else {
		    com_err(progname, errno, 
			    "while opening stash file %s for realm %s",
			    rdp->realm_stash, realm);
		    goto whoops;
		}
	    }
	    else {
		/*
		 * No stash, fetch it.
		 */
		if (kret = krb5_db_fetch_mkey(rdp->realm_context,
					      rdp->realm_mprinc,
					      &rdp->realm_encblock,
					      manual,
					      FALSE,
					      0,
					      &rdp->realm_mkey)) {
		    com_err(progname, kret, 
			    "while fetching master key %s for realm %s",
			    rdp->realm_mpname, realm);
		    goto whoops;
		}
	    }

	    /* Set and open the database. */
	    if (rdp->realm_dbname &&
		(kret = krb5_db_set_name(rdp->realm_context,
					 rdp->realm_dbname))) {
		com_err(progname, kret,
			"while setting database name to %s for realm %s",
			rdp->realm_dbname, realm);
		goto whoops;
	    }
	    if (kret = krb5_db_init(rdp->realm_context)) {
		com_err(progname, kret,
			"while initializing database for realm %s", realm);
		goto whoops;
	    }
	    else
		db_inited = 1;

	    /* Verify the master key */
	    if (kret = krb5_db_verify_master_key(rdp->realm_context,
						 rdp->realm_mprinc,
						 &rdp->realm_mkey,
						 &rdp->realm_encblock)) {
		com_err(progname, kret,
			"while verifying master key for realm %s", realm);
		goto whoops;
	    }

	    /* Fetch the master key and get its version number */
	    num2get = 1;
	    if (!(kret = krb5_db_get_principal(rdp->realm_context,
					       rdp->realm_mprinc,
					       &db_entry,
					       &num2get,
					       &more))) {
		if (num2get != 1)
		    kret = KRB5_KDB_NOMASTERKEY;
		else {
		    if (more) {
			krb5_db_free_principal(rdp->realm_context,
					       &db_entry,
					       num2get);
			kret = KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE;
		    }
		}
	    }
	    if (kret) {
		com_err(progname, kret,
			"while fetching master entry for realm %s", realm);
		goto whoops;
	    }
	    else {
		rdp->realm_mkvno = db_entry.kvno;
		krb5_db_free_principal(rdp->realm_context,
				       &db_entry,
				       num2get);
	    }

	    /* Now preprocess the master key */
	    if (kret = krb5_process_key(rdp->realm_context,
					&rdp->realm_encblock,
					&rdp->realm_mkey)) {
		com_err(progname, kret,
			"while processing master key for realm %s", realm);
		goto whoops;
	    }

	    /* Preformat the TGS name */
	    if (kret = krb5_build_principal(rdp->realm_context,
					    &rdp->realm_tgsprinc,
					    strlen(realm),
					    realm,
					    KRB5_TGS_NAME,
					    realm,
					    (char *) NULL)) {
		com_err(progname, kret,
			"while building TGS name for realm %s", realm);
		goto whoops;
	    }

	    /* Get the TGS database entry */
	    num2get = 1;
	    if (!(kret = krb5_db_get_principal(rdp->realm_context,
					       rdp->realm_tgsprinc,
					       &db_entry,
					       &num2get,
					       &more))) {
		if (num2get != 1)
		    kret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
		else {
		    if (more) {
			krb5_db_free_principal(rdp->realm_context,
					       &db_entry,
					       num2get);
			kret = KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE;
		    }
		}
	    }
	    if (kret) {
		com_err(progname, kret,
			"while fetching TGS entry for realm %s", realm);
		goto whoops;
	    }
	    else {
		if (!(kret = krb5_kdb_decrypt_key(rdp->realm_context,
						  &rdp->realm_encblock,
						  &db_entry.key,
						  &rdp->realm_tgskey))) {
		    rdp->realm_tgskvno = db_entry.kvno;
		}
		krb5_db_free_principal(rdp->realm_context,
				       &db_entry,
				       num2get);
		if (kret) {
		    com_err(progname, kret,
			    "while decrypting TGS key for realm %s", realm);
		    goto whoops;
		}
	    }
	    if (!rkey_init_done) {
		/*
		 * If all that worked, then initialize the random key
		 * generators.
		 */
		for (etype = 0; etype <= krb5_max_cryptosystem; etype++) {
		    if (krb5_csarray[etype]) {
			if ((kret = (*krb5_csarray[etype]->system->
				     init_random_key)
			     (&rdp->realm_mkey,
			      &krb5_csarray[etype]->random_sequence))) {
			    com_err(progname, kret, 
				    "while setting up random key generator for etype %d--etype disabled",
				    etype);
			    krb5_csarray[etype] = 0;
			}
		    }
		}
		rkey_init_done = 1;
	    }
	}
	else {
	    com_err(progname, kret, "while getting context for realm %s",
		    realm);
	    goto whoops;
	}
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

krb5_sigtype
request_exit(signo)
    int signo;
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
    fprintf(stderr, "usage: %s [-d dbpathname] [-r dbrealmname] [-R replaycachename ]\n\t[-m] [-k masterkeytype] [-M masterkeyname] [-p port] [-n]\n", name);
    return;
}

void
initialize_realms(kcontext, altp, argc, argv)
    krb5_context 	kcontext;
    krb5_pointer	altp;
    int			argc;
    char		**argv;
{
    int 		c;
    char		*db_name = (char *) NULL;
    char		*mkey_name = (char *) NULL;
    char		*rcname = KDCRCACHE;
    char		*lrealm;
    krb5_error_code	retval, retval2;
    krb5_keytype	mkeytype = KEYTYPE_DES;
    krb5_enctype	kdc_etype = DEFAULT_KDC_ETYPE;
    kdc_realm_t		*rdatap;
    krb5_boolean	manual = FALSE;
    krb5_int32		pport;

    extern char *optarg;

    /*
     * Loop through the option list.  Each time we encounter a realm name,
     * use the previously scanned options to fill in for defaults.
     */
    while ((c = getopt(argc, argv, "r:d:mM:k:R:e:p:n")) != EOF) {
	switch(c) {
	case 'r':			/* realm name for db */
	    if (!find_realm_data(optarg, (krb5_ui_4) strlen(optarg))) {
		if (rdatap = (kdc_realm_t *) malloc(sizeof(kdc_realm_t))) {
		    if (retval = init_realm(argv[0],
					    rdatap,
					    altp,
					    optarg,
					    db_name,
					    mkey_name,
					    mkeytype,
					    pport,
					    kdc_etype,
					    manual)) {
			fprintf(stderr,"%s: cannot initialize realm %s\n",
				argv[0], optarg);
			exit(1);
		    }
		    kdc_realmlist[kdc_numrealms] = rdatap;
		    kdc_numrealms++;
		}
	    }
	    break;
	case 'd':			/* pathname for db */
	    db_name = optarg;
	    break;
	case 'm':			/* manual type-in of master key */
	    manual = TRUE;
	    break;
	case 'M':			/* master key name in DB */
	    mkey_name = optarg;
	    break;
	case 'n':
	    nofork++;			/* don't detach from terminal */
	    break;
	case 'k':			/* keytype for master key */
	    mkeytype = atoi(optarg);
	    break;
	case 'R':
	    rcname = optarg;
	    break;
	case 'p':
	    pport = atoi(optarg);
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

    /*
     * Check to see if we processed any realms.
     */
    if (kdc_numrealms == 0) {
	/* no realm specified, use default realm */
	if ((retval = krb5_get_default_realm(kcontext, &lrealm))) {
	    com_err(argv[0], retval,
		    "while attempting to retrieve default realm");
	    exit(1);
	}
	if (rdatap = (kdc_realm_t *) malloc(sizeof(kdc_realm_t))) {
	    if (retval = init_realm(argv[0],
				    rdatap,
				    altp,
				    lrealm,
				    db_name,
				    mkey_name,
				    mkeytype,
				    pport,
				    kdc_etype,
				    manual)) {
		fprintf(stderr,"%s: cannot initialize realm %s\n",
			argv[0], lrealm);
		exit(1);
	    }
	    kdc_realmlist[0] = rdatap;
	    kdc_numrealms++;
	}
    }

    /*
     * Now handle the replay cache.
     */
    if (retval = kdc_initialize_rcache(kcontext, rcname)) {
	com_err(argv[0], retval,
		"while initializing KDC replay cache");
	exit(1);
    }

    /* Ensure that this is set for our first request. */
    kdc_active_realm = kdc_realmlist[0];
    return;
}

void
finish_realms(prog)
    char *prog;
{
    int i;

    for (i=0; i<kdc_numrealms; i++)
	finish_realm(kdc_realmlist[i]);
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

int main(argc, argv)
int argc;
char *argv[];
{
    krb5_error_code	retval;
    krb5_context	kcontext;
    krb5_pointer	alt_profile;
    int errout = 0;

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    if (!(kdc_realmlist = (kdc_realm_t **) malloc(sizeof(kdc_realm_t *) * 
						  KRB5_KDC_MAX_REALMS))) {
	fprintf(stderr, "%s: cannot get memory for realm list\n", argv[0]);
	exit(1);
    }
    memset((char *) kdc_realmlist, 0,
	   (size_t) (sizeof(kdc_realm_t *) * KRB5_KDC_MAX_REALMS));

    /*
     * A note about Kerberos contexts: This context, "kcontext", is used
     * for the KDC operations, i.e. setup, network connection and error
     * reporting.  The per-realm operations use the "realm_context"
     * associated with each realm.
     */
    krb5_init_context(&kcontext);
    krb5_init_ets(kcontext);
    krb5_klog_init(kcontext, "kdc", argv[0], 1);
    if (retval = krb5_aprof_init(DEFAULT_KDC_PROFILE,
				 KDC_PROFILE_ENV,
				 &alt_profile)) {
	fprintf(stderr, "%s: warning - cannot find kdc profile\n", argv[0]);
	alt_profile = (krb5_pointer) NULL;
    }

    /*
     * Scan through the argument list
     */
    initialize_realms(kcontext, alt_profile, argc, argv);

    if (alt_profile)
	krb5_aprof_finish(alt_profile);
    setup_signal_handlers();

    if ((retval = setup_network(argv[0]))) {
	com_err(argv[0], retval, "while initializing network");
	finish_realms(argv[0]);
	return 1;
    }
    if (!nofork && daemon(0, 0)) {
	com_err(argv[0], errno, "while detaching from tty");
	finish_realms(argv[0]);
	return 1;
    }
    krb5_klog_syslog(LOG_INFO, "commencing operation");
    if ((retval = listen_and_process(argv[0]))) {
	com_err(argv[0], retval, "while processing network requests");
	errout++;
    }
    if ((retval = closedown_network(argv[0]))) {
	com_err(argv[0], retval, "while shutting down network");
	errout++;
    }
    krb5_klog_syslog(LOG_INFO, "shutting down");
    krb5_klog_close(kdc_context);
    finish_realms(argv[0]);
    return errout;
}


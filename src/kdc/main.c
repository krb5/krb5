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
#include <netdb.h>

#include "k5-int.h"
#include "com_err.h"
#include "adm.h"
#include "adm_proto.h"
#include "kdc_util.h"
#include "extern.h"
#include "kdc5_err.h"
#include "kdb_kt.h"
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

kdc_realm_t *find_realm_data PROTOTYPE((char *, krb5_ui_4));

void usage PROTOTYPE((char *));

krb5_sigtype request_exit PROTOTYPE((int));

void setup_signal_handlers PROTOTYPE((void));

void initialize_realms PROTOTYPE((krb5_context, int, char **));

void finish_realms PROTOTYPE((char *));

static int nofork = 0;
static char *kdc_current_rcname = (char *) NULL;
static int rkey_init_done = 0;

#define	KRB5_KDC_MAX_REALMS	32

#ifdef USE_RCACHE
/*
 * initialize the replay cache.
 */
krb5_error_code
kdc_initialize_rcache(kcontext, rcache_name)
    krb5_context	kcontext;
    char 		*rcache_name;
{
    krb5_error_code	retval;
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
					  kcontext->clockskew))
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
#endif

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
    if (rdp->realm_ports)
	free(rdp->realm_ports);
    if (rdp->realm_kstypes)
	free(rdp->realm_kstypes);
    if (rdp->realm_keytab)
	krb5_kt_close(rdp->realm_context, rdp->realm_keytab);
    if (rdp->realm_context) {
	if (rdp->realm_mprinc)
	    krb5_free_principal(rdp->realm_context, rdp->realm_mprinc);
	if (rdp->realm_mkey.length && rdp->realm_mkey.contents) {
	    memset(rdp->realm_mkey.contents, 0, rdp->realm_mkey.length);
	    free(rdp->realm_mkey.contents);
	}
	if (rdp->realm_tgskey.length && rdp->realm_tgskey.contents) {
	    memset(rdp->realm_tgskey.contents, 0, rdp->realm_tgskey.length);
	    free(rdp->realm_tgskey.contents);
	}
	if (rdp->realm_encblock.crypto_entry)
		krb5_finish_key(rdp->realm_context, &rdp->realm_encblock);
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
init_realm(progname, rdp, realm, def_dbname, def_mpname,
		 def_enctype, def_ports, def_manual)
    char		*progname;
    kdc_realm_t		*rdp;
    char		*realm;
    char		*def_dbname;
    char		*def_mpname;
    krb5_enctype	def_enctype;
    char		*def_ports;
    krb5_boolean	def_manual;
{
    krb5_error_code	kret;
    krb5_boolean	manual;
    krb5_db_entry	db_entry;
    int			num2get;
    krb5_boolean	more;
    krb5_boolean	db_inited;
    krb5_realm_params	*rparams;
    krb5_key_data	*kdata;
    krb5_key_salt_tuple	*kslist;
    krb5_int32		nkslist;
    int			i;

    db_inited = 0;
    memset((char *) rdp, 0, sizeof(kdc_realm_t));
    if (!realm) {
	kret = EINVAL;
	goto whoops;
    }
	
    rdp->realm_name = realm;
    kret = krb5_init_context(&rdp->realm_context);
    if (kret) {
	com_err(progname, kret, "while getting context for realm %s",
		realm);
	goto whoops;
    }

    kret = krb5_read_realm_params(rdp->realm_context, rdp->realm_name,
				  (char *) NULL, (char *) NULL, &rparams);
    if (kret) {
	com_err(progname, kret, "while reading realm parameters");
	goto whoops;
    }
    
    /* Handle profile file name */
    if (rparams && rparams->realm_profile)
	rdp->realm_profile = strdup(rparams->realm_profile);

    /* Handle database name */
    if (rparams && rparams->realm_dbname)
	rdp->realm_dbname = strdup(rparams->realm_dbname);
    else
	rdp->realm_dbname = (def_dbname) ? strdup(def_dbname) :
	    strdup(DEFAULT_KDB_FILE);

    /* Handle master key name */
    if (rparams && rparams->realm_mkey_name)
	rdp->realm_mpname = strdup(rparams->realm_mkey_name);
    else
	rdp->realm_mpname = (def_mpname) ? strdup(def_mpname) :
	    strdup(KRB5_KDB_M_NAME);

    /* Handle KDC port */
    if (rparams && rparams->realm_kdc_ports)
	rdp->realm_ports = strdup(rparams->realm_kdc_ports);
    else
	rdp->realm_ports = strdup(def_ports);
	    
    /* Handle stash file */
    if (rparams && rparams->realm_stash_file) {
	rdp->realm_stash = strdup(rparams->realm_stash_file);
	manual = FALSE;
    } else
	manual = def_manual;

    /* Handle master key type */
    if (rparams && rparams->realm_enctype_valid)
	rdp->realm_mkey.enctype = (krb5_enctype) rparams->realm_enctype;
    else
	rdp->realm_mkey.enctype = manual ? def_enctype : ENCTYPE_UNKNOWN;

    /* Handle ticket maximum life */
    rdp->realm_maxlife = (rparams && rparams->realm_max_life_valid) ?
	rparams->realm_max_life : KRB5_KDB_MAX_LIFE;

    /* Handle ticket renewable maximum life */
    rdp->realm_maxrlife = (rparams && rparams->realm_max_rlife_valid) ?
	rparams->realm_max_rlife : KRB5_KDB_MAX_LIFE;

    /* Handle key/salt list */
    if (rparams && rparams->realm_num_keysalts) {
	rdp->realm_kstypes = rparams->realm_keysalts;
	rdp->realm_nkstypes = rparams->realm_num_keysalts;
	rparams->realm_keysalts = NULL;
	rparams->realm_num_keysalts = 0;
	kslist = (krb5_key_salt_tuple *) rdp->realm_kstypes;
	nkslist = rdp->realm_nkstypes;
    } else {
	/*
	 * XXX  Initialize default key/salt list.
	 */
	if ((kslist = (krb5_key_salt_tuple *)
	     malloc(sizeof(krb5_key_salt_tuple)))) {
	    kslist->ks_enctype = ENCTYPE_DES_CBC_CRC;
	    kslist->ks_salttype = KRB5_KDB_SALTTYPE_NORMAL;
	    rdp->realm_kstypes = kslist;
	    rdp->realm_nkstypes = 1;
	    nkslist = 1;
	}
	else {
	    com_err(progname, ENOMEM,
		    "while setting up key/salt list for realm %s",
		    realm);
	    exit(1);
	}
    }

    if (rparams)
	krb5_free_realm_params(rdp->realm_context, rparams);

    /*
     * We've got our parameters, now go and setup our realm context.
     */

    /* Set the default realm of this context */
    if ((kret = krb5_set_default_realm(rdp->realm_context, realm))) {
	com_err(progname, kret, "while setting default realm to %s",
		realm);
	goto whoops;
    }

    /* Assemble and parse the master key name */
    if ((kret = krb5_db_setup_mkey_name(rdp->realm_context, rdp->realm_mpname,
					rdp->realm_name, (char **) NULL,
					&rdp->realm_mprinc))) {
	com_err(progname, kret,
		"while setting up master key name %s for realm %s",
		rdp->realm_mpname, realm);
	goto whoops;
    }

    /* Select the specified encryption type */
    /* krb5_db_fetch_mkey will setup the encblock for stashed keys */
    if (manual)
	krb5_use_enctype(rdp->realm_context, &rdp->realm_encblock, 
			 rdp->realm_mkey.enctype);
    
    /*
     * Get the master key.
     */
    if ((kret = krb5_db_fetch_mkey(rdp->realm_context, rdp->realm_mprinc,
				   &rdp->realm_encblock, manual,
				   FALSE, rdp->realm_stash,
				   0, &rdp->realm_mkey))) {
	com_err(progname, kret,
		"while fetching master key %s for realm %s",
		rdp->realm_mpname, realm);
	goto whoops;
    }

    /* Set and open the database. */
    if (rdp->realm_dbname &&
	(kret = krb5_db_set_name(rdp->realm_context, rdp->realm_dbname))) {
	com_err(progname, kret,
		"while setting database name to %s for realm %s",
		rdp->realm_dbname, realm);
	goto whoops;
    }
    if ((kret = krb5_db_init(rdp->realm_context))) {
	com_err(progname, kret,
		"while initializing database for realm %s", realm);
	goto whoops;
    } else
	db_inited = 1;

    /* Verify the master key */
    if ((kret = krb5_db_verify_master_key(rdp->realm_context,
					  rdp->realm_mprinc,
					  &rdp->realm_mkey,
					  &rdp->realm_encblock))) {
	com_err(progname, kret,
		"while verifying master key for realm %s", realm);
	goto whoops;
    }

    /* Fetch the master key and get its version number */
    num2get = 1;
    kret = krb5_db_get_principal(rdp->realm_context, rdp->realm_mprinc,
				 &db_entry, &num2get, &more);
    if (!kret) {
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
	
    /*
     * Get the most recent master key.  Search the key list in
     * the order specified by the key/salt list.
     */
    kdata = (krb5_key_data *) NULL;
    for (i=0; i<nkslist; i++) {
	if (!(kret = krb5_dbe_find_enctype(rdp->realm_context,
					   &db_entry,
					   kslist[i].ks_enctype,
					   -1,
					   -1,
					   &kdata)))
	    break;
    }
    if (!kdata) {
	com_err(progname, kret,
		"while finding master key for realm %s",
		realm);
	goto whoops;
    }
    rdp->realm_mkvno = kdata->key_data_kvno;
    krb5_db_free_principal(rdp->realm_context, &db_entry, num2get);

    /* Now preprocess the master key */
    if ((kret = krb5_process_key(rdp->realm_context,
				 &rdp->realm_encblock,
				 &rdp->realm_mkey))) {
	com_err(progname, kret,
		"while processing master key for realm %s", realm);
	goto whoops;
    }

    if ((kret = krb5_db_set_mkey(rdp->realm_context, 
				 &rdp->realm_encblock))) {
	com_err(progname, kret,
		"while setting master key for realm %s", realm);
	goto whoops;
    }

    /* Set up the keytab */
    if ((kret = krb5_ktkdb_resolve(rdp->realm_context, 
				   &rdp->realm_keytab))) {
	com_err(progname, kret,
		"while resolving kdb keytab for realm %s", realm);
	goto whoops;
    }

    /* Preformat the TGS name */
    if ((kret = krb5_build_principal(rdp->realm_context, &rdp->realm_tgsprinc,
				     strlen(realm), realm, KRB5_TGS_NAME,
				     realm, (char *) NULL))) {
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
    /*
     * Get the most recent TGS key.  Search the key list in
     * the order specified by the key/salt list.
     */
    kdata = (krb5_key_data *) NULL;
    for (i=0; i<nkslist; i++) {
	if (!(kret = krb5_dbe_find_enctype(rdp->realm_context,
					   &db_entry,
					   kslist[i].ks_enctype,
					   -1,
					   -1,
					   &kdata)))
	    break;
    }
    if (!kdata) {
	com_err(progname, kret, "while finding TGS key for realm %s",
		realm);
	goto whoops;
    }
    if (!(kret = krb5_dbekd_decrypt_key_data(rdp->realm_context,
					     &rdp->realm_encblock,
					     kdata,
					     &rdp->realm_tgskey, NULL))){
	rdp->realm_tgskvno = kdata->key_data_kvno;
    }
    krb5_db_free_principal(rdp->realm_context,
			   &db_entry,
			   num2get);
    if (kret) {
	com_err(progname, kret,
		"while decrypting TGS key for realm %s", realm);
	goto whoops;
    }

    if (!rkey_init_done) {
	krb5_enctype enctype;
	krb5_encrypt_block temp_eblock;
#ifdef KRB5_KRB4_COMPAT
	krb5_keyblock *temp_key;
#endif
	/*
	 * If all that worked, then initialize the random key
	 * generators.
	 */
	for (enctype = 0; enctype <= krb5_max_enctype; enctype++) {
	    if (krb5_enctype_array[enctype] &&
		!krb5_enctype_array[enctype]->random_sequence) {
		krb5_use_enctype(rdp->realm_context, &temp_eblock, enctype);
		if ((kret = krb5_init_random_key(
			 rdp->realm_context, &temp_eblock,
			 &rdp->realm_mkey,
			&krb5_enctype_array[enctype]->random_sequence))) {
		    com_err(progname, kret, 
			    "while setting up random key generator for enctype %d--enctype disabled",
			    enctype);
		    krb5_enctype_array[enctype] = 0;
		} else {
#ifdef KRB5_KRB4_COMPAT
		    if (enctype == ENCTYPE_DES_CBC_CRC) {
			if ((kret = krb5_random_key(
			    rdp->realm_context, &temp_eblock,
				krb5_enctype_array[enctype]->random_sequence,
				&temp_key)))
			    com_err(progname, kret,
				    "while initializing V4 random key generator");
			else {
			    (void) des_init_random_number_generator(temp_key->contents);
			    krb5_free_keyblock(rdp->realm_context, temp_key);
			}
		    }
#endif
		}
	    }
	}
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
    fprintf(stderr, "usage: %s [-d dbpathname] [-r dbrealmname] [-R replaycachename ]\n\t[-m] [-k masterenctype] [-M masterkeyname] [-p port] [-4 v4mode] [-n]\n", name);
    return;
}

void
initialize_realms(kcontext, argc, argv)
    krb5_context 	kcontext;
    int			argc;
    char		**argv;
{
    int 		c;
    char		*db_name = (char *) NULL;
    char		*mkey_name = (char *) NULL;
    char		*rcname = KDCRCACHE;
    char		*lrealm;
    krb5_error_code	retval;
    krb5_enctype	menctype = ENCTYPE_UNKNOWN;
    kdc_realm_t		*rdatap;
    krb5_boolean	manual = FALSE;
    char		*default_ports = 0;
    krb5_pointer	aprof;
    const char		*hierarchy[3];
#ifdef KRB5_KRB4_COMPAT
    char                *v4mode = 0;
#endif
    extern char *optarg;

    if (!krb5_aprof_init(DEFAULT_KDC_PROFILE, KDC_PROFILE_ENV, &aprof)) {
	hierarchy[0] = "kdcdefaults";
	hierarchy[1] = "kdc_ports";
	hierarchy[2] = (char *) NULL;
	if (krb5_aprof_get_string(aprof, hierarchy, TRUE, &default_ports))
	    default_ports = 0;
#ifdef KRB5_KRB4_COMPAT
	hierarchy[1] = "v4_mode";
	if (krb5_aprof_get_string(aprof, hierarchy, TRUE, &v4mode))
	    v4mode = 0;
#endif
	/* aprof_init can return 0 with aprof == NULL */
	if (aprof)
	     krb5_aprof_finish(aprof);
    }
    if (default_ports == 0)
	default_ports = strdup(DEFAULT_KDC_PORTLIST);
    /*
     * Loop through the option list.  Each time we encounter a realm name,
     * use the previously scanned options to fill in for defaults.
     */
    while ((c = getopt(argc, argv, "r:d:mM:k:R:e:p:s:n4:")) != EOF) {
	switch(c) {
	case 'r':			/* realm name for db */
	    if (!find_realm_data(optarg, (krb5_ui_4) strlen(optarg))) {
		if ((rdatap = (kdc_realm_t *) malloc(sizeof(kdc_realm_t)))) {
		    if ((retval = init_realm(argv[0], rdatap, optarg, db_name,
					     mkey_name, menctype,
					     default_ports, manual))) {
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
	    if (menctype == ENCTYPE_UNKNOWN)
		menctype = ENCTYPE_DES_CBC_CRC;
	    break;
	case 'M':			/* master key name in DB */
	    mkey_name = optarg;
	    break;
	case 'n':
	    nofork++;			/* don't detach from terminal */
	    break;
	case 'k':			/* enctype for master key */
	    if (krb5_string_to_enctype(optarg, &menctype))
		com_err(argv[0], 0, "invalid enctype %s", optarg);
	    break;
	case 'R':
	    rcname = optarg;
	    break;
	case 'p':
	    if (default_ports)
		free(default_ports);
	    default_ports = strdup(optarg);
	    break;
	case '4':
#ifdef KRB5_KRB4_COMPAT
	    if (v4mode)
		free(v4mode);
	    v4mode = strdup(optarg);
#endif
	    break;
	case '?':
	default:
	    usage(argv[0]);
	    exit(1);
	}
    }

#ifdef KRB5_KRB4_COMPAT
    /*
     * Setup the v4 mode 
     */
    process_v4_mode(argv[0], v4mode);
#endif

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
	if ((rdatap = (kdc_realm_t *) malloc(sizeof(kdc_realm_t)))) {
	    if ((retval = init_realm(argv[0], rdatap, lrealm, db_name,
				     mkey_name, menctype, default_ports,
				     manual))) {
		fprintf(stderr,"%s: cannot initialize realm %s\n",
			argv[0], lrealm);
		exit(1);
	    }
	    kdc_realmlist[0] = rdatap;
	    kdc_numrealms++;
	}
    }

#ifdef USE_RCACHE
    /*
     * Now handle the replay cache.
     */
    if ((retval = kdc_initialize_rcache(kcontext, rcname))) {
	com_err(argv[0], retval, "while initializing KDC replay cache");
	exit(1);
    }
#endif

    /* Ensure that this is set for our first request. */
    kdc_active_realm = kdc_realmlist[0];
    if (default_ports)
	free(default_ports);

    return;
}

void
finish_realms(prog)
    char *prog;
{
    int i;

    for (i = 0; i < kdc_numrealms; i++)
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
    int			*port_list;
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
    port_list = NULL;

    /*
     * A note about Kerberos contexts: This context, "kcontext", is used
     * for the KDC operations, i.e. setup, network connection and error
     * reporting.  The per-realm operations use the "realm_context"
     * associated with each realm.
     */
    retval = krb5_init_context(&kcontext);
    if (retval) {
	    com_err(argv[0], retval, "while initializing krb5");
	    exit(1);
    }
    krb5_klog_init(kcontext, "kdc", argv[0], 1);
    initialize_kdc5_error_table();

    /*
     * Scan through the argument list
     */
    initialize_realms(kcontext, argc, argv);

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
    krb5_free_context(kcontext);
    return errout;
}


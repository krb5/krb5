/*
 * kadmin/server/adm_server.c
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Top-level loop of the Kerberos Version 5 Administration server
 */

/* 
 * Sandia National Laboratories also makes no representations about the 
 * suitability of the modifications, or additions to this software for 
 * any purpose.  It is provided "as is" without express or implied warranty.
 */


/*
  adm_server.c
  this holds the main loop and initialization and cleanup code for the server
*/

#include <stdio.h>
#include <sys/types.h>
#include <syslog.h>
#include <string.h>
#include "com_err.h"

#include <signal.h>
#ifndef sigmask
#define sigmask(m)    (1 <<((m)-1))
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#ifndef hpux
#include <arpa/inet.h>
#endif

#ifndef __STDC__
#include <varargs.h>
#endif

#include "k5-int.h"
#include "adm_extern.h"

char prog[32];
char *progname = prog;
char *acl_file_name = DEFAULT_ADMIN_ACL;
char *adm5_ver_str = ADM5_VERSTR;
int  adm5_ver_len;

char *adm5_tcp_portname = ADM5_PORTNAME;
int adm5_tcp_port_fd = -1;
 
unsigned pidarraysize = 0;
int *pidarray = (int *) 0;

int exit_now = 0;

global_client_server_info client_server_info;

#ifdef SANDIA
int classification;             /* default = Unclassified */
#endif

krb5_db_entry master_entry;

krb5_flags NEW_ATTRIBUTES;

cleanexit(context, val)
    krb5_context context;
    int	val;
{
    (void) krb5_db_fini(context);
    exit(val);
}

krb5_error_code
closedown_db(context)
    krb5_context context;
{
    krb5_error_code retval;

    /* clean up master key stuff */
    retval = krb5_finish_key(context, &master_encblock);

    memset((char *)&master_encblock, 0, sizeof(master_encblock));
    memset((char *)tgs_key.contents, 0, tgs_key.length);

    /* close database */
    if (retval) {
	(void) krb5_db_fini(context);
	return(retval);
    } else
	return(krb5_db_fini(context));
}
 
void
usage(name)
char *name;
{
    fprintf(stderr, "Usage: %s\t[-a aclfile] [-d dbname] [-k masterkeytype]", 
			name);
    fprintf(stderr, "\n\t[-h] [-m] [-M masterkeyname] [-r realm] [-p port]\n");
    return;
}
 
krb5_error_code
process_args(context, argc, argv)
    krb5_context context;
    int argc;
    char **argv;
{
    krb5_error_code retval;
    int c;
    krb5_boolean manual = FALSE;
    int keytypedone = 0;
    char *mkey_name = 0;
    char *local_realm;
    krb5_enctype etype;
    krb5_enctype kdc_etype = DEFAULT_KDC_ETYPE;

#ifdef SANDIA
    char input_string[80];
    FILE *startup_file;
#endif

    extern char *optarg;

#ifdef SANDIA
    classification = 0;

    if ((startup_file =
        fopen(DEFAULT_KDCPARM_NAME, "r")) == (FILE *) 0) {
        syslog(LOG_ERR, 
		"Cannot open parameter file (%s) - Using default parameters",
		DEFAULT_KDCPARM_NAME);
        syslog(LOG_ERR, "Only Unclassified Principals will be allowed");
    } else {
        for ( ;; ) {
            if ((fgets(input_string, sizeof(input_string), startup_file)) == NULL)
                break;
            kadmin_parse_and_set(input_string);
        }
        fclose(startup_file);
    }
#endif
    while ((c = getopt(argc, argv, "hmM:a:d:k:r:De:p:")) != EOF) {
	switch(c) {
	    case 'a':			/* new acl directory */
		acl_file_name = optarg;
		break;

	    case 'd':
		/* put code to deal with alt database place */
		dbm_db_name = optarg;
		if (retval = krb5_dbm_db_set_name(context, dbm_db_name)) {
			fprintf(stderr, "opening database %s: %s",
				dbm_db_name, error_message(retval));
			exit(1);
		}
		break;

	    case 'e':
		kdc_etype = atoi(optarg);
		break;
		
	    case 'k':			/* keytype for master key */
		master_keyblock.keytype = atoi(optarg);
		keytypedone++;
		break;

	    case 'm':			/* manual type-in of master key */
		manual = TRUE;
	        break;

	    case 'M':			/* master key name in DB */
		mkey_name = optarg;
		break;

	    case 'r':
		realm = optarg;
		break;

	    case 'D':
		adm_debug_flag = 1;
		break;

	    case 'p':
		admin_port = htons(atoi(optarg));
		break;

	    case 'h':			/* get help on using adm_server */
	    default:
		usage(argv[0]);
		exit(1);		/* Failure - Exit */
	}

    }

    if (!realm) {
		/* no realm specified, use default realm */
	if (retval = krb5_get_default_realm(context, &local_realm)) {
		com_err(argv[0], retval,
			"while attempting to retrieve default realm");
		exit(1);
	}
	realm = local_realm;
    }        
 
    if (!mkey_name) {
	mkey_name = KRB5_KDB_M_NAME;
    }
 
    if (!keytypedone) {
	master_keyblock.keytype = KEYTYPE_DES;
    }
 
    /* assemble & parse the master key name */
    if (retval = krb5_db_setup_mkey_name(context, mkey_name, 
					realm, 
					(char **) 0,
					&master_princ)) {
	com_err(argv[0], retval, "while setting up master key name");
	exit(1);
    }

    if (!valid_etype(kdc_etype)) {
	com_err(argv[0], KRB5_PROG_ETYPE_NOSUPP,
		"while setting up etype %d", kdc_etype);
	exit(1);
    }
    krb5_use_cstype(context, &master_encblock, kdc_etype);
 
    if (retval = krb5_db_fetch_mkey(context, 
		master_princ, 
		&master_encblock, 
		manual,
		FALSE,			/* only read it once, if at all */
		(char *) NULL,		/* No stash file */
		0,			/* No salt supplied */
		&master_keyblock)) {
	com_err(argv[0], retval, "while fetching master key");
	exit(1);
    }

    /* initialize random key generators */
    for (etype = 0; etype <= krb5_max_cryptosystem; etype++) {
	if (krb5_csarray[etype]) {
		if (retval = (*krb5_csarray[etype]->system->
				init_random_key)(&master_keyblock,
				&krb5_csarray[etype]->random_sequence)) {
			com_err(argv[0], retval, 
	"while setting up random key generator for etype %d--etype disabled", 
				etype);
			krb5_csarray[etype] = 0;
		}
	}
    }
 
    return(0);
}

krb5_error_code
init_db(context, dbname, masterkeyname, masterkeyblock)
    krb5_context context;
    char *dbname;
    krb5_principal masterkeyname;
    krb5_keyblock *masterkeyblock;
{
    krb5_error_code retval;

    krb5_db_entry server_entry;
    krb5_boolean more;
    int number_of_entries;
    char tgs_name[255];
    krb5_keysalt	salt;

    /* set db name if appropriate */
    if (dbname && (retval = krb5_db_set_name(context, dbname)))
        return(retval);

    /* initialize database */
    if (retval = krb5_db_init(context))
        return(retval);

    if (retval = krb5_db_verify_master_key(context, masterkeyname, 
					masterkeyblock,
                                        &master_encblock)) {
        master_encblock.crypto_entry = 0;
        return(retval);
    }
 
    /* do any necessary key pre-processing */
    if (retval = krb5_process_key(context, &master_encblock, masterkeyblock)) {
        master_encblock.crypto_entry = 0;
        (void) krb5_db_fini(context);
        return(retval);
    }

/*
 * fetch the master database entry, and hold on to it.
 */
    number_of_entries = 1;
    if (retval = krb5_db_get_principal(context, masterkeyname, &master_entry, 
				       &number_of_entries, &more)) {
	return(retval);
    }
    if (number_of_entries != 1) {
	if (number_of_entries)
	    krb5_db_free_principal(context, &master_entry, number_of_entries);
	return(KRB5_KDB_NOMASTERKEY);
    } else if (more) {
	krb5_db_free_principal(context, &master_entry, number_of_entries);
	return(KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE);
    }	

/*
	fetch the TGS key, and hold onto it; this is an efficiency hack 
	the master key name here is from the master_princ global,
	so we can safely share its substructure
 */
    strcpy(tgs_name, KRB5_TGS_NAME);
    strcat(tgs_name, "/");
    strcat(tgs_name, masterkeyname->realm.data);
    strcat(tgs_name, "@");
    strcat(tgs_name, masterkeyname->realm.data);
    krb5_parse_name(context, tgs_name, &tgs_server);

    tgs_server->type  = KRB5_NT_SRV_INST;

    number_of_entries = 1;
    if (retval = krb5_db_get_principal(context, 
				tgs_server,
				&server_entry, 
				&number_of_entries,
				&more)) {
	return(retval);
    }

    if (more) {
	krb5_db_free_principal(context, &server_entry, number_of_entries);
	(void) krb5_finish_key(context, &master_encblock);
	memset((char *)&master_encblock, 0, sizeof(master_encblock));
	(void) krb5_db_fini(context);
	return(KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE);
    } else if (number_of_entries != 1) {
	krb5_db_free_principal(context, &server_entry, number_of_entries);
	(void) krb5_finish_key(context, &master_encblock);
	memset((char *)&master_encblock, 0, sizeof(master_encblock));
	(void) krb5_db_fini(context);
	return(KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }

/* 
	convert server.key into a real key 
	(it may be encrypted in the database) 
 */
    if (retval = krb5_dbekd_decrypt_key_data(context,&master_encblock,
				      &server_entry.key_data[0],&tgs_key,
				      &salt)) {
	krb5_db_free_principal(context, &server_entry, number_of_entries);
	(void) krb5_finish_key(context, &master_encblock);
	memset((char *)&master_encblock, 0, sizeof(master_encblock));
	(void) krb5_db_fini(context);
	return(retval);
    }

    tgs_kvno = server_entry.key_data[0].key_data_kvno;
    krb5_db_free_principal(context, &server_entry, number_of_entries);
    return(0);
}
 
krb5_sigtype
request_exit()
{
    signal_requests_exit = 1;
    return;
}

void
setup_signal_handlers()
{
  krb5_sigtype     request_exit();

    (void)signal(SIGINT, request_exit);
    (void)signal(SIGHUP, request_exit);
    (void)signal(SIGTERM, request_exit);
    return;
}
 
static void
kdc_com_err_proc(whoami, code, format, pvar)
    const char *whoami;
    long code;
    const char *format;
    va_list pvar;
{
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
		nfmt = (char *) malloc(
				strlen(format)+strlen(error_message(code))+2);
		strcpy(nfmt, error_message(code));
		strcat(nfmt, " ");
		strcat(nfmt, format);
		vsyslog(LOG_ERR, nfmt, pvar);
		free(nfmt);
	} else {
		vsyslog(LOG_ERR, format, pvar);
	}
    } else {
	if (code) {
		syslog(LOG_ERR, "%s", error_message(code));
	}
    }
    return;
}
 
void
setup_com_err(context)
    krb5_context context;
{
    krb5_init_ets(context);

    (void) set_com_err_hook(kdc_com_err_proc);
    return;
}

/*
** Main does the logical thing, it sets up the database and RPC interface,
**  as well as handling the creation and maintenance of the syslog file...
*/
main(argc, argv)		/* adm_server main routine */
int argc;
char **argv;
{
    krb5_context context;
    krb5_error_code retval;
    int errout = 0;

    adm5_ver_len = ADM5_VERSIZE;

	/* Get the Name of this program (adm_server) for Error Messages */
    if (strrchr(argv[0], '/'))
	argv[0] = (char *)strrchr(argv[0], '/') + 1;

    krb5_init_context(&context);
    setup_com_err(context);

	/* Use Syslog for Messages */
#ifndef LOG_AUTH        /* 4.2 syslog */
#define LOG_AUTH 0
    openlog(argv[0], LOG_CONS|LOG_NDELAY|LOG_PID, LOG_LOCAL6);
#else
    openlog(argv[0], LOG_AUTH|LOG_CONS|LOG_NDELAY|LOG_PID, LOG_LOCAL6);
#endif  /* LOG_AUTH */

    process_args(context, argc, argv);           /* includes reading master key */

    setup_signal_handlers();

    if (retval = init_db(context, dbm_db_name, master_princ,&master_keyblock)) {
	com_err(argv[0], retval, "while initializing database");
	exit(1);
    }

    if (retval = setup_network(context, argv[0])) {
	exit(1);
    }

    syslog(LOG_AUTH | LOG_INFO, "Admin Server Commencing Operation");

    if (retval = adm5_listen_and_process(context, argv[0])){
        krb5_free_principal(context, client_server_info.server);
	com_err(argv[0], retval, "while processing network requests");
	errout++;
    }

    free(client_server_info.name_of_service);
    krb5_free_principal(context, client_server_info.server);

    if (errout = closedown_network(argv[0])) {
	com_err(argv[0], retval, "while shutting down network");
	retval = retval + errout;
    }

    if (errout = closedown_db(context)) {
	com_err(argv[0], retval, "while closing database");
	retval = retval + errout;
    }

    syslog(LOG_AUTH | LOG_INFO, "Admin Server Shutting Down");

    printf("Admin Server (kadmind) has completed operation.\n");

    exit(retval);
}

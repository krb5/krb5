/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include    <stdio.h>
#include    <string.h>
#include    <unistd.h>

#include    <kadm5/adb.h>
#include    "import_err.h"
#include    "import.h"

#define	TMP_POLICY_FMT   "/krb5/#ovsec_import_policy.%d"

int
main(int argc, char *argv[])
{
    char		*filename,
			*whoami;
    int			ret, merge_princs;
    FILE		*fp;
    osa_adb_policy_t	policy_db;
    char		pol_dbfile[BUFSIZ];
    kadm5_config_params	params;
    krb5_context context;
    
    filename = NULL;
    initialize_imp_error_table();
    initialize_adb_error_table();
    krb5_init_context(&context);
    krb5_init_ets(context);
    
    whoami = argv[0];
    merge_princs = 0;
    while(--argc) {
	if(*++argv == NULL)
	    break;
	if (!strcmp(*argv, "-merge_princs")) {
	     merge_princs++;
	     continue;
	}
	if (*argv[0] == '-') {
	    com_err(whoami, IMPORT_UNK_OPTION, NULL);
	    exit(2);
	}
	if(filename == NULL) 
	    filename = *argv;
	else {
	    com_err(whoami, IMPORT_UNK_OPTION, NULL);
	    exit(2);
	}
    }
    if(filename != NULL) {
	if ((fp = fopen(filename, "r")) == NULL) {
	    com_err(whoami, errno, "%s (%s)", error_message(IMPORT_OPEN_DUMP),
		    filename);
	    exit(2);
	}
    } else fp = stdin;

    sprintf(pol_dbfile, TMP_POLICY_FMT, getpid());
    if(access(pol_dbfile, F_OK) == 0) {
	if(unlink(pol_dbfile) != 0)
	    return errno;
    }

    params.mask = 0;
    if (ret = kadm5_get_config_params(context, NULL, NULL, &params,
				      &params)) {
	 com_err(whoami, ret, error_message(IMPORT_GET_PARAMS));
	 exit(2);
    }
#define REQUIRED_MASK (KADM5_CONFIG_DBNAME | \
		       KADM5_CONFIG_ADBNAME)
    if ((params.mask & REQUIRED_MASK) != REQUIRED_MASK) {
	 com_err(whoami, KADM5_BAD_SERVER_PARAMS,
		 error_message(IMPORT_GET_PARAMS));
	 exit(2);
    }
    /*
     * This trick lets me use the temporary policy db name but the
     * standard policy db lockfile, thus ensuring that no one changes
     * the policy while this program is working.
     */
    params.admin_dbname = pol_dbfile;
    
    if((ret = osa_adb_open_policy(&policy_db, &params)) != OSA_ADB_OK) {
	 com_err(whoami, ret, error_message(IMPORT_RENAME_OPEN));
	 exit(2);
    }
    if ((ret = osa_adb_get_lock(policy_db, OSA_ADB_PERMANENT) != OSA_ADB_OK)) {
	 com_err(whoami, ret, error_message(IMPORT_RENAME_LOCK));
	 exit(2);
    }
    if (merge_princs) {
	 if ((ret = krb5_db_set_name(context, params.dbname)) ||
	     (ret = krb5_db_init(context))) {
	      com_err(whoami, ret, error_message(IMPORT_RENAME_OPEN));
	      exit(2);
	 }
    }
    
    if((ret = import_file(context, fp, merge_princs, policy_db)) !=
       OSA_ADB_OK) { 
	unlink(pol_dbfile);
	com_err(whoami, ret, error_message(IMPORT_IMPORT));
	exit(2);
    }

    if (merge_princs && (ret = krb5_db_fini(context))) {
	 com_err(whoami, ret, error_message(IMPORT_RENAME_CLOSE));
	 exit(2);
    }

    kadm5_free_config_params(context, &params);
    params.mask = 0;
    if (ret = kadm5_get_config_params(context, NULL, NULL, &params,
				      &params)) {
	 com_err(whoami, ret, error_message(IMPORT_GET_PARAMS));
	 exit(2);
    }
    
    if (access(params.admin_dbname, F_OK) == 0) {
	puts(error_message(IMPORT_WARN_DB));
	if(!confirm()) {
	    com_err(whoami, IMPORT_FAILED, NULL);
	    exit(2);
	}
    }
    
    if((ret = osa_adb_open_policy(&policy_db, &params)) != OSA_ADB_OK) {
	 com_err(whoami, ret, error_message(IMPORT_RENAME_OPEN));
	 exit(2);
    }
    if ((ret = osa_adb_get_lock(policy_db, OSA_ADB_PERMANENT) != OSA_ADB_OK)) {
	 com_err(whoami, ret, error_message(IMPORT_RENAME_LOCK));
	 exit(2);
    }
    if (rename(pol_dbfile, params.admin_dbname) != 0) {
	 com_err(whoami, IMPORT_RENAME_FAILED, NULL);

	 /* WARNING!  Permanent lock is not replaced.  This will */
	 /* require manual administrative action! */
	 exit(2);
    }
    if ((ret = osa_adb_release_lock(policy_db)) != OSA_ADB_OK) {
	 com_err(whoami, ret, error_message(IMPORT_RENAME_UNLOCK));

	 /* WARNING!  Permanent lock is not replaced.  This will */
	 /* require manual administrative action! */
	 exit(2);
    }
    if ((ret = osa_adb_close_policy(policy_db)) != OSA_ADB_OK) {
	 com_err(whoami, ret, error_message(IMPORT_RENAME_CLOSE));
	 exit(2);
    }
    exit(0);
}

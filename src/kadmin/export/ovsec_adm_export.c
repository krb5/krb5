/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include    <sys/types.h>
#include    <sys/file.h>
#include    <sys/stat.h>
#include    <fcntl.h>
#include    <kadm5/adb.h>
#include    <stdio.h>
#include    <string.h>
#include    <unistd.h>
#include    "export_err.h"
#include    "local.h"

int
main(int argc, char *argv[])
{
    char		*filename;
    struct  retdata	d;
    struct  stat	statb;
    int			ret, fd;
    time_t		now;
    char		*whoami = argv[0];
    osa_adb_policy_t	policy_db;
    kadm5_config_params	params;
    
    memset(&params, 0, sizeof(params));
    memset(&d, 0, sizeof(d));
    
    filename = NULL;
    initialize_exp_error_table();
    initialize_adb_error_table();
    krb5_init_context(&d.context);
    krb5_init_ets(d.context);
    
    while(--argc) {
	if(*++argv == NULL)
	    break;
	if(!strcmp(*argv, "-princ")) {
	     params.dbname = *++argv;
	     params.mask |= KADM5_CONFIG_DBNAME;
	     continue;
	}
	if(!strcmp(*argv, "-policy")) {
	     params.admin_dbname = *++argv;
	     params.mask |= KADM5_CONFIG_ADBNAME;
	     continue;
	}
	if(!strcmp(*argv, "-ovsec")) {
	     d.ovsec_compat++;
	     continue;
	}
	if (*argv[0] == '-') {
	    com_err(whoami, EXPORT_UNK_OPTION, NULL);
	    exit(2);
	}
	if(filename == NULL) 
	    filename = *argv;
	else {
	    com_err(whoami, EXPORT_UNK_OPTION, NULL);
	    exit(2);
	}
    }

    if (ret = kadm5_get_config_params(d.context, NULL, NULL, &params,
				      &params)) {
	 com_err(whoami, ret, error_message(EXPORT_GET_CONFIG));
	 exit(2);
    }
#define REQUIRED_MASK (KADM5_CONFIG_DBNAME | \
		       KADM5_CONFIG_ADBNAME)
    if ((params.mask & REQUIRED_MASK) != REQUIRED_MASK) {
	 com_err(whoami, KADM5_BAD_SERVER_PARAMS,
		 error_message(EXPORT_GET_CONFIG));
	 exit(2);
    }
    
    if(filename != NULL) {
	if((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0400)) == -1) {
	    com_err(whoami, errno, "%s (%s)",
		    error_message(EXPORT_OUTPUT_OPEN), filename);
	    exit(2);
	}
	if(fstat(fd, &statb) == -1) {
	    com_err(whoami, errno, "%s (%s)",
		    error_message(EXPORT_OUTPUT_STAT), filename);
	    exit(2);
	}
	if(S_ISREG(statb.st_mode)) {
	    int mask = umask(0);
	    (void) umask(mask);
	    if (fchmod(fd, (0400 & ~mask)) == -1) {
		com_err(whoami, errno, "%s (%s)",
			error_message(EXPORT_OUTPUT_CHMOD), filename);
		exit(2);
	    }
	}
	if ((d.fp = fdopen(fd, "w")) == NULL) {
	    com_err(whoami, errno, "%s (%s)",
		    error_message(EXPORT_OUTPUT_OPEN), filename);
	    exit(2);
	}
    } else d.fp = stdout;

    if((ret = osa_adb_open_policy(&policy_db, &params)) != OSA_ADB_OK) {
	 com_err(argv[0], ret, error_message(EXPORT_DATABASE_OPEN));
	 exit(2);
    }
    if ((ret = osa_adb_get_lock(policy_db, OSA_ADB_SHARED) != OSA_ADB_OK)) {
	 com_err(argv[0], ret, error_message(EXPORT_LOCK));
	 exit(2);
    }
    
    d.count = 0;
    
    now = time(NULL);
    if (d.ovsec_compat)
	 fprintf(d.fp, "OpenV*Secure V1.0\t%s", ctime(&now));
    else
	 fprintf(d.fp, "Kerberos KADM5 database V2.0\t%s",
		 ctime(&now));
    
    if ((ret = export_policy(&d, policy_db)) != OSA_ADB_OK) {
       com_err(whoami, ret, "%s (%s)", error_message(EXPORT_POLICY),
	       params.admin_dbname);
       exit(2);
    }
    if ((ret = export_principal(&d, &params)) !=
	 OSA_ADB_OK) { 
       com_err(whoami, ret, "%s (%s)", error_message(EXPORT_PRINCIPAL),
	       params.dbname);
       exit(2);
    }
    fprintf(d.fp, "End of Database\t%d\trecords\n", d.count);

    if ((ret = osa_adb_release_lock(policy_db)) != OSA_ADB_OK) {
	 com_err(argv[0], ret, error_message(EXPORT_UNLOCK));
	 exit(2);
    }
    if ((ret = osa_adb_close_policy(policy_db)) != OSA_ADB_OK) {
	 com_err(argv[0], ret, error_message(EXPORT_CLOSE));
	 exit(2);
    }
    
    fprintf(stderr, error_message(EXPORT_NO_ERR), d.count,
	    (d.count == 1) ? error_message(EXPORT_SINGLE_RECORD) :
	    error_message(EXPORT_PLURAL_RECORDS));
    exit(0);
}
    
	
	    

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* #pragma ident	"@(#)kproplog.c	1.4	04/03/19 SMI" */

/*
 * This module will parse the update logs on the master or slave servers.
 */

#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <limits.h>
#include <locale.h>
#include <syslog.h>
#include "k5-int.h"
#include <kdb_log.h>
#include <kadm5/admin.h>

#ifndef gettext
#define textdomain(X) 0
#endif

static char	*progname;

static void
usage()
{
    (void) fprintf(stderr, _("\nUsage: %s [-h] [-v] [-e num]\n\n"),
		   progname);
    exit(1);
}

/*
 * Print the individual types if verbose mode was specified.
 */
static void
print_attr(kdbe_attr_type_t type)
{
    switch (type) {
    case AT_ATTRFLAGS:
	(void) printf(_("\t\tAttribute flags\n"));
	break;
    case AT_MAX_LIFE:
	(void) printf(_("\t\tMaximum ticket life\n"));
	break;
    case AT_MAX_RENEW_LIFE:
	(void) printf(_("\t\tMaximum renewable life\n"));
	break;
    case AT_EXP:
	(void) printf(_("\t\tPrincipal expiration\n"));
	break;
    case AT_PW_EXP:
	(void) printf(_("\t\tPassword expiration\n"));
	break;
    case AT_LAST_SUCCESS:
	(void) printf(_("\t\tLast successful auth\n"));
	break;
    case AT_LAST_FAILED:
	(void) printf(_("\t\tLast failed auth\n"));
	break;
    case AT_FAIL_AUTH_COUNT:
	(void) printf(_("\t\tFailed passwd attempt\n"));
	break;
    case AT_PRINC:
	(void) printf(_("\t\tPrincipal\n"));
	break;
    case AT_KEYDATA:
	(void) printf(_("\t\tKey data\n"));
	break;
    case AT_TL_DATA:
	(void) printf(_("\t\tTL data\n"));
	break;
    case AT_LEN:
	(void) printf(_("\t\tLength\n"));
	break;
    case AT_MOD_PRINC:
	(void) printf(_("\t\tModifying principal\n"));
	break;
    case AT_MOD_TIME:
	(void) printf(_("\t\tModification time\n"));
	break;
    case AT_MOD_WHERE:
	(void) printf(_("\t\tModified where\n"));
	break;
    case AT_PW_LAST_CHANGE:
	(void) printf(_("\t\tPassword last changed\n"));
	break;
    case AT_PW_POLICY:
	(void) printf(_("\t\tPassword policy\n"));
	break;
    case AT_PW_POLICY_SWITCH:
	(void) printf(_("\t\tPassword policy switch\n"));
	break;
    case AT_PW_HIST_KVNO:
	(void) printf(_("\t\tPassword history KVNO\n"));
	break;
    case AT_PW_HIST:
	(void) printf(_("\t\tPassword history\n"));
	break;
    } /* switch */

}
/*
 * Print the update entry information
 */
static void
print_update(kdb_hlog_t *ulog, uint32_t entry, bool_t verbose)
{
    XDR			xdrs;
    uint32_t		start_sno, i, j, indx;
    char		*dbprinc;
    kdb_ent_header_t	*indx_log;
    kdb_incr_update_t	upd;

    if (entry && (entry < ulog->kdb_num))
	start_sno = ulog->kdb_last_sno - entry;
    else
	start_sno = ulog->kdb_first_sno - 1;

    for (i = start_sno; i < ulog->kdb_last_sno; i++) {
	indx = i % ulog->kdb_num;

	indx_log = (kdb_ent_header_t *)INDEX(ulog, indx);

	/*
	 * Check for corrupt update entry
	 */
	if (indx_log->kdb_umagic != KDB_ULOG_MAGIC) {
	    (void) fprintf(stderr,
			   _("Corrupt update entry\n\n"));
	    exit(1);
	}

	(void) memset((char *)&upd, 0, sizeof (kdb_incr_update_t));
	xdrmem_create(&xdrs, (char *)indx_log->entry_data,
		      indx_log->kdb_entry_size, XDR_DECODE);
	if (!xdr_kdb_incr_update_t(&xdrs, &upd)) {
	    (void) printf(_("Entry data decode failure\n\n"));
	    exit(1);
	}

	(void) printf("---\n");
	(void) printf(_("Update Entry\n"));

	(void) printf(_("\tUpdate serial # : %u\n"),
		      indx_log->kdb_entry_sno);

	(void) printf(_("\tUpdate operation : "));
	if (upd.kdb_deleted)
	    (void) printf(_("Delete\n"));
	else
	    (void) printf(_("Add\n"));

	dbprinc = malloc(upd.kdb_princ_name.utf8str_t_len + 1);
	if (dbprinc == NULL) {
	    (void) printf(_("Could not allocate "
			    "principal name\n\n"));
	    exit(1);
	}
	(void) strncpy(dbprinc, upd.kdb_princ_name.utf8str_t_val,
		       (upd.kdb_princ_name.utf8str_t_len + 1));
	dbprinc[upd.kdb_princ_name.utf8str_t_len] = 0;
	(void) printf(_("\tUpdate principal : %s\n"), dbprinc);

	(void) printf(_("\tUpdate size : %u\n"),
		      indx_log->kdb_entry_size);

	(void) printf(_("\tUpdate committed : %s\n"),
		      indx_log->kdb_commit ? "True" : "False");

	if (indx_log->kdb_time.seconds == 0L)
	    (void) printf(_("\tUpdate time stamp : None\n"));
	else
	    (void) printf(_("\tUpdate time stamp : %s"),
			  ctime((time_t *)&(indx_log->kdb_time.seconds)));

	(void) printf(_("\tAttributes changed : %d\n"),
		      upd.kdb_update.kdbe_t_len);

	if (verbose)
	    for (j = 0; j < upd.kdb_update.kdbe_t_len; j++)
		print_attr(
		    upd.kdb_update.kdbe_t_val[j].av_type);

	xdr_free(xdr_kdb_incr_update_t, (char *)&upd);
	free(dbprinc);
    } /* for */
}

int
main(int argc, char **argv)
{
    int			c;
    bool_t		verbose = FALSE;
    bool_t		headeronly = FALSE;
    uint32_t		entry = 0;
    krb5_context	context;
    kadm5_config_params	params;
    kdb_log_context	*log_ctx;
    kdb_hlog_t		*ulog = NULL;
    char		**db_args = NULL; /* XXX */

    (void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif /* TEXT_DOMAIN */

    (void) textdomain(TEXT_DOMAIN);

    progname = argv[0];

    while ((c = getopt(argc, argv, "vhe:")) != -1) {
	switch (c) {
	case 'h':
	    headeronly = TRUE;
	    break;
	case 'e':
	    entry = atoi(optarg);
	    break;
	case 'v':
	    verbose = TRUE;
	    break;
	default:
	    usage();
	}
    }

    if (krb5_init_context(&context)) {
	(void) fprintf(stderr,
		       _("Unable to initialize Kerberos\n\n"));
	exit(1);
    }

    (void) memset((char *)&params, 0, sizeof (params));

    if (kadm5_get_config_params(context, 1, &params, &params)) {
	(void) fprintf(stderr,
		       _("Couldn't read database_name\n\n"));
	exit(1);
    }

    (void) printf(_("\nKerberos update log (%s.ulog)\n"),
		  params.dbname);

    if (ulog_map(context, params.iprop_logfile, 0, FKPROPLOG, db_args)) {
	(void) fprintf(stderr, _("Unable to map log file "
				 "%s.ulog\n\n"), params.dbname);
	exit(1);
    }

    log_ctx = context->kdblog_context;
    if (log_ctx)
	ulog = log_ctx->ulog;
    else {
	(void) fprintf(stderr, _("Unable to map log file "
				 "%s.ulog\n\n"), params.dbname);
	exit(1);
    }

    if (ulog->kdb_hmagic != KDB_ULOG_HDR_MAGIC) {
	(void) fprintf(stderr,
		       _("Corrupt header log, exiting\n\n"));
	exit(1);
    }

    (void) printf(_("Update log dump :\n"));
    (void) printf(_("\tLog version # : %u\n"), ulog->db_version_num);
    (void) printf(_("\tLog state : "));
    switch (ulog->kdb_state) {
    case KDB_STABLE:
	(void) printf(_("Stable\n"));
	break;
    case KDB_UNSTABLE:
	(void) printf(_("Unstable\n"));
	break;
    case KDB_CORRUPT:
	(void) printf(_("Corrupt\n"));
	break;
    default:
	(void) printf(_("Unknown state: %d\n"),
		      ulog->kdb_state);
	break;
    }
    (void) printf(_("\tEntry block size : %u\n"), ulog->kdb_block);
    (void) printf(_("\tNumber of entries : %u\n"), ulog->kdb_num);

    if (ulog->kdb_last_sno == 0)
	(void) printf(_("\tLast serial # : None\n"));
    else {
	if (ulog->kdb_first_sno == 0)
	    (void) printf(_("\tFirst serial # : None\n"));
	else {
	    (void) printf(_("\tFirst serial # : "));
	    (void) printf("%u\n", ulog->kdb_first_sno);
	}

	(void) printf(_("\tLast serial # : "));
	(void) printf("%u\n", ulog->kdb_last_sno);
    }

    if (ulog->kdb_last_time.seconds == 0L) {
	(void) printf(_("\tLast time stamp : None\n"));
    } else {
	if (ulog->kdb_first_time.seconds == 0L)
	    (void) printf(_("\tFirst time stamp : None\n"));
	else {
	    (void) printf(_("\tFirst time stamp : %s"),
			  ctime((time_t *)
				&(ulog->kdb_first_time.seconds)));
	}

	(void) printf(_("\tLast time stamp : %s\n"),
		      ctime((time_t *)&(ulog->kdb_last_time.seconds)));
    }

    if ((!headeronly) && ulog->kdb_num) {
	print_update(ulog, entry, verbose);
    }

    (void) printf("\n");

    return (0);
}

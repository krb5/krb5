/*
 * kadmin/v5client/kadmin5.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 */

/*
 * kadmin5.c	- Perform administrative functions using the new
 *		  administrative protocol.
 */
#include "k5-int.h"
#include "com_err.h"
#include "adm.h"
#include "kadmin5.h"
#if	HAVE_PWD_H
#include <pwd.h>
#endif	/* HAVE_PWD_H */
#if	HAVE_REGEX_H
#include <regex.h>
#endif	/* HAVE_REGEX_H */

/*
 * Use compile(3) if no regcomp present.
 */
#if	!defined(HAVE_REGCOMP) && defined(HAVE_REGEXP_H)
#define	INIT		char *sp = instring;
#define	GETC()		(*sp++)
#define	PEEKC()		(*sp)
#define	UNGETC(c)	(--sp)
#define	RETURN(c)	return(c)
#define	ERROR(c)	
#define	RE_BUF_SIZE	1024
#include <regexp.h>
#endif	/* !HAVE_REGCOMP && HAVE_REGEXP_H */

/*
 * Global storage.
 */
int		exit_status = 0;
krb5_context	kcontext;
char		*programname = (char *) NULL;
char		*requestname = (char *) NULL;
krb5_boolean	multiple = 0;
char 		*principal_name = (char *) NULL;
char		*password_prompt = (char *) NULL;
char		*ccname2use = (char *) NULL;
krb5_timestamp	ticket_life = 0;
krb5_boolean	delete_ccache = 0;

extern krb5_kt_ops krb5_ktf_writable_ops;

/*
 * Own storage
 */
static char 		*realm_name = (char *) NULL;
#if	!HAVE_RE_COMP && !HAVE_REGCOMP && !HAVE_REGEXP_H
static char		*re_string = (char *) NULL;
#endif	/* !HAVE_RE_COMP && !HAVE_REGCOMP && !HAVE_REGEXP_H */

/*
 * Static strings.
 */
static const char *help_option		= "-help";
static const char *verbose_option	= "-verbose";
static const char *force_option		= "-force";
static const char *kadmin_instance	= "admin";

static const char *wr_ktab_type		= "WRFILE";

static const char *gent_opterr_fmt	= "- cannot decode protocol";
static const char *gen_conn_err_fmt	= "- cannot connect to server";
static const char *db_print_header	= "------------------------------------\n";
static const char *db_print_1_fmt	= "Principal: %s\n";
static const char *db_print_2_fmt	= "Maximum ticket lifetime: %s\n";
static const char *db_print_2a_fmt	= "Maximum renewable lifetime: %s\n";
static const char *db_print_3_fmt	= "Principal expiration: %s\n";
static const char *db_print_3a_fmt	= "Password expiration: %s\n";
static const char *db_print_4_fmt	= "Last password change: %s\n";
static const char *db_print_5_fmt	= "Last successful entry: %s\n";
static const char *db_print_6_fmt	= "Last unsuccessful entry: %s";
static const char *db_print_6_opt_fmt	= " - failed %d times";
static const char *db_print_7_fmt	= "Last modified by: %s (%s)\n";
static const char *db_print_8_fmt	= "Flags: %s\n";
static const char *db_print_ufo_tl_fmt	= "Unknown Tagged Data: Tag=%d, Length=%d\n";
static const char *db_print_9_fmt	= "Key: Type=%s, Salt=%s, Version=%d\n";
static const char *db_print_trailer	= "------------------------------------\n";

static const char *db_indef_dt_msg	= "indefinite";
static const char *db_never_msg		= "never";
static const char *db_none_msg		= "none";

static const char *sprinc_usage_fmt	= "usage is %s principal [...]";
static const char *add_usage_fmt	= "usage is %s principal [attributes...]";
static const char *add_prompt1_fmt	= "   Enter new password for %s : ";
static const char *add_prompt2_fmt	= "Re-enter new password for %s : ";
static const char *add_succ_fmt		= "principal %s added";
static const char *add_protoerr_fmt	= "- protocol encode error";
static const char *add_noconf_fmt	= "password not confirmed";
static const char *add_synerr_fmt	= "syntax error";
static const char *cpw_usage_fmt	= "usage is %s principal";
static const char *cpw_prompt1_fmt	= "   Enter new password for %s: ";
static const char *cpw_prompt2_fmt	= "Re-enter new password for %s: ";
static const char *cpw_succ_fmt		= "password changed for %s";
static const char *cpw_nochange_fmt	= "password not changed for %s";
static const char *dprinc_usage_fmt	= "usage is %s [%s] principal [...]";
static const char *del_conf_fmt		= "Enter '%c' to delete principal %s: ";
static const char del_conf_char		= 'y';
static const char *del_princ_fmt	= "principal %s deleted.";
static const char *del_noconf_fmt	= "not confirmed - principal %s not deleted";
static const char *xst_ktab_name_fmt	= "%s:%s-new-srvtab";
static const char *xst_k4tab_name_fmt	= "%s-new-v4-srvtab";
static const char *xst_dfl_ktname	= "DEFAULT";
static const char *xst_usage_fmt	= "usage is %s instance principal [...]";
static const char *xst_wr_reg_fmt	= "(%s) cannot register writeable keytable";
static const char *xst_inst2long_fmt	= "'%s' is too long for a filename, using '%s' instead";
static const char *xst_nokeytab_fmt	= "cannot open key table %s";
static const char *xst_nodeskey_fmt	= "%s does not have a DES key";
static const char *xst_adderr_fmt	= "cannot add entry %s";
static const char *xst_success_fmt	= "extracted entry %s to key table %s";
static const char *xst_proto_fmt	= "cannot decode service key table entry from protocol";
static const char *xst_kclose_fmt	= "cannot close key table %s";
static const char *mod_usage_fmt	= "usage is %s principal [attributes...]";
static const char *mod_succ_fmt		= "principal %s modified.";
static const char *mod_protoerr_fmt	= "protocol encode error";
static const char *mod_synerr_fmt	= "syntax error";
static const char *rprinc_usage_fmt	= "usage is %s [%s] principal principal";
static const char *ren_conf_fmt		= "Enter '%c' to rename principal %s to %s: ";
static const char ren_conf_char		= 'y';
static const char *ren_princ_fmt	= "principal %s renamed to %s.";
static const char *ren_noconf_fmt	= "not confirmed - principal %s not renamed to %s.";
#if	HAVE_RE_COMP || HAVE_REGCOMP || HAVE_REGEXP_H
static const char *lprinc_usage_fmt	= "usage is %s [%s] <regexp>";
#else	/* HAVE_RE_COMP || HAVE_REGCOMP || HAVE_REGEXP_H */
static const char *lprinc_usage_fmt	= "usage is %s [%s] princpal";
#endif	/* HAVE_RE_COMP || HAVE_REGCOMP || HAVE_REGEXP_H */
static const char *lprinc_all_regexp	= ".*";
static const char *lprinc_regexp_fmt	= "%s - regular expression error: %s";
static const char *lprinc_regsrch_fmt	= "%s on %s - RE search error: %s";
static const char *lprinc_first_msg	= "first database entry";
static const char *cant_get_fmt		= "cannot get entry for %s";
static const char *no_memory_fmt	= "cannot get memory";
static const char *lang_usage_fmt	= "usage is %s language";
static const char *cd_cannot_fmt	= "cannot change directory to %s";
static const char *cd_usage_fmt		= "usage is %s directory";
static const char *pwd_mess_fmt		= "Current directory is %s\n";
static const char *pwd_err_fmt		= "cannot get current directory: %s";
static const char *pwd_usage_fmt	= "usage is %s";
static const char *kadmin_badtime_fmt	= "%s is a bad time value";
static const char *kadmin_usage_fmt	= "usage is %s [-c ccache] [-r realm] [-p principal] [-l lifetime] [-dms] [command ...]";
static const char *kadmin_sd_err_fmt	= "-d and -s are mutually exclusive";
static const char *kadmin_defrealm_msg	= ": cannot get default realm";
static const char *kadmin_srealm_fmt	= ": cannot set realm to \"%s\"";
static const char *kadmin_ccache_fmt	= ": cannot find credential cache %s";
static const char *kadmin_nopname_msg	= ": cannot find a principal name";
static const char *kadmin_unparse_msg	= ": cannot flatten principal name";
static const char *kadmin_nocomp_msg	= ": no components in principal name";
static const char *kadmin_noprompt_msg	= ": cannot make password prompt";

static const char *kadmin_pprompt_fmt	= "Enter password for %s: ";

#if	!HAVE_RE_COMP && !HAVE_REGCOMP && !HAVE_REGEXP_H
/*
 * re_comp()	- Compile a regular expression for subsequent usage by re_exec
 *
 * This routine is only a shell.  Null expressions or expressions matching
 * lprinc_all_regexp are taken to match everything, all others are
 * interpreted as "string".*.
 */
static char *
re_comp(rstring)
    char	*rstring;
{
    if (strlen(rstring) && strcmp(rstring, lprinc_all_regexp)) {
	re_string = rstring;
    }
    else {
	re_string = (char *) NULL;
    }
    return((char *) NULL);
}

/*
 * re_exec()	- Attempt to match a string to a regular expression previously
 *		  specified to re_comp().
 *
 * This routine is only a shell.
 */
static int
re_exec(sstring)
    char	*sstring;
{
    if (re_string)
	return(strncmp(sstring, re_string, strlen(re_string)) ? 0 : 1);
    else
	return(1);
}
#endif	/* !HAVE_RE_COMP && !HAVE_REGCOMP && !HAVE_REGEXP_H */

/*
 * kadmin_get_entry()	- Get a principal entry.
 */
static krb5_error_code
kadmin_get_entry(pname, validp, dbentp, nextp)
    char		*pname;
    krb5_ui_4		*validp;
    krb5_db_entry	*dbentp;
    char		**nextp;
{
    krb5_error_code	kret;
    krb5_int32		proto_stat;
    krb5_int32		ncomps;
    krb5_data		*complist;
    char		*pword;

    if (!(kret = net_do_proto(KRB5_ADM_INQ_PRINC_CMD,
			      pname,
			      (char *) NULL,
			      0,
			      (krb5_data *) NULL,
			      &proto_stat,
			      &ncomps,
			      &complist,
			      0))) {
	if (proto_stat == KRB5_ADM_SUCCESS) {
	    *nextp = (char *) malloc((size_t) complist[0].length + 1);
	    if (*nextp) {
		strncpy(*nextp, complist[0].data, (size_t) complist[0].length);
		(*nextp)[complist[0].length] = '\0';
	    }
	    if (!(kret = krb5_adm_proto_to_dbent(kcontext,
						 ncomps-1,
						 &complist[1],
						 validp,
						 dbentp,
						 &pword))) {
		if (pword)
		    krb5_xfree(pword);
	    }
	    else {
		com_err(requestname, kret, gent_opterr_fmt);
	    }
	    krb5_free_adm_data(kcontext, ncomps, complist);
	}
	else
	    kret = EIO;
    }
    return(kret);
}

/*
 * kadmin_princ_entry()	- Print out a database entry.
 */
static void
kadmin_print_entry(name, valid, dbentp)
    char		*name;
    krb5_ui_4		valid;
    krb5_db_entry	*dbentp;
{
    krb5_tl_data	*tl;
    krb5_tl_mod_princ	*modprinc;
    krb5_timestamp	now;
    int			i;
    char		keytype[128];
    char		salttype[128];

    printf(db_print_header);
    printf(db_print_1_fmt, name);
    printf(db_print_2_fmt,
	   ((valid & KRB5_ADM_M_MAXLIFE) ?
	    delta2string(dbentp->max_life) : db_indef_dt_msg));
    printf(db_print_2a_fmt,
	   ((valid & KRB5_ADM_M_MAXRENEWLIFE) ?
	    delta2string(dbentp->max_renewable_life) : db_indef_dt_msg));
    printf(db_print_3_fmt,
	   ((valid & KRB5_ADM_M_EXPIRATION) ?
	    abs2string(dbentp->expiration) : db_never_msg));
    printf(db_print_3a_fmt,
	   ((valid & KRB5_ADM_M_PWEXPIRATION) ?
	    abs2string(dbentp->pw_expiration) : db_never_msg));
    printf(db_print_5_fmt,
	   ((valid & KRB5_ADM_M_LASTSUCCESS) ?
	    abs2string(dbentp->last_success) : db_never_msg));
    if ((valid & KRB5_ADM_M_FAILCOUNT) && (dbentp->fail_auth_count > 0)) {
	printf(db_print_6_fmt,
	       ((valid & KRB5_ADM_M_LASTFAILED) ?
		abs2string(dbentp->last_failed) : db_never_msg));
	printf(db_print_6_opt_fmt, dbentp->fail_auth_count);
	printf("\n");
    }

    printf(db_print_8_fmt,
	   ((valid & KRB5_ADM_M_FLAGS) ?
	    dbflags2string(dbentp->attributes) : ""));

    for (tl=dbentp->tl_data; tl; tl = tl->tl_data_next) {
	switch (tl->tl_data_type) {
	case KRB5_TL_LAST_PWD_CHANGE:
	    krb5_kdb_decode_int32(tl->tl_data_contents, now);
	    printf(db_print_4_fmt, abs2string(now));
	    break;
	case KRB5_TL_MOD_PRINC:
	    krb5_kdb_decode_int32(tl->tl_data_contents, now);
	    printf(db_print_7_fmt, &tl->tl_data_contents[4], abs2string(now));
	    break;
	default:
	    printf(db_print_ufo_tl_fmt, tl->tl_data_type, tl->tl_data_length);
	    break;
	}
    }
    for (i=0; i<dbentp->n_key_data; i++) {
	krb5_keytype_to_string((krb5_keytype) dbentp->key_data[i].
			       key_data_type[0],
			       keytype,
			       sizeof(keytype));
	krb5_salttype_to_string((krb5_keytype) dbentp->key_data[i].
				key_data_type[1],
				salttype,
				sizeof(salttype));
	printf(db_print_9_fmt, keytype, salttype,
	       (int) dbentp->key_data[i].key_data_kvno);
    }

    printf(db_print_trailer);
}

/*
 * Dispatch procedures.
 */

/*
 * kadmin_show_principal()	- Show a principal.
 */
void
kadmin_show_principal(argc, argv)
    int 	argc;
    char	*argv[];
{
    int			i;
    krb5_error_code	kret;
    char		*xxx;
    krb5_ui_4		valid;
    krb5_db_entry	*dbentry;

    requestname = argv[0];
    if (argc == 1) {
	com_err(argv[0], 0, sprinc_usage_fmt, argv[0]);
	return;
    }
    for (i=1; i<argc; i++) {
	if (dbentry = (krb5_db_entry *) malloc(sizeof(krb5_db_entry))) {
	    memset((char *) dbentry, 0, sizeof(*dbentry));
	    kret = kadmin_get_entry(argv[i], &valid, dbentry, &xxx);
	    if (kret) {
		com_err(argv[0], 0, cant_get_fmt, argv[i]);
		break;
	    }
	    if (xxx)
		free(xxx);
	    kadmin_print_entry(argv[i], valid, dbentry);
	    krb5_db_free_principal(kcontext, dbentry, 1);
	}
	else {
	    com_err(argv[0], 0, no_memory_fmt);
	}
    }
}

/*
 * kadmin_add_new_key()	- Add a new principal.
 */
void
kadmin_add_new_key(argc, argv)
    int 	argc;
    char	*argv[];
{
    krb5_error_code	kret;
    char		*p1, *p2;
    char		*npass;
    int			nplen;
    krb5_int32		proto_stat;
    krb5_int32		nargs;
    krb5_data		*arglist;
    krb5_int32		ncomps;
    krb5_data		*complist;
    char		*principal;
    krb5_ui_4		valid;
    krb5_db_entry	*dbentp;

    requestname = argv[0];
    if (argc < 2) {
	com_err(argv[0], 0, add_usage_fmt, argv[0]);
	help_princ_options();
	return;
    }
    principal = argv[1];
    argc -= 2;
    argv += 2;

    p1 = (char *) malloc(strlen(add_prompt1_fmt)+strlen(principal)+1);
    p2 = (char *) malloc(strlen(add_prompt2_fmt)+strlen(principal)+1);
    npass = (char *) malloc(KRB5_ADM_MAX_PASSWORD_LEN);
    dbentp = (krb5_db_entry *) malloc(sizeof(krb5_db_entry));
    if (p1 && p2 && npass && dbentp) {
	memset((char *) dbentp, 0, sizeof(krb5_db_entry));
	valid = 0;
	if (parse_princ_options(argc, argv, &valid, dbentp)) {
	    if (!(kret = net_connect())) {
		valid |= KRB5_ADM_M_SET;	/* We are setting options */
		sprintf(p1, add_prompt1_fmt, principal);
		sprintf(p2, add_prompt2_fmt, principal);
		nplen = KRB5_ADM_MAX_PASSWORD_LEN;
		valid |= KRB5_ADM_M_PASSWORD;	/* We have a password */
		if (!(kret = krb5_read_password(kcontext,
						p1, p2, npass, &nplen))) {
		    npass[nplen] = '\0';
		    nargs = ncomps = 0;
		    if (!(kret = krb5_adm_dbent_to_proto(kcontext,
							 valid,
							 dbentp,
							 npass,
							 &nargs,
							 &arglist)) &&
			!(kret = net_do_proto(KRB5_ADM_ADD_PRINC_CMD,
					      principal,
					      (char *) NULL,
					      nargs,
					      arglist,
					      &proto_stat,
					      &ncomps,
					      &complist,
					      1))) {
			if (proto_stat == KRB5_ADM_SUCCESS) {
			    com_err(programname, 0, add_succ_fmt, principal);
			}
		    }
		    else {
			com_err(requestname, kret, add_protoerr_fmt);
		    }
		    if (ncomps)
			krb5_free_adm_data(kcontext, ncomps, complist);
		    if (nargs) 
			krb5_free_adm_data(kcontext, nargs, arglist);
		    memset(npass, 0, KRB5_ADM_MAX_PASSWORD_LEN);
		}
		else {
		    com_err(requestname, 0, add_noconf_fmt);
		}
		net_disconnect(0);
	    }
	    else {
		com_err(requestname, kret, gen_conn_err_fmt);
	    }
	}
	else {
	    com_err(requestname, 0, add_synerr_fmt);
	    help_princ_options();
	}
    }
    else {
	com_err(requestname, 0, no_memory_fmt);
    }
    if (p1)
	free(p1);
    if (p2)
	free(p2);
    if (npass)
	free(npass);
    if (dbentp)
	free(dbentp);
}


/*
 * kadmin_change_pwd()	- Change principal's password.
 */
void
kadmin_change_pwd(argc, argv)
    int 	argc;
    char	*argv[];
{
    krb5_error_code	kret;
    char		*p1, *p2;
    char		*npass;
    int			nplen;
    krb5_int32		proto_stat;
    krb5_int32		ncomps;
    krb5_data		*complist;

    requestname = argv[0];
    if (argc != 2) {
	com_err(argv[0], 0, cpw_usage_fmt, argv[0]);
	return;
    }
    p1 = (char *) malloc(strlen(cpw_prompt1_fmt)+strlen(argv[1])+1);
    p2 = (char *) malloc(strlen(cpw_prompt2_fmt)+strlen(argv[1])+1);
    npass = (char *) malloc(KRB5_ADM_MAX_PASSWORD_LEN);
    if (p1 && p2 && npass) {
	sprintf(p1, cpw_prompt1_fmt, argv[1]);
	sprintf(p2, cpw_prompt2_fmt, argv[1]);

	if (!(kret = net_connect())) {
	    nplen = KRB5_ADM_MAX_PASSWORD_LEN;
	    if (!(kret = krb5_read_password(kcontext,
					    p1,
					    p2,
					    npass,
					    &nplen))) {
		npass[nplen] = '\0';
		if (!(kret = net_do_proto(KRB5_ADM_CHG_OPW_CMD,
					  argv[1],
					  npass,
					  0,
					  (krb5_data *) NULL,
					  &proto_stat,
					  &ncomps,
					  &complist,
					  1))) {
		    if (proto_stat == KRB5_ADM_SUCCESS) {
			com_err(programname, 0, cpw_succ_fmt, argv[1]);
			krb5_free_adm_data(kcontext, ncomps, complist);
		    }
		}
		memset(npass, 0, KRB5_ADM_MAX_PASSWORD_LEN);
	    }
	    else {
		com_err(argv[0], kret, cpw_nochange_fmt, argv[1]);
	    }
	    net_disconnect(0);
	}
	else {
	    com_err(argv[0], kret, gen_conn_err_fmt);
	}
    }
    else {
	com_err(requestname, 0, no_memory_fmt);
    }
    if (p1)
	free(p1);
    if (p2)
	free(p2);
    if (npass)
	free(npass);
}

/*
 * kadmin_add_rnd_key()	- Add principal with random key.
 */
void
kadmin_add_rnd_key(argc, argv)
    int 	argc;
    char	*argv[];
{
    krb5_error_code	kret;
    krb5_int32		proto_stat;
    krb5_int32		nargs;
    krb5_data		*arglist;
    krb5_int32		ncomps;
    krb5_data		*complist;
    char		*principal;
    krb5_ui_4		valid;
    krb5_db_entry	*dbentp;

    requestname = argv[0];
    if (argc < 2) {
	com_err(argv[0], 0, add_usage_fmt, argv[0]);
	help_princ_options();
	return;
    }
    principal = argv[1];
    argc -= 2;
    argv += 2;

    dbentp = (krb5_db_entry *) malloc(sizeof(krb5_db_entry));
    if (dbentp) {
	memset((char *) dbentp, 0, sizeof(krb5_db_entry));
	valid = 0;
	if (parse_princ_options(argc, argv, &valid, dbentp)) {
	    valid |= KRB5_ADM_M_SET;	/* We are setting options */
	    valid |= KRB5_ADM_M_RANDOMKEY;	/* We have a random key */
	    ncomps = nargs = 0;
	    if (!(kret = krb5_adm_dbent_to_proto(kcontext,
						 valid,
						 dbentp,
						 (char *) NULL,
						 &nargs,
						 &arglist)) &&
		!(kret = net_do_proto(KRB5_ADM_ADD_PRINC_CMD,
				      principal,
				      (char *) NULL,
				      nargs,
				      arglist,
				      &proto_stat,
				      &ncomps,
				      &complist,
				      0))) {
		if (proto_stat == KRB5_ADM_SUCCESS) {
		    com_err(programname, 0, add_succ_fmt, principal);
		}
	    }
	    else {
		com_err(requestname, kret, add_protoerr_fmt);
	    }
	    if (ncomps)
		krb5_free_adm_data(kcontext, ncomps, complist);
	    if (nargs)
		krb5_free_adm_data(kcontext, nargs, arglist);
	}
	else {
	    com_err(requestname, 0, add_synerr_fmt);
	    help_princ_options();
	}
    }
    else {
	com_err(requestname, 0, no_memory_fmt);
    }
    if (dbentp)
	free(dbentp);
}

/*
 * kadmin_change_rnd()	- Change random key.
 */
void
kadmin_change_rnd(argc, argv)
    int 	argc;
    char	*argv[];
{
    krb5_error_code	kret;
    krb5_int32		proto_stat;
    krb5_int32		ncomps;
    krb5_data		*complist;

    requestname = argv[0];
    if (argc != 2) {
	com_err(argv[0], 0, cpw_usage_fmt, argv[0]);
	return;
    }
    if (!(kret = net_do_proto(KRB5_ADM_CHG_ORPW_CMD,
			      argv[1],
			      (char *) NULL,
			      0,
			      (krb5_data *) NULL,
			      &proto_stat,
			      &ncomps,
			      &complist,
			      0))) {
	if (proto_stat == KRB5_ADM_SUCCESS) {
	    com_err(programname, 0, cpw_succ_fmt, argv[1]);
	    krb5_free_adm_data(kcontext, ncomps, complist);
	}
    }
}

/*
 * kadmin_delete_entry()	- Delete principal.
 */
void
kadmin_delete_entry(argc, argv)
    int 	argc;
    char	*argv[];
{
    int			i;
    krb5_error_code	kret;
    krb5_int32		proto_stat;
    krb5_int32		ncomps;
    krb5_data		*complist;
    krb5_boolean	force, doit;

    requestname = argv[0];
    force = 0;
    if (argc == 1) {
	com_err(argv[0], 0, dprinc_usage_fmt, argv[0], force_option);
	return;

    }
    for (i=1; i<argc; i++) {
	if (!strcmp(argv[i], force_option)) {
	    force = 1;
	    continue;
	}
	doit = 0;
	if (force) {
	    doit = 1;
	}
	else {
	    int c;
	    printf(del_conf_fmt, del_conf_char, argv[i]);
	    if (getchar() == del_conf_char)
		doit = 1;
	    while (((c = getchar()) != '\n') && (c != EOF));
	}

	if (doit) {
	    if (!(kret = net_do_proto(KRB5_ADM_DEL_PRINC_CMD,
				      argv[i],
				      (char *) NULL,
				      0,
				      (krb5_data *) NULL,
				      &proto_stat,
				      &ncomps,
				      &complist,
				      0))) {
		if (proto_stat == KRB5_ADM_SUCCESS) {
		    com_err(programname, 0, del_princ_fmt, argv[i]);
		    krb5_free_adm_data(kcontext, ncomps, complist);
		}
	    }
	}
	else {
	    com_err(programname, 0, del_noconf_fmt, argv[i]);
	}
    }
}

/*
 * kadmin_extract()	- Extract srvtab entry.
 */
void
kadmin_extract(argc, argv)
    int 	argc;
    char	*argv[];
{
    int			i;
    krb5_error_code	kret;
    krb5_int32		proto_stat;
    krb5_int32		ncomps;
    krb5_data		*complist;
    char		*instance;
    krb5_boolean	force, doit;
    krb5_keytab_entry	keytab_entry;
    char		keytab_name[MAXPATHLEN+sizeof(wr_ktab_type)+2];
    krb5_keytab		keytab_id;
    char		*actname;

    requestname = argv[0];
    force = 0;
    if (argc < 3) {
	com_err(argv[0], 0, xst_usage_fmt, argv[0]);
	return;

    }
    instance = argv[1];
    argc -= 2;
    argv += 2;

    /*
     * First prepare us for writeable keytable operations.
     */
    if (kret = krb5_kt_register(kcontext, &krb5_ktf_writable_ops)) {
	if (kret != KRB5_KT_TYPE_EXISTS) {
	    com_err(programname, kret, xst_wr_reg_fmt, requestname);
	    return;
	}
    }

    /*
     * Format new srvtab name.
     */
    if (strlen(instance)+strlen(wr_ktab_type)+strlen(xst_ktab_name_fmt)-3
	>= sizeof(keytab_name)) {
	com_err(requestname, 0, xst_inst2long_fmt, instance, xst_dfl_ktname);
	sprintf(keytab_name, xst_ktab_name_fmt, wr_ktab_type, xst_dfl_ktname);
    }
    else
	sprintf(keytab_name, xst_ktab_name_fmt, wr_ktab_type, instance);
    actname = &keytab_name[strlen(wr_ktab_type)+1];

    if (kret = krb5_kt_resolve(kcontext, keytab_name, &keytab_id)) {
	com_err(requestname, kret, xst_nokeytab_fmt, actname);
	return;
    }
    memset((char *) &keytab_entry, 0, sizeof(krb5_keytab_entry));

    for (i=0; i<argc; i++) {
	if (!(kret = net_do_proto(KRB5_ADM_EXT_KEY_CMD,
				  instance,
				  argv[i],
				  0,
				  (krb5_data *) NULL,
				  &proto_stat,
				  &ncomps,
				  &complist,
				  0))) {
	    if (proto_stat == KRB5_ADM_SUCCESS) {
		if (!(kret = krb5_adm_proto_to_ktent(kcontext,
						     ncomps,
						     complist,
						     &keytab_entry))) {
		    if (kret = krb5_kt_add_entry(kcontext,
						 keytab_id,
						 &keytab_entry)) {
			com_err(requestname, kret, xst_adderr_fmt,
				argv[i], actname);
			break;
		    }
		    else
			com_err(requestname, 0, xst_success_fmt,
				argv[i], actname);
		    if (keytab_entry.key.contents) {
			memset((char *) keytab_entry.key.contents, 0,
			       (size_t) keytab_entry.key.length);
			krb5_xfree(keytab_entry.key.contents);
		    }
		}
		else {
		    com_err(requestname, kret, xst_proto_fmt);
		}
		memset((char *) &keytab_entry, 0, sizeof(krb5_keytab_entry));
		krb5_free_adm_data(kcontext, ncomps, complist);
	    }
	}
    }
    if (kret = krb5_kt_close(kcontext, keytab_id)) {
	com_err(requestname, kret, xst_kclose_fmt, keytab_name);
    }
}

/*
 * kadmin_extract_v4()	- Extract srvtab entry in V4 format.
 */
void
kadmin_extract_v4(argc, argv)
    int 	argc;
    char	*argv[];
{
    int			i;
    krb5_error_code	kret;
    krb5_int32		proto_stat;
    krb5_int32		ncomps;
    krb5_data		*complist;
    char		*instance;
    krb5_boolean	force, doit;
    krb5_keytab_entry	keytab_entry;
    char		keytab_name[MAXPATHLEN+1];
    FILE		*v4tab;

    requestname = argv[0];
    force = 0;
    if (argc < 3) {
	com_err(argv[0], 0, xst_usage_fmt, argv[0]);
	return;

    }
    instance = argv[1];
    argc -= 2;
    argv += 2;

    /*
     * Format new srvtab name.
     */
    if (strlen(instance)+strlen(xst_k4tab_name_fmt)-3 >= sizeof(keytab_name)) {
	com_err(requestname, 0, xst_inst2long_fmt, instance, xst_dfl_ktname);
	sprintf(keytab_name, xst_k4tab_name_fmt, xst_dfl_ktname);
    }
    else
	sprintf(keytab_name, xst_k4tab_name_fmt, instance);

    if ((v4tab = fopen(keytab_name, "w")) == NULL) {
	com_err(requestname, errno, xst_nokeytab_fmt, keytab_name);
	return;
    }
    memset((char *) &keytab_entry, 0, sizeof(krb5_keytab_entry));

    for (i=0; i<argc; i++) {
	if (!(kret = net_do_proto(KRB5_ADM_EXT_KEY_CMD,
				  instance,
				  argv[i],
				  0,
				  (krb5_data *) NULL,
				  &proto_stat,
				  &ncomps,
				  &complist,
				  0))) {
	    if (proto_stat == KRB5_ADM_SUCCESS) {
		if (!(kret = krb5_adm_proto_to_ktent(kcontext,
						     ncomps,
						     complist,
						     &keytab_entry))) {
		    if (keytab_entry.key.keytype != 1) {
			com_err(requestname, 0, xst_nodeskey_fmt, argv[i]);
			break;
		    }
		    if ((fwrite(argv[i],
				strlen(argv[i])+1,
				1,
				v4tab) != 1) ||
			(fwrite(instance,
				strlen(instance)+1,
				1,
				v4tab) != 1) ||
			(fwrite(realm_name,
				strlen(realm_name)+1,
				1,
				v4tab) != 1) ||
			(fwrite((char *) &keytab_entry.vno,
				sizeof(keytab_entry.vno),
				1,
				v4tab) != 1) ||
			(fwrite((char *) keytab_entry.key.contents,
				keytab_entry.key.length,
				1,
				v4tab) != 1)) {
			com_err(requestname, kret, xst_adderr_fmt,
				argv[i], keytab_name);
			break;
		    }
		    else
			com_err(requestname, 0, xst_success_fmt,
				argv[i], keytab_name);
		    if (keytab_entry.key.contents) {
			memset((char *) keytab_entry.key.contents, 0,
			       (size_t) keytab_entry.key.length);
			krb5_xfree(keytab_entry.key.contents);
		    }
		}
		else {
		    com_err(requestname, kret, xst_proto_fmt);
		}
		memset((char *) &keytab_entry, 0, sizeof(krb5_keytab_entry));
		krb5_free_adm_data(kcontext, ncomps, complist);
	    }
	}
    }
    fclose(v4tab);
}

/*
 * kadmin_modify()	- Modify principal.
 */
void
kadmin_modify(argc, argv)
    int 	argc;
    char	*argv[];
{
    krb5_error_code	kret;
    krb5_int32		proto_stat;
    krb5_int32		nargs;
    krb5_data		*arglist;
    krb5_int32		ncomps;
    krb5_data		*complist;
    char		*principal;
    krb5_ui_4		valid;
    krb5_db_entry	*dbentp;

    requestname = argv[0];
    if (argc < 2) {
	com_err(argv[0], 0, mod_usage_fmt, argv[0]);
	help_princ_options();
	return;
    }
    principal = argv[1];
    argc -= 2;
    argv += 2;

    dbentp = (krb5_db_entry *) malloc(sizeof(krb5_db_entry));
    if (dbentp) {
	memset((char *) dbentp, 0, sizeof(krb5_db_entry));
	valid = 0;
	if (parse_princ_options(argc, argv, &valid, dbentp)) {
	    valid |= KRB5_ADM_M_SET;	/* We are setting options */
	    nargs = ncomps = 0;
	    if (!(kret = krb5_adm_dbent_to_proto(kcontext,
						 valid,
						 dbentp,
						 (char *) NULL,
						 &nargs,
						 &arglist)) &&
		!(kret = net_do_proto(KRB5_ADM_MOD_PRINC_CMD,
				      principal,
				      (char *) NULL,
				      nargs,
				      arglist,
				      &proto_stat,
				      &ncomps,
				      &complist,
				      0))) {
		if (proto_stat == KRB5_ADM_SUCCESS) {
		    com_err(programname, 0, mod_succ_fmt, principal);
		}
	    }
	    else {
		com_err(requestname, kret, mod_protoerr_fmt);
	    }
	    if (ncomps)
		krb5_free_adm_data(kcontext, ncomps, complist);
	    if (nargs)
		krb5_free_adm_data(kcontext, nargs, arglist);
	}
	else {
	    com_err(requestname, 0, mod_synerr_fmt);
	    help_princ_options();
	}
    }
    else {
	com_err(requestname, 0, no_memory_fmt);
    }
    if (dbentp)
	free(dbentp);
}

/*
 * kadmin_rename()	- Rename principal.
 */
void
kadmin_rename(argc, argv)
    int 	argc;
    char	*argv[];
{
    int			i;
    krb5_error_code	kret;
    krb5_int32		proto_stat;
    krb5_int32		ncomps;
    krb5_data		*complist;
    krb5_boolean	force, doit, uerr;

    requestname = argv[0];
    uerr = force = 0;

    argc--; argv++;
    if (argc > 0) {
	if (!strcmp(argv[0], force_option)) {
	    force = 1;
	    argc--;
	    argv++;
	}
	if (argc != 2)
	    uerr++;
    }
    else
	uerr++;
    if (uerr) {
	com_err(requestname, 0, rprinc_usage_fmt, requestname, force_option);
	return;
    }

    doit = 0;
    if (force) {
	doit = 1;
    }
    else {
	int c;
	printf(ren_conf_fmt, ren_conf_char, argv[0], argv[1]);
	    if (getchar() == ren_conf_char)
		doit = 1;
	while (((c = getchar()) != '\n') && (c != EOF));
    }

    if (doit) {
	if (!(kret = net_do_proto(KRB5_ADM_REN_PRINC_CMD,
				  argv[0],
				  argv[1],
				  0,
				  (krb5_data *) NULL,
				  &proto_stat,
				  &ncomps,
				  &complist,
				  0))) {
	    if (proto_stat == KRB5_ADM_SUCCESS) {
		com_err(programname, 0, ren_princ_fmt, argv[0], argv[1]);
		krb5_free_adm_data(kcontext, ncomps, complist);
	    }
	}
    }
    else {
	com_err(programname, 0, ren_noconf_fmt, argv[0], argv[1]);
    }
}

/*
 * kadmin_list()	- List principals.
 */
void
kadmin_list(argc, argv)
    int 	argc;
    char	*argv[];
{
    krb5_error_code	kret;
    int			error;
    int			i;
    krb5_boolean	verbose;
    char		*re_result;
#if	HAVE_REGCOMP
    regex_t		match_exp;
    regmatch_t		match_match;
    int			match_error;
    char		match_errmsg[BUFSIZ];
    size_t		errmsg_size;
#elif	HAVE_REGEXP_H
    char		regexp_buffer[RE_BUF_SIZE];
#elif	HAVE_RE_COMP
    extern char		*re_comp();
#endif	/* HAVE_REGEXP_H */

    requestname = argv[0];
    error = 0;
    verbose = 0;

    for (i=1; i<argc; i++) {
	if (!strcmp(argv[i], help_option)) {
	    com_err(argv[0], 0, lprinc_usage_fmt, argv[0], verbose_option);
	    error = 1;
	    break;
	}
	if (!strcmp(argv[i], verbose_option)) {
	    verbose = 1;
	    continue;
	}
    }

    if (!error) {
	char 		*next;
	char 		*nnext;
	krb5_ui_4	valid;
	krb5_db_entry	*dbentry;
	int		match;

	if (dbentry = (krb5_db_entry *) malloc(sizeof(krb5_db_entry))) {
	    memset((char *) dbentry, 0, sizeof(*dbentry));
	    kret = kadmin_get_entry("", &valid, dbentry, &next);
	    if (kret) {
		com_err(argv[0], 0, cant_get_fmt, lprinc_first_msg);
		next = (char *) NULL;
	    }
	    else {
		krb5_db_free_principal(kcontext, dbentry, 1);
	    }
	    while (next && strlen(next)) {
		if (dbentry = (krb5_db_entry *)
		    malloc(sizeof(krb5_db_entry))) {
		    memset((char *) dbentry, 0, sizeof(*dbentry));
		    kret = kadmin_get_entry(next, &valid, dbentry, &nnext);
		    if (kret) {
			com_err(argv[0], 0, cant_get_fmt, lprinc_first_msg);
			break;
		    }
		    match = 0;
		    for (i=1; i<argc; i++) {
			if (!strcmp(argv[i], verbose_option))
			    continue;
#if	HAVE_REGCOMP
			if (match_error = regcomp(&match_exp,
						  argv[i],
						  REG_EXTENDED)) {
			    errmsg_size = regerror(match_error,
						   &match_exp,
						   match_errmsg,
						   sizeof(match_errmsg));
			    com_err(requestname, 0,
				    lprinc_regexp_fmt,
				    argv[i],
				    match_errmsg);
			    error = 1;
			    break;
			}
			if (match_error = regexec(&match_exp,
						  next,
						  1,
						  &match_match,
						  0)) {
			    if (match_error != REG_NOMATCH) {
				errmsg_size = regerror(match_error,
						       &match_exp,
						       match_errmsg,
						       sizeof(match_errmsg));
				com_err(requestname, 0,
					lprinc_regsrch_fmt,
					argv[i],
					next,
					match_errmsg);
				error = 1;
			    }
			}
			else {
			    /*
			     * We have a match.  See if it matches the whole
			     * name.
			     */
			    if ((match_match.rm_so == 0) &&
				(match_match.rm_eo == strlen(next))) {
				match = 1;
			    }
			}
			regfree(&match_exp);
#elif	HAVE_REGEXP_H
			compile(argv[i],
				regexp_buffer,
				&regexp_buffer[RE_BUF_SIZE],
				'\0');
			if (step(next, regexp_buffer)) {
			    if ((loc1 == next) &&
				(loc2 == &next[strlen(next)]))
				match = 1;
			}
#else	/* HAVE_REGEXP_H */
			if (!(re_result = re_comp(argv[i]))) {
			    com_err(argv[0], 0, lprinc_regexp_fmt, re_result);
			    error = 1;
			    break;
			}
			if (re_exec(next))
			    match = 1;
#endif	/* HAVE_REGEXP_H */
		    }
		    if (error)
			break;
		    if (match || (argc == 1)) {
			if (verbose)
			    kadmin_print_entry(next, valid, dbentry);
			else
			    printf("%s\n", next);
		    }
		    free(next);
		    next = nnext;
		    krb5_db_free_principal(kcontext, dbentry, 1);
		}
	    }
	}
	else {
	    com_err(argv[0], 0, no_memory_fmt);
	}
    }
}

#ifdef	LANGUAGES_SUPPORTED
/*
 * kadmin_language()	- Tell server to enable output in target language.
 */
void
kadmin_language(argc, argv)
    int 	argc;
    char	*argv[];
{
    krb5_error_code	kret;
    krb5_int32		proto_stat;
    krb5_int32		ncomps;
    krb5_data		*complist;

    requestname = argv[0];
    if (argc == 2) {
	if (!(kret = net_do_proto(KRB5_ADM_LANGUAGE_CMD,
				  argv[1],
				  (char *) NULL,
				  0,
				  (krb5_data *) NULL,
				  &proto_stat,
				  &ncomps,
				  &complist,
				  0))) {
	    if (proto_stat == KRB5_ADM_SUCCESS) {
		krb5_free_adm_data(kcontext, ncomps, complist);
	    }
	    if (!(kret = net_do_proto(KRB5_ADM_MIME_CMD,
				      (char *) NULL,
				      (char *) NULL,
				      0,
				      (krb5_data *) NULL,
				      &proto_stat,
				      &ncomps,
				      &complist,
				      0))) {
		if (proto_stat == KRB5_ADM_SUCCESS) {
		    krb5_free_adm_data(kcontext, ncomps, complist);
		}
	    }
	}
    }
    else
	com_err(argv[0], 0, lang_usage_fmt, argv[0]);
}
#endif	/* LANGUAGES_SUPPORTED */

/*
 * kadmin_cd()	- Change working directory.
 */
void
kadmin_cd(argc, argv)
    int 	argc;
    char	*argv[];
{
    requestname = argv[0];
    if (argc == 2) {
	if (chdir(argv[1]) == -1) {
	    com_err(argv[0], errno, cd_cannot_fmt, argv[1]);
	}
    }
    else {
	com_err(argv[0], 0, cd_usage_fmt, argv[0]);
    }
}

/*
 * kadmin_pwd()	- Print working directory.
 */
void
kadmin_pwd(argc, argv)
    int 	argc;
    char	*argv[];
{
    char	cwd[MAXPATHLEN];

    requestname = argv[0];
    if (argc == 1) {
	if (
#if	HAVE_GETCWD
	    getcwd(cwd, MAXPATHLEN)
#else	/* HAVE_GETCWD */
	    getwd(cwd)
#endif	/* HAVE_GETCWD */
	    )
	    printf(pwd_mess_fmt, cwd);
	else
	    com_err(argv[0], errno, pwd_err_fmt, cwd);
    }
    else
	com_err(argv[0], 0, pwd_usage_fmt, argv[0]);
}

/*
 * Startup fuction
 */
char *
kadmin_startup(argc, argv)
    int		argc;
    char	*argv[];
{
    krb5_error_code	kret;
    int			option;
    extern char		*optarg;
    extern int		optind;
    char 		*action = (char *) NULL;
    krb5_boolean	saveit = 0;
    krb5_boolean	delit = 0;
    krb5_ccache		ccache;

    programname = strrchr(argv[0], (int) '/');
    programname = (programname) ? programname+1 : argv[0];
    ccache = (krb5_ccache) NULL;
    while ((option = getopt(argc, argv, "c:dsl:r:p:m")) != EOF) {
	switch (option) {
	case 'c':
	    ccname2use = optarg;
	    break;
	case 'd':
	    delit = 1;
	    break;
	case 's':
	    saveit = 1;
	    break;
	case 'l':
	    {
		int hours, minutes;

		if (sscanf(optarg, "%d:%d", &hours, &minutes) == 2)
		    ticket_life = (hours * 3600) + (minutes * 60);
		else if (sscanf(optarg, "%d", &minutes) == 1)
		    ticket_life = minutes * 60;
		else {
		    com_err(argv[0], 0, kadmin_badtime_fmt, optarg);
		    exit(1);
		}
	    }
	    break;
	case 'r':
	    realm_name = optarg;
	    break;
	case 'p':
	    principal_name = optarg;
	    break;
	case 'm':
	    multiple = 1;
	    break;
	default:
	    com_err(argv[0], 0, kadmin_usage_fmt, argv[0]);
	    exit(1);
	}
    }

    if (delit && saveit) {
	com_err(argv[0], 0, kadmin_sd_err_fmt);
	exit(1);
    }

    delete_ccache = (delit || saveit) ? (delit & !saveit) :
	((ccname2use) ? 0 : 1);

    /* Now we do some real work */
    krb5_init_context(&kcontext);
    krb5_init_ets(kcontext);

    /* Get or verify current realm */
    if (!realm_name) {
	kret = krb5_get_default_realm(kcontext, &realm_name);
	if (kret) {
	    com_err(argv[0], kret, kadmin_defrealm_msg);
	    exit(2);
	}
    }
    else {
	kret = krb5_set_default_realm(kcontext, realm_name);
	if (kret) {
	    com_err(argv[0], kret, kadmin_srealm_fmt, realm_name);
	    exit(3);
	}
    }

    /* Verify ccache name if supplied. */
    if (ccname2use) {
	if (kret = krb5_cc_resolve(kcontext, ccname2use, &ccache)) {
	    com_err(argv[0], kret, kadmin_ccache_fmt, ccname2use);
	    exit(4);
	}
    }

    /* If no principal name, formulate a reasonable response */
    if (!principal_name) {
	krb5_principal	me;
	krb5_ccache	ccache;
	char		*user;
#if	HAVE_PWD_H
	struct passwd	*pw;
#endif	/* HAVE_PWD_H */

	me = (krb5_principal) NULL;
	ccache = (krb5_ccache) NULL;
	user = (char *) NULL;

	/* First try supplied credentials cache */
	if (ccache && 
	    !(kret = krb5_cc_get_principal(kcontext, ccache, &me))) {

	    /* Use our first component, if it exists. */
	    if (krb5_princ_size(kcontext, me) > 0) {
		krb5_data	*dp;

		dp = krb5_princ_component(kcontext, me, 0);
		if (user = (char *) malloc((size_t) dp->length + 1)) {
		    strncpy(user, dp->data, (size_t) dp->length);
		    user[dp->length] = '\0';
		}
		else {
		    kret = ENOMEM;
		}
	    }
	    else {
		com_err(argv[0], 0, kadmin_nocomp_msg);
		exit(1);
	    }
	}
	/* Then try our default credentials cache */
	else if (!(kret = krb5_cc_default(kcontext, &ccache)) &&
		 !(kret = krb5_cc_get_principal(kcontext, ccache, &me))) {

	    /* Use our first component, if it exists. */
	    if (krb5_princ_size(kcontext, me) > 0) {
		krb5_data	*dp;

		dp = krb5_princ_component(kcontext, me, 0);
		if (user = (char *) malloc((size_t) dp->length + 1)) {
		    strncpy(user, dp->data, (size_t) dp->length);
		    user[dp->length] = '\0';
		}
		else {
		    kret = ENOMEM;
		}
	    }
	    else {
		com_err(argv[0], 0, kadmin_nocomp_msg);
		exit(1);
	    }
	}
	else if (user = getenv("USER")) {
	    char *xxx;

	    xxx = (char *) malloc(strlen(user)+1);
	    if (xxx) {
		strcpy(xxx, user);
		kret = 0;
	    }
	    user = xxx;
	}
#if	HAVE_PWD_H
	else if (pw = getpwuid(getuid())) {
	    if (user = (char *) malloc(strlen(pw->pw_name)+1)) {
		strcpy(user, pw->pw_name);
		kret = 0;
	    }
	    else
		kret = ENOMEM;
	}
#endif	/* HAVE_PWD_H */

	if (user) {
	    if (principal_name = (char *) malloc(strlen(user)+1+
						 strlen(kadmin_instance)+1+
						 strlen(realm_name)+1)) {
		sprintf(principal_name, "%s/%s@%s",
			user, kadmin_instance, realm_name);
		free(user);
	    }
	    else
		kret = ENOMEM;
	}
	if (kret || !user) {
	    com_err(argv[0], kret, kadmin_nopname_msg);
	    exit(1);
	}
	if (ccache)
	    krb5_cc_close(kcontext, ccache);
	if (me)
	    krb5_free_principal(kcontext, me);
    }

    /* Formulate the password prompt while we're here */
    if (password_prompt = (char *) malloc(strlen(kadmin_pprompt_fmt)+
					  strlen(principal_name)+1)) {
	sprintf(password_prompt, kadmin_pprompt_fmt, principal_name);
    }
    else {
	com_err(argv[0], ENOMEM, kadmin_noprompt_msg);
	exit(1);
    }

    if (ccache)
	krb5_cc_close(kcontext, ccache);

    /* See if something's left, e.g. a request */
    if (argc > optind) {
	size_t	n2alloc;
	int	i;

	n2alloc = 0;
	for (i=optind; i<argc; i++)
	    n2alloc += strlen(argv[i]) + 1;

	n2alloc++;
	if (action = (char *) malloc(n2alloc)) {
	    for (i=optind; i<argc; i++) {
		strcat(action, argv[i]);
		strcat(action, " ");
	    }
	    action[n2alloc-1] = '\0';
	}
    }
    return(action);
}

/*
 * Cleanup function.
 */
int
kadmin_cleanup()
{
    if (password_prompt)
	free(password_prompt);
    net_disconnect(1);
    return 0; /*No currently defined failure conditions*/
}

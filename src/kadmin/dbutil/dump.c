/*
 * kadmin/dbutil/dump.c
 *
 * Copyright 1990,1991,2001 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Dump a KDC database
 */

#include <stdio.h>
#include <k5-int.h>
#include <kadm5/admin.h>
#include <kadm5/adb.h>
#include <com_err.h>
#include "kdb5_util.h"
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
#include <regex.h>
#endif	/* HAVE_REGEX_H */

/*
 * Needed for master key conversion.
 */
static int			mkey_convert;
static krb5_keyblock		new_master_keyblock;

static int	backwards;
static int	recursive;

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

struct dump_args {
    char		*programname;
    FILE		*ofile;
    krb5_context	kcontext;
    char		**names;
    int			nnames;
    int			verbose;
};

static krb5_error_code dump_k5beta_iterator (krb5_pointer,
					     krb5_db_entry *);
static krb5_error_code dump_k5beta6_iterator (krb5_pointer,
					      krb5_db_entry *);
static krb5_error_code dump_k5beta6_iterator_ext (krb5_pointer,
						  krb5_db_entry *,
						  int);
static krb5_error_code dump_k5beta7_princ (krb5_pointer,
					   krb5_db_entry *);
static krb5_error_code dump_k5beta7_princ_ext (krb5_pointer,
					       krb5_db_entry *,
					       int);
static krb5_error_code dump_k5beta7_princ_withpolicy
			(krb5_pointer, krb5_db_entry *);
static krb5_error_code dump_ov_princ (krb5_pointer,
				      krb5_db_entry *);
static void dump_k5beta7_policy (void *, osa_policy_ent_t);

typedef krb5_error_code (*dump_func)(krb5_pointer,
				     krb5_db_entry *);

static int process_k5beta_record (char *, krb5_context,
				  FILE *, int, int *, void *);
static int process_k5beta6_record (char *, krb5_context,
				   FILE *, int, int *, void *);
static int process_k5beta7_record (char *, krb5_context,
				   FILE *, int, int *, void *);
static int process_ov_record (char *, krb5_context,
			      FILE *, int, int *, void *);
typedef krb5_error_code (*load_func)(char *, krb5_context,
				     FILE *, int, int *, void *);

typedef struct _dump_version {
     char *name;
     char *header;
     int updateonly;
     int create_kadm5;
     dump_func dump_princ;
     osa_adb_iter_policy_func dump_policy;
     load_func load_record;
} dump_version;

dump_version old_version = {
     "Kerberos version 5 old format",
     "kdb5_edit load_dump version 2.0\n",
     0,
     1,
     dump_k5beta_iterator,
     NULL,
     process_k5beta_record,
};
dump_version beta6_version = {
     "Kerberos version 5 beta 6 format",
     "kdb5_edit load_dump version 3.0\n",
     0,
     1,
     dump_k5beta6_iterator,
     NULL,
     process_k5beta6_record,
};
dump_version beta7_version = {
     "Kerberos version 5",
     "kdb5_util load_dump version 4\n",
     0,
     0,
     dump_k5beta7_princ,
     dump_k5beta7_policy,
     process_k5beta7_record,
};
dump_version ov_version = {
     "OpenV*Secure V1.0",
     "OpenV*Secure V1.0\t",
     1,
     1,
     dump_ov_princ,
     dump_k5beta7_policy,
     process_ov_record,
};

dump_version r1_3_version = {
     "Kerberos version 5 release 1.3",
     "kdb5_util load_dump version 5\n",
     0,
     0,
     dump_k5beta7_princ_withpolicy,
     dump_k5beta7_policy,
     process_k5beta7_record,
};

/* External data */
extern char		*current_dbname;
extern krb5_boolean	dbactive;
extern int		exit_status;
extern krb5_context	util_context;
extern kadm5_config_params global_params;

/* Strings */

#define k5beta_dump_header	"kdb5_edit load_dump version 2.0\n"

static const char null_mprinc_name[] = "kdb5_dump@MISSING";

/* Message strings */
#define regex_err		"%s: regular expression error - %s\n"
#define regex_merr		"%s: regular expression match error - %s\n"
#define pname_unp_err		"%s: cannot unparse principal name (%s)\n"
#define mname_unp_err		"%s: cannot unparse modifier name (%s)\n"
#define nokeys_err		"%s: cannot find any standard key for %s\n"
#define sdump_tl_inc_err	"%s: tagged data list inconsistency for %s (counted %d, stored %d)\n"
#define stand_fmt_name		"Kerberos version 5"
#define old_fmt_name		"Kerberos version 5 old format"
#define b6_fmt_name		"Kerberos version 5 beta 6 format"
#define ofopen_error		"%s: cannot open %s for writing (%s)\n"
#define oflock_error		"%s: cannot lock %s (%s)\n"
#define dumprec_err		"%s: error performing %s dump (%s)\n"
#define dumphdr_err		"%s: error dumping %s header (%s)\n"
#define trash_end_fmt		"%s(%d): ignoring trash at end of line: "
#define read_name_string	"name string"
#define read_key_type		"key type"
#define read_key_data		"key data"
#define read_pr_data1		"first set of principal attributes"
#define read_mod_name		"modifier name"
#define read_pr_data2		"second set of principal attributes"
#define read_salt_data		"salt data"
#define read_akey_type		"alternate key type"
#define read_akey_data		"alternate key data"
#define read_asalt_type		"alternate salt type"
#define read_asalt_data		"alternate salt data"
#define read_exp_data		"expansion data"
#define store_err_fmt		"%s(%d): cannot store %s(%s)\n"
#define add_princ_fmt		"%s\n"
#define parse_err_fmt		"%s(%d): cannot parse %s (%s)\n"
#define read_err_fmt		"%s(%d): cannot read %s\n"
#define no_mem_fmt		"%s(%d): no memory for buffers\n"
#define rhead_err_fmt		"%s(%d): cannot match size tokens\n"
#define err_line_fmt		"%s: error processing line %d of %s\n"
#define head_bad_fmt		"%s: dump header bad in %s\n"
#define read_bytecnt		"record byte count"
#define read_encdata		"encoded data"
#define n_name_unp_fmt		"%s(%s): cannot unparse name\n"
#define n_dec_cont_fmt		"%s(%s): cannot decode contents\n"
#define read_nint_data		"principal static attributes"
#define read_tcontents		"tagged data contents"
#define read_ttypelen		"tagged data type and length"
#define read_kcontents		"key data contents"
#define read_ktypelen		"key data type and length"
#define read_econtents		"extra data contents"
#define k5beta_fmt_name		"Kerberos version 5 old format"
#define standard_fmt_name	"Kerberos version 5 format"
#define no_name_mem_fmt		"%s: cannot get memory for temporary name\n"
#define ctx_err_fmt		"%s: cannot initialize Kerberos context\n"
#define stdin_name		"standard input"
#define remaster_err_fmt	"while re-encoding keys for principal %s with new master key"
#define restfail_fmt		"%s: %s restore failed\n"
#define close_err_fmt		"%s: cannot close database (%s)\n"
#define dbinit_err_fmt		"%s: cannot initialize database (%s)\n"
#define dblock_err_fmt		"%s: cannot initialize database lock (%s)\n"
#define dbname_err_fmt		"%s: cannot set database name to %s (%s)\n"
#define dbdelerr_fmt		"%s: cannot delete bad database %s (%s)\n"
#define dbunlockerr_fmt		"%s: cannot unlock database %s (%s)\n"
#define dbrenerr_fmt		"%s: cannot rename database %s to %s (%s)\n"
#define dbcreaterr_fmt		"%s: cannot create database %s (%s)\n"
#define dfile_err_fmt		"%s: cannot open %s (%s)\n"

static const char oldoption[] = "-old";
static const char b6option[] = "-b6";
static const char b7option[] = "-b7";
static const char verboseoption[] = "-verbose";
static const char updateoption[] = "-update";
static const char hashoption[] = "-hash";
static const char ovoption[] = "-ov";
static const char dump_tmptrail[] = "~";

/*
 * Re-encrypt the key_data with the new master key...
 */
static krb5_error_code master_key_convert(context, db_entry)
    krb5_context	  context;
    krb5_db_entry	* db_entry;
{
    krb5_error_code	retval;
    krb5_keyblock 	v5plainkey, *key_ptr;
    krb5_keysalt 	keysalt;
    int	      i, j;
    krb5_key_data	new_key_data, *key_data;
    krb5_boolean	is_mkey;

    is_mkey = krb5_principal_compare(context, master_princ, db_entry->princ);

    if (is_mkey && db_entry->n_key_data != 1)
	    fprintf(stderr,
		    "Master key db entry has %d keys, expecting only 1!\n",
		    db_entry->n_key_data);
    for (i=0; i < db_entry->n_key_data; i++) {
	key_data = &db_entry->key_data[i];
	if (key_data->key_data_length == 0)
	    continue;
	retval = krb5_dbekd_decrypt_key_data(context, &master_keyblock,
					     key_data, &v5plainkey,
					     &keysalt);
	if (retval)
		return retval;

	memset(&new_key_data, 0, sizeof(new_key_data));
	key_ptr = is_mkey ? &new_master_keyblock : &v5plainkey;
	retval = krb5_dbekd_encrypt_key_data(context, &new_master_keyblock,
					     key_ptr, &keysalt,
					     key_data->key_data_kvno,
					     &new_key_data);
	if (retval)
		return retval;
	krb5_free_keyblock_contents(context, &v5plainkey);
	for (j = 0; j < key_data->key_data_ver; j++) {
	    if (key_data->key_data_length[j]) {
		free(key_data->key_data_contents[j]);
	    }
	}
	*key_data = new_key_data;
    }
    return 0;
}

/*
 * Update the "ok" file.
 */
void update_ok_file (file_name)
     char *file_name;
{
	/* handle slave locking/failure stuff */
	char *file_ok;
	int fd;
	static char ok[]=".dump_ok";

	if ((file_ok = (char *)malloc(strlen(file_name) + strlen(ok) + 1))
	    == NULL) {
		com_err(progname, ENOMEM,
			"while allocating filename for update_ok_file");
		exit_status++;
		return;
	}
	strcpy(file_ok, file_name);
	strcat(file_ok, ok);
	if ((fd = open(file_ok, O_WRONLY|O_CREAT|O_TRUNC, 0600)) < 0) {
		com_err(progname, errno, "while creating 'ok' file, '%s'",
			file_ok);
		exit_status++;
		free(file_ok);
		return;
	}
	if (write(fd, "", 1) != 1) {
	    com_err(progname, errno, "while writing to 'ok' file, '%s'",
		    file_ok);
	     exit_status++;
	     free(file_ok);
	     return;
	}

	free(file_ok);
	close(fd);
	return;
}

/*
 * name_matches()	- See if a principal name matches a regular expression
 *			  or string.
 */
static int
name_matches(name, arglist)
    char		*name;
    struct dump_args	*arglist;
{
#if	HAVE_REGCOMP
    regex_t	match_exp;
    regmatch_t	match_match;
    int		match_error;
    char	match_errmsg[BUFSIZ];
    size_t	errmsg_size;
#elif	HAVE_REGEXP_H
    char	regexp_buffer[RE_BUF_SIZE];
#elif	HAVE_RE_COMP
    extern char	*re_comp();
    char	*re_result;
#endif	/* HAVE_RE_COMP */
    int		i, match;

    /*
     * Plow, brute force, through the list of names/regular expressions.
     */
    match = (arglist->nnames) ? 0 : 1;
    for (i=0; i<arglist->nnames; i++) {
#if	HAVE_REGCOMP
	/*
	 * Compile the regular expression.
	 */
	match_error = regcomp(&match_exp, arglist->names[i], REG_EXTENDED);
	if (match_error) {
	    errmsg_size = regerror(match_error,
				   &match_exp,
				   match_errmsg,
				   sizeof(match_errmsg));
	    fprintf(stderr, regex_err, arglist->programname, match_errmsg);
	    break;
	}
	/*
	 * See if we have a match.
	 */
	match_error = regexec(&match_exp, name, 1, &match_match, 0);
	if (match_error) {
	    if (match_error != REG_NOMATCH) {
		errmsg_size = regerror(match_error,
				       &match_exp,
				       match_errmsg,
				       sizeof(match_errmsg));
		fprintf(stderr, regex_merr,
			arglist->programname, match_errmsg);
		break;
	    }
	}
	else {
	    /*
	     * We have a match.  See if it matches the whole
	     * name.
	     */
	    if ((match_match.rm_so == 0) &&
		(match_match.rm_eo == strlen(name)))
		match = 1;
	}
	regfree(&match_exp);
#elif	HAVE_REGEXP_H
	/*
	 * Compile the regular expression.
	 */
	compile(arglist->names[i],
		regexp_buffer, 
		&regexp_buffer[RE_BUF_SIZE],
		'\0');
	if (step(name, regexp_buffer)) {
	    if ((loc1 == name) &&
		(loc2 == &name[strlen(name)]))
		match = 1;
	}
#elif	HAVE_RE_COMP
	/*
	 * Compile the regular expression.
	 */
	if (re_result = re_comp(arglist->names[i])) {
	    fprintf(stderr, regex_err, arglist->programname, re_result);
	    break;
	}
	if (re_exec(name))
	    match = 1;
#else	/* HAVE_RE_COMP */
	/*
	 * If no regular expression support, then just compare the strings.
	 */
	if (!strcmp(arglist->names[i], name))
	    match = 1;
#endif	/* HAVE_REGCOMP */
	if (match)
	    break;
    }
    return(match);
}

static krb5_error_code
find_enctype(dbentp, enctype, salttype, kentp)
    krb5_db_entry	*dbentp;
    krb5_enctype	enctype;
    krb5_int32		salttype;
    krb5_key_data	**kentp;
{
    int			i;
    int			maxkvno;
    krb5_key_data	*datap;

    maxkvno = -1;
    datap = (krb5_key_data *) NULL;
    for (i=0; i<dbentp->n_key_data; i++) {
	if (( (krb5_enctype)dbentp->key_data[i].key_data_type[0] == enctype) &&
	    ((dbentp->key_data[i].key_data_type[1] == salttype) ||
	     (salttype < 0))) {
	    maxkvno = dbentp->key_data[i].key_data_kvno;
	    datap = &dbentp->key_data[i];
	}
    }
    if (maxkvno >= 0) {
	*kentp = datap;
	return(0);
    }
    return(ENOENT);    
}

#if 0
/*
 * dump_k5beta_header()	- Make a dump header that is recognizable by Kerberos
 *			  Version 5 Beta 5 and previous releases.
 */
static krb5_error_code
dump_k5beta_header(arglist)
    struct dump_args *arglist;
{
    /* The old header consists of the leading string */
    fprintf(arglist->ofile, k5beta_dump_header);
    return(0);
}
#endif

/*
 * dump_k5beta_iterator()	- Dump an entry in a format that is usable
 *				  by Kerberos Version 5 Beta 5 and previous
 *				  releases.
 */
static krb5_error_code
dump_k5beta_iterator(ptr, entry)
    krb5_pointer	ptr;
    krb5_db_entry	*entry;
{
    krb5_error_code	retval;
    struct dump_args	*arg;
    char		*name, *mod_name;
    krb5_principal	mod_princ;
    krb5_key_data	*pkey, *akey, nullkey;
    krb5_timestamp	mod_date, last_pwd_change;
    int			i;

    /* Initialize */
    arg = (struct dump_args *) ptr;
    name = (char *) NULL;
    mod_name = (char *) NULL;
    memset(&nullkey, 0, sizeof(nullkey));

    /*
     * Flatten the principal name.
     */
    if ((retval = krb5_unparse_name(arg->kcontext,
				    entry->princ,
				    &name))) {
	fprintf(stderr, pname_unp_err, 
		arg->programname, error_message(retval));
	return(retval);
    }

    /*
     * Re-encode the keys in the new master key, if necessary.
     */
    if (mkey_convert) {
	retval = master_key_convert(arg->kcontext, entry);
	if (retval) {
	    com_err(arg->programname, retval, remaster_err_fmt, name);
	    return retval;
	}
    }
    
    /*
     * If we don't have any match strings, or if our name matches, then
     * proceed with the dump, otherwise, just forget about it.
     */
    if (!arg->nnames || name_matches(name, arg)) {
	/*
	 * Deserialize the modifier record.
	 */
	mod_name = (char *) NULL;
	mod_princ = NULL;
	last_pwd_change = mod_date = 0;
	pkey = akey = (krb5_key_data *) NULL;
	if (!(retval = krb5_dbe_lookup_mod_princ_data(arg->kcontext,
						      entry,
						      &mod_date,
						      &mod_princ))) {
	    if (mod_princ) {
		/*
		 * Flatten the modifier name.
		 */
		if ((retval = krb5_unparse_name(arg->kcontext,
						mod_princ,
						&mod_name)))
		    fprintf(stderr, mname_unp_err, arg->programname,
			    error_message(retval));
		krb5_free_principal(arg->kcontext, mod_princ);
	    }
	}
	if (!mod_name)
	    mod_name = strdup(null_mprinc_name);

	/*
	 * Find the last password change record and set it straight.
	 */
	if ((retval =
	     krb5_dbe_lookup_last_pwd_change(arg->kcontext, entry,
					     &last_pwd_change))) {
	    fprintf(stderr, nokeys_err, arg->programname, name);
	    krb5_xfree(mod_name);
	    krb5_xfree(name);
	    return(retval);
	}

	/*
	 * Find the 'primary' key and the 'alternate' key.
	 */
	if ((retval = find_enctype(entry,
				   ENCTYPE_DES_CBC_CRC,
				   KRB5_KDB_SALTTYPE_NORMAL,
				   &pkey)) &&
	    (retval = find_enctype(entry,
				   ENCTYPE_DES_CBC_CRC,
				   KRB5_KDB_SALTTYPE_V4,
				   &akey))) {
	    fprintf(stderr, nokeys_err, arg->programname, name);
	    krb5_xfree(mod_name);
	    krb5_xfree(name);
	    return(retval);
	}

	/* If we only have one type, then ship it out as the primary. */
	if (!pkey && akey) {
	    pkey = akey;
	    akey = &nullkey;
	}
	else {
	    if (!akey)
		akey = &nullkey;
	}

	/*
	 * First put out strings representing the length of the variable
	 * length data in this record, then the name and the primary key type.
	 */
	fprintf(arg->ofile, "%d\t%d\t%d\t%d\t%d\t%d\t%s\t%d\t", strlen(name),
		strlen(mod_name),
		(krb5_int32) pkey->key_data_length[0],
		(krb5_int32) akey->key_data_length[0],
		(krb5_int32) pkey->key_data_length[1],
		(krb5_int32) akey->key_data_length[1],
		name,
		(krb5_int32) pkey->key_data_type[0]);
	for (i=0; i<pkey->key_data_length[0]; i++) {
	    fprintf(arg->ofile, "%02x", pkey->key_data_contents[0][i]);
	}
	/*
	 * Second, print out strings representing the standard integer
	 * data in this record.
	 */
	fprintf(arg->ofile,
		"\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%s\t%u\t%u\t%u\t",
		(krb5_int32) pkey->key_data_kvno,
		entry->max_life, entry->max_renewable_life,
		1 /* Fake mkvno */, entry->expiration, entry->pw_expiration,
		last_pwd_change, entry->last_success, entry->last_failed,
		entry->fail_auth_count, mod_name, mod_date,
		entry->attributes, pkey->key_data_type[1]);

	/* Pound out the salt data, if present. */
	for (i=0; i<pkey->key_data_length[1]; i++) {
	    fprintf(arg->ofile, "%02x", pkey->key_data_contents[1][i]);
	}
	/* Pound out the alternate key type and contents */
	fprintf(arg->ofile, "\t%u\t", akey->key_data_type[0]);
	for (i=0; i<akey->key_data_length[0]; i++) {
	    fprintf(arg->ofile, "%02x", akey->key_data_contents[0][i]);
	}
	/* Pound out the alternate salt type and contents */
	fprintf(arg->ofile, "\t%u\t", akey->key_data_type[1]);
	for (i=0; i<akey->key_data_length[1]; i++) {
	    fprintf(arg->ofile, "%02x", akey->key_data_contents[1][i]);
	}
	/* Pound out the expansion data. (is null) */
	for (i=0; i < 8; i++) {
	    fprintf(arg->ofile, "\t%u", 0);
	}
	fprintf(arg->ofile, ";\n");
	/* If we're blabbing, do it */
	if (arg->verbose)
	    fprintf(stderr, "%s\n", name);
	krb5_xfree(mod_name);
    }
    krb5_xfree(name);
    return(0);
}

/*
 * dump_k5beta6_iterator()	- Output a dump record in krb5b6 format.
 */
static krb5_error_code
dump_k5beta6_iterator(ptr, entry)
    krb5_pointer	ptr;
    krb5_db_entry	*entry;
{
    return dump_k5beta6_iterator_ext(ptr, entry, 0);
}

static krb5_error_code
dump_k5beta6_iterator_ext(ptr, entry, kadm)
    krb5_pointer	ptr;
    krb5_db_entry	*entry;
    int			kadm;
{
    krb5_error_code	retval;
    struct dump_args	*arg;
    char		*name;
    krb5_tl_data	*tlp;
    krb5_key_data	*kdata;
    int			counter, skip, i, j;

    /* Initialize */
    arg = (struct dump_args *) ptr;
    name = (char *) NULL;

    /*
     * Flatten the principal name.
     */
    if ((retval = krb5_unparse_name(arg->kcontext,
				    entry->princ,
				    &name))) {
	fprintf(stderr, pname_unp_err, 
		arg->programname, error_message(retval));
	return(retval);
    }

    /*
     * Re-encode the keys in the new master key, if necessary.
     */
    if (mkey_convert) {
	retval = master_key_convert(arg->kcontext, entry);
	if (retval) {
	    com_err(arg->programname, retval, remaster_err_fmt, name);
	    return retval;
	}
    }
    
    /*
     * If we don't have any match strings, or if our name matches, then
     * proceed with the dump, otherwise, just forget about it.
     */
    if (!arg->nnames || name_matches(name, arg)) {
	/*
	 * We'd like to just blast out the contents as they would appear in
	 * the database so that we can just suck it back in, but it doesn't
	 * lend itself to easy editing.
	 */

	/*
	 * The dump format is as follows:
	 *	len strlen(name) n_tl_data n_key_data e_length
	 *	name
	 *	attributes max_life max_renewable_life expiration
	 *	pw_expiration last_success last_failed fail_auth_count
	 *	n_tl_data*[type length <contents>]
	 *	n_key_data*[ver kvno ver*(type length <contents>)]
	 *	<e_data>
	 * Fields which are not encapsulated by angle-brackets are to appear
	 * verbatim.  A bracketed field's absence is indicated by a -1 in its
	 * place
	 */

	/*
	 * Make sure that the tagged list is reasonably correct.
	 */
	counter = skip = 0;
	for (tlp = entry->tl_data; tlp; tlp = tlp->tl_data_next) {
	     /*
	      * don't dump tl data types we know aren't understood by
	      * earlier revisions [krb5-admin/89]
	      */
	     switch (tlp->tl_data_type) {
	     case KRB5_TL_KADM_DATA:
		  if (kadm)
		      counter++;
		  else
		      skip++;
		  break;
	     default:
		  counter++;
		  break;
	     }
	}
	
	if (counter + skip == entry->n_tl_data) {
	    /* Pound out header */
	    fprintf(arg->ofile, "%d\t%d\t%d\t%d\t%d\t%s\t",
		    (int) entry->len,
		    strlen(name),
		    counter,
		    (int) entry->n_key_data,
		    (int) entry->e_length,
		    name);
	    fprintf(arg->ofile, "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t",
		    entry->attributes,
		    entry->max_life,
		    entry->max_renewable_life,
		    entry->expiration,
		    entry->pw_expiration,
		    entry->last_success,
		    entry->last_failed,
		    entry->fail_auth_count);
	    /* Pound out tagged data. */
	    for (tlp = entry->tl_data; tlp; tlp = tlp->tl_data_next) {
		if (tlp->tl_data_type == KRB5_TL_KADM_DATA && !kadm)
		     continue; /* see above, [krb5-admin/89] */

		fprintf(arg->ofile, "%d\t%d\t",
			(int) tlp->tl_data_type,
			(int) tlp->tl_data_length);
		if (tlp->tl_data_length)
		    for (i=0; i<tlp->tl_data_length; i++)
			fprintf(arg->ofile, "%02x", tlp->tl_data_contents[i]);
		else
		    fprintf(arg->ofile, "%d", -1);
		fprintf(arg->ofile, "\t");
	    }

	    /* Pound out key data */
	    for (counter=0; counter<entry->n_key_data; counter++) {
		kdata = &entry->key_data[counter];
		fprintf(arg->ofile, "%d\t%d\t",
			(int) kdata->key_data_ver,
			(int) kdata->key_data_kvno);
		for (i=0; i<kdata->key_data_ver; i++) {
		    fprintf(arg->ofile, "%d\t%d\t",
			    kdata->key_data_type[i],
			    kdata->key_data_length[i]);
		    if (kdata->key_data_length[i])
			for (j=0; j<kdata->key_data_length[i]; j++)
			    fprintf(arg->ofile, "%02x",
				    kdata->key_data_contents[i][j]);
		    else
			fprintf(arg->ofile, "%d", -1);
		    fprintf(arg->ofile, "\t");
		}
	    }

	    /* Pound out extra data */
	    if (entry->e_length)
		for (i=0; i<entry->e_length; i++)
		    fprintf(arg->ofile, "%02x", entry->e_data[i]);
	    else
		fprintf(arg->ofile, "%d", -1);

	    /* Print trailer */
	    fprintf(arg->ofile, ";\n");

	    if (arg->verbose)
		fprintf(stderr, "%s\n", name);
	}
	else {
	    fprintf(stderr, sdump_tl_inc_err,
		    arg->programname, name, counter+skip,
		    (int) entry->n_tl_data); 
	    retval = EINVAL;
	}
    }
    krb5_xfree(name);
    return(retval);
}

/*
 * dump_k5beta7_iterator()	- Output a dump record in krb5b7 format.
 */
static krb5_error_code
dump_k5beta7_princ(ptr, entry)
    krb5_pointer	ptr;
    krb5_db_entry	*entry;
{
    return dump_k5beta7_princ_ext(ptr, entry, 0);
}

static krb5_error_code
dump_k5beta7_princ_ext(ptr, entry, kadm)
    krb5_pointer	ptr;
    krb5_db_entry	*entry;
    int			kadm;
{
     krb5_error_code retval;
     struct dump_args *arg;
     char *name;
     int tmp_nnames;

     /* Initialize */
     arg = (struct dump_args *) ptr;
     name = (char *) NULL;

     /*
      * Flatten the principal name.
      */
     if ((retval = krb5_unparse_name(arg->kcontext,
				     entry->princ,
				     &name))) {
	  fprintf(stderr, pname_unp_err, 
		  arg->programname, error_message(retval));
	  return(retval);
     }
     /*
      * If we don't have any match strings, or if our name matches, then
      * proceed with the dump, otherwise, just forget about it.
      */
     if (!arg->nnames || name_matches(name, arg)) {
	  fprintf(arg->ofile, "princ\t");
	  
	  /* save the callee from matching the name again */
	  tmp_nnames = arg->nnames;
	  arg->nnames = 0;
	  retval = dump_k5beta6_iterator_ext(ptr, entry, kadm);
	  arg->nnames = tmp_nnames;
     }

     free(name);
     return retval;
}

static krb5_error_code
dump_k5beta7_princ_withpolicy(ptr, entry)
    krb5_pointer	ptr;
    krb5_db_entry	*entry;
{
    return dump_k5beta7_princ_ext(ptr, entry, 1);
}

void dump_k5beta7_policy(void *data, osa_policy_ent_t entry)
{
     struct dump_args *arg;

     arg = (struct dump_args *) data;
     fprintf(arg->ofile, "policy\t%s\t%d\t%d\t%d\t%d\t%d\t%d\n", entry->name,
	     entry->pw_min_life, entry->pw_max_life, entry->pw_min_length,
	     entry->pw_min_classes, entry->pw_history_num,
	     entry->policy_refcnt);
}

static void print_key_data(FILE *f, krb5_key_data *key_data)
{
     int c;
     
     fprintf(f, "%d\t%d\t", key_data->key_data_type[0],
	     key_data->key_data_length[0]);
     for(c = 0; c < key_data->key_data_length[0]; c++) 
	  fprintf(f, "%02x ",
		  key_data->key_data_contents[0][c]);
}

/*
 * Function: print_princ
 * 
 * Purpose: output osa_adb_princ_ent data in a human
 *	    readable format (which is a format suitable for
 *	    ovsec_adm_import consumption)
 *
 * Arguments:
 *	data		(input) pointer to a structure containing a FILE *
 *			        and a record counter.
 *	entry		(input) entry to get dumped.
 * 	<return value>	void
 *
 * Requires:
 *	nuttin
 * 
 * Effects:
 *	writes data to the specified file pointerp.
 *
 * Modifies:
 *	nuttin
 * 
 */
static krb5_error_code dump_ov_princ(krb5_pointer ptr, krb5_db_entry *kdb)
{
    char *princstr;
    int	x, y, foundcrc;
    struct dump_args *arg;
    krb5_tl_data tl_data;
    osa_princ_ent_rec adb;
    XDR xdrs;

    arg = (struct dump_args *) ptr;
    /*
     * XXX Currently, lookup_tl_data always returns zero; it sets
     * tl_data->tl_data_length to zero if the type isn't found.
     * This should be fixed...
     */
    /*
     * XXX Should this function do nothing for a principal with no
     * admin data, or print a record of "default" values?   See
     * comment in server_kdb.c to help decide.
     */
    tl_data.tl_data_type = KRB5_TL_KADM_DATA;
    if (krb5_dbe_lookup_tl_data(arg->kcontext, kdb, &tl_data)
	|| (tl_data.tl_data_length == 0))
	 return 0;

    memset(&adb, 0, sizeof(adb));
    xdrmem_create(&xdrs, tl_data.tl_data_contents,
		  tl_data.tl_data_length, XDR_DECODE);
    if (! xdr_osa_princ_ent_rec(&xdrs, &adb)) {
	 xdr_destroy(&xdrs);
	 return(OSA_ADB_XDR_FAILURE);
    }
    xdr_destroy(&xdrs);
    
    krb5_unparse_name(arg->kcontext, kdb->princ, &princstr);
    fprintf(arg->ofile, "princ\t%s\t", princstr);
    if(adb.policy == NULL)
	fputc('\t', arg->ofile);
    else
	fprintf(arg->ofile, "%s\t", adb.policy);
    fprintf(arg->ofile, "%lx\t%d\t%d\t%d", adb.aux_attributes,
	    adb.old_key_len,adb.old_key_next, adb.admin_history_kvno);

    for (x = 0; x < adb.old_key_len; x++) {
	 foundcrc = 0;
	 for (y = 0; y < adb.old_keys[x].n_key_data; y++) {
	      krb5_key_data *key_data = &adb.old_keys[x].key_data[y];

	      if (key_data->key_data_type[0] != ENCTYPE_DES_CBC_CRC)
		   continue;
	      if (foundcrc) {
		   fprintf(stderr, "Warning!  Multiple DES-CBC-CRC keys "
			   "for principal %s; skipping duplicates.\n",
			   princstr);
		   continue;
	      }
	      foundcrc++;

	      fputc('\t', arg->ofile);
	      print_key_data(arg->ofile, key_data);
	 }
	 if (!foundcrc)
	      fprintf(stderr, "Warning!  No DES-CBC-CRC key for principal "
		      "%s, cannot generate OV-compatible record; skipping\n",
		      princstr);
    }

    fputc('\n', arg->ofile);
    free(princstr);
    return 0;
}

/*
 * usage is:
 *	dump_db [-old] [-b6] [-b7] [-ov] [-verbose] [-mkey_convert]
 *		[-new_mkey_file mkey_file] [-rev] [-recurse]
 *		[filename [principals...]]
 */
void
dump_db(argc, argv)
    int		argc;
    char	**argv;
{
    FILE		*f;
    struct dump_args	arglist;
    char		*programname;
    char		*ofile;
    krb5_error_code	kret, retval;
    dump_version	*dump;
    int			aindex;
    krb5_boolean	locked;
    extern osa_adb_policy_t policy_db;
    char		*new_mkey_file = 0;
	
    /*
     * Parse the arguments.
     */
    programname = argv[0];
    if (strrchr(programname, (int) '/'))
	programname = strrchr(argv[0], (int) '/') + 1;
    ofile = (char *) NULL;
    dump = &r1_3_version;
    arglist.verbose = 0;
    new_mkey_file = 0;
    mkey_convert = 0;
    backwards = 0;
    recursive = 0;

    /*
     * Parse the qualifiers.
     */
    for (aindex = 1; aindex < argc; aindex++) {
	if (!strcmp(argv[aindex], oldoption))
	     dump = &old_version;
	else if (!strcmp(argv[aindex], b6option))
	     dump = &beta6_version;
	else if (!strcmp(argv[aindex], b7option))
	     dump = &beta7_version;
	else if (!strcmp(argv[aindex], ovoption))
	     dump = &ov_version;
	else if (!strcmp(argv[aindex], verboseoption))
	    arglist.verbose++;
	else if (!strcmp(argv[aindex], "-mkey_convert"))
	    mkey_convert = 1;
	else if (!strcmp(argv[aindex], "-new_mkey_file")) {
	    new_mkey_file = argv[++aindex];
	    mkey_convert = 1;
        } else if (!strcmp(argv[aindex], "-rev"))
	    backwards = 1;
	else if (!strcmp(argv[aindex], "-recurse"))
	    recursive = 1;
	else
	    break;
    }

    arglist.names = (char **) NULL;
    arglist.nnames = 0;
    if (aindex < argc) {
	ofile = argv[aindex];
	aindex++;
	if (aindex < argc) {
	    arglist.names = &argv[aindex];
	    arglist.nnames = argc - aindex;
	}
    }

    /*
     * Make sure the database is open.  The policy database only has
     * to be opened if we try a dump that uses it.
     */
    if (!dbactive || (dump->dump_policy != NULL && policy_db == NULL)) {
	com_err(argv[0], 0, Err_no_database);
	exit_status++;
	return;
    }

    /*
     * If we're doing a master key conversion, set up for it.
     */
    if (mkey_convert) {
	    if (!valid_master_key) {
		    /* TRUE here means read the keyboard, but only once */
		    retval = krb5_db_fetch_mkey(util_context,
						master_princ,
						master_keyblock.enctype,
						TRUE, FALSE,
						(char *) NULL, 0,
						&master_keyblock);
		    if (retval) {
			    com_err(argv[0], retval,
				    "while reading master key");
			    exit(1);
		    }
		    retval = krb5_db_verify_master_key(util_context,
						       master_princ,
						       &master_keyblock);
		    if (retval) {
			    com_err(argv[0], retval,
				    "while verifying master key");
			    exit(1);
		    }
	    }
	    new_master_keyblock.enctype = global_params.enctype;
	    if (new_master_keyblock.enctype == ENCTYPE_UNKNOWN)
		    new_master_keyblock.enctype = DEFAULT_KDC_ENCTYPE;
	    if (!new_mkey_file)
		    printf("Please enter new master key....\n");
	    if ((retval = krb5_db_fetch_mkey(util_context, master_princ, 
					     new_master_keyblock.enctype,
					     (new_mkey_file == 0) ? 
					        (krb5_boolean) 1 : 0, 
					     TRUE, 
					     new_mkey_file, 0,
					     &new_master_keyblock))) { 
		    com_err(argv[0], retval, "while reading new master key");
		    exit(1);
	    }
    }

    kret = 0;
    locked = 0;
    if (ofile && strcmp(ofile, "-")) {
	/*
	 * Discourage accidental dumping to filenames beginning with '-'.
	 */
	if (ofile[0] == '-')
	    usage();
	/*
	 * Make sure that we don't open and truncate on the fopen,
	 * since that may hose an on-going kprop process.
	 * 
	 * We could also control this by opening for read and
	 * write, doing an flock with LOCK_EX, and then
	 * truncating the file once we have gotten the lock,
	 * but that would involve more OS dependencies than I
	 * want to get into.
	 */
	unlink(ofile);
	if (!(f = fopen(ofile, "w"))) {
	    fprintf(stderr, ofopen_error,
		    programname, ofile, error_message(errno));
	    exit_status++;
	    return;
       }
	if ((kret = krb5_lock_file(util_context,
				   fileno(f),
				   KRB5_LOCKMODE_EXCLUSIVE))) {
	    fprintf(stderr, oflock_error,
		    programname, ofile, error_message(kret));
	    exit_status++;
	}
	else
	    locked = 1;
    } else {
	f = stdout;
    }
    if (f && !(kret)) {
	arglist.programname = programname;
	arglist.ofile = f;
	arglist.kcontext = util_context;
	fprintf(arglist.ofile, "%s", dump->header);
	if (dump->header[strlen(dump->header)-1] != '\n')
	     fputc('\n', arglist.ofile);
	
	if ((kret = krb5_db_iterate_ext(util_context,
					dump->dump_princ,
					(krb5_pointer) &arglist,
					backwards, recursive))) {
	     fprintf(stderr, dumprec_err,
		     programname, dump->name, error_message(kret));
	     exit_status++;
	}
	if (dump->dump_policy &&
	    (kret = osa_adb_iter_policy(policy_db, dump->dump_policy,
					&arglist))) { 
	     fprintf(stderr, dumprec_err, programname, dump->name,
		     error_message(kret));
	     exit_status++;
	}
	if (ofile && f != stdout && !exit_status) {
	     fclose(f);
	     update_ok_file(ofile);
	}
    }
    if (locked)
	(void) krb5_lock_file(util_context, fileno(f), KRB5_LOCKMODE_UNLOCK);
}

/*
 * Read a string of bytes while counting the number of lines passed.
 */
static int
read_string(f, buf, len, lp)
    FILE	*f;
    char	*buf;
    int		len;
    int		*lp;
{
    int c;
    int i, retval;

    retval = 0;
    for (i=0; i<len; i++) {
	c = fgetc(f);
	if (c < 0) {
	    retval = 1;
	    break;
	}
	if (c == '\n')
	    (*lp)++;
	buf[i] = (char) c;
    }
    buf[len] = '\0';
    return(retval);
}

/*
 * Read a string of two character representations of bytes.
 */
static int
read_octet_string(f, buf, len)
    FILE	*f;
    krb5_octet	*buf;
    int		len;
{
    int c;
    int i, retval;

    retval = 0;
    for (i=0; i<len; i++) {
	if (fscanf(f, "%02x", &c) != 1) {
	    retval = 1;
	    break;
	}
	buf[i] = (krb5_octet) c;
    }
    return(retval);
}

/*
 * Find the end of an old format record.
 */
static void
find_record_end(f, fn, lineno)
    FILE	*f;
    char	*fn;
    int		lineno;
{
    int	ch;

    if (((ch = fgetc(f)) != ';') || ((ch = fgetc(f)) != '\n')) {
	fprintf(stderr, trash_end_fmt, fn, lineno);
	while (ch != '\n') {
	    putc(ch, stderr);
	    ch = fgetc(f);
	}
	putc(ch, stderr);
    }
}

#if 0
/*
 * update_tl_data()	- Generate the tl_data entries.
 */
static krb5_error_code
update_tl_data(kcontext, dbentp, mod_name, mod_date, last_pwd_change)
    krb5_context	kcontext;
    krb5_db_entry	*dbentp;
    krb5_principal	mod_name;
    krb5_timestamp	mod_date;
    krb5_timestamp	last_pwd_change;
{
    krb5_error_code	kret;

    kret = 0 ;

    /*
     * Handle modification principal.
     */
    if (mod_name) {
	krb5_tl_mod_princ	mprinc;

	memset(&mprinc, 0, sizeof(mprinc));
	if (!(kret = krb5_copy_principal(kcontext,
					 mod_name,
					 &mprinc.mod_princ))) {
	    mprinc.mod_date = mod_date;
	    kret = krb5_dbe_encode_mod_princ_data(kcontext,
						  &mprinc,
						  dbentp);
	}
	if (mprinc.mod_princ)
	    krb5_free_principal(kcontext, mprinc.mod_princ);
    }

    /*
     * Handle last password change.
     */
    if (!kret) {
	krb5_tl_data	*pwchg;
	krb5_boolean	linked;

	/* Find a previously existing entry */
	for (pwchg = dbentp->tl_data;
	     (pwchg) && (pwchg->tl_data_type != KRB5_TL_LAST_PWD_CHANGE);
	     pwchg = pwchg->tl_data_next);

	/* Check to see if we found one. */
	linked = 0;
	if (!pwchg) {
	    /* No, allocate a new one */
	    if ((pwchg = (krb5_tl_data *) malloc(sizeof(krb5_tl_data)))) {
		memset(pwchg, 0, sizeof(krb5_tl_data));
		if (!(pwchg->tl_data_contents =
		      (krb5_octet *) malloc(sizeof(krb5_timestamp)))) {
		    free(pwchg);
		    pwchg = (krb5_tl_data *) NULL;
		}
		else {
		    pwchg->tl_data_type = KRB5_TL_LAST_PWD_CHANGE;
		    pwchg->tl_data_length =
			(krb5_int16) sizeof(krb5_timestamp);
		}
	    }
	}
	else
	    linked = 1;

	/* Do we have an entry? */
	if (pwchg && pwchg->tl_data_contents) {
	    /* Encode it */
	    krb5_kdb_encode_int32(last_pwd_change, pwchg->tl_data_contents);
	    /* Link it in if necessary */
	    if (!linked) {
		pwchg->tl_data_next = dbentp->tl_data;
		dbentp->tl_data = pwchg;
		dbentp->n_tl_data++;
	    }
	}
	else
	    kret = ENOMEM;
    }

    return(kret);
}
#endif

/*
 * process_k5beta_record()	- Handle a dump record in old format.
 *
 * Returns -1 for end of file, 0 for success and 1 for failure.
 */
static int
process_k5beta_record(fname, kcontext, filep, verbose, linenop, pol_db)
    char		*fname;
    krb5_context	kcontext;
    FILE		*filep;
    int			verbose;
    int			*linenop;
   void *pol_db;
{
    int			nmatched;
    int			retval;
    krb5_db_entry	dbent;
    int			name_len, mod_name_len, key_len;
    int			alt_key_len, salt_len, alt_salt_len;
    char		*name;
    char		*mod_name;
    int			tmpint1, tmpint2, tmpint3;
    int			error;
    const char		*try2read;
    int			i;
    krb5_key_data	*pkey, *akey;
    krb5_timestamp	last_pwd_change, mod_date;
    krb5_principal	mod_princ;
    krb5_error_code	kret;

    try2read = (char *) NULL;
    (*linenop)++;
    retval = 1;
    memset((char *)&dbent, 0, sizeof(dbent));

    /* Make sure we've got key_data entries */
    if (krb5_dbe_create_key_data(kcontext, &dbent) ||
	krb5_dbe_create_key_data(kcontext, &dbent)) {
	krb5_db_free_principal(kcontext, &dbent, 1);
	return(1);
    }
    pkey = &dbent.key_data[0];
    akey = &dbent.key_data[1];

    /*
     * Match the sizes.  6 tokens to match.
     */
    nmatched = fscanf(filep, "%d\t%d\t%d\t%d\t%d\t%d\t",
		      &name_len, &mod_name_len, &key_len,
		      &alt_key_len, &salt_len, &alt_salt_len);
    if (nmatched == 6) {
        pkey->key_data_length[0] = key_len;
	akey->key_data_length[0] = alt_key_len;
	pkey->key_data_length[1] = salt_len;
	akey->key_data_length[1] = alt_salt_len;
	name = (char *) NULL;
	mod_name = (char *) NULL;
	/*
	 * Get the memory for the variable length fields.
	 */
	if ((name = (char *) malloc((size_t) (name_len + 1))) &&
	    (mod_name = (char *) malloc((size_t) (mod_name_len + 1))) &&
	    (!key_len ||
	     (pkey->key_data_contents[0] = 
	      (krb5_octet *) malloc((size_t) (key_len + 1)))) &&
	    (!alt_key_len ||
	     (akey->key_data_contents[0] = 
	      (krb5_octet *) malloc((size_t) (alt_key_len + 1)))) &&
	    (!salt_len ||
	     (pkey->key_data_contents[1] = 
	      (krb5_octet *) malloc((size_t) (salt_len + 1)))) &&
	    (!alt_salt_len ||
	     (akey->key_data_contents[1] = 
	      (krb5_octet *) malloc((size_t) (alt_salt_len + 1))))
	    ) {
	    error = 0;

	    /* Read the principal name */
	    if (read_string(filep, name, name_len, linenop)) {
		try2read = read_name_string;
		error++;
	    }
	    /* Read the key type */
	    if (!error && (fscanf(filep, "\t%d\t", &tmpint1) != 1)) {
		try2read = read_key_type;
		error++;
	    }
	    pkey->key_data_type[0] = tmpint1;
	    /* Read the old format key */
	    if (!error && read_octet_string(filep,
					    pkey->key_data_contents[0],
					    pkey->key_data_length[0])) {
		try2read = read_key_data;
		error++;
	    }
	    /* convert to a new format key */
	    /* the encrypted version is stored as the unencrypted key length
	       (4 bytes, MSB first) followed by the encrypted key. */
	    if ((pkey->key_data_length[0] > 4)
		&& (pkey->key_data_contents[0][0] == 0)
		&& (pkey->key_data_contents[0][1] == 0)) {
	      /* this really does look like an old key, so drop and swap */
	      /* the *new* length is 2 bytes, LSB first, sigh. */
	      size_t shortlen = pkey->key_data_length[0]-4+2;
	      krb5_octet *shortcopy = (krb5_octet *) malloc(shortlen);
	      krb5_octet *origdata = pkey->key_data_contents[0];
	      shortcopy[0] = origdata[3];
	      shortcopy[1] = origdata[2];
	      memcpy(shortcopy+2,origdata+4,shortlen-2);
	      free(origdata);
	      pkey->key_data_length[0] = shortlen;
	      pkey->key_data_contents[0] = shortcopy;
	    }
	      
	    /* Read principal attributes */
	    if (!error && (fscanf(filep,
				  "\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t",
				  &tmpint1, &dbent.max_life,
				  &dbent.max_renewable_life,
				  &tmpint2, &dbent.expiration,
				  &dbent.pw_expiration, &last_pwd_change,
				  &dbent.last_success, &dbent.last_failed,
				  &tmpint3) != 10)) {
		try2read = read_pr_data1;
		error++;
	    }
	    pkey->key_data_kvno = tmpint1;
	    dbent.fail_auth_count = tmpint3;
	    /* Read modifier name */
	    if (!error && read_string(filep,
				      mod_name,
				      mod_name_len,
				      linenop)) {
		try2read = read_mod_name;
		error++;
	    }
	    /* Read second set of attributes */
	    if (!error && (fscanf(filep, "\t%u\t%u\t%u\t",
				  &mod_date, &dbent.attributes,
				  &tmpint1) != 3)) {
		try2read = read_pr_data2;
		error++;
	    }
	    pkey->key_data_type[1] = tmpint1;
	    /* Read salt data */
	    if (!error && read_octet_string(filep,
					    pkey->key_data_contents[1],
					    pkey->key_data_length[1])) {
		try2read = read_salt_data;
		error++;
	    }
	    /* Read alternate key type */
	    if (!error && (fscanf(filep, "\t%u\t", &tmpint1) != 1)) {
		try2read = read_akey_type;
		error++;
	    }
	    akey->key_data_type[0] = tmpint1;
	    /* Read alternate key */
	    if (!error && read_octet_string(filep,
					    akey->key_data_contents[0],
					    akey->key_data_length[0])) {
		try2read = read_akey_data;
		error++;
	    }

	    /* convert to a new format key */
	    /* the encrypted version is stored as the unencrypted key length
	       (4 bytes, MSB first) followed by the encrypted key. */
	    if ((akey->key_data_length[0] > 4)
		&& (akey->key_data_contents[0][0] == 0)
		&& (akey->key_data_contents[0][1] == 0)) {
	      /* this really does look like an old key, so drop and swap */
	      /* the *new* length is 2 bytes, LSB first, sigh. */
	      size_t shortlen = akey->key_data_length[0]-4+2;
	      krb5_octet *shortcopy = (krb5_octet *) malloc(shortlen);
	      krb5_octet *origdata = akey->key_data_contents[0];
	      shortcopy[0] = origdata[3];
	      shortcopy[1] = origdata[2];
	      memcpy(shortcopy+2,origdata+4,shortlen-2);
	      free(origdata);
	      akey->key_data_length[0] = shortlen;
	      akey->key_data_contents[0] = shortcopy;
	    }
	      
	    /* Read alternate salt type */
	    if (!error && (fscanf(filep, "\t%u\t", &tmpint1) != 1)) {
		try2read = read_asalt_type;
		error++;
	    }
	    akey->key_data_type[1] = tmpint1;
	    /* Read alternate salt data */
	    if (!error && read_octet_string(filep,
					    akey->key_data_contents[1],
					    akey->key_data_length[1])) {
		try2read = read_asalt_data;
		error++;
	    }
	    /* Read expansion data - discard it */
	    if (!error) {
		for (i=0; i<8; i++) {
		    if (fscanf(filep, "\t%u", &tmpint1) != 1) {
			try2read = read_exp_data;
			error++;
			break;
		    }
		}
		if (!error)
		    find_record_end(filep, fname, *linenop);
	    }
	
	    /*
	     * If no error, then we're done reading.  Now parse the names
	     * and store the database dbent.
	     */
	    if (!error) {
		if (!(kret = krb5_parse_name(kcontext,
					     name,
					     &dbent.princ))) {
		    if (!(kret = krb5_parse_name(kcontext,
						 mod_name,
						 &mod_princ))) {
			if (!(kret =
			      krb5_dbe_update_mod_princ_data(kcontext,
							     &dbent,
							     mod_date,
							     mod_princ)) &&
			    !(kret =
			      krb5_dbe_update_last_pwd_change(kcontext,
							      &dbent,
							      last_pwd_change))) {
			    int one = 1;

			    dbent.len = KRB5_KDB_V1_BASE_LENGTH;
			    pkey->key_data_ver = (pkey->key_data_type[1] || pkey->key_data_length[1]) ?
				2 : 1;
			    akey->key_data_ver = (akey->key_data_type[1] || akey->key_data_length[1]) ?
				2 : 1;
			    if ((pkey->key_data_type[0] ==
				 akey->key_data_type[0]) &&
				(pkey->key_data_type[1] ==
				 akey->key_data_type[1]))
				dbent.n_key_data--;
			    else if ((akey->key_data_type[0] == 0)
				     && (akey->key_data_length[0] == 0)
				     && (akey->key_data_type[1] == 0)
				     && (akey->key_data_length[1] == 0))
			        dbent.n_key_data--;
			    if ((kret = krb5_db_put_principal(kcontext,
							      &dbent,
							      &one)) ||
				(one != 1)) {
				fprintf(stderr, store_err_fmt,
					fname, *linenop, name,
					error_message(kret));
				error++;
			    }
			    else {
				if (verbose)
				    fprintf(stderr, add_princ_fmt, name);
				retval = 0;
			    }
			    dbent.n_key_data = 2;
			}
			krb5_free_principal(kcontext, mod_princ);
		    }
		    else {
			fprintf(stderr, parse_err_fmt, 
				fname, *linenop, mod_name, 
				error_message(kret));
			error++;
		    }
		}
		else {
		    fprintf(stderr, parse_err_fmt,
			    fname, *linenop, name, error_message(kret));
		    error++;
		}
	    }
	    else {
		fprintf(stderr, read_err_fmt, fname, *linenop, try2read);
	    }
	}
	else {
	    fprintf(stderr, no_mem_fmt, fname, *linenop);
	}

	krb5_db_free_principal(kcontext, &dbent, 1);
	if (mod_name)
	    free(mod_name);
	if (name)
	    free(name);
    }
    else {
	if (nmatched != EOF)
	    fprintf(stderr, rhead_err_fmt, fname, *linenop);
	else
	    retval = -1;
    }
    return(retval);
}

/*
 * process_k5beta6_record()	- Handle a dump record in krb5b6 format.
 *
 * Returns -1 for end of file, 0 for success and 1 for failure.
 */
static int
process_k5beta6_record(fname, kcontext, filep, verbose, linenop, pol_db)
    char		*fname;
    krb5_context	kcontext;
    FILE		*filep;
    int			verbose;
    int			*linenop;
   void *pol_db;
{
    int			retval;
    krb5_db_entry	dbentry;
    krb5_int32		t1, t2, t3, t4, t5, t6, t7, t8, t9;
    int			nread;
    int			error;
    int			i, j, one;
    char		*name;
    krb5_key_data	*kp, *kdatap;
    krb5_tl_data	**tlp, *tl;
    krb5_octet 		*op;
    krb5_error_code	kret;
    const char		*try2read;

    try2read = (char *) NULL;
    memset((char *) &dbentry, 0, sizeof(dbentry));
    (*linenop)++;
    retval = 1;
    name = (char *) NULL;
    kp = (krb5_key_data *) NULL;
    op = (krb5_octet *) NULL;
    error = 0;
    kret = 0;
    nread = fscanf(filep, "%d\t%d\t%d\t%d\t%d\t", &t1, &t2, &t3, &t4, &t5);
    if (nread == 5) {
	/* Get memory for flattened principal name */
	if (!(name = (char *) malloc((size_t) t2 + 1)))
	    error++;

	/* Get memory for and form tagged data linked list */
	tlp = &dbentry.tl_data;
	for (i=0; i<t3; i++) {
	    if ((*tlp = (krb5_tl_data *) malloc(sizeof(krb5_tl_data)))) {
		memset(*tlp, 0, sizeof(krb5_tl_data));
		tlp = &((*tlp)->tl_data_next);
		dbentry.n_tl_data++;
	    }
	    else {
		error++;
		break;
	    }
	}

	/* Get memory for key list */
	if (t4 && !(kp = (krb5_key_data *) malloc((size_t)
						  (t4*sizeof(krb5_key_data)))))
	    error++;

	/* Get memory for extra data */
	if (t5 && !(op = (krb5_octet *) malloc((size_t) t5)))
	    error++;

	if (!error) {
	    dbentry.len = t1;
	    dbentry.n_key_data = t4;
	    dbentry.e_length = t5;
	    if (kp) {
		memset(kp, 0, (size_t) (t4*sizeof(krb5_key_data)));
		dbentry.key_data = kp;
		kp = (krb5_key_data *) NULL;
	    }
	    if (op) {
		memset(op, 0, (size_t) t5);
		dbentry.e_data = op;
		op = (krb5_octet *) NULL;
	    }

	    /* Read in and parse the principal name */
	    if (!read_string(filep, name, t2, linenop) &&
		!(kret = krb5_parse_name(kcontext, name, &dbentry.princ))) {

		/* Get the fixed principal attributes */
		nread = fscanf(filep, "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t",
			       &t2, &t3, &t4, &t5, &t6, &t7, &t8, &t9);
		if (nread == 8) {
		    dbentry.attributes = (krb5_flags) t2;
		    dbentry.max_life = (krb5_deltat) t3;
		    dbentry.max_renewable_life = (krb5_deltat) t4;
		    dbentry.expiration = (krb5_timestamp) t5;
		    dbentry.pw_expiration = (krb5_timestamp) t6;
		    dbentry.last_success = (krb5_timestamp) t7;
		    dbentry.last_failed = (krb5_timestamp) t8;
		    dbentry.fail_auth_count = (krb5_kvno) t9;
		} else {
		    try2read = read_nint_data;
		    error++;
		}

		/*
		 * Get the tagged data.
		 *
		 * Really, this code ought to discard tl data types
		 * that it knows are special to the current version
		 * and were not supported in the previous version.
		 * But it's a pain to implement that here, and doing
		 * it at dump time has almost as good an effect, so
		 * that's what I did.  [krb5-admin/89]
		 */
		if (!error && dbentry.n_tl_data) {
		    for (tl = dbentry.tl_data; tl; tl = tl->tl_data_next) {
			nread = fscanf(filep, "%d\t%d\t", &t1, &t2);
			if (nread == 2) {
			    tl->tl_data_type = (krb5_int16) t1;
			    tl->tl_data_length = (krb5_int16) t2;
			    if (tl->tl_data_length) {
				if (!(tl->tl_data_contents =
				      (krb5_octet *) malloc((size_t) t2+1)) ||
				    read_octet_string(filep,
						      tl->tl_data_contents,
						      t2)) {
				    try2read = read_tcontents;
				    error++;
				    break;
				}
			    }
			    else {
				/* Should be a null field */
				nread = fscanf(filep, "%d", &t9);
				if ((nread != 1) || (t9 != -1)) {
				    error++;
				    try2read = read_tcontents;
				    break;
				}
			    }
			}
			else {
			    try2read = read_ttypelen;
			    error++;
			    break;
			}
		    }
		}

		/* Get the key data */
		if (!error && dbentry.n_key_data) {
		    for (i=0; !error && (i<dbentry.n_key_data); i++) {
			kdatap = &dbentry.key_data[i];
			nread = fscanf(filep, "%d\t%d\t", &t1, &t2);
			if (nread == 2) {
			    kdatap->key_data_ver = (krb5_int16) t1;
			    kdatap->key_data_kvno = (krb5_int16) t2;

			    for (j=0; j<t1; j++) {
				nread = fscanf(filep, "%d\t%d\t", &t3, &t4);
				if (nread == 2) {
				    kdatap->key_data_type[j] = t3;
				    kdatap->key_data_length[j] = t4;
				    if (t4) {
					if (!(kdatap->key_data_contents[j] =
					      (krb5_octet *)
					      malloc((size_t) t4+1)) ||
					    read_octet_string(filep,
							      kdatap->key_data_contents[j],
							      t4)) {
					    try2read = read_kcontents;
					    error++;
					    break;
					}
				    }
				    else {
					/* Should be a null field */
					nread = fscanf(filep, "%d", &t9);
					if ((nread != 1) || (t9 != -1)) {
					    error++;
					    try2read = read_kcontents;
					    break;
					}
				    }
				}
				else {
				    try2read = read_ktypelen;
				    error++;
				    break;
				}
			    }
			}
		    }
		}

		/* Get the extra data */
		if (!error && dbentry.e_length) {
		    if (read_octet_string(filep,
					  dbentry.e_data,
					  (int) dbentry.e_length)) {
			try2read = read_econtents;
			error++;
		    }
		}
		else {
		    nread = fscanf(filep, "%d", &t9);
		    if ((nread != 1) || (t9 != -1)) {
			error++;
			try2read = read_econtents;
		    }
		}

		/* Finally, find the end of the record. */
		if (!error)
		    find_record_end(filep, fname, *linenop);

		/*
		 * We have either read in all the data or choked.
		 */
		if (!error) {
		    one = 1;
		    if ((kret = krb5_db_put_principal(kcontext,
						      &dbentry,
						      &one))) {
			fprintf(stderr, store_err_fmt,
				fname, *linenop,
				name, error_message(kret));
		    }
		    else {
			if (verbose)
			    fprintf(stderr, add_princ_fmt, name);
			retval = 0;
		    }
		}
		else {
		    fprintf(stderr, read_err_fmt, fname, *linenop, try2read);
		}
	    }
	    else {
		if (kret)
		    fprintf(stderr, parse_err_fmt,
			    fname, *linenop, name, error_message(kret));
		else
		    fprintf(stderr, no_mem_fmt, fname, *linenop);
	    }
	}
	else {
	    fprintf(stderr, rhead_err_fmt, fname, *linenop);
	}

	if (op)
	    free(op);
	if (kp)
	    free(kp);
	if (name)
	    free(name);
	krb5_db_free_principal(kcontext, &dbentry, 1);
    }
    else {
	if (nread == EOF)
	    retval = -1;
    }
    return(retval);
}

static int 
process_k5beta7_policy(fname, kcontext, filep, verbose, linenop, pol_db)
    char		*fname;
    krb5_context	kcontext;
    FILE		*filep;
    int			verbose;
    int			*linenop;
    void *pol_db;
{
    osa_policy_ent_rec rec;
    char namebuf[1024];
    int nread, ret;

    (*linenop)++;
    rec.name = namebuf;

    nread = fscanf(filep, "%1024s\t%d\t%d\t%d\t%d\t%d\t%d", rec.name,
		   &rec.pw_min_life, &rec.pw_max_life,
		   &rec.pw_min_length, &rec.pw_min_classes,
		   &rec.pw_history_num, &rec.policy_refcnt);
    if (nread == EOF)
	 return -1;
    else if (nread != 7) {
	 fprintf(stderr, "cannot parse policy on line %d (%d read)\n",
		 *linenop, nread);
	 return 1;
    }

    if ((ret = osa_adb_create_policy(pol_db, &rec))) {
	 if (ret == OSA_ADB_DUP &&
	     ((ret = osa_adb_put_policy(pol_db, &rec)))) {
	      fprintf(stderr, "cannot create policy on line %d: %s\n",
		      *linenop, error_message(ret));
	      return 1;
	 }
    }
    if (verbose)
	 fprintf(stderr, "created policy %s\n", rec.name);
    
    return 0;
}

/*
 * process_k5beta7_record()	- Handle a dump record in krb5b7 format.
 *
 * Returns -1 for end of file, 0 for success and 1 for failure.
 */
static int
process_k5beta7_record(fname, kcontext, filep, verbose, linenop, pol_db)
    char		*fname;
    krb5_context	kcontext;
    FILE		*filep;
    int			verbose;
    int			*linenop;
   void *pol_db;
{
     int nread;
     char rectype[100];

     nread = fscanf(filep, "%100s\t", rectype);
     if (nread == EOF)
	  return -1;
     else if (nread != 1)
	  return 1;
     if (strcmp(rectype, "princ") == 0)
	  process_k5beta6_record(fname, kcontext, filep, verbose,
				 linenop, pol_db);
     else if (strcmp(rectype, "policy") == 0)
	  process_k5beta7_policy(fname, kcontext, filep, verbose,
				 linenop, pol_db);
     else {
	  fprintf(stderr, "unknown record type \"%s\" on line %d\n",
		  rectype, *linenop);
	  return 1;
     }

     return 0;
}

/*
 * process_ov_record()	- Handle a dump record in OpenV*Secure 1.0 format.
 *
 * Returns -1 for end of file, 0 for success and 1 for failure.
 */
static int
process_ov_record(fname, kcontext, filep, verbose, linenop, pol_db)
    char		*fname;
    krb5_context	kcontext;
    FILE		*filep;
    int			verbose;
    int			*linenop;
   void *pol_db;
{
     int nread;
     char rectype[100];

     nread = fscanf(filep, "%100s\t", rectype);
     if (nread == EOF)
	  return -1;
     else if (nread != 1)
	  return 1;
     if (strcmp(rectype, "princ") == 0)
	  process_ov_principal(fname, kcontext, filep, verbose,
			       linenop, pol_db);
     else if (strcmp(rectype, "policy") == 0)
	  process_k5beta7_policy(fname, kcontext, filep, verbose,
				 linenop, pol_db);
     else if (strcmp(rectype, "End") == 0)
	  return -1;
     else {
	  fprintf(stderr, "unknown record type \"%s\" on line %d\n",
		  rectype, *linenop);
	  return 1;
     }

     return 0;
}

/*
 * restore_dump()	- Restore the database from any version dump file.
 */
static int
restore_dump(programname, kcontext, dumpfile, f, verbose, dump, pol_db)
    char		*programname;
    krb5_context	kcontext;
    char		*dumpfile;
    FILE		*f;
    int			verbose;
    dump_version	*dump;
    osa_adb_policy_t	pol_db;
{
    int		error;	
    int		lineno;

    error = 0;
    lineno = 1;

    /*
     * Process the records.
     */
    while (!(error = (*dump->load_record)(dumpfile,
					  kcontext, 
					  f,
					  verbose,
					  &lineno,
					  pol_db)))
	 ;
    if (error != -1)
	 fprintf(stderr, err_line_fmt, programname, lineno, dumpfile);
    else
	 error = 0;

    return(error);
}

/*
 * Usage: load_db [-old] [-ov] [-b6] [-b7] [-verbose] [-update] [-hash]
 *		filename
 */
void
load_db(argc, argv)
    int		argc;
    char	**argv;
{
    kadm5_config_params newparams;
    osa_adb_policy_t	tmppol_db;
    krb5_error_code	kret;
    krb5_context	kcontext;
    FILE		*f;
    extern char		*optarg;
    extern int		optind;
    char		*programname;
    char		*dumpfile;
    char		*dbname;
    char		*dbname_tmp;
    char		buf[BUFSIZ];
    dump_version	*load;
    int			update, verbose;
    krb5_int32		crflags;
    int			aindex;

    /*
     * Parse the arguments.
     */
    programname = argv[0];
    if (strrchr(programname, (int) '/'))
	programname = strrchr(argv[0], (int) '/') + 1;
    dumpfile = (char *) NULL;
    dbname = global_params.dbname;
    load = NULL;
    update = 0;
    verbose = 0;
    crflags = KRB5_KDB_CREATE_BTREE;
    exit_status = 0;
    dbname_tmp = (char *) NULL;
    tmppol_db = NULL;
    for (aindex = 1; aindex < argc; aindex++) {
	if (!strcmp(argv[aindex], oldoption))
	     load = &old_version;
	else if (!strcmp(argv[aindex], b6option))
	     load = &beta6_version;
	else if (!strcmp(argv[aindex], b7option))
	     load = &beta7_version;
	else if (!strcmp(argv[aindex], ovoption))
	     load = &ov_version;
	else if (!strcmp(argv[aindex], verboseoption))
	    verbose = 1;
	else if (!strcmp(argv[aindex], updateoption))
	    update = 1;
	else if (!strcmp(argv[aindex], hashoption))
	    crflags = KRB5_KDB_CREATE_HASH;
	else
	    break;
    }
    if ((argc - aindex) != 1) {
	usage();
	return;
    }
    dumpfile = argv[aindex];

    if (!(dbname_tmp = (char *) malloc(strlen(dbname)+
				       strlen(dump_tmptrail)+1))) {
	fprintf(stderr, no_name_mem_fmt, argv[0]);
	exit_status++;
	return;
    }
    strcpy(dbname_tmp, dbname);
    strcat(dbname_tmp, dump_tmptrail);

    /*
     * Initialize the Kerberos context and error tables.
     */
    if ((kret = krb5_init_context(&kcontext))) {
	fprintf(stderr, ctx_err_fmt, programname);
	free(dbname_tmp);
	exit_status++;
	return;
    }

    /*
     * Open the dumpfile
     */
    if (dumpfile) {
	if ((f = fopen(dumpfile, "r+")) == NULL) {
	     fprintf(stderr, dfile_err_fmt, programname, dumpfile,
		     error_message(errno)); 
	     exit_status++;
	     return;
	}
	if ((kret = krb5_lock_file(kcontext, fileno(f),
				   KRB5_LOCKMODE_SHARED))) {
	     fprintf(stderr, "%s: Cannot lock %s: %s\n", programname,
		     dumpfile, error_message(errno));
	     exit_status++;
	     return;
	}
    } else
	f = stdin;

    /*
     * Auto-detect dump version if we weren't told, verify if we
     * were told.
     */
    fgets(buf, sizeof(buf), f);
    if (load) {
	 /* only check what we know; some headers only contain a prefix */
	 if (strncmp(buf, load->header, strlen(load->header)) != 0) {
	      fprintf(stderr, head_bad_fmt, programname, dumpfile);
	      exit_status++;
	      if (dumpfile) fclose(f);
	      return;
	 }
    } else {
	 /* perhaps this should be in an array, but so what? */
	 if (strcmp(buf, old_version.header) == 0)
	      load = &old_version;
	 else if (strcmp(buf, beta6_version.header) == 0)
	      load = &beta6_version;
	 else if (strcmp(buf, beta7_version.header) == 0)
	      load = &beta7_version;
	 else if (strcmp(buf, r1_3_version.header) == 0)
	      load = &r1_3_version;
	 else if (strncmp(buf, ov_version.header,
			  strlen(ov_version.header)) == 0)
	      load = &ov_version;
	 else {
	      fprintf(stderr, head_bad_fmt, programname, dumpfile);
	      exit_status++;
	      if (dumpfile) fclose(f);
	      return;
	 }
    }
    if (load->updateonly && !update) {
	 fprintf(stderr, "%s: dump version %s can only be loaded with the "
		 "-update flag\n", programname, load->name);
	 exit_status++;
	 return;
    }

    /*
     * Cons up params for the new databases.  If we are not in update
     * mode use a temp name that we'll rename later.
     */
    newparams = global_params;
    if (! update) {
	 newparams.mask |= KADM5_CONFIG_DBNAME;
	 newparams.dbname = dbname_tmp;

	 if ((kret = kadm5_get_config_params(kcontext, NULL, NULL,
					     &newparams, &newparams))) {
	      com_err(argv[0], kret,
		      "while retreiving new configuration parameters");
	      exit_status++;
	      return;
	 }
    }
    
    /*
     * If not an update restoration, create the temp database.  Always
     * create a temp policy db, even if we are not loading a dump file
     * with policy info, because they may be loading an old dump
     * intending to use it with the new kadm5 system.
     */
    if (!update && ((kret = krb5_db_create(kcontext, dbname_tmp, crflags)))) {
	 fprintf(stderr, dbcreaterr_fmt,
		 programname, dbname_tmp, error_message(kret));
	 exit_status++;
	 kadm5_free_config_params(kcontext, &newparams);
	 if (dumpfile) fclose(f);
	 return;
    }
    if (!update && (kret = osa_adb_create_policy_db(&newparams))) {
	 fprintf(stderr, "%s: %s while creating policy database\n",
		 programname, error_message(kret));
	 exit_status++;
	 kadm5_free_config_params(kcontext, &newparams);
	 if (dumpfile) fclose(f);
	 return;
    }

    /*
     * Point ourselves at the new databases.
     */
    if ((kret = krb5_db_set_name(kcontext,
				(update) ? dbname : dbname_tmp))) {
	 fprintf(stderr, dbname_err_fmt,
		 programname, 
		 (update) ? dbname : dbname_tmp, error_message(kret));
	 exit_status++;
	 goto error;
    }
    if ((kret = osa_adb_open_policy(&tmppol_db, &newparams))) {
	 fprintf(stderr, "%s: %s while opening policy database\n",
		 programname, error_message(kret));
	 exit_status++;
	 goto error;
    }
    /*
     * If an update restoration, make sure the db is left unusable if
     * the update fails.
     */
    if (update) {
	 if ((kret = osa_adb_get_lock(tmppol_db, OSA_ADB_PERMANENT))) {
	      fprintf(stderr, "%s: %s while permanently locking database\n",
		      programname, error_message(kret));
	      exit_status++;
	      goto error;
	 }
    }
		      
    /*
     * Initialize the database.
     */
    if ((kret = krb5_db_init(kcontext))) {
	 fprintf(stderr, dbinit_err_fmt,
		 programname, error_message(kret));
	 exit_status++;
	 goto error;
    }
    /* 
     * grab an extra lock, since there are no other users
     */
    if (!update) {
	 kret = krb5_db_lock(kcontext, KRB5_LOCKMODE_EXCLUSIVE);
	 if (kret) {
		 fprintf(stderr, dblock_err_fmt,
			 programname, error_message(kret));
		 exit_status++;
		 goto error;
	 }
    }
    
    if (restore_dump(programname, kcontext, (dumpfile) ? dumpfile : stdin_name,
		     f, verbose, load, tmppol_db)) {
	 fprintf(stderr, restfail_fmt,
		 programname, load->name);
	 exit_status++;
    }

    if (!update && (kret = krb5_db_unlock(kcontext))) {
	 /* change this error? */
	 fprintf(stderr, dbunlockerr_fmt,
		 programname, dbname_tmp, error_message(kret));
	 exit_status++;
    }
    if ((kret = krb5_db_fini(kcontext))) {
	 fprintf(stderr, close_err_fmt,
		 programname, error_message(kret));
	 exit_status++;
    }

    if (!update && load->create_kadm5 &&
	((kret = kadm5_create_magic_princs(&newparams, kcontext)))) {
	 /* error message printed by create_magic_princs */
	 exit_status++;
    }
    
    /* close policy db below */

error:
    /*
     * If not an update: if there was an error, destroy the temp database,
     * otherwise rename it into place.
     *
     * If an update: if there was no error, unlock the database.
     */
    if (!update) {
	 if (exit_status) {
	      if ((kret = krb5_db_destroy(kcontext, dbname_tmp))) {
		   fprintf(stderr, dbdelerr_fmt,
			   programname, dbname_tmp, error_message(kret));
		   exit_status++;
	      }
	      if ((kret = osa_adb_destroy_policy_db(&newparams))) {
		   fprintf(stderr, "%s: %s while destroying policy database\n",
			   programname, error_message(kret));
		   exit_status++;
	      }
	 }
	 else {
	      if ((kret = krb5_db_rename(kcontext,
					 dbname_tmp,
					 dbname))) {
		   fprintf(stderr, dbrenerr_fmt,
			   programname, dbname_tmp, dbname,
			   error_message(kret));
		   exit_status++;
	      } 

	      if ((kret = osa_adb_close_policy(tmppol_db))) {
		   fprintf(stderr, close_err_fmt,
			   programname, error_message(kret));
		   exit_status++;
	      }

	      if ((kret = osa_adb_rename_policy_db(&newparams,
						   &global_params))) {
		   fprintf(stderr,
			   "%s: %s while renaming policy db %s to %s\n",
			   programname, error_message(kret),
			   newparams.admin_dbname,
			   global_params.admin_dbname);
		   exit_status++;
	      }
	 }
    } else /* update */ {
	 if (! exit_status && ((kret = osa_adb_release_lock(tmppol_db)))) {
	      fprintf(stderr, "%s: %s while releasing permanent lock\n",
		      programname, error_message(kret));
	      exit_status++;
	 }

	 if (tmppol_db && ((kret = osa_adb_close_policy(tmppol_db)))) {
	      fprintf(stderr, close_err_fmt,
		      programname, error_message(kret));
	      exit_status++;
	 }
    }

    if (dumpfile) {
	 (void) krb5_lock_file(kcontext, fileno(f), KRB5_LOCKMODE_UNLOCK);
	 fclose(f);
    }

    if (dbname_tmp)
	 free(dbname_tmp);
    krb5_free_context(kcontext);
}

/*
 * admin/edit/dump.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 *
 * Dump a KDC database
 */

#include "k5-int.h"
#include "com_err.h"
#include <stdio.h>
#include "kdb5_edit.h"
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

struct dump_args {
    char		*programname;
    FILE		*ofile;
    krb5_context	kcontext;
    char		**names;
    int			nnames;
    int			verbose;
};

/* External data */
extern char		*current_dbname;
extern krb5_boolean	dbactive;
extern int		exit_status;
extern krb5_context	edit_context;

/* Strings */

static const char k5beta_dump_header[] = "kdb5_edit load_dump version 2.0\n";
static const char k5_dump_header[] = "kdb5_edit load_dump version 3.0\n";

static const char null_mprinc_name[] = "kdb5_dump@MISSING";

/* Message strings */
static const char regex_err[] = "%s: regular expression error - %s\n";
static const char regex_merr[] = "%s: regular expression match error - %s\n";
static const char pname_unp_err[] = "%s: cannot unparse principal name (%s)\n";
static const char mname_unp_err[] = "%s: cannot unparse modifier name (%s)\n";
static const char nokeys_err[] = "%s: cannot find any standard key for %s\n";
static const char sdump_tl_inc_err[] = "%s: tagged data list inconsistency for %s (counted %d, stored %d)\n";
static const char stand_fmt_name[] = "Kerberos version 5";
static const char old_fmt_name[] = "Kerberos version 5 old format";
static const char ofopen_error[] = "%s: cannot open %s for writing (%s)\n";
static const char oflock_error[] = "%s: cannot lock %s (%s)\n";
static const char dumprec_err[] = "%s: error performing %s dump (%s)\n";
static const char dumphdr_err[] = "%s: error dumping %s header (%s)\n";
static const char trash_end_fmt[] = "%s(%d): ignoring trash at end of line: ";
static const char read_name_string[] = "name string";
static const char read_key_type[] = "key type";
static const char read_key_data[] = "key data";
static const char read_pr_data1[] = "first set of principal attributes";
static const char read_mod_name[] = "modifier name";
static const char read_pr_data2[] = "second set of principal attributes";
static const char read_salt_data[] = "salt data";
static const char read_akey_type[] = "alternate key type";
static const char read_akey_data[] = "alternate key data";
static const char read_asalt_type[] = "alternate salt type";
static const char read_asalt_data[] = "alternate salt data";
static const char read_exp_data[] = "expansion data";
static const char store_err_fmt[] = "%s(%d): cannot store %s(%s)\n";
static const char add_princ_fmt[] = "%s\n";
static const char parse_err_fmt[] = "%s(%d): cannot parse %s (%s)\n";
static const char read_err_fmt[] = "%s(%d): cannot read %s\n";
static const char no_mem_fmt[] = "%s(%d): no memory for buffers\n";
static const char rhead_err_fmt[] = "%s(%d): cannot match size tokens\n";
static const char err_line_fmt[] = "%s: error processing line %d of %s\n";
static const char head_bad_fmt[] = "%s: dump header bad in %s\n";
static const char read_bytecnt[] = "record byte count";
static const char read_encdata[] = "encoded data";
static const char n_name_unp_fmt[] = "%s(%s): cannot unparse name\n";
static const char n_dec_cont_fmt[] = "%s(%s): cannot decode contents\n";
static const char read_nint_data[] = "principal static attributes";
static const char read_tcontents[] = "tagged data contents";
static const char read_ttypelen[] = "tagged data type and length";
static const char read_kcontents[] = "key data contents";
static const char read_ktypelen[] = "key data type and length";
static const char read_econtents[] = "extra data contents";
static const char k5beta_fmt_name[] = "Kerberos version 5 old format";
static const char standard_fmt_name[] = "Kerberos version 5 format";
static const char lusage_err_fmt[] = "%s: usage is %s [%s] [%s] [%s] filename dbname\n";
static const char no_name_mem_fmt[] = "%s: cannot get memory for temporary name\n";
static const char ctx_err_fmt[] = "%s: cannot initialize Kerberos context\n";
static const char stdin_name[] = "standard input";
static const char restfail_fmt[] = "%s: %s restore failed\n";
static const char close_err_fmt[] = "%s: cannot close database (%s)\n";
static const char dbinit_err_fmt[] = "%s: cannot initialize database (%s)\n";
static const char dbname_err_fmt[] = "%s: cannot set database name to %s (%s)\n";
static const char dbdelerr_fmt[] = "%s: cannot delete bad database %s (%s)\n";
static const char dbrenerr_fmt[] = "%s: cannot rename database %s to %s (%s)\n";
static const char dbcreaterr_fmt[] = "%s: cannot create database %s (%s)\n";
static const char dfile_err_fmt[] = "%s: cannot open %s (%s)\n";

static const char oldoption[] = "-old";
static const char verboseoption[] = "-verbose";
static const char updateoption[] = "-update";
static const char dump_tmptrail[] = "~";

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
	if (match_error = regcomp(&match_exp,
				  arglist->names[i],
				  REG_EXTENDED)) {
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
	if (match_error = regexec(&match_exp, name, 1, &match_match, 0)) {
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
find_keytype(dbentp, keytype, salttype, kentp)
    krb5_db_entry	*dbentp;
    krb5_keytype	keytype;
    krb5_int32		salttype;
    krb5_key_data	**kentp;
{
    int			i;
    int			maxkvno;
    krb5_key_data	*datap;

    maxkvno = -1;
    datap = (krb5_key_data *) NULL;
    for (i=0; i<dbentp->n_key_data; i++) {
	if ((dbentp->key_data[i].key_data_type[0] == keytype) &&
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
    krb5_tl_mod_princ	*mprinc;
    krb5_tl_data	*pwchg;
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
     * If we don't have any match strings, or if our name matches, then
     * proceed with the dump, otherwise, just forget about it.
     */
    if (!arg->nnames || name_matches(name, arg)) {
	/*
	 * Deserialize the modifier record.
	 */
	mprinc = (krb5_tl_mod_princ *) NULL;
	mod_name = (char *) NULL;
	last_pwd_change = mod_date = 0;
	pkey = akey = (krb5_key_data *) NULL;
	if (!(retval = krb5_dbe_decode_mod_princ_data(arg->kcontext,
						      entry,
						      &mprinc))) {
	    if (mprinc) {
		if (mprinc->mod_princ) {
		    /*
		     * Flatten the modifier name.
		     */
		    if ((retval = krb5_unparse_name(arg->kcontext,
						    mprinc->mod_princ,
						    &mod_name)))
			fprintf(stderr, mname_unp_err, arg->programname,
				error_message(retval));
		    krb5_free_principal(arg->kcontext, mprinc->mod_princ);
		}
		mod_date = mprinc->mod_date;
		krb5_xfree(mprinc);
	    }
	}
	if (!mod_name)
	    mod_name = strdup(null_mprinc_name);

	/*
	 * Find the last password change record and set it straight.
	 */
	for (pwchg = entry->tl_data;
	     (pwchg) && (pwchg->tl_data_type != KRB5_TL_LAST_PWD_CHANGE);
	     pwchg = pwchg->tl_data_next);
	if (pwchg) {
	    krb5_kdb_decode_int32(pwchg->tl_data_contents, last_pwd_change);
	}

	/*
	 * Find the 'primary' key and the 'alternate' key.
	 */
	if ((retval = find_keytype(entry,
				   KEYTYPE_DES_CBC_CRC,
				   KRB5_KDB_SALTTYPE_NORMAL,
				   &pkey)) &&
	    (retval = find_keytype(entry,
				   KEYTYPE_DES_CBC_CRC,
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
		entry->mkvno, entry->expiration, entry->pw_expiration,
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
 * dump_standard_header()	- Output the standard dump header.
 */
static krb5_error_code
dump_standard_header(arglist)
    struct dump_args *arglist;
{
    /* The standard header consists of the leading string */
    fprintf(arglist->ofile, k5_dump_header);
    return(0);
}

/*
 * dump_standard_iterator()	- Output a dump record in standard format.
 */
static krb5_error_code
dump_standard_iterator(ptr, entry)
    krb5_pointer	ptr;
    krb5_db_entry	*entry;
{
    krb5_error_code	retval;
    struct dump_args	*arg;
    char		*name;
    krb5_tl_data	*tlp;
    krb5_key_data	*kdata;
    int			counter, i, j;

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
	/*
	 * We'd like to just blast out the contents as they would appear in
	 * the database so that we can just suck it back in, but it doesn't
	 * lend itself to easy editing.
	 */

	/*
	 * The dump format is as follows:
	 *	len strlen(name) n_tl_data n_key_data e_length
	 *	name
	 *	mkvno attributes max_life max_renewable_life expiration
	 *	pw_expiration last_success last_failed fail_auth_count
	 *	n_tl_data*[type length <contents>]
	 *	n_key_data*[ver kvno ver*(type length <contents>)]
	 *	<e_data>
	 * Fields which are not encapsulated by angle-brackets are to appear
	 * verbatim.  Bracketed fields absence is indicated by a -1 in its
	 * place
	 */

	/*
	 * Make sure that the tagged list is reasonably correct.
	 */
	counter = 0;
	for (tlp = entry->tl_data; tlp; tlp = tlp->tl_data_next)
	    counter++;
	if (counter == entry->n_tl_data) {
	    /* Pound out header */
	    fprintf(arg->ofile, "%d\t%d\t%d\t%d\t%d\t%s\t",
		    (int) entry->len,
		    strlen(name),
		    (int) entry->n_tl_data,
		    (int) entry->n_key_data,
		    (int) entry->e_length,
		    name);
	    fprintf(arg->ofile, "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t",
		    entry->mkvno,
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
		    arg->programname, name, counter, (int) entry->n_tl_data);
	    retval = EINVAL;
	}
    }
    krb5_xfree(name);
    return(retval);
}

/*
 * usage is:
 *	dump_db [-old] [-verbose] [filename [principals...]]
 */
void
dump_db(argc, argv)
    int		argc;
    char	**argv;
{
    FILE		*f;
    struct dump_args	arglist;
    int			error;
    char		*programname;
    char		*ofile;
    krb5_error_code	kret;
    krb5_error_code	(*dump_iterator) PROTOTYPE((krb5_pointer,
						    krb5_db_entry *));
    krb5_error_code	(*dump_header) PROTOTYPE((struct dump_args *));
    const char		* dump_name;
    int			aindex;
    krb5_boolean	locked;
	
    /*
     * Parse the arguments.
     */
    programname = argv[0];
    if (strrchr(programname, (int) '/'))
	programname = strrchr(argv[0], (int) '/') + 1;
    ofile = (char *) NULL;
    error = 0;
    dump_iterator = dump_standard_iterator;
    dump_header = dump_standard_header;
    dump_name = stand_fmt_name;
    arglist.verbose = 0;

    /*
     * Parse the qualifiers.
     */
    for (aindex = 1; aindex < argc; aindex++) {
	if (!strcmp(argv[aindex], oldoption)) {
	    dump_iterator = dump_k5beta_iterator;
	    dump_header = dump_k5beta_header;
	    dump_name = old_fmt_name;
	}
	else if (!strcmp(argv[aindex], verboseoption)) {
	    arglist.verbose++;
	}
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
     * Attempt to open the database.
     */
    if (!dbactive) {
	com_err(argv[0], 0, Err_no_database);
	exit_status++;
	return;
    }

    kret = 0;
    locked = 0;
    if (ofile) {
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
	}
	if ((kret = krb5_lock_file(edit_context,
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
	arglist.kcontext = edit_context;
	if (!(kret = (*dump_header)(&arglist))) {
	    if ((kret = krb5_db_iterate(edit_context,
					dump_iterator,
					(krb5_pointer) &arglist))) {
		fprintf(stderr, dumprec_err,
			programname, dump_name, error_message(kret));
		exit_status++;
	    }
	}
	else {
	    fprintf(stderr, dumphdr_err,
		    programname, dump_name, error_message(kret));
	    exit_status++;
	}
	if (ofile && !exit_status) {
	    fclose(f);
	    update_ok_file(ofile);
	}
    }
    if (locked)
	(void) krb5_lock_file(edit_context, fileno(f), KRB5_LOCKMODE_UNLOCK);
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
	c = (char) fgetc(f);
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

/*
 * process_k5beta_record()	- Handle a dump record in old format.
 *
 * Returns -1 for end of file, 0 for success and 1 for failure.
 */
static int
process_k5beta_record(fname, kcontext, filep, verbose, linenop)
    char		*fname;
    krb5_context	kcontext;
    FILE		*filep;
    int			verbose;
    int			*linenop;
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
	    /* Read the key */
	    if (!error && read_octet_string(filep,
					    pkey->key_data_contents[0],
					    pkey->key_data_length[0])) {
		try2read = read_key_data;
		error++;
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
	    dbent.mkvno = tmpint2;
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
			if (!(kret = update_tl_data(kcontext,
						    &dbent,
						    mod_princ,
						    mod_date,
						    last_pwd_change))) {
			    int one = 1;

			    dbent.len = KRB5_KDB_V1_BASE_LENGTH;
			    pkey->key_data_ver = (pkey->key_data_length[1]) ?
				2 : 1;
			    akey->key_data_ver = (akey->key_data_length[1]) ?
				2 : 1;
			    if ((pkey->key_data_type[0] ==
				 akey->key_data_type[0]) &&
				(pkey->key_data_type[1] ==
				 akey->key_data_type[1]))
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
 * process_k5_record()	- Handle a dump record in new format.
 *
 * Returns -1 for end of file, 0 for success and 1 for failure.
 */
static int
process_k5_record(fname, kcontext, filep, verbose, linenop)
    char		*fname;
    krb5_context	kcontext;
    FILE		*filep;
    int			verbose;
    int			*linenop;
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
	if (!(name = (char *) malloc((size_t) t2)))
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
		nread = fscanf(filep, "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t",
			       &t1, &t2, &t3, &t4, &t5, &t6, &t7, &t8, &t9);
		if (nread == 9) {
		    dbentry.mkvno = (krb5_kvno) t1;
		    dbentry.attributes = (krb5_flags) t2;
		    dbentry.max_life = (krb5_deltat) t3;
		    dbentry.max_renewable_life = (krb5_deltat) t4;
		    dbentry.expiration = (krb5_timestamp) t5;
		    dbentry.pw_expiration = (krb5_timestamp) t6;
		    dbentry.last_success = (krb5_timestamp) t7;
		    dbentry.last_failed = (krb5_timestamp) t8;
		    dbentry.fail_auth_count = (krb5_kvno) t9;
		}
		else {
		    try2read = read_nint_data;
		    error++;
		}

		/* Get the tagged data */
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

/*
 * restore_k5beta_compat()	- Restore the database from a K5 Beta
 * 				  format dump file.
 */
static int
restore_k5beta_compat(programname, kcontext, dumpfile, f, verbose)
    const char		*programname;
    krb5_context	kcontext;
    const char		*dumpfile;
    FILE		*f;
    int			verbose;
{
    int		error;	
    int		lineno;
    char	buf[2*sizeof(k5beta_dump_header)];

    /*
     * Get/check the header.
     */
    error = 0;
    fgets(buf, sizeof(buf), f);
    if (!strcmp(buf, k5beta_dump_header)) {
	lineno = 1;
	/*
	 * Process the records.
	 */
	while (!(error = process_k5beta_record(dumpfile,
					       kcontext, 
					       f,
					       verbose,
					       &lineno)))
	    ;
	if (error != -1)
	    fprintf(stderr, err_line_fmt, programname, lineno, dumpfile);
	else
	    error = 0;

	/*
	 * Close the input file.
	 */
	if (f != stdin)
	    fclose(f);
    }
    else {
	fprintf(stderr, head_bad_fmt, programname, dumpfile);
	error++;
    }
    return(error);
}

/*
 * restore_dump()	- Restore the database from a standard dump file.
 */
static int
restore_dump(programname, kcontext, dumpfile, f, verbose)
    const char		*programname;
    krb5_context	kcontext;
    const char		*dumpfile;
    FILE		*f;
    int			verbose;
{
    int		error;	
    int		lineno;
    char	buf[2*sizeof(k5_dump_header)];

    /*
     * Get/check the header.
     */
    error = 0;
    fgets(buf, sizeof(buf), f);
    if (!strcmp(buf, k5_dump_header)) {
	lineno = 1;
	/*
	 * Process the records.
	 */
	while (!(error = process_k5_record(dumpfile,
					   kcontext, 
					   f,
					   verbose,
					   &lineno)))
	    ;
	if (error != -1)
	    fprintf(stderr, err_line_fmt, programname, lineno, dumpfile);
	else
	    error = 0;

	/*
	 * Close the input file.
	 */
	if (f != stdin)
	    fclose(f);
    }
    else {
	fprintf(stderr, head_bad_fmt, programname, dumpfile);
	error++;
    }
    return(error);
}

/*
 * Usage is
 * load_db [-old] [-verbose] [-update] filename dbname
 */
void
load_db(argc, argv)
    int		argc;
    char	**argv;
{
    krb5_error_code	kret;
    krb5_context	kcontext;
    FILE		*f;
    extern char		*optarg;
    extern int		optind;
    const char		*programname;
    const char		*dumpfile;
    char		*dbname;
    char		*dbname_tmp;
    int			(*restore_function) PROTOTYPE((const char *,
						       krb5_context,
						       const char *,
						       FILE *,
						       int));
    const char		* restore_name;
    int			update, verbose;
    int			aindex;

    /*
     * Parse the arguments.
     */
    programname = argv[0];
    if (strrchr(programname, (int) '/'))
	programname = strrchr(argv[0], (int) '/') + 1;
    dumpfile = (char *) NULL;
    dbname = (char *) NULL;
    restore_function = restore_dump;
    restore_name = standard_fmt_name;
    update = 0;
    verbose = 0;
    exit_status = 0;
    dbname_tmp = (char *) NULL;
    for (aindex = 1; aindex < argc; aindex++) {
	if (!strcmp(argv[aindex], oldoption)) {
	    restore_function = restore_k5beta_compat;
	    restore_name = k5beta_fmt_name;
	}
	else if (!strcmp(argv[aindex], verboseoption)) {
	    verbose = 1;
	}
	else if (!strcmp(argv[aindex], updateoption)) {
	    update = 1;
	}
	else
	    break;
    }
    if ((argc - aindex) != 2) {
	fprintf(stderr, lusage_err_fmt, argv[0], argv[0],
		oldoption, verboseoption, updateoption);
	exit_status++;
	return;
    }

    dumpfile = argv[aindex];
    dbname = argv[aindex+1];
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
    krb5_init_ets(kcontext);

    /*
     * Open the dumpfile
     */
    if (dumpfile) {
	if ((f = fopen(dumpfile, "r"))) {
	    kret = krb5_lock_file(kcontext, fileno(f), KRB5_LOCKMODE_SHARED);
	}
    }
    else {
	f = stdin;
    }
    if (f && !kret) {
	/*
	 * Create the new database if not an update restoration.
	 */
	if (update || !(kret = krb5_db_create(kcontext, dbname_tmp))) {
	    /*
	     * Point ourselves at it.
	     */
	    if (!(kret = krb5_db_set_name(kcontext,
					  (update) ? dbname : dbname_tmp))) {
		/*
		 * Initialize the database.
		 */
		if (!(kret = krb5_db_init(kcontext))) {
		    if ((*restore_function)(programname,
					    kcontext,
					    (dumpfile) ? dumpfile : stdin_name,
					    f,
					    verbose)) {
			fprintf(stderr, restfail_fmt,
				programname, restore_name);
			exit_status++;
		    }
		    if ((kret = krb5_db_fini(kcontext))) {
			fprintf(stderr, close_err_fmt,
				programname, error_message(kret));
			exit_status++;
		    }
		}
		else {
		    fprintf(stderr, dbinit_err_fmt,
			    programname, error_message(kret));
		    exit_status++;
		}
	    }
	    else {
		fprintf(stderr, dbname_err_fmt,
			programname, 
			(update) ? dbname : dbname_tmp, error_message(kret));
		exit_status++;
	    }
	    /*
	     * If there was an error and this is not an update, then
	     * destroy the database.
	     */
	    if (!update) {
		if (exit_status) {
		    if ((kret = kdb5_db_destroy(kcontext, dbname))) {
			fprintf(stderr, dbdelerr_fmt,
				programname, dbname_tmp, error_message(kret));
			exit_status++;
		    }
		}
		else {
		    if ((kret = krb5_db_rename(kcontext,
					       dbname_tmp,
					       dbname))) {
			fprintf(stderr, dbrenerr_fmt,
				programname, dbname, dbname_tmp,
				error_message(kret));
			exit_status++;
		    }
		}
	    }
	}
	else {
	    fprintf(stderr, dbcreaterr_fmt,
		    programname, dbname, error_message(kret));
	    exit_status++;
	}
	if (dumpfile) {
	    (void) krb5_lock_file(kcontext, fileno(f), KRB5_LOCKMODE_UNLOCK);
	    fclose(f);
	}
    }
    else {
	fprintf(stderr, dfile_err_fmt, dumpfile, error_message(errno));
	exit_status++;
    }
    free(dbname_tmp);
    krb5_free_context(kcontext);
}

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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * Dump a KDC database.  This file was originally written to be part
 * of kdb5_edit but has now been adapted for kadmin.
 */

#include <stdio.h>
#include <k5-int.h>
#include <kadm5/admin.h>

struct dump_args {
    char		*programname;
    FILE		*ofile;
    krb5_context	context;
    int			verbose;
};

/* External data */
extern int		exit_status;
extern krb5_context	context;
extern void		*handle;

/* Strings */

static const char k5beta5_dump_header[] = "kdb5_edit load_dump version 2.0\n";
static const char k5_dump_header[] = "kdb5_edit load_dump version 3.0\n";
static const char kadm5_dump_header[] = "kadm5 load_dump version 4.0\n";

static const char null_mprinc_name[] = "kdb5_dump@MISSING";

/* Message strings */
static const char regex_err[] = "%s: regular expression error - %s\n";
static const char regex_merr[] = "%s: regular expression match error - %s\n";
static const char pname_unp_err[] = "%s: cannot unparse principal name (%s)\n";
static const char mname_unp_err[] = "%s: cannot unparse modifier name (%s)\n";
static const char nokeys_err[] = "%s: cannot find any standard key for %s\n";
static const char sdump_tl_inc_err[] = "%s: tagged data list inconsistency for %s (counted %d, stored %d)\n";
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
static const char k5beta5_fmt_name[] = "Kerberos version 5 old format";
static const char k5beta6_fmt_name[] = "Kerberos version 5 beta 6 format";
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
static const char hashoption[] = "-hash";
static const char dump_tmptrail[] = "~";

/* Can't use krb5_dbe_find_enctype because we have a */
/* kadm5_principal_ent_t and not a krb5_db_entry */
static krb5_error_code
find_enctype(dbentp, enctype, salttype, kentp)
    kadm5_principal_ent_rec *dbentp;
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
	if ((dbentp->key_data[i].key_data_type[0] == enctype) &&
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
 * dump_k5beta5_header()	- Make a dump header that is recognizable by Kerberos
 *			  Version 5 Beta 5 and previous releases.
 */
static krb5_error_code
dump_k5beta5_header(arglist)
    struct dump_args *arglist;
{
    /* The old header consists of the leading string */
    fprintf(arglist->ofile, k5beta5_dump_header);
    return(0);
}


/*
 * dump_k5beta5_iterator()	- Dump an entry in a format that is usable
 *				  by Kerberos Version 5 Beta 5 and previous
 *				  releases.
 */
static krb5_error_code
dump_k5beta5_iterator(ptr, name, entry)
    krb5_pointer	ptr;
    char		*name;
    kadm5_principal_ent_rec *entry;
{
    krb5_error_code	retval;
    struct dump_args	*arg;
    char		*mod_name;
    krb5_tl_data	*pwchg;
    krb5_key_data	*pkey, *akey, nullkey;
    int			i;

    /* Initialize */
    arg = (struct dump_args *) ptr;
    mod_name = (char *) NULL;
    memset(&nullkey, 0, sizeof(nullkey));

    /*
     * Deserialize the modifier record.
     */
    mod_name = (char *) NULL;
    pkey = akey = (krb5_key_data *) NULL;

    /*
     * Flatten the modifier name.
     */
    if ((retval = krb5_unparse_name(arg->context,
				    entry->mod_name,
				    &mod_name)))
	 fprintf(stderr, mname_unp_err, arg->programname,
		 error_message(retval));

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
	    1 /* Fake mkvno */, entry->princ_expire_time, entry->pw_expiration,
	    entry->last_pwd_change, entry->last_success, entry->last_failed,
	    entry->fail_auth_count, mod_name, entry->mod_date,
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

    return(0);
}


/*
 * dump_k5beta6_header()	- Output the k5beta6 dump header.
 */
static krb5_error_code
dump_k5beta6_header(arglist)
    struct dump_args *arglist;
{
    /* The k5beta6 header consists of the leading string */
    fprintf(arglist->ofile, k5_dump_header);
    return(0);
}


/*
 * dump_k5beta6_iterator()	- Output a dump record in k5beta6 format.
 */
static krb5_error_code
dump_k5beta6_iterator(ptr, name, entry)
    krb5_pointer	ptr;
    char		*name;
    kadm5_principal_ent_rec *entry;
{
    krb5_error_code	retval = 0;
    struct dump_args	*arg;
    krb5_tl_data	*tlp, *etl;
    krb5_key_data	*kdata;
    int			counter, i, j;

    /* Initialize */
    arg = (struct dump_args *) ptr;

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
     * verbatim.  Bracketed fields absence is indicated by a -1 in its
     * place
     */

    /*
     * Make sure that the tagged list is reasonably correct, and find
     * E_DATA while we're at it.
     */
    counter = 0;
    etl = NULL;
    for (tlp = entry->tl_data; tlp; tlp = tlp->tl_data_next) {
	 if (tlp->tl_data_type == KRB5_TL_KADM5_E_DATA)
	      etl = tlp;
	 counter++;
    }
    
    if (counter == entry->n_tl_data) {
	 /* Pound out header */
	 fprintf(arg->ofile, "%d\t%d\t%d\t%d\t%d\t%s\t",
		 KRB5_KDB_V1_BASE_LENGTH + (etl ? etl->tl_data_length : 0), 
		 strlen(name),
		 (int) entry->n_tl_data,
		 (int) entry->n_key_data,
		 etl ? etl->tl_data_length : 0,
		 name);
	 fprintf(arg->ofile, "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t",
		 entry->attributes,
		 entry->max_life,
		 entry->max_renewable_life,
		 entry->princ_expire_time,
		 entry->pw_expiration,
		 entry->last_success,
		 entry->last_failed,
		 entry->fail_auth_count);
	 /* Pound out tagged data. */
	 for (tlp = entry->tl_data; tlp; tlp = tlp->tl_data_next) {
	      /* skip E_DATA since it is included later */
	      if (tlp->tl_data_type == KRB5_TL_KADM5_E_DATA)
		   continue;
	      
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
	 if (etl && etl->tl_data_length)
	      for (i=0; i<etl->tl_data_length; i++)
		   fprintf(arg->ofile, "%02x", etl->tl_data_contents[i]);
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
    return(retval);
}


/*
 * usage is:
 *	dump_db [-old] [-verbose] [filename|- [principals...]]
 */
void dump_db(argc, argv)
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
						    char *,
						    kadm5_principal_ent_rec *));
    krb5_error_code	(*dump_header) PROTOTYPE((struct dump_args *));
    const char		* dump_name;
    int			aindex, num, i;
    krb5_boolean	locked;
    char		**princs;
    kadm5_principal_ent_rec princ_ent;
    krb5_principal	princ;
	
    /*
     * Parse the arguments.
     */
    programname = argv[0];
    if (strrchr(programname, (int) '/'))
	programname = strrchr(argv[0], (int) '/') + 1;
    ofile = (char *) NULL;
    error = 0;
    dump_iterator = dump_k5beta6_iterator;
    dump_header = dump_k5beta6_header;
    dump_name = k5beta6_fmt_name;
    arglist.verbose = 0;

    memset(&princ_ent, 0, sizeof(princ));

    /*
     * Parse the qualifiers.
     */
    for (aindex = 1; aindex < argc; aindex++) {
	if (!strcmp(argv[aindex], oldoption)) {
	    dump_iterator = dump_k5beta5_iterator;
	    dump_header = dump_k5beta5_header;
	    dump_name = k5beta5_fmt_name;
        }
	else if (!strcmp(argv[aindex], verboseoption)) {
	    arglist.verbose++;
	}
	else
	    break;
    }

    if (aindex < argc) {
	ofile = argv[aindex];
	aindex++;
    }

    /* this works because of the way aindex and argc are used below */
    if (aindex == argc) {
	 argv[aindex] = "*";
	 argc++;
    }

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
	    goto cleanup;
	}
	if ((kret = krb5_lock_file(context,
				   fileno(f),
				   KRB5_LOCKMODE_EXCLUSIVE))) {
	    fprintf(stderr, oflock_error,
		    programname, ofile, error_message(kret));
	    exit_status++;
	    goto cleanup;
	}
	else
	    locked = 1;
    } else {
	f = stdout;
    }
    
    arglist.programname = programname;
    arglist.ofile = f;
    arglist.context = context;

    if (kret = (*dump_header)(&arglist)) {
	 fprintf(stderr, dumphdr_err,
		 programname, dump_name, error_message(kret));
	 exit_status++;
	 goto cleanup;
    }

    while (aindex < argc) {
	 if (kret = kadm5_get_principals(handle, argv[aindex],
					 &princs, &num)) {
	      fprintf(stderr, "%s: error retrieving principals "
		      "matching %s: (%s)\n", programname,
		      argv[aindex], error_message(kret));
	      exit_status++;
	      goto cleanup;
	 }

	 for (i = 0; i < num; i++) {
	      if (kret = krb5_parse_name(context, princs[i],
					 &princ)) {
		   com_err(programname, kret,
			   "while parsing principal name");
		   exit_status++;
		   break;
	      }
	      if (kret = kadm5_get_principal(handle, princ,
					     &princ_ent,
					     KADM5_PRINCIPAL_NORMAL_MASK |
					     KADM5_KEY_DATA|KADM5_TL_DATA)){
		   com_err(programname, kret,
			   "while retrieving principal entry");
		   krb5_free_principal(context, princ);
		   exit_status++;
		   break;
	      }
	      if (kret = (*dump_iterator)(&arglist, princs[i], &princ_ent)) {
		   exit_status++;
		   krb5_free_principal(context, princ);
		   kadm5_free_principal_ent(handle, &princ_ent);
		   break;
	      }
	      
	      krb5_free_principal(context, princ);
	      kadm5_free_principal_ent(handle, &princ_ent);
	 }
	 
	 kadm5_free_name_list(handle, princs, num);
	 aindex++;
	 if (kret)
	      goto cleanup;
    }

cleanup:
    if (ofile)
	 fclose(f);
    
    if (locked)
	(void) krb5_lock_file(context, fileno(f), KRB5_LOCKMODE_UNLOCK);
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

#if 0
/*
 * process_k5beta5_record()	- Handle a dump record in old format.
 *
 * Returns -1 for end of file, 0 for success and 1 for failure.
 */
static int
process_k5beta5_record(fname, context, filep, verbose, linenop)
    char		*fname;
    krb5_context	context;
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
    if (krb5_dbe_create_key_data(context, &dbent) ||
	krb5_dbe_create_key_data(context, &dbent)) {
	krb5_db_free_principal(context, &dbent, 1);
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
	      char *shortcopy = (krb5_octet *) malloc(shortlen);
	      char *origdata = pkey->key_data_contents[0];
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
	      char *shortcopy = (krb5_octet *) malloc(shortlen);
	      char *origdata = akey->key_data_contents[0];
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
		if (!(kret = krb5_parse_name(context,
					     name,
					     &dbent.princ))) {
		    if (!(kret = krb5_parse_name(context,
						 mod_name,
						 &mod_princ))) {
			if (!(kret =
			      krb5_dbe_update_mod_princ_data(context,
							     &dbent,
							     mod_date,
							     mod_princ)) &&
			    !(kret =
			      krb5_dbe_update_last_pwd_change(context,
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
			    if ((kret = krb5_db_put_principal(context,
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
			krb5_free_principal(context, mod_princ);
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

	krb5_db_free_principal(context, &dbent, 1);
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
process_k5_record(fname, context, filep, verbose, linenop)
    char		*fname;
    krb5_context	context;
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
		!(kret = krb5_parse_name(context, name, &dbentry.princ))) {

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
		    if ((kret = krb5_db_put_principal(context,
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
	krb5_db_free_principal(context, &dbentry, 1);
    }
    else {
	if (nread == EOF)
	    retval = -1;
    }
    return(retval);
}


/*
 * restore_k5beta5_compat()	- Restore the database from a K5 Beta
 * 				  format dump file.
 */
static int
restore_k5beta5_compat(programname, context, dumpfile, f, verbose)
    const char		*programname;
    krb5_context	context;
    const char		*dumpfile;
    FILE		*f;
    int			verbose;
{
    int		error;	
    int		lineno;
    char	buf[2*sizeof(k5beta5_dump_header)];

    /*
     * Get/check the header.
     */
    error = 0;
    fgets(buf, sizeof(buf), f);
    if (!strcmp(buf, k5beta5_dump_header)) {
	lineno = 1;
	/*
	 * Process the records.
	 */
	while (!(error = process_k5beta5_record(dumpfile,
					       context, 
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
restore_dump(programname, context, dumpfile, f, verbose)
    const char		*programname;
    krb5_context	context;
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
					   context, 
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
 * load_db [-old] [-verbose] [-update] [-hash] filename dbname
 */
void
load_db(argc, argv)
    int		argc;
    char	**argv;
{
    krb5_error_code	kret;
    krb5_context	context;
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
    krb5_int32		crflags;
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
    crflags = KRB5_KDB_CREATE_BTREE;
    exit_status = 0;
    dbname_tmp = (char *) NULL;
    for (aindex = 1; aindex < argc; aindex++) {
	if (!strcmp(argv[aindex], oldoption)) {
	    restore_function = restore_k5beta5_compat;
	    restore_name = k5beta5_fmt_name;
	}
	else if (!strcmp(argv[aindex], verboseoption)) {
	    verbose = 1;
	}
	else if (!strcmp(argv[aindex], updateoption)) {
	    update = 1;
	}
	else if (!strcmp(argv[aindex], hashoption)) {
	    crflags = KRB5_KDB_CREATE_HASH;
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
    if ((kret = krb5_init_context(&context))) {
	fprintf(stderr, ctx_err_fmt, programname);
	free(dbname_tmp);
	exit_status++;
	return;
    }

    /*
     * Open the dumpfile
     */
    if (dumpfile) {
	if ((f = fopen(dumpfile, "r+"))) {
	    kret = krb5_lock_file(context, fileno(f), KRB5_LOCKMODE_SHARED);
	}
    }
    else {
	f = stdin;
    }
    if (f && !kret) {
	/*
	 * Create the new database if not an update restoration.
	 */
	if (update || !(kret = krb5_db_create(context, dbname_tmp, crflags))) {
	    /*
	     * Point ourselves at it.
	     */
	    if (!(kret = krb5_db_set_name(context,
					  (update) ? dbname : dbname_tmp))) {
		/*
		 * Initialize the database.
		 */
		if (!(kret = krb5_db_init(context))) {
		    if ((*restore_function)(programname,
					    context,
					    (dumpfile) ? dumpfile : stdin_name,
					    f,
					    verbose)) {
			fprintf(stderr, restfail_fmt,
				programname, restore_name);
			exit_status++;
		    }
		    if ((kret = krb5_db_fini(context))) {
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
		    if ((kret = krb5_db_destroy(context, dbname))) {
			fprintf(stderr, dbdelerr_fmt,
				programname, dbname_tmp, error_message(kret));
			exit_status++;
		    }
		}
		else {
		    if ((kret = krb5_db_rename(context,
					       dbname_tmp,
					       dbname))) {
			fprintf(stderr, dbrenerr_fmt,
				programname, dbname_tmp, dbname,
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
	    (void) krb5_lock_file(context, fileno(f), KRB5_LOCKMODE_UNLOCK);
	    fclose(f);
	}
    }
    else {
	fprintf(stderr, dfile_err_fmt, dumpfile, error_message(errno));
	exit_status++;
    }
    free(dbname_tmp);
    krb5_free_context(context);
}
#endif
